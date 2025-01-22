// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/v66/github"
)

type Policy struct {
	ID            string   `json:"id"`
	Repository    string   `json:"repository"`
	FreshnessDays int      `json:"freshness_days"`
	PolicyLink    string   `json:"policy_link"`
	Description   string   `json:"description"`
	Branches      []string `json:"branches"`
}

type Event struct {
	Fixed      string `json:"fixed,omitempty"`
	Introduced string `json:"introduced,omitempty"`
}

type Range struct {
	Type   string  `json:"type"`
	Repo   string  `json:"repo"`
	Events []Event `json:"events"`
}

type AffectedItem struct {
	Ranges []Range `json:"ranges"`
}

type Advisory struct {
	SchemaVersion string         `json:"schema_version"`
	ID            string         `json:"id"`
	Modified      string         `json:"modified"`
	Published     string         `json:"published"`
	Summary       string         `json:"summary"`
	Details       string         `json:"details"`
	Affected      []AffectedItem `json:"affected"`
}

var now = time.Now()
var nowTimestamp = now.Format(time.RFC3339)

var policyPath = "policies/V8-policy.json"
var cachePath = "src/V8-cache.json"
var advisoryPath = "advisories/V8-advisory.json"

func main() {
	policy, err := loadPolicy()
	if err != nil {
		panic(err)
	}

	cache, err := loadCache()
	if err != nil {
		panic(err)
	}

	advisory, err := loadAdvisory()
	if err != nil {
		panic(err)
	}

	cache, err = updateCache(policy.Repository, policy.Branches, cache)
	if err != nil {
		panic(err)
	}

	advisory = updateAdvisory(advisory, policy, cache)

	if err := saveAdvisory(advisory); err != nil {
		panic(err)
	}

	if err := saveCache(cache, policy); err != nil {
		panic(err)
	}

	fmt.Println("Advisory data saved to " + advisoryPath)
}

func loadPolicy() (*Policy, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, err
	}

	var policy Policy
	err = json.Unmarshal(data, &policy)
	if err != nil {
		return nil, err
	}

	return &policy, nil
}

func loadCache() (map[string][]string, error) {
	cacheData := make(map[string][]string)
	data, err := os.ReadFile(cachePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("error reading cache file: %w", err)
		}
		return cacheData, nil
	}
	err = json.Unmarshal(data, &cacheData)
	if err != nil {
		return nil, fmt.Errorf("error parsing cache file: %w", err)
	}
	return cacheData, nil
}

func saveCache(cacheData map[string][]string, policy *Policy) error {

	updatedData, err := json.MarshalIndent(cacheData, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling cache data: %w", err)
	}
	err = os.WriteFile(cachePath, updatedData, 0644)
	if err != nil {
		return fmt.Errorf("error writing cache file: %w", err)
	}
	return nil
}

func loadAdvisory() (*Advisory, error) {
	advisoryData, err := os.ReadFile(advisoryPath)
	var advisory Advisory
	if err == nil {
		err = json.Unmarshal(advisoryData, &advisory)
		if err != nil {
			return nil, err
		}
	} else if os.IsNotExist(err) {
		advisory = Advisory{
			Published: nowTimestamp,
		}
	} else {
		// Some other error occurred while reading the file
		return nil, err
	}

	return &advisory, nil
}

func updateAdvisory(advisory *Advisory, policy *Policy, cache map[string][]string) *Advisory {

	affectedItem, err := createAffectedItem(policy, cache)
	if err != nil {
		panic(err)
	}

	if advisory.Published == "" {
		advisory.Published = nowTimestamp
	}

	advisory.ID = policy.ID
	advisory.Modified = nowTimestamp
	advisory.Summary = policy.PolicyLink
	advisory.Details = policy.Description
	advisory.Affected = []AffectedItem{*affectedItem}

	return advisory
}

func saveAdvisory(advisory *Advisory) error {
	advisoryJSON, err := json.MarshalIndent(advisory, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(advisoryPath, advisoryJSON, 0644)
	if err != nil {
		return err
	}

	return nil
}

func updateCache(repoURL string, branches []string, cache map[string][]string) (map[string][]string, error) {
	client := github.NewClient(nil)
	parts := strings.Split(repoURL, "/")
	owner := parts[len(parts)-2]
	repoName := parts[len(parts)-1]
	hashes := make([]string, len(branches))

	for i, branchName := range branches {
		listOptions := &github.CommitsListOptions{
			SHA: branchName,
		}

		commits, _, err := client.Repositories.ListCommits(context.Background(), owner, repoName, listOptions)
		if err != nil {
			return nil, err
		}

		hashes[i] = *commits[0].SHA
	}

	today := now.Format("2006-01-02")
	cache[today] = hashes

	return cache, nil
}

func createAffectedItem(policy *Policy, cache map[string][]string) (*AffectedItem, error) {

	hashes, err := getCacheEntry(cache, policy.FreshnessDays)
	if err != nil {
		panic(err)
	}

	fixedEvents := make([]Event, len(hashes))

	for i, hash := range hashes {
		fixedEvents[i] = Event{Fixed: hash}
	}

	r := Range{
		Type:   "GIT",
		Repo:   policy.Repository,
		Events: append([]Event{{Introduced: "0"}}, fixedEvents...),
	}

	affectedItem := AffectedItem{
		Ranges: []Range{r},
	}

	return &affectedItem, nil
}

func getCacheEntry(cache map[string][]string, d int) ([]string, error) {
	targetDate := time.Now().AddDate(0, 0, -d).Format("2006-01-02")

	if hashes, ok := cache[targetDate]; ok {
		return hashes, nil
	}

	// No entry found for the target date, try closer dates.
	for i := d - 1; i >= 0; i-- {
		targetDate = time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		if hashes, ok := cache[targetDate]; ok {
			return hashes, nil
		}
	}

	// Today's entry definitely exists, since we added that.
	return cache[now.Format("2006-01-02")], nil
}
