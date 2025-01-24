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
	"path/filepath"
	"runtime"
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

const (
	policyBasePath   = "policies/V8-policy.json"
	cacheBasePath    = "src/V8-cache.json"
	advisoryBasePath = "advisories/V8-advisory.json"
)

var (
	now          = time.Now()
	nowTimestamp = now.Format(time.RFC3339)
	today        = format(now)
	dir          string
	policyPath   string
	cachePath    string
	advisoryPath string
)

type Repositories interface {
	ListCommits(ctx context.Context, owner, repo string, opts *github.CommitsListOptions) ([]*github.RepositoryCommit, *github.Response, error)
}

func main() {
	// Construct absolute path of the runner.
	_, filename, _, _ := runtime.Caller(0)
	dir = filepath.Dir(filename)

	workspace := os.Getenv("GITHUB_WORKSPACE")
	fmt.Println("GITHUB_WORKSPACE:", workspace)

	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	fmt.Println("PWD:", dir)

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
	client := github.NewClient(nil)
	cache, err = updateCache(policy.Repository, client.Repositories, policy.Branches, cache)
	if err != nil {
		panic(err)
	}

	advisory, err = updateAdvisory(advisory, policy, cache)
	if err != nil {
		panic(err)
	}

	if err = saveAdvisory(advisory); err != nil {
		panic(err)
	}

	if err = saveCache(cache); err != nil {
		panic(err)
	}

	fmt.Println("Advisory data saved to " + advisoryPath)
}

func loadPolicy() (*Policy, error) {
	policyPath = filepath.Join(dir, "../", policyBasePath)
	fmt.Printf("policyPath: %q\n", policyPath)
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
	cachePath = filepath.Join(dir, "../", cacheBasePath)
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

func saveCache(cacheData map[string][]string) error {
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
	advisoryPath = filepath.Join(dir, "../", advisoryBasePath)
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

// updateAdvisory updates Advisory fields with the latest vulnerable ranges information.
func updateAdvisory(advisory *Advisory, policy *Policy, cache map[string][]string) (*Advisory, error) {
	hashes, err := getCacheEntry(cache, policy.FreshnessDays)
	if err != nil {
		return nil, fmt.Errorf("failed to get cache entry: %w", err)
	}

	affectedItem, err := createAffectedItem(policy, hashes)
	if err != nil {
		return nil, fmt.Errorf("failed to create AffectedItem: %w", err)
	}

	if advisory.Published == "" {
		advisory.Published = nowTimestamp
	}

	advisory.ID = policy.ID
	advisory.Modified = nowTimestamp
	advisory.Summary = policy.PolicyLink
	advisory.Details = policy.Description
	advisory.Affected = []AffectedItem{*affectedItem}

	return advisory, nil
}

// saveAdvisory stores the advisory into the advisory file.
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

// updateCache polls the requested repository's branches' latest commit hashes and stores them in the cache.
func updateCache(repoURL string, repos Repositories, branches []string, cache map[string][]string) (map[string][]string, error) {
	s := strings.Split(repoURL, "/")
	owner := s[len(s)-2]
	repoName := s[len(s)-1]
	hashes := make(map[string]bool)
	for _, branchName := range branches {
		listOptions := &github.CommitsListOptions{
			SHA: branchName,
		}

		commits, _, err := repos.ListCommits(context.Background(), owner, repoName, listOptions)
		if err != nil {
			return nil, err
		}
		// Get the latest commit of this branch.
		hashes[*commits[0].SHA] = true
	}

	uniqueHashes := make([]string, 0, len(hashes))
	for key := range hashes {
		uniqueHashes = append(uniqueHashes, key)
	}
	today := today
	cache[today] = uniqueHashes

	return cache, nil
}

func createAffectedItem(policy *Policy, hashes []string) (*AffectedItem, error) {
	fixedEvents := make([]Event, len(hashes))

	for i, hash := range hashes {
		fixedEvents[i] = Event{Fixed: hash}
	}

	affectedItem := AffectedItem{
		Ranges: []Range{{
			Type:   "GIT",
			Repo:   policy.Repository,
			Events: append([]Event{{Introduced: "0"}}, fixedEvents...),
		}},
	}

	return &affectedItem, nil
}

func getCacheEntry(cache map[string][]string, d int) ([]string, error) {
	if d < 0 {
		return nil, fmt.Errorf("can only get cache entries with a positive days difference")
	}
	if cache[today] == nil {
		return nil, fmt.Errorf("today's entry must exist in the cache")
	}
	targetDate := format(time.Now().AddDate(0, 0, -d))

	if hashes, ok := cache[targetDate]; ok {
		return hashes, nil
	}

	// No entry found for the target date, try closer dates.
	for i := d - 1; i >= 0; i-- {
		targetDate = format(time.Now().AddDate(0, 0, -i))
		if hashes, ok := cache[targetDate]; ok {
			return hashes, nil
		}
	}

	// Today's entry definitely exists, since we added that.
	return cache[today], nil
}

func format(t time.Time) string {
	return t.Format("2006-01-02")
}
