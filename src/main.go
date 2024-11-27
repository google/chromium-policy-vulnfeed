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
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []Range `json:"ranges"`
}

type Advisory struct {
	SchemaVersion string   `json:"schema_version"`
	ID            string   `json:"id"`
	Modified      string   `json:"modified"`
	Published     string   `json:"published"`
	Aliases       []string `json:"aliases"`
	Summary       string   `json:"summary"`
	Details       string   `json:"details"`
	Affected      []AffectedItem
}

func main() {
	policy, err := loadPolicy("policies/v8-policy.json")
	if err != nil {
		panic(err)
	}

	advisory, err := loadAdvisory("advisories/V8_advisory.json")
	if err != nil {
		panic(err)
	}

	advisory = updateAdvisory(advisory, policy)

	client := github.NewClient(nil)
	affected, err := generateAffectedItems(client, policy)
	if err != nil {
		panic(err)
	}
	advisory.Affected = affected

	err = saveAdvisory("advisories/V8_advisory.json", advisory)
	if err != nil {
		panic(err)
	}

	fmt.Println("Advisory data saved to advisories/V8_advisory.json")
}

func loadPolicy(policyPath string) (*Policy, error) {
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

func loadAdvisory(advisoryPath string) (*Advisory, error) {
	advisoryData, err := os.ReadFile(advisoryPath)
	var advisory Advisory
	if err == nil {
		err = json.Unmarshal(advisoryData, &advisory)
		if err != nil {
			return nil, err
		}
	} else if os.IsNotExist(err) {
		currentTime := time.Now().Format(time.RFC3339)
		advisory = Advisory{
			Published: currentTime,
		}
	} else {
		// Some other error occurred while reading the file
		return nil, err
	}

	return &advisory, nil
}

func updateAdvisory(advisory *Advisory, policy *Policy) *Advisory {
	currentTime := time.Now()
	timestamp := currentTime.Format(time.RFC3339)

	if advisory.Published == "" {
		advisory.Published = timestamp
	}

	advisory.ID = policy.ID
	advisory.Modified = timestamp
	advisory.Summary = policy.PolicyLink
	advisory.Details = policy.Description
	advisory.Affected = nil
	advisory.Aliases = nil

	return advisory
}

func generateAffectedItems(client *github.Client, policy *Policy) ([]AffectedItem, error) {
	repoURL := policy.Repository
	parts := strings.Split(repoURL, "/")
	owner := parts[len(parts)-2]
	repoName := parts[len(parts)-1]

	sinceDate := time.Now().AddDate(0, 0, -policy.FreshnessDays)

	var affectedItems []AffectedItem
	for _, branch := range policy.Branches {

		listOptions := &github.CommitsListOptions{
			SHA:   branch,
			Since: sinceDate,
		}

		repoLink := repoURL + "/tree/" + branch

		commits, _, err := client.Repositories.ListCommits(context.Background(), owner, repoName, listOptions)
		if err != nil {
			return nil, err
		}

		affectedItem, err := processBranch(repoLink, commits)
		if err != nil {
			return nil, err
		}
		if affectedItem != nil {
			affectedItems = append(affectedItems, *affectedItem)
		}
	}
	return affectedItems, nil
}

func saveAdvisory(advisoryPath string, advisory *Advisory) error {
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

func processBranch(repoLink string, commits []*github.RepositoryCommit) (*AffectedItem, error) {
	if len(commits) > 0 {
		// Get the oldest commit within the timeframe
		oldestCommit := commits[len(commits)-1]
		commitSHA := oldestCommit.GetSHA()
		commitDate := oldestCommit.GetCommit().GetCommitter().GetDate().Format("2006-01-02")
		//commitTitle := oldestCommit.GetCommit().GetMessage()
		fmt.Println("Commit Date:", commitDate, ", SHA:", commitSHA)

		affectedRange := Range{
			Type: "GIT",
			Repo: repoLink,
			Events: []Event{
				{
					Introduced: "0",
				},
				{
					Fixed: commitSHA,
				},
			},
		}

		affectedItem := AffectedItem{
			Package: struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			}{
				Name:      "V8",
				Ecosystem: "Chrome",
			},
			Ranges: []Range{affectedRange},
		}

		return &affectedItem, nil

	} else {
		fmt.Println("No commits found within the specified timeframe.")
		return nil, nil
	}
}
