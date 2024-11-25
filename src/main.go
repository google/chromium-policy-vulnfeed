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
	} else if !os.IsNotExist(err) {
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

	advisory.SchemaVersion = "1.4.0"
	advisory.ID = policy.ID
	advisory.Modified = timestamp
	advisory.Summary = policy.PolicyLink
	advisory.Details = "Known exploits stem from outdated V8 versions. Please make sure your repository follows the policy at " + policy.PolicyLink + ". Specifically, track either the stable, beta or extended stable branch and update at least weekly."
	advisory.Affected = nil

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
