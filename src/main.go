package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/go-github/v66/github"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Policy struct {
	ID            string `json:"id"`
	Repository    string `json:"repository"`
	FreshnessDays int    `json:"freshness_days"`
	PolicyLink    string `json:"policy_link"`
	Description   string `json:"description"`
}

type Range struct {
	Type   string `json:"type"`
	Events []struct {
		Introduced   string `json:"introduced"`
		Fixed        string `json:"fixed"`
		LastAffected string `json:"last_affected"`
	} `json:"events"`
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

var supportedBranches = []string{"stable", "beta"}

func main() {
	policyPath := filepath.Join("policies", "v8-policy.json")
	data, err := os.ReadFile(policyPath)
	if err != nil {
		panic(err)
	}

	var policy Policy
	err = json.Unmarshal(data, &policy)
	if err != nil {
		panic(err)
	}

	currentTime := time.Now()
	timestamp := currentTime.Format(time.RFC3339)

	advisoryPath := filepath.Join("advisories", "V8_advisory.json")
	advisoryData, err := os.ReadFile(advisoryPath)
	var advisory Advisory
	if err == nil {
		// If the file exists, unmarshal the existing data
		err = json.Unmarshal(advisoryData, &advisory)
		if err != nil {
			panic(err)
		}
	} else if !os.IsNotExist(err) {
		// Panic only if the error is something other than file not existing
		panic(err)
	}

	if advisory.Published == "" {
		// If Published is empty (i.e., new advisory), set it to the current timestamp
		advisory.Published = timestamp
	}

	advisory.SchemaVersion = "1.4.0"
	advisory.ID = policy.ID
	advisory.Modified = timestamp
	advisory.Summary = policy.PolicyLink
	advisory.Details = "Known exploits stem from outdated V8 versions. Please make sure your repository follows the policy at " + policy.PolicyLink + ". Specifically, track either the stable, beta or extended stable branch and update at least weekly."
	advisory.Affected = nil

	client := github.NewClient(nil)
	repoURL := policy.Repository
	parts := strings.Split(repoURL, "/")
	owner := parts[len(parts)-2]
	repoName := parts[len(parts)-1]

	sinceDate := time.Now().AddDate(0, 0, -policy.FreshnessDays)

	for _, branch := range supportedBranches {

		listOptions := &github.CommitsListOptions{
			SHA:   branch,
			Since: sinceDate,
		}

		commits, _, err := client.Repositories.ListCommits(context.Background(), owner, repoName, listOptions)
		if err != nil {
			panic(err)
		}
		processBranch(commits, &advisory)
	}
	advisoryJSON, err := json.MarshalIndent(advisory, "", "  ")
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(advisoryPath, advisoryJSON, 0644)
	if err != nil {
		panic(err)
	}

	fmt.Println("Advisory data saved to", advisoryPath)
}

func processBranch(commits []*github.RepositoryCommit, advisory *Advisory) {
	if len(commits) > 0 {
		// Get the oldest commit within the timeframe
		oldestCommit := commits[len(commits)-1]
		commitSHA := oldestCommit.GetSHA()
		commitDate := oldestCommit.GetCommit().GetCommitter().GetDate().Format("2006-01-02")
		//commitTitle := oldestCommit.GetCommit().GetMessage()
		fmt.Println("Commit Date:", commitDate, ", SHA:", commitSHA)

		affectedRange := Range{
			Type: "GIT",
			Events: []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			}{
				{
					Introduced:   "0000000",
					Fixed:        commitSHA,
					LastAffected: "",
				},
			},
		}

		affectedItem := AffectedItem{
			Package: struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			}{
				Name:      "V8",
				Ecosystem: "OSS-Fuzz",
			},
			Ranges: []Range{affectedRange},
		}

		advisory.Affected = append(advisory.Affected, affectedItem)

	} else {
		fmt.Println("No commits found within the specified timeframe.")
	}
}
