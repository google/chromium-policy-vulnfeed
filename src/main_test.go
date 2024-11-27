package main

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

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-github/v66/github"
)

func TestProcessBranch(t *testing.T) {
	t.Run("with commits", func(t *testing.T) {
		commits := []*github.RepositoryCommit{
			{
				SHA: github.String("mockSHA"),
				Commit: &github.Commit{
					Committer: &github.CommitAuthor{
						Date: &github.Timestamp{
							Time: time.Now(),
						},
					},
				},
			},
		}

		affectedItem, err := processBranch("mock-repo/tree/mock-branch", commits)
		if err != nil {
			t.Fatalf("processBranch returned an error: %v", err)
		}

		if affectedItem == nil {
			t.Fatal("Expected an affected item, but got nil")
		}

		if affectedItem.Ranges[0].Events[0].Introduced != "0" {
			t.Error("Expected introduced to be 0")
		}

		if affectedItem.Ranges[0].Events[1].Fixed != "mockSHA" {
			t.Error("Expected fixed to be mockSHA")
		}

		if affectedItem.Ranges[0].Repo != "mock-repo/tree/mock-branch" {
			t.Error("Expected repo to be mock-repo/tree/mock-branch")
		}
	})
}

func TestLoadPolicy(t *testing.T) {
	t.Run("valid policy file", func(t *testing.T) {
		tmpfile, err := os.CreateTemp("", "policy.json")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpfile.Name())

		policyJSON := []byte(`{"id": "test-id", "repository": "test-repo", "freshness_days": 1, "policy_link": "test-link", "description": "test-description", "branches": ["main"]}`)
		if _, err := tmpfile.Write(policyJSON); err != nil {
			t.Fatal(err)
		}
		if err := tmpfile.Close(); err != nil {
			t.Fatal(err)
		}

		policy, err := loadPolicy(tmpfile.Name())
		if err != nil {
			t.Fatalf("loadPolicy returned an error: %v", err)
		}

		if policy.ID != "test-id" {
			t.Errorf("Expected ID to be test-id, got %s", policy.ID)
		}
		if policy.FreshnessDays != 1 {
			t.Errorf("Expected freshness-days to be 1, got %d", policy.FreshnessDays)
		}
	})

	t.Run("invalid policy file", func(t *testing.T) {
		tmpfile, err := os.CreateTemp("", "policy.json")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpfile.Name())

		if _, err := tmpfile.Write([]byte(`{"id": "test-id"`)); err != nil {
			t.Fatal(err)
		}
		if err := tmpfile.Close(); err != nil {
			t.Fatal(err)
		}

		_, err = loadPolicy(tmpfile.Name())
		if err == nil {
			t.Error("Expected loadPolicy to return an error, but got nil")
		}
	})

	t.Run("missing policy file", func(t *testing.T) {
		_, err := loadPolicy("non-existent.json")
		if err == nil {
			t.Error("Expected loadPolicy to return an error, but got nil")
		}
	})
}

func TestLoadAdvisory(t *testing.T) {
	t.Run("valid advisory file", func(t *testing.T) {
		tmpfile, err := os.CreateTemp("", "advisory.json")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpfile.Name())

		advisoryJSON := []byte(`{"schema_version": "1.4.0", "id": "test-id", "modified": "2024-11-25T12:00:00Z", "published": "2024-11-24T12:00:00Z", "aliases": ["test-alias"], "summary": "test-summary", "details": "test-details", "affected": []}`)
		if _, err := tmpfile.Write(advisoryJSON); err != nil {
			t.Fatal(err)
		}
		if err := tmpfile.Close(); err != nil {
			t.Fatal(err)
		}

		advisory, err := loadAdvisory(tmpfile.Name())
		if err != nil {
			t.Fatalf("loadAdvisory returned an error: %v", err)
		}

		if advisory.ID != "test-id" {
			t.Errorf("Expected ID to be test-id, got %s", advisory.ID)
		}
	})

	t.Run("invalid advisory file", func(t *testing.T) {
		tmpfile, err := os.CreateTemp("", "advisory.json")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpfile.Name())

		if _, err := tmpfile.Write([]byte(`{"schema_version": "1.4.0"`)); err != nil {
			t.Fatal(err)
		}
		if err := tmpfile.Close(); err != nil {
			t.Fatal(err)
		}

		_, err = loadAdvisory(tmpfile.Name())
		if err == nil {
			t.Error("Expected loadAdvisory to return an error, but got nil")
		}
	})

	t.Run("missing advisory file", func(t *testing.T) {
		advisory, err := loadAdvisory("non-existent.json")
		if err != nil {
			t.Fatalf("loadAdvisory returned an error: %v", err)
		}

		if _, err := time.Parse(time.RFC3339, advisory.Published); err != nil {
			t.Errorf("Expected Published to be a valid timestamp, got %s", advisory.Published)
		}
	})
}

func TestUpdateAdvisory(t *testing.T) {
	t.Run("new advisory", func(t *testing.T) {
		policy := &Policy{
			ID:         "test-policy-id",
			PolicyLink: "test-policy-link",
		}
		advisory := &Advisory{}

		advisory = updateAdvisory(advisory, policy)

		if advisory.ID != "test-policy-id" {
			t.Errorf("Expected ID to be test-policy-id, got %s", advisory.ID)
		}
	})

	t.Run("existing advisory", func(t *testing.T) {
		policy := &Policy{
			ID:         "test-policy-id",
			PolicyLink: "test-policy-link",
		}
		advisory := &Advisory{
			Published: "2024-11-20T10:00:00Z",
		}

		advisory = updateAdvisory(advisory, policy)

		if advisory.Published != "2024-11-20T10:00:00Z" {
			t.Errorf("Expected Published to remain unchanged, got %s", advisory.Published)
		}
	})
}
