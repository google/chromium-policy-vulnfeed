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
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-github/v66/github"
)

var (
	yesterday = format(time.Now().AddDate(0, 0, -1))
)

// MockRepositories mocks the GitHub API's client behavior.
type MockRepositories struct{}

func (m MockRepositories) ListCommits(ctx context.Context, owner, repo string, opts *github.CommitsListOptions) ([]*github.RepositoryCommit, *github.Response, error) {
	var sha string
	switch opts.SHA {
	case "branch1":
		sha = "mockSHA1"
	case "branch2":
		sha = "mockSHA2"
	case "branch3":
		sha = "mockSHA1"
	default:
		sha = "defaultSHA"
	}
	commits := &github.RepositoryCommit{
		SHA: github.String(sha),
	}
	return []*github.RepositoryCommit{commits}, nil, nil
}
func TestUpdateCache(t *testing.T) {
	mockRepositories := MockRepositories{}

	tests := []struct {
		name     string
		branches []string
		oldCache map[string][]string
		want     map[string][]string
	}{
		{
			name:     "No existing cache creates a new entry for today",
			oldCache: make(map[string][]string),
			branches: []string{"branch1"},
			want: map[string][]string{
				today: {"mockSHA1"},
			},
		},
		{
			name: "Existing cache appends today's entry",
			oldCache: map[string][]string{
				yesterday: {"oldSHA"},
			},
			branches: []string{"branch1"},
			want: map[string][]string{
				today:     {"mockSHA1"},
				yesterday: {"oldSHA"},
			},
		},
		{
			name: "Existing entry for today rewrites the entry",
			oldCache: map[string][]string{
				today: {"oldSHA"},
			},
			branches: []string{"branch1"},
			want: map[string][]string{
				today: {"mockSHA1"},
			},
		},
		{
			name:     "Multiple branches adds entries for each branch",
			oldCache: make(map[string][]string),
			branches: []string{"branch1", "branch2"},
			want: map[string][]string{
				today: {"mockSHA1", "mockSHA2"},
			},
		},
		{
			name:     "Same commit hashes are deduplicated",
			oldCache: make(map[string][]string),
			branches: []string{"branch1", "branch3"},
			want: map[string][]string{
				today: {"mockSHA1"},
			},
		},
	}
	repository := "owner/repo"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := updateCache(repository, mockRepositories, tt.branches, tt.oldCache)
			if err != nil {
				t.Fatalf("updateCache failed: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unexpected AffectedItem: got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateAffectedItem(t *testing.T) {
	tests := []struct {
		name   string
		policy *Policy
		hashes []string
		want   *AffectedItem
	}{
		{
			name: "Successful creation",
			policy: &Policy{
				Repository: "owner/repo",
			},
			hashes: []string{"mockSHA1"},
			want: &AffectedItem{
				Ranges: []Range{
					{
						Type: "GIT",
						Repo: "owner/repo",
						Events: []Event{
							{Introduced: "0"},
							{Fixed: "mockSHA1"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createAffectedItem(tt.policy, tt.hashes)
			if err != nil {
				t.Errorf("createAffectedItem failed: %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unexpected AffectedItem: got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetCacheEntry(t *testing.T) {
	// Today's entry always exists because we have constructed it within this run.
	defaultCache := map[string][]string{
		today:     {"today-SHA1", "today-SHA2"},
		yesterday: {"yesterday-SHA1", "yesterday-SHA1"},
	}
	tests := []struct {
		name    string
		daysAgo int
		cache   map[string][]string
		want    []string
		wantErr bool
	}{
		{
			name:    "Entry found for target date",
			daysAgo: 1,
			cache:   defaultCache,
			want:    []string{"yesterday-SHA1", "yesterday-SHA1"},
		},
		{
			name:    "No entry for target date returns closer date entry",
			daysAgo: 5,
			cache:   defaultCache,
			want:    []string{"yesterday-SHA1", "yesterday-SHA1"},
		},
		{
			name:    "Negative days input returns error",
			daysAgo: -2,
			cache:   defaultCache,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "nil cache returns error",
			daysAgo: 2,
			cache:   nil,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Empty cache returns error",
			daysAgo: 2,
			cache:   map[string][]string{},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Cache without today's entry returns error",
			daysAgo: 2,
			cache: map[string][]string{
				yesterday: {"yesterday-SHA1", "yesterday-SHA1"},
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getCacheEntry(tt.cache, tt.daysAgo)
			if (err != nil) != tt.wantErr {
				t.Errorf("getCacheEntry() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCacheEntry() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpdateAdvisory(t *testing.T) {
	policy := &Policy{
		ID:            "policyID",
		Repository:    "owner/repo",
		FreshnessDays: 1,
		PolicyLink:    "policyLink",
		Description:   "policyDescription",
	}

	cache := map[string][]string{
		today:     {"mockSHA1"},
		yesterday: {"mockSHA2"},
	}

	advisory := &Advisory{
		SchemaVersion: "1.0",
	}

	updatedAdvisory, err := updateAdvisory(advisory, policy, cache)
	if err != nil {
		t.Errorf("updateAdvisory failed: %v", err)
		return
	}

	expectedAdvisory := &Advisory{
		SchemaVersion: "1.0",
		ID:            "policyID",
		Modified:      nowTimestamp,
		Published:     nowTimestamp,
		Summary:       "policyLink",
		Details:       "policyDescription",
		Affected: []AffectedItem{
			{
				Ranges: []Range{
					{
						Type: "GIT",
						Repo: "owner/repo",
						Events: []Event{
							{Introduced: "0"},
							{Fixed: "mockSHA2"},
						},
					},
				},
			},
		},
	}
	if !reflect.DeepEqual(updatedAdvisory, expectedAdvisory) {
		t.Errorf("unexpected Advisory: got %v, want %v", updatedAdvisory, expectedAdvisory)
	}
}

func TestLoadPolicy(t *testing.T) {
	file, err := os.CreateTemp("", "policy.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	policyData := []byte(`{"id": "policyID", "repository": "owner/repo"}`)
	if _, err := file.Write(policyData); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	originalPolicyPath := policyPath
	policyPath = file.Name()
	defer func() { policyPath = originalPolicyPath }()

	policy, err := loadPolicy()
	if err != nil {
		t.Fatalf("loadPolicy failed: %v", err)
	}

	expectedPolicy := &Policy{
		ID:         "policyID",
		Repository: "owner/repo",
	}
	if !reflect.DeepEqual(policy, expectedPolicy) {
		t.Errorf("unexpected Policy: got %v, want %v", policy, expectedPolicy)
	}
}

func TestLoadCache(t *testing.T) {
	file, err := os.CreateTemp("", "cache.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	cacheData := []byte(`{"2024-12-04": ["hash1", "hash2"]}`)
	if _, err := file.Write(cacheData); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	originalCachePath := cachePath
	cachePath = file.Name()
	defer func() { cachePath = originalCachePath }()

	cache, err := loadCache()
	if err != nil {
		t.Fatalf("loadCache failed: %v", err)
	}

	expectedCache := map[string][]string{
		"2024-12-04": {"hash1", "hash2"},
	}
	if !reflect.DeepEqual(cache, expectedCache) {
		t.Errorf("unexpected cache: got %v, want %v", cache, expectedCache)
	}
}

func TestSaveCache(t *testing.T) {
	file, err := os.CreateTemp("", "cache.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	originalCachePath := cachePath
	cachePath = file.Name()
	defer func() { cachePath = originalCachePath }()

	cache := map[string][]string{
		"2024-12-04": {"hash1", "hash2"},
	}

	err = saveCache(cache)
	if err != nil {
		t.Fatalf("saveCache failed: %v", err)
	}

	savedCacheData, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}

	expectedCacheData := []byte(`{
  "2024-12-04": [
    "hash1",
    "hash2"
  ]
}`)
	if !reflect.DeepEqual(savedCacheData, expectedCacheData) {
		t.Errorf("unexpected cache data: got %v, want %v", savedCacheData, expectedCacheData)
	}
}

func TestLoadAdvisory(t *testing.T) {
	file, err := os.CreateTemp("", "advisory.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	advisoryData := []byte(`{"schema_version": "1.0", "id": "advisoryID"}`)
	if _, err := file.Write(advisoryData); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	originalAdvisoryPath := advisoryPath
	advisoryPath = file.Name()
	defer func() { advisoryPath = originalAdvisoryPath }()

	advisory, err := loadAdvisory()
	if err != nil {
		t.Fatalf("loadAdvisory failed: %v", err)
	}

	expectedAdvisory := &Advisory{
		SchemaVersion: "1.0",
		ID:            "advisoryID",
	}
	if !reflect.DeepEqual(advisory, expectedAdvisory) {
		t.Errorf("unexpected Advisory: got %v, want %v", advisory, expectedAdvisory)
	}
}

func TestSaveAdvisory(t *testing.T) {
	file, err := os.CreateTemp("", "advisory.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	originalAdvisoryPath := advisoryPath
	advisoryPath = file.Name()
	defer func() { advisoryPath = originalAdvisoryPath }()

	advisory := &Advisory{
		SchemaVersion: "1.0",
		ID:            "advisoryID",
		Affected:      []AffectedItem{},
	}

	err = saveAdvisory(advisory)
	if err != nil {
		t.Fatalf("saveAdvisory failed: %v", err)
	}

	savedAdvisoryData, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}

	expectedAdvisoryData := []byte(`{
  "schema_version": "1.0",
  "id": "advisoryID",
  "modified": "",
  "published": "",
  "summary": "",
  "details": "",
  "affected": []
}`)
	if !reflect.DeepEqual(savedAdvisoryData, expectedAdvisoryData) {
		t.Errorf("unexpected advisory data: got %s, want %s", savedAdvisoryData, expectedAdvisoryData)
	}
}
