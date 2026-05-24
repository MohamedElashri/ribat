package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/MohamedElashri/ribat/internal/image"
)

const testPolicy = `
version: 1

default_policy:
  mutable_tags:
    action: quarantine
    min_digest_age: 7d
    allow_first_seen_pull: false

  digest_pinned_images:
    action: allow

  failed_registry_resolution:
    action: deny

  failed_signature_check:
    action: deny

rules:
  - match: "docker.io/library/nginx:latest"
    mutable_tags:
      min_digest_age: 14d

  - match: "docker.io/library/*:stable"
    mutable_tags:
      min_digest_age: 3d
      allow_first_seen_pull: true

  - match: "*:main"
    mutable_tags:
      min_digest_age: 24h
`

func TestLoadPolicy(t *testing.T) {
	cfg, err := Load(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Version != 1 {
		t.Fatalf("version = %d, want 1", cfg.Version)
	}
	if cfg.DefaultPolicy.MutableTags.Action != ActionQuarantine {
		t.Fatalf("default mutable action = %q, want quarantine", cfg.DefaultPolicy.MutableTags.Action)
	}
	if cfg.DefaultPolicy.MutableTags.MinDigestAge.Duration != 7*24*time.Hour {
		t.Fatalf("default min age = %s, want 7d", cfg.DefaultPolicy.MutableTags.MinDigestAge)
	}
	if len(cfg.Rules) != 3 {
		t.Fatalf("rules length = %d, want 3", len(cfg.Rules))
	}
}

func TestLoadPolicyInvalidDurationIsActionable(t *testing.T) {
	_, err := Load(strings.NewReader(strings.Replace(testPolicy, "7d", "seven days", 1)))
	if err == nil {
		t.Fatal("Load() error = nil, want invalid duration error")
	}
	if !strings.Contains(err.Error(), "default_policy.mutable_tags.min_digest_age") {
		t.Fatalf("error = %q, want field path", err.Error())
	}
}

func TestEffectivePolicyForUsesFirstMatchingRule(t *testing.T) {
	cfg, err := Load(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	ref := mustParseRef(t, "nginx:latest")

	result, err := cfg.EffectivePolicyFor(ref)
	if err != nil {
		t.Fatalf("EffectivePolicyFor() error = %v", err)
	}
	if result.MatchedRule != "docker.io/library/nginx:latest" {
		t.Fatalf("matched rule = %q, want exact nginx rule", result.MatchedRule)
	}
	if result.Policy.MutableTags.MinDigestAge.Duration != 14*24*time.Hour {
		t.Fatalf("min age = %s, want 14d", result.Policy.MutableTags.MinDigestAge)
	}
	if result.Policy.MutableTags.Action != ActionQuarantine {
		t.Fatalf("action = %q, want inherited quarantine", result.Policy.MutableTags.Action)
	}
}

func TestEffectivePolicyForWildcardRegistryRepositoryAndTag(t *testing.T) {
	cfg, err := Load(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	tests := []struct {
		name        string
		image       string
		matchedRule string
		minAge      time.Duration
		firstSeen   bool
	}{
		{
			name:        "repository wildcard",
			image:       "docker.io/library/redis:stable",
			matchedRule: "docker.io/library/*:stable",
			minAge:      3 * 24 * time.Hour,
			firstSeen:   true,
		},
		{
			name:        "tag wildcard",
			image:       "ghcr.io/example/app:main",
			matchedRule: "*:main",
			minAge:      24 * time.Hour,
			firstSeen:   false,
		},
		{
			name:        "default",
			image:       "ghcr.io/example/app:dev",
			matchedRule: "default_policy",
			minAge:      7 * 24 * time.Hour,
			firstSeen:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cfg.EffectivePolicyFor(mustParseRef(t, tt.image))
			if err != nil {
				t.Fatalf("EffectivePolicyFor() error = %v", err)
			}
			if result.MatchedRule != tt.matchedRule {
				t.Fatalf("matched rule = %q, want %q", result.MatchedRule, tt.matchedRule)
			}
			if result.Policy.MutableTags.MinDigestAge.Duration != tt.minAge {
				t.Fatalf("min age = %s, want %s", result.Policy.MutableTags.MinDigestAge.Duration, tt.minAge)
			}
			if result.Policy.MutableTags.AllowFirstSeenPull != tt.firstSeen {
				t.Fatalf("allow first seen = %t, want %t", result.Policy.MutableTags.AllowFirstSeenPull, tt.firstSeen)
			}
		})
	}
}

func mustParseRef(t *testing.T, input string) image.Reference {
	t.Helper()

	ref, err := image.ParseReference(input)
	if err != nil {
		t.Fatalf("ParseReference(%q) error = %v", input, err)
	}
	return ref
}
