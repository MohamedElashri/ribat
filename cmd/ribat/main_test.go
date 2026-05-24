package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MohamedElashri/ribat/internal/store"
)

func TestRunVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"version"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run(version) exit code = %d, want 0", code)
	}
	if got := strings.TrimSpace(stdout.String()); got != "ribat dev" {
		t.Fatalf("version output = %q, want %q", got, "ribat dev")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"wat"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("run(unknown) exit code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), `unknown command "wat"`) {
		t.Fatalf("stderr = %q, want unknown command message", stderr.String())
	}
}

func TestRunInspectDigestPinned(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"inspect", "ghcr.io/example/app@sha256:abc123"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run(inspect digest pinned) exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"Image: ghcr.io/example/app@sha256:abc123",
		"Digest pinned: true",
		"Digest: sha256:abc123",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("inspect output = %q, want %q", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunPolicyCheck(t *testing.T) {
	configPath := writeTestPolicy(t, `
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
  - match: "*:latest"
    mutable_tags:
      min_digest_age: 14d
`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"policy", "check", "--config", configPath, "nginx:latest"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run(policy check) exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"Image: docker.io/library/nginx:latest",
		"Matched rule: *:latest",
		"min_digest_age: 14d",
		"allow_first_seen_pull: false",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("policy check output = %q, want %q", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunPolicyCheckInvalidConfig(t *testing.T) {
	configPath := writeTestPolicy(t, `
version: 1

default_policy:
  mutable_tags:
    action: quarantine
    min_digest_age: nope
    allow_first_seen_pull: false

  digest_pinned_images:
    action: allow

  failed_registry_resolution:
    action: deny

  failed_signature_check:
    action: deny
`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"policy", "check", "--config", configPath, "nginx:latest"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("run(policy check invalid config) exit code = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "default_policy.mutable_tags.min_digest_age") {
		t.Fatalf("stderr = %q, want policy field context", stderr.String())
	}
}

func TestRunStatusShowsKnownLocalState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.db")
	configPath := writeTestPolicyWithState(t, statePath)
	db, err := store.OpenSQLite(statePath)
	if err != nil {
		t.Fatalf("OpenSQLite() error = %v", err)
	}
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	if _, err := db.CreateObservation(context.Background(), "docker.io", "library/nginx", "latest", "sha256:abc123", now); err != nil {
		t.Fatalf("CreateObservation() error = %v", err)
	}
	if _, err := db.ApproveDigest(context.Background(), "docker.io", "library/nginx", "latest", "sha256:abc123", now, "alice", "reviewed", nil); err != nil {
		t.Fatalf("ApproveDigest() error = %v", err)
	}
	if _, err := db.FreezeTag(context.Background(), "docker.io", "library/nginx", "latest", "", now, "bob", "incident", nil); err != nil {
		t.Fatalf("FreezeTag() error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"status", "--config", configPath, "nginx:latest"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run(status) exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"Image: docker.io/library/nginx:latest",
		"Local state: observed",
		"Digest: sha256:abc123",
		"Local override: deny (freeze)",
		"Freeze reason: incident",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("status output = %q, want %q", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func writeTestPolicy(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ribat.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}
	return path
}

func writeTestPolicyWithState(t *testing.T, statePath string) string {
	t.Helper()

	return writeTestPolicy(t, `
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

state:
  backend: sqlite
  path: "`+statePath+`"
`)
}
