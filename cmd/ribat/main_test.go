package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func writeTestPolicy(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ribat.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}
	return path
}
