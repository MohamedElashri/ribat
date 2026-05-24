package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MohamedElashri/ribat/internal/audit"
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

func TestRunDecideAllowsDigestPinnedImage(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.db")
	configPath := writeTestPolicyWithState(t, statePath)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"decide", "--config", configPath, "ghcr.io/example/app@sha256:abc123"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run(decide digest pinned) exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"Image: ghcr.io/example/app@sha256:abc123",
		"Decision: ALLOW",
		"Reason: digest-pinned image allowed by policy",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("decide output = %q, want %q", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	db, err := store.OpenSQLite(statePath)
	if err != nil {
		t.Fatalf("OpenSQLite() error = %v", err)
	}
	defer db.Close()
	count, err := db.CountDecisions(context.Background())
	if err != nil {
		t.Fatalf("CountDecisions() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("decision count = %d, want 1", count)
	}
}

func TestRunAuthzRequiresSocket(t *testing.T) {
	configPath := writeTestPolicyWithState(t, filepath.Join(t.TempDir(), "state.db"))
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"authz", "--config", configPath}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("run(authz without socket) exit code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "authz requires --socket PATH") {
		t.Fatalf("stderr = %q, want socket requirement", stderr.String())
	}
}

func TestRunProxyRequiresListenAddress(t *testing.T) {
	configPath := writeTestPolicyWithState(t, filepath.Join(t.TempDir(), "state.db"))
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"proxy", "--config", configPath}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("run(proxy without listen) exit code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "proxy requires --listen ADDRESS") {
		t.Fatalf("stderr = %q, want listen requirement", stderr.String())
	}
}

func TestRunApproveBypassFreezeCommands(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.db")
	configPath := writeTestPolicyWithState(t, statePath)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"approve", "--config", configPath, "--ttl", "24h", "--reason", "reviewed", "nginx:latest@sha256:approved"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(approve) exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Approved: docker.io/library/nginx:latest@sha256:approved") {
		t.Fatalf("approve output = %q, want approved state", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"bypass", "--config", configPath, "--ttl", "1h", "--reason", "incident", "nginx:latest"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(bypass) exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Bypass active: docker.io/library/nginx:latest") {
		t.Fatalf("bypass output = %q, want bypass state", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"freeze", "--config", configPath, "--reason", "compromise", "nginx:latest"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(freeze) exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Freeze active: docker.io/library/nginx:latest") {
		t.Fatalf("freeze output = %q, want freeze state", stdout.String())
	}

	db, err := store.OpenSQLite(statePath)
	if err != nil {
		t.Fatalf("OpenSQLite() error = %v", err)
	}
	defer db.Close()
	override, err := db.LocalOverride(context.Background(), "docker.io", "library/nginx", "latest", "sha256:approved", time.Now().UTC())
	if err != nil {
		t.Fatalf("LocalOverride() error = %v", err)
	}
	if override.Approval == nil || override.Bypass == nil || override.Freeze == nil {
		t.Fatalf("LocalOverride() = %#v, want approval, bypass, and freeze", override)
	}
	if override.Decision != store.DecisionDeny {
		t.Fatalf("LocalOverride decision = %q, want deny from freeze", override.Decision)
	}
	expiredBypass, err := db.ActiveBypass(context.Background(), "docker.io", "library/nginx", "latest", time.Now().UTC().Add(2*time.Hour))
	if err != nil {
		t.Fatalf("ActiveBypass(expired) error = %v", err)
	}
	if expiredBypass != nil {
		t.Fatalf("ActiveBypass(expired) = %#v, want nil", expiredBypass)
	}
}

func TestRunAuditFiltersByImageAndSince(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	configPath := writeTestPolicyWithStateAndAudit(t, filepath.Join(dir, "state.db"), auditPath)
	now := time.Now().UTC()
	events := []audit.Event{
		{
			Timestamp:  now.Add(-time.Hour),
			ImageRef:   "docker.io/library/nginx:latest",
			Registry:   "docker.io",
			Repository: "library/nginx",
			Tag:        "latest",
			Decision:   "deny",
			Reason:     "new digest",
		},
		{
			Timestamp:  now.Add(-time.Hour),
			ImageRef:   "docker.io/library/redis:latest",
			Registry:   "docker.io",
			Repository: "library/redis",
			Tag:        "latest",
			Decision:   "deny",
			Reason:     "new digest",
		},
		{
			Timestamp:  now.Add(-10 * 24 * time.Hour),
			ImageRef:   "docker.io/library/nginx:stable",
			Registry:   "docker.io",
			Repository: "library/nginx",
			Tag:        "stable",
			Decision:   "allow",
			Reason:     "old",
		},
	}
	var body []byte
	for _, event := range events {
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		body = append(body, encoded...)
		body = append(body, '\n')
	}
	if err := os.WriteFile(auditPath, body, 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"audit", "--config", configPath, "--image", "nginx:latest", "--since", "7d"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(audit) exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, `"image_ref":"docker.io/library/nginx:latest"`) {
		t.Fatalf("audit output = %q, want nginx latest event", output)
	}
	if strings.Contains(output, "redis") || strings.Contains(output, "stable") {
		t.Fatalf("audit output = %q, want filtered results", output)
	}
}

func TestRunExportImportState(t *testing.T) {
	sourceState := filepath.Join(t.TempDir(), "source.db")
	sourceConfig := writeTestPolicyWithState(t, sourceState)
	sourceDB, err := store.OpenSQLite(sourceState)
	if err != nil {
		t.Fatalf("OpenSQLite(source) error = %v", err)
	}
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	if _, err := sourceDB.CreateObservation(context.Background(), "docker.io", "library/nginx", "latest", "sha256:first", now); err != nil {
		t.Fatalf("CreateObservation() error = %v", err)
	}
	if _, err := sourceDB.ApproveDigest(context.Background(), "docker.io", "library/nginx", "latest", "sha256:first", now, "alice", "reviewed", nil); err != nil {
		t.Fatalf("ApproveDigest() error = %v", err)
	}
	if err := sourceDB.Close(); err != nil {
		t.Fatalf("Close(source) error = %v", err)
	}

	var exportOut bytes.Buffer
	var exportErr bytes.Buffer
	code := run([]string{"export-state", "--config", sourceConfig}, &exportOut, &exportErr)
	if code != 0 {
		t.Fatalf("run(export-state) exit code = %d, stderr = %q", code, exportErr.String())
	}
	exportPath := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(exportPath, exportOut.Bytes(), 0o600); err != nil {
		t.Fatalf("write export: %v", err)
	}

	targetState := filepath.Join(t.TempDir(), "target.db")
	targetConfig := writeTestPolicyWithState(t, targetState)
	var importOut bytes.Buffer
	var importErr bytes.Buffer
	code = run([]string{"import-state", "--config", targetConfig, "--input", exportPath}, &importOut, &importErr)
	if code != 0 {
		t.Fatalf("run(import-state) exit code = %d, stderr = %q", code, importErr.String())
	}
	if !strings.Contains(importOut.String(), "observations=1 approvals=1") {
		t.Fatalf("import output = %q, want imported counts", importOut.String())
	}
	targetDB, err := store.OpenSQLite(targetState)
	if err != nil {
		t.Fatalf("OpenSQLite(target) error = %v", err)
	}
	defer targetDB.Close()
	approval, err := targetDB.ActiveApproval(context.Background(), "docker.io", "library/nginx", "latest", "sha256:first", now)
	if err != nil {
		t.Fatalf("ActiveApproval() error = %v", err)
	}
	if approval == nil {
		t.Fatal("imported approval = nil, want approval")
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

func writeTestPolicyWithStateAndAudit(t *testing.T, statePath, auditPath string) string {
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

audit:
  path: "`+auditPath+`"

state:
  backend: sqlite
  path: "`+statePath+`"
`)
}
