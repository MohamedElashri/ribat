package verify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MohamedElashri/ribat/internal/image"
	"github.com/MohamedElashri/ribat/internal/policy"
)

func TestCosignVerifyArgsUsesDigestReferenceAndIdentityPolicy(t *testing.T) {
	ref := mustParseRef(t, "ghcr.io/example/app:latest")
	args, err := CosignVerifyArgs(ref, "sha256:abc123", policy.CosignPolicy{
		Mode:          "keyless",
		Issuer:        "https://token.actions.githubusercontent.com",
		IdentityRegex: "^https://github.com/example/app/.github/workflows/release.yml@refs/tags/v.*$",
	})
	if err != nil {
		t.Fatalf("CosignVerifyArgs() error = %v", err)
	}

	joined := strings.Join(args, " ")
	for _, want := range []string{
		"verify",
		"--certificate-oidc-issuer https://token.actions.githubusercontent.com",
		"--certificate-identity-regexp ^https://github.com/example/app/.github/workflows/release.yml@refs/tags/v.*$",
		"ghcr.io/example/app@sha256:abc123",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args = %q, want %q", joined, want)
		}
	}
	if strings.Contains(joined, "latest@sha256") {
		t.Fatalf("args = %q, want digest-pinned repository reference without mutable tag", joined)
	}
}

func TestCosignVerifyArgsSupportsKeyMode(t *testing.T) {
	ref := mustParseRef(t, "ghcr.io/example/app:latest")
	args, err := CosignVerifyArgs(ref, "sha256:abc123", policy.CosignPolicy{
		Mode: "key",
		Key:  "/etc/ribat/cosign.pub",
	})
	if err != nil {
		t.Fatalf("CosignVerifyArgs() error = %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--key /etc/ribat/cosign.pub") {
		t.Fatalf("args = %q, want key flag", joined)
	}
}

func TestCosignVerifierRunsSubprocess(t *testing.T) {
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args.txt")
	scriptPath := filepath.Join(dir, "cosign-test")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$COSIGN_ARGS_FILE\"\nexit 0\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake cosign: %v", err)
	}
	t.Setenv("COSIGN_ARGS_FILE", argsPath)

	ref := mustParseRef(t, "ghcr.io/example/app:latest")
	result, err := NewCosignVerifier(scriptPath).Verify(context.Background(), ref, "sha256:abc123", policy.CosignPolicy{
		Mode:     "keyless",
		Identity: "https://github.com/example/app/.github/workflows/release.yml@refs/tags/v1.0.0",
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.Success {
		t.Fatalf("result = %#v, want success", result)
	}
	body, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read args: %v", err)
	}
	if !strings.Contains(string(body), "ghcr.io/example/app@sha256:abc123") {
		t.Fatalf("captured args = %q, want digest reference", body)
	}
}

func TestCosignVerifierFailureIncludesCommandOutput(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "cosign-test")
	script := "#!/bin/sh\necho 'identity did not match' >&2\nexit 1\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake cosign: %v", err)
	}

	ref := mustParseRef(t, "ghcr.io/example/app:latest")
	result, err := NewCosignVerifier(scriptPath).Verify(context.Background(), ref, "sha256:abc123", policy.CosignPolicy{Mode: "keyless"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Success {
		t.Fatalf("result = %#v, want failure", result)
	}
	if !strings.Contains(result.Reason, "identity did not match") {
		t.Fatalf("reason = %q, want command output", result.Reason)
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
