package ribat_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/MohamedElashri/ribat/internal/policy"
)

func TestSystemdServiceUsesInstallContract(t *testing.T) {
	body := readFile(t, "packaging/systemd/ribat.service")
	for _, want := range []string{
		"Before=docker.service",
		"ExecStartPre=/usr/bin/install -d -m 0755 /run/docker/plugins",
		"ExecStart=/usr/local/bin/ribat authz --config /etc/ribat/config.yaml --socket /run/docker/plugins/ribat.sock",
		"StateDirectory=ribat",
		"LogsDirectory=ribat",
		"ConfigurationDirectory=ribat",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("ribat.service missing %q\n%s", want, body)
		}
	}
}

func TestDockerDropInRequiresRibat(t *testing.T) {
	body := readFile(t, "packaging/systemd/docker-ribat.conf")
	for _, want := range []string{
		"Requires=ribat.service",
		"After=ribat.service",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("docker-ribat.conf missing %q\n%s", want, body)
		}
	}
}

func TestDockerDaemonExampleEnablesRibatAuthz(t *testing.T) {
	body := readFile(t, "packaging/docker/daemon-ribat.json")
	var parsed struct {
		AuthorizationPlugins []string `json:"authorization-plugins"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("daemon-ribat.json is invalid JSON: %v", err)
	}
	if len(parsed.AuthorizationPlugins) != 1 || parsed.AuthorizationPlugins[0] != "ribat" {
		t.Fatalf("authorization-plugins = %#v, want [ribat]", parsed.AuthorizationPlugins)
	}
}

func TestInstallDocsCoverOperationsAndRollback(t *testing.T) {
	body := readFile(t, "docs/install.md")
	for _, want := range []string{
		"/etc/ribat/config.yaml",
		"/var/lib/ribat/state.db",
		"/var/log/ribat/audit.jsonl",
		"/run/docker/plugins/ribat.sock",
		"sudo make install",
		"sudo make install-docker-dropin",
		"authorization-plugins",
		"ribat_v0.1.0_linux_amd64.tar.gz",
		"## Disable",
		"## Rollback",
		"docs/troubleshooting.md",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("docs/install.md missing %q", want)
		}
	}
}

func TestMakefileInstallsPackagingArtifacts(t *testing.T) {
	body := readFile(t, "Makefile")
	for _, want := range []string{
		"-trimpath",
		"-buildvcs=false",
		"-buildid=",
		"install: build",
		"release-snapshot:",
		"test-integration:",
		"RIBAT_INTEGRATION_TESTS=1",
		"ribat_$(VERSION)_",
		"SOURCE_DATE_EPOCH",
		"checksums.txt",
		"configs/ribat.example.yaml",
		"packaging/systemd/ribat.service",
		"install-docker-dropin:",
		"packaging/systemd/docker-ribat.conf",
		"uninstall:",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Makefile missing %q", want)
		}
	}
}

func TestDocumentationSetCoversPhase12Topics(t *testing.T) {
	docs := map[string][]string{
		"README.md": {
			"## Quick Start",
			"## Example Denial",
			"configs/ribat.strict.yaml",
			"configs/ribat.cosign.example.yaml",
			"docker build --pull",
			"RIBAT_INTEGRATION_TESTS",
		},
		"docs/threat-model.md": {
			"Security Invariant",
			"Default-Deny Behavior",
			"Watchtower",
			"Portainer",
		},
		"docs/policy.md": {
			"First-Seen Denial",
			"registry + repository + tag + digest",
			"Cosign Verification",
			"failed_registry_resolution",
		},
		"docs/operations.md": {
			"ribat approve",
			"ribat freeze",
			"ribat bypass",
			"ribat audit",
			"ribat export-state",
			"ribat import-state",
		},
		"docs/troubleshooting.md": {
			"Docker Does Not Start",
			"Cosign Verification Fails",
			"Build Pulls Are Denied",
			"Registry Proxy Pull Fails",
		},
	}
	for path, wants := range docs {
		body := readFile(t, path)
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Fatalf("%s missing %q", path, want)
			}
		}
	}
}

func TestReleaseWorkflowBuildsVersionedArtifacts(t *testing.T) {
	body := readFile(t, ".github/workflows/release.yml")
	for _, want := range []string{
		"tags:",
		"v*.*.*",
		"CGO_ENABLED",
		"-trimpath",
		"-buildvcs=false",
		"-buildid=",
		"ribat_${version}_${os}_${arch}",
		"sha256sum *.tar.gz > checksums.txt",
		"gh release create",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("release workflow missing %q", want)
		}
	}
}

func TestExampleConfigsLoad(t *testing.T) {
	for _, path := range []string{
		"configs/ribat.example.yaml",
		"configs/ribat.strict.yaml",
		"configs/ribat.cosign.example.yaml",
	} {
		if _, err := policy.LoadFile(path); err != nil {
			t.Fatalf("policy.LoadFile(%q) error = %v", path, err)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}
