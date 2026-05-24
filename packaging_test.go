package ribat_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
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
		"## Disable",
		"## Rollback",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("docs/install.md missing %q", want)
		}
	}
}

func TestMakefileInstallsPackagingArtifacts(t *testing.T) {
	body := readFile(t, "Makefile")
	for _, want := range []string{
		"install: build",
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

func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}
