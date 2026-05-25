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
	body := readFile(t, "docs/content/user/installation.md")
	for _, want := range []string{
		"curl -fsSL https://melashri.net/ribat/install.sh | sh",
		"RIBAT_VERSION",
		"RIBAT_INSTALL_DIR",
		"RIBAT_INSTALL_SYSTEM",
		"RIBAT_INSTALL_DOCKER_DROPIN",
		"## Privileges",
		"Docker enforcement does need root privileges",
		"Do not run the whole installer as root",
		"Manual Archive Install",
		"Build From Source",
		"/etc/ribat/config.yaml",
		"/var/lib/ribat/state.db",
		"/var/log/ribat/audit.jsonl",
		"/run/docker/plugins/ribat.sock",
		"sudo make install",
		"sudo make install-docker-dropin",
		"RIBAT_INSTALL_SYSTEM=1 RIBAT_INSTALL_DOCKER_DROPIN=1",
		"authorization-plugins",
		"Plugin.Activate",
		"docker info --format",
		"systemctl enable --now ribat.service",
		"sudo editor /etc/ribat/config.yaml",
		"ribat_v0.1.0_linux_amd64.tar.gz",
		"## Disable",
		"## Rollback",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("docs/content/user/installation.md missing %q", want)
		}
	}
}

func TestInstallScriptDownloadsReleaseArchive(t *testing.T) {
	body := readFile(t, "docs/static/install.sh")
	for _, want := range []string{
		`repo="MohamedElashri/ribat"`,
		"RIBAT_VERSION",
		"RIBAT_INSTALL_DIR",
		"RIBAT_INSTALL_SYSTEM",
		"RIBAT_INSTALL_DOCKER_DROPIN",
		"configs/ribat.example.yaml",
		"packaging/systemd/ribat.service",
		"packaging/systemd/docker-ribat.conf",
		"systemctl daemon-reload",
		"releases/latest",
		`archive="ribat_${tag}_${os}_${arch}.tar.gz"`,
		"checksums.txt",
		"sha256sum -c",
		"shasum -a 256",
		`install -m 0755 "$tmp/extract/ribat" "$install_dir/ribat"`,
		`"$install_dir/ribat" version`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("docs/static/install.sh missing %q", want)
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
		"test-docker-live:",
		"docs-build:",
		"docs-serve:",
		"github.com/MohamedElashri/nida/cmd/nida@main",
		"RIBAT_INTEGRATION_TESTS=1",
		"RIBAT_DOCKER_LIVE_TESTS=1",
		"scripts/live-docker-validation.sh",
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
			"https://melashri.net/ribat/",
			"make docs-build",
			"make docs-serve",
		},
		"docs/content/user/security-model.md": {
			"Security Invariant",
			"Default-Deny Behavior",
			"Watchtower",
			"Portainer",
		},
		"docs/content/user/policy.md": {
			"First-Seen Denial",
			"registry + repository + tag + digest",
			"Cosign Verification",
			"failed_registry_resolution",
		},
		"docs/content/user/operations.md": {
			"ribat approve",
			"ribat freeze",
			"ribat bypass",
			"ribat audit",
			"ribat export-state",
			"ribat import-state",
		},
		"docs/content/user/troubleshooting.md": {
			"Docker Does Not Start",
			"Cosign Verification Fails",
			"Build Pulls Are Denied",
			"Registry Proxy Pull Fails",
		},
		"docs/content/user/live-validation.md": {
			"make test-docker-live",
			"RIBAT_VALIDATE_INSTALLED_AUTHZ",
			"does not edit Docker daemon configuration",
			"first-seen mutable tag pull is denied",
		},
		"docs/content/developer/architecture.md": {
			"internal/quarantine",
			"AuthZ mode",
			"proxy mode",
		},
		"docs/content/developer/docs-site.md": {
			"built with Nida",
			".github/workflows/pages.yml",
			"docs/public",
		},
		"docs/content/reference/cli.md": {
			"## Command Summary",
			"Exit codes:",
			"| Option | Argument | Required | Default | Description |",
			"`--by`",
			"Side effects:",
		},
		"docs/content/reference/config.md": {
			"## Top-Level Fields",
			"| Field | Type | Required | Description |",
			"`default_policy.mutable_tags`",
			"`default_policy.signatures.cosign`",
			"Duration Values",
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

func TestNidaDocsSiteShape(t *testing.T) {
	config := readFile(t, "docs/config.toml")
	for _, want := range []string{
		`base_url = "https://melashri.net/ribat/"`,
		`content_dir = "content"`,
		`template_dir = "templates"`,
		`static_dir = "static"`,
		`output_dir = "public"`,
		`user = "/user/{slug}/"`,
		`developer = "/developer/{slug}/"`,
		`repo_url = "https://github.com/MohamedElashri/ribat"`,
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("docs/config.toml missing %q", want)
		}
	}

	for _, path := range []string{
		"docs/templates/base.html",
		"docs/templates/index.html",
		"docs/templates/page.html",
		"docs/templates/section.html",
		"docs/templates/partials/nav.html",
		"docs/static/style.css",
		"docs/static/favicon.svg",
		"docs/static/install.sh",
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected Nida docs site file %s: %v", path, err)
		}
	}
}

func TestPagesWorkflowBuildsNidaDocs(t *testing.T) {
	body := readFile(t, ".github/workflows/pages.yml")
	for _, want := range []string{
		`- "docs/**"`,
		`- ".github/workflows/pages.yml"`,
		"repository: MohamedElashri/nida",
		"path: .docs-tools/nida",
		"go-version-file: .docs-tools/nida/go.mod",
		"go run ./cmd/nida build --site",
		"path: docs/public",
		"actions/configure-pages",
		"actions/upload-pages-artifact",
		"actions/deploy-pages",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("pages workflow missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`- "README.md"`,
		`- "cmd/**"`,
		`- "internal/**"`,
		`- "configs/**"`,
		`- "scripts/**"`,
		`- "Makefile"`,
		`- "go.mod"`,
		`- "go.sum"`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("pages workflow should not run for non-doc path %q", forbidden)
		}
	}
}

func TestLiveDockerValidationScriptIsOptIn(t *testing.T) {
	body := readFile(t, "scripts/live-docker-validation.sh")
	for _, want := range []string{
		"RIBAT_DOCKER_LIVE_TESTS",
		"RIBAT_VALIDATE_INSTALLED_AUTHZ",
		"docker pull",
		"proxy --config",
		"approve --config",
		"Plugin.Activate",
		`"decision":"deny"`,
		`"decision":"allow"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("live Docker validation script missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"daemon.json",
		"systemctl restart docker",
		"systemctl stop docker",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("live Docker validation script should not manage Docker daemon configuration; found %q", forbidden)
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
