package image

import (
	"strings"
	"testing"
)

func TestParseReferenceDockerHubDefaults(t *testing.T) {
	ref, err := ParseReference("nginx")
	if err != nil {
		t.Fatalf("ParseReference(nginx) error = %v", err)
	}

	assertReference(t, ref, Reference{
		Registry:       "docker.io",
		Repository:     "library/nginx",
		Tag:            "latest",
		IsMutableTag:   true,
		IsDigestPinned: false,
		CanonicalRef:   "docker.io/library/nginx:latest",
	})
}

func TestParseReferenceDockerHubTagDefault(t *testing.T) {
	ref, err := ParseReference("redis:7")
	if err != nil {
		t.Fatalf("ParseReference(redis:7) error = %v", err)
	}

	assertReference(t, ref, Reference{
		Registry:       "docker.io",
		Repository:     "library/redis",
		Tag:            "7",
		IsMutableTag:   true,
		IsDigestPinned: false,
		CanonicalRef:   "docker.io/library/redis:7",
	})
}

func TestParseReferenceDockerHubNamespace(t *testing.T) {
	ref, err := ParseReference("library/nginx:1.27")
	if err != nil {
		t.Fatalf("ParseReference(library/nginx:1.27) error = %v", err)
	}

	assertReference(t, ref, Reference{
		Registry:       "docker.io",
		Repository:     "library/nginx",
		Tag:            "1.27",
		IsMutableTag:   true,
		IsDigestPinned: false,
		CanonicalRef:   "docker.io/library/nginx:1.27",
	})
}

func TestParseReferenceExplicitRegistry(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		registry  string
		repo      string
		tag       string
		canonical string
	}{
		{
			name:      "docker hub explicit",
			input:     "docker.io/library/nginx:1.27",
			registry:  "docker.io",
			repo:      "library/nginx",
			tag:       "1.27",
			canonical: "docker.io/library/nginx:1.27",
		},
		{
			name:      "ghcr",
			input:     "ghcr.io/example/my--app:main",
			registry:  "ghcr.io",
			repo:      "example/my--app",
			tag:       "main",
			canonical: "ghcr.io/example/my--app:main",
		},
		{
			name:      "localhost with port",
			input:     "localhost:5000/example/app",
			registry:  "localhost:5000",
			repo:      "example/app",
			tag:       "latest",
			canonical: "localhost:5000/example/app:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := ParseReference(tt.input)
			if err != nil {
				t.Fatalf("ParseReference(%q) error = %v", tt.input, err)
			}

			assertReference(t, ref, Reference{
				Registry:       tt.registry,
				Repository:     tt.repo,
				Tag:            tt.tag,
				IsMutableTag:   true,
				IsDigestPinned: false,
				CanonicalRef:   tt.canonical,
			})
		})
	}
}

func TestParseReferenceDigestPinned(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		registry  string
		repo      string
		tag       string
		digest    string
		canonical string
	}{
		{
			name:      "explicit registry without tag",
			input:     "ghcr.io/example/app@sha256:abc123",
			registry:  "ghcr.io",
			repo:      "example/app",
			digest:    "sha256:abc123",
			canonical: "ghcr.io/example/app@sha256:abc123",
		},
		{
			name:      "docker hub default",
			input:     "alpine@sha256:abc123",
			registry:  "docker.io",
			repo:      "library/alpine",
			digest:    "sha256:abc123",
			canonical: "docker.io/library/alpine@sha256:abc123",
		},
		{
			name:      "tag plus digest",
			input:     "docker.io/library/alpine:3.20@sha256:abc123",
			registry:  "docker.io",
			repo:      "library/alpine",
			tag:       "3.20",
			digest:    "sha256:abc123",
			canonical: "docker.io/library/alpine:3.20@sha256:abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := ParseReference(tt.input)
			if err != nil {
				t.Fatalf("ParseReference(%q) error = %v", tt.input, err)
			}

			assertReference(t, ref, Reference{
				Registry:       tt.registry,
				Repository:     tt.repo,
				Tag:            tt.tag,
				Digest:         tt.digest,
				IsMutableTag:   false,
				IsDigestPinned: true,
				CanonicalRef:   tt.canonical,
			})
		})
	}
}

func TestParseReferenceRejectsMalformedReferences(t *testing.T) {
	tests := []string{
		"",
		" nginx",
		"nginx latest",
		"https://docker.io/library/nginx:latest",
		"docker.io/",
		"docker.io//nginx",
		"docker.io/library/nginx:",
		"docker.io/library/NGINX:latest",
		"ghcr.io/example/app@",
		"ghcr.io/example/app@sha256",
		"ghcr.io/example/app@sha256:abc@sha256:def",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if ref, err := ParseReference(input); err == nil {
				t.Fatalf("ParseReference(%q) = %+v, want error", input, ref)
			}
		})
	}
}

func TestParseReferenceErrorMessagesAreActionable(t *testing.T) {
	_, err := ParseReference("docker.io/library/nginx:")
	if err == nil {
		t.Fatal("ParseReference malformed tag error = nil")
	}
	if !strings.Contains(err.Error(), "empty tag") {
		t.Fatalf("error = %q, want empty tag context", err.Error())
	}
}

func assertReference(t *testing.T, got, want Reference) {
	t.Helper()

	if got != want {
		t.Fatalf("reference mismatch\n got: %+v\nwant: %+v", got, want)
	}
}
