package registry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/MohamedElashri/ribat/internal/image"
)

func TestResolveDigestFromManifestHead(t *testing.T) {
	const digest = "sha256:abc123"
	resolver := testResolver(func(r *http.Request) *http.Response {
		if r.Method != http.MethodHead {
			t.Fatalf("method = %s, want HEAD", r.Method)
		}
		if r.URL.Path != "/v2/example/app/manifests/latest" {
			t.Fatalf("path = %s, want manifest path", r.URL.Path)
		}
		if !strings.Contains(r.Header.Get("Accept"), MediaTypeOCIImageIndex) {
			t.Fatalf("Accept = %q, want OCI index media type", r.Header.Get("Accept"))
		}
		return response(http.StatusOK, map[string]string{
			"Docker-Content-Digest": digest,
			"Content-Type":          MediaTypeDockerManifestList,
		}, "")
	})

	got, err := resolver.Resolve(context.Background(), mustParseRef(t, "example.test/example/app:latest"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got.Digest != digest {
		t.Fatalf("digest = %q, want %q", got.Digest, digest)
	}
	if got.MediaType != MediaTypeDockerManifestList {
		t.Fatalf("media type = %q, want %q", got.MediaType, MediaTypeDockerManifestList)
	}
}

func TestResolveHandlesBearerChallenge(t *testing.T) {
	const digest = "sha256:def456"
	resolver := testResolver(func(r *http.Request) *http.Response {
		switch r.URL.Path {
		case "/v2/example/app/manifests/latest":
			if r.Header.Get("Authorization") == "" {
				return response(http.StatusUnauthorized, map[string]string{
					"WWW-Authenticate": `Bearer realm="https://example.test/token",service="test-registry",scope="repository:example/app:pull"`,
				}, "")
			}
			if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
				t.Fatalf("Authorization = %q, want bearer test-token", got)
			}
			return response(http.StatusOK, map[string]string{
				"Docker-Content-Digest": digest,
				"Content-Type":          MediaTypeOCIImageIndex,
			}, "")
		case "/token":
			if got := r.URL.Query().Get("service"); got != "test-registry" {
				t.Fatalf("service query = %q, want test-registry", got)
			}
			if got := r.URL.Query().Get("scope"); got != "repository:example/app:pull" {
				t.Fatalf("scope query = %q, want repository pull scope", got)
			}
			return response(http.StatusOK, map[string]string{"Content-Type": "application/json"}, `{"token":"test-token"}`)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return response(http.StatusInternalServerError, nil, "")
	})

	got, err := resolver.Resolve(context.Background(), mustParseRef(t, "example.test/example/app:latest"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got.Digest != digest {
		t.Fatalf("digest = %q, want %q", got.Digest, digest)
	}
}

func TestResolveFallsBackToGetWhenHeadIsUnavailable(t *testing.T) {
	const digest = "sha256:feedface"
	resolver := testResolver(func(r *http.Request) *http.Response {
		if r.Method == http.MethodHead {
			return response(http.StatusMethodNotAllowed, nil, "")
		}
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET fallback", r.Method)
		}
		return response(http.StatusOK, map[string]string{"Docker-Content-Digest": digest}, "")
	})

	got, err := resolver.Resolve(context.Background(), mustParseRef(t, "example.test/example/app:latest"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got.Digest != digest {
		t.Fatalf("digest = %q, want %q", got.Digest, digest)
	}
}

func TestResolveTagNotFound(t *testing.T) {
	resolver := testResolver(func(r *http.Request) *http.Response {
		return response(http.StatusNotFound, nil, "")
	})

	_, err := resolver.Resolve(context.Background(), mustParseRef(t, "example.test/example/app:missing"))
	if !errors.Is(err, ErrTagNotFound) {
		t.Fatalf("Resolve() error = %v, want ErrTagNotFound", err)
	}
}

func TestResolveMissingDigestIsActionable(t *testing.T) {
	resolver := testResolver(func(r *http.Request) *http.Response {
		return response(http.StatusOK, nil, "")
	})

	_, err := resolver.Resolve(context.Background(), mustParseRef(t, "example.test/example/app:latest"))
	if err == nil {
		t.Fatal("Resolve() error = nil, want missing digest error")
	}
	if !strings.Contains(err.Error(), "Docker-Content-Digest") {
		t.Fatalf("error = %q, want Docker-Content-Digest context", err.Error())
	}
}

func testResolver(handler func(*http.Request) *http.Response) *Resolver {
	return &Resolver{
		Client: &http.Client{Transport: roundTripFunc(handler)},
		Endpoints: map[string]string{
			"example.test": "https://example.test",
		},
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

type roundTripFunc func(*http.Request) *http.Response

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func response(status int, headers map[string]string, body string) *http.Response {
	h := make(http.Header)
	for key, value := range headers {
		h.Set(key, value)
	}
	return &http.Response{
		StatusCode: status,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
