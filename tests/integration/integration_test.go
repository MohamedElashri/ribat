package integration_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MohamedElashri/ribat/internal/audit"
	"github.com/MohamedElashri/ribat/internal/policy"
	"github.com/MohamedElashri/ribat/internal/proxy"
	"github.com/MohamedElashri/ribat/internal/quarantine"
	"github.com/MohamedElashri/ribat/internal/registry"
	"github.com/MohamedElashri/ribat/internal/store"
)

const (
	localRegistryName   = "local.registry"
	localRepository     = "example/app"
	localTag            = "latest"
	localManifestDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	localConfigDigest   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	localLayerDigest    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

func TestLocalRegistryProxyIntegration(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 25, 10, 0, 0, 0, time.UTC)
	fixture := newLocalRegistryFixture(t)
	resolver := registry.NewResolver(fixture.Client())
	resolver.Endpoints = map[string]string{localRegistryName: fixture.Endpoint}

	db, cfg, auditPath := integrationState(t)
	engine := quarantine.Engine{
		Config:   cfg,
		Store:    db,
		Resolver: resolver,
		Audit:    audit.NewLogger(auditPath),
		Now:      func() time.Time { return now },
	}
	gate := proxy.Server{Engine: &engine, Resolver: resolver}
	proxyHandler := gate.Handler()

	denied := proxyGet(t, proxyHandler, "/v2/local.registry/example/app/manifests/latest")
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("fresh manifest status = %d, want 403; body: %s", denied.StatusCode, denied.Body)
	}
	if !strings.Contains(denied.Body, "new digest observed for mutable tag") {
		t.Fatalf("fresh manifest denial missing quarantine reason: %s", denied.Body)
	}

	obs, err := db.GetObservation(ctx, localRegistryName, localRepository, localTag, localManifestDigest)
	if err != nil {
		t.Fatalf("GetObservation error = %v", err)
	}
	if obs == nil {
		t.Fatalf("fresh manifest request did not record observation for %s", localManifestDigest)
	}

	blockedBlob := proxyGet(t, proxyHandler, "/v2/local.registry/example/app/blobs/"+localLayerDigest)
	if blockedBlob.StatusCode != http.StatusForbidden {
		t.Fatalf("blob before allowed manifest status = %d, want 403; body: %s", blockedBlob.StatusCode, blockedBlob.Body)
	}

	expiresAt := now.Add(time.Hour)
	if _, err := db.ApproveDigest(ctx, localRegistryName, localRepository, localTag, localManifestDigest, now, "integration-test", "reviewed fixture digest", &expiresAt); err != nil {
		t.Fatalf("ApproveDigest error = %v", err)
	}

	allowed := proxyGet(t, proxyHandler, "/v2/local.registry/example/app/manifests/latest")
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("approved manifest status = %d, want 200; body: %s", allowed.StatusCode, allowed.Body)
	}
	if got := allowed.Header.Get("Docker-Content-Digest"); got != localManifestDigest {
		t.Fatalf("Docker-Content-Digest = %q, want %q", got, localManifestDigest)
	}
	if strings.TrimSpace(allowed.Body) != strings.TrimSpace(fixture.Manifest) {
		t.Fatalf("proxied manifest body mismatch:\n%s", allowed.Body)
	}

	allowedBlob := proxyGet(t, proxyHandler, "/v2/local.registry/example/app/blobs/"+localLayerDigest)
	if allowedBlob.StatusCode != http.StatusOK {
		t.Fatalf("blob after allowed manifest status = %d, want 200; body: %s", allowedBlob.StatusCode, allowedBlob.Body)
	}
	if allowedBlob.Body != fixture.Blobs[localLayerDigest] {
		t.Fatalf("proxied blob body = %q, want %q", allowedBlob.Body, fixture.Blobs[localLayerDigest])
	}

	decisions, err := db.CountDecisions(ctx)
	if err != nil {
		t.Fatalf("CountDecisions error = %v", err)
	}
	if decisions != 2 {
		t.Fatalf("decision count = %d, want 2", decisions)
	}
	auditBody, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	for _, want := range []string{
		`"decision":"deny"`,
		`"decision":"allow"`,
		localManifestDigest,
		`"request_uri":"/v2/local.registry/example/app/manifests/latest"`,
	} {
		if !strings.Contains(string(auditBody), want) {
			t.Fatalf("audit log missing %q:\n%s", want, string(auditBody))
		}
	}
}

func TestDockerHubDecisionIntegration(t *testing.T) {
	if os.Getenv("RIBAT_INTEGRATION_TESTS") != "1" && os.Getenv("RIBAT_INTEGRATION_DOCKERHUB") != "1" {
		t.Skip("set RIBAT_INTEGRATION_TESTS=1 or RIBAT_INTEGRATION_DOCKERHUB=1 to run live Docker Hub validation")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	db, cfg, auditPath := integrationState(t)
	engine := quarantine.Engine{
		Config:   cfg,
		Store:    db,
		Resolver: registry.NewResolver(&http.Client{Timeout: 30 * time.Second}),
		Audit:    audit.NewLogger(auditPath),
		Now:      func() time.Time { return time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC) },
	}

	decision, err := engine.Decide(ctx, quarantine.Request{
		ImageRef:      "docker.io/library/alpine:latest",
		ClientUser:    "integration-test",
		RequestMethod: http.MethodPost,
		RequestURI:    "/v1.44/images/create?fromImage=alpine&tag=latest",
	})
	if err != nil {
		t.Fatalf("Decide returned error = %v", err)
	}
	if decision.Allowed {
		t.Fatalf("first live Docker Hub decision allowed; want first-seen denial: %#v", decision)
	}
	if !strings.HasPrefix(decision.Digest, "sha256:") {
		t.Fatalf("resolved digest = %q, want sha256 digest", decision.Digest)
	}
	if !strings.Contains(decision.Reason, "new digest observed") {
		t.Fatalf("reason = %q, want first-seen quarantine reason", decision.Reason)
	}
	obs, err := db.GetObservation(ctx, "docker.io", "library/alpine", "latest", decision.Digest)
	if err != nil {
		t.Fatalf("GetObservation error = %v", err)
	}
	if obs == nil {
		t.Fatalf("Docker Hub decision did not record observation for %s", decision.Digest)
	}
}

type response struct {
	StatusCode int
	Header     http.Header
	Body       string
}

func proxyGet(t *testing.T, handler http.Handler, target string) response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return response{
		StatusCode: rec.Code,
		Header:     rec.Header().Clone(),
		Body:       rec.Body.String(),
	}
}

func integrationState(t *testing.T) (*store.SQLiteStore, policy.Config, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.OpenSQLite(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("OpenSQLite error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	auditPath := filepath.Join(dir, "audit.jsonl")
	cfg := policy.Config{
		Version: 1,
		DefaultPolicy: policy.EffectivePolicy{
			MutableTags: policy.MutableTagPolicy{
				Action:       policy.ActionQuarantine,
				MinDigestAge: policy.Duration{Duration: 24 * time.Hour},
			},
			DigestPinnedImages:       policy.ActionPolicy{Action: policy.ActionAllow},
			FailedRegistryResolution: policy.ActionPolicy{Action: policy.ActionDeny},
			FailedSignatureCheck:     policy.ActionPolicy{Action: policy.ActionDeny},
		},
		Audit: policy.AuditConfig{Path: auditPath},
		State: policy.StateConfig{Backend: "sqlite", Path: filepath.Join(dir, "state.db")},
	}
	return db, cfg, auditPath
}

type localRegistryFixture struct {
	Endpoint string
	Manifest string
	Blobs    map[string]string
}

func newLocalRegistryFixture(t *testing.T) localRegistryFixture {
	t.Helper()
	manifest := `{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "` + localConfigDigest + `",
    "size": 16
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar",
      "digest": "` + localLayerDigest + `",
      "size": 11
    }
  ]
}`
	blobs := map[string]string{
		localConfigDigest: `{"config":true}`,
		localLayerDigest:  "hello layer",
	}
	return localRegistryFixture{Endpoint: "https://local.registry", Manifest: manifest, Blobs: blobs}
}

func (f localRegistryFixture) Client() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("Docker-Distribution-API-Version", "registry/2.0")
		status := http.StatusOK
		body := ""
		switch req.URL.Path {
		case "/v2/", "/v2":
		case "/v2/example/app/manifests/latest", "/v2/example/app/manifests/" + localManifestDigest:
			if req.Method != http.MethodGet && req.Method != http.MethodHead {
				status = http.StatusMethodNotAllowed
				body = "method not allowed\n"
				break
			}
			header.Set("Content-Type", registry.MediaTypeOCIManifest)
			header.Set("Docker-Content-Digest", localManifestDigest)
			header.Set("Content-Length", strconv.Itoa(len(f.Manifest)))
			if req.Method == http.MethodGet {
				body = f.Manifest
			}
		case "/v2/example/app/blobs/" + localConfigDigest, "/v2/example/app/blobs/" + localLayerDigest:
			if req.Method != http.MethodGet && req.Method != http.MethodHead {
				status = http.StatusMethodNotAllowed
				body = "method not allowed\n"
				break
			}
			digest := strings.TrimPrefix(req.URL.Path, "/v2/example/app/blobs/")
			header.Set("Content-Type", "application/octet-stream")
			header.Set("Docker-Content-Digest", digest)
			if req.Method == http.MethodGet {
				body = f.Blobs[digest]
			}
		default:
			status = http.StatusNotFound
			body = "not found\n"
		}
		if header.Get("Content-Length") == "" {
			header.Set("Content-Length", strconv.Itoa(len(body)))
		}
		return &http.Response{
			StatusCode:    status,
			Status:        http.StatusText(status),
			Header:        header,
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
			Request:       req,
		}, nil
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
