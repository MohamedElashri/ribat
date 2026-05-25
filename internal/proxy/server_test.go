package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MohamedElashri/ribat/internal/policy"
	"github.com/MohamedElashri/ribat/internal/quarantine"
	"github.com/MohamedElashri/ribat/internal/registry"
	"github.com/MohamedElashri/ribat/internal/store"
)

const (
	testManifestDigest      = "sha256:manifest"
	testChildManifestDigest = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	testConfigDigest        = "sha256:config"
	testLayerDigest         = "sha256:layer"
)

func TestFreshDigestManifestRequestReturnsForbidden(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	handler, db := newProxyTestHandler(t, now)

	req := httptest.NewRequest(http.MethodGet, "/v2/example.test/example/app/manifests/latest", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Pull blocked by Ribat") {
		t.Fatalf("body = %q, want Ribat denial", rec.Body.String())
	}
	obs, err := db.GetObservation(context.Background(), "example.test", "example/app", "latest", testManifestDigest)
	if err != nil {
		t.Fatalf("GetObservation() error = %v", err)
	}
	if obs == nil {
		t.Fatal("observation = nil, want fresh digest recorded")
	}
	count, err := db.CountDecisions(context.Background())
	if err != nil {
		t.Fatalf("CountDecisions() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("decision count = %d, want 1", count)
	}
}

func TestMatureDigestManifestRequestProxiesManifest(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	handler, db := newProxyTestHandler(t, now)
	if _, err := db.CreateObservation(context.Background(), "example.test", "example/app", "latest", testManifestDigest, now.Add(-8*24*time.Hour)); err != nil {
		t.Fatalf("CreateObservation() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v2/example.test/example/app/manifests/latest", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Docker-Content-Digest"); got != testManifestDigest {
		t.Fatalf("Docker-Content-Digest = %q, want %q", got, testManifestDigest)
	}
	if !strings.Contains(rec.Body.String(), testLayerDigest) {
		t.Fatalf("body = %q, want proxied manifest", rec.Body.String())
	}
}

func TestDigestPathManifestRequestNormalizesToDigestPinnedImage(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	handler, _ := newProxyTestHandler(t, now)

	pathDigest := strings.Replace(testChildManifestDigest, ":", "-", 1)
	req := httptest.NewRequest(http.MethodGet, "/v2/example.test/example/app/manifests/"+pathDigest, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Docker-Content-Digest"); got != testChildManifestDigest {
		t.Fatalf("Docker-Content-Digest = %q, want %q", got, testChildManifestDigest)
	}
	if !strings.Contains(rec.Body.String(), testLayerDigest) {
		t.Fatalf("body = %q, want proxied manifest", rec.Body.String())
	}
}

func TestBlobRequestBeforeAllowedManifestIsDenied(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	handler, _ := newProxyTestHandler(t, now)

	req := httptest.NewRequest(http.MethodGet, "/v2/example.test/example/app/blobs/"+testLayerDigest, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no allowed manifest") {
		t.Fatalf("body = %q, want blob gate reason", rec.Body.String())
	}
}

func TestBlobRequestAfterAllowedManifestIsProxied(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	handler, db := newProxyTestHandler(t, now)
	if _, err := db.CreateObservation(context.Background(), "example.test", "example/app", "latest", testManifestDigest, now.Add(-8*24*time.Hour)); err != nil {
		t.Fatalf("CreateObservation() error = %v", err)
	}

	manifestReq := httptest.NewRequest(http.MethodGet, "/v2/example.test/example/app/manifests/latest", nil)
	manifestRec := httptest.NewRecorder()
	handler.ServeHTTP(manifestRec, manifestReq)
	if manifestRec.Code != http.StatusOK {
		t.Fatalf("manifest status = %d, want 200; body = %q", manifestRec.Code, manifestRec.Body.String())
	}

	blobReq := httptest.NewRequest(http.MethodGet, "/v2/example.test/example/app/blobs/"+testLayerDigest, nil)
	blobRec := httptest.NewRecorder()
	handler.ServeHTTP(blobRec, blobReq)
	if blobRec.Code != http.StatusOK {
		t.Fatalf("blob status = %d, want 200; body = %q", blobRec.Code, blobRec.Body.String())
	}
	if got := blobRec.Body.String(); got != "layer bytes" {
		t.Fatalf("blob body = %q, want proxied layer", got)
	}
}

func newProxyTestHandler(t *testing.T, now time.Time) (http.Handler, *store.SQLiteStore) {
	t.Helper()
	resolver := registry.NewResolver(&http.Client{Transport: proxyRoundTripFunc(func(r *http.Request) *http.Response {
		headers := map[string]string{}
		switch r.URL.Path {
		case "/v2/example/app/manifests/latest":
			if r.Method != http.MethodHead && r.Method != http.MethodGet {
				t.Fatalf("manifest method = %s, want HEAD or GET", r.Method)
			}
			headers["Docker-Content-Digest"] = testManifestDigest
			headers["Content-Type"] = registry.MediaTypeOCIManifest
			if r.Method == http.MethodGet {
				return proxyResponse(http.StatusOK, headers, `{"schemaVersion":2,"mediaType":"`+registry.MediaTypeOCIManifest+`","config":{"digest":"`+testConfigDigest+`"},"layers":[{"digest":"`+testLayerDigest+`"}]}`)
			}
			return proxyResponse(http.StatusOK, headers, "")
		case "/v2/example/app/manifests/" + testChildManifestDigest:
			if r.Method != http.MethodGet {
				t.Fatalf("child manifest method = %s, want GET", r.Method)
			}
			headers["Docker-Content-Digest"] = testChildManifestDigest
			headers["Content-Type"] = registry.MediaTypeOCIManifest
			return proxyResponse(http.StatusOK, headers, `{"schemaVersion":2,"mediaType":"`+registry.MediaTypeOCIManifest+`","config":{"digest":"`+testConfigDigest+`"},"layers":[{"digest":"`+testLayerDigest+`"}]}`)
		case "/v2/example/app/blobs/" + testLayerDigest:
			headers["Docker-Content-Digest"] = testLayerDigest
			headers["Content-Type"] = "application/octet-stream"
			return proxyResponse(http.StatusOK, headers, "layer bytes")
		default:
			t.Fatalf("unexpected upstream path %s", r.URL.Path)
		}
		return proxyResponse(http.StatusInternalServerError, nil, "")
	})})
	resolver.Endpoints = map[string]string{"example.test": "https://example.test"}

	db, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	engine := quarantine.Engine{
		Config:   testProxyConfig(),
		Store:    db,
		Resolver: resolver,
		Now:      func() time.Time { return now },
	}
	server := &Server{Engine: &engine, Resolver: resolver}
	return server.Handler(), db
}

type proxyRoundTripFunc func(*http.Request) *http.Response

func (f proxyRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func proxyResponse(status int, headers map[string]string, body string) *http.Response {
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

func testProxyConfig() policy.Config {
	return policy.Config{
		Version: 1,
		DefaultPolicy: policy.EffectivePolicy{
			MutableTags: policy.MutableTagPolicy{
				Action:             policy.ActionQuarantine,
				MinDigestAge:       policy.Duration{Duration: 7 * 24 * time.Hour},
				AllowFirstSeenPull: false,
			},
			DigestPinnedImages:       policy.ActionPolicy{Action: policy.ActionAllow},
			FailedRegistryResolution: policy.ActionPolicy{Action: policy.ActionDeny},
			FailedSignatureCheck:     policy.ActionPolicy{Action: policy.ActionDeny},
		},
	}
}
