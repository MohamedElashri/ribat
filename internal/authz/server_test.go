package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MohamedElashri/ribat/internal/audit"
	"github.com/MohamedElashri/ribat/internal/image"
	"github.com/MohamedElashri/ribat/internal/policy"
	"github.com/MohamedElashri/ribat/internal/quarantine"
	"github.com/MohamedElashri/ribat/internal/registry"
	"github.com/MohamedElashri/ribat/internal/store"
)

func TestActivateAdvertisesAuthZ(t *testing.T) {
	handler := Server{Engine: fakeEngine{}}.Handler()
	req := httptest.NewRequest(http.MethodPost, "/Plugin.Activate", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), `"authz"`) {
		t.Fatalf("body = %s, want authz implementation", rr.Body.String())
	}
}

func TestListenAndServeUsesUnixSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socketPath := filepath.Join(t.TempDir(), "ribat.sock")
	errCh := make(chan error, 1)

	go func() {
		errCh <- ListenAndServe(ctx, socketPath, Server{Engine: fakeEngine{}})
	}()

	waitForSocket(t, socketPath, errCh)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}

	resp, err := client.Post("http://unix/Plugin.Activate", "application/json", nil)
	if err != nil {
		t.Fatalf("post activate over unix socket: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read activate response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"authz"`) {
		t.Fatalf("body = %s, want authz implementation", body)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ListenAndServe() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ListenAndServe() did not stop after context cancellation")
	}
}

func TestAuthZReqAllowsNonPullRequests(t *testing.T) {
	handler := Server{Engine: fakeEngine{}}.Handler()
	resp := postAuthZReq(t, handler, PluginRequest{
		RequestMethod: http.MethodGet,
		RequestURI:    "/v1.46/containers/json",
	})

	if !resp.Allow {
		t.Fatalf("Allow = false, want true: %#v", resp)
	}
}

func TestAuthZReqDeniesFirstSeenPullAndAuditsDockerRequest(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	engine, db, auditPath := newAuthZEngine(t, now, "sha256:first")
	handler := Server{Engine: &engine}.Handler()

	resp := postAuthZReq(t, handler, PluginRequest{
		User:          "alice",
		RequestMethod: http.MethodPost,
		RequestURI:    "/v1.46/images/create?fromImage=alpine&tag=latest",
	})

	if resp.Allow {
		t.Fatalf("Allow = true, want denial: %#v", resp)
	}
	for _, want := range []string{
		"Pull blocked by Ribat.",
		"Image: docker.io/library/alpine:latest",
		"Resolved digest: sha256:first",
		"Reason: new digest observed for mutable tag; digest entered quarantine",
	} {
		if !strings.Contains(resp.Err, want) {
			t.Fatalf("Err = %q, want %q", resp.Err, want)
		}
	}
	count, err := db.CountDecisions(context.Background())
	if err != nil {
		t.Fatalf("CountDecisions() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("decision count = %d, want 1", count)
	}
	auditBody, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	for _, want := range []string{
		`"client_user":"alice"`,
		`"request_method":"POST"`,
		`"request_uri":"/v1.46/images/create?fromImage=alpine\u0026tag=latest"`,
		`"decision":"deny"`,
	} {
		if !bytes.Contains(auditBody, []byte(want)) {
			t.Fatalf("audit log = %s, want %s", auditBody, want)
		}
	}
}

func TestAuthZReqAllowsApprovedDigest(t *testing.T) {
	firstSeen := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	engine, db, _ := newAuthZEngine(t, firstSeen.Add(time.Hour), "sha256:first")
	if _, err := db.CreateObservation(context.Background(), "docker.io", "library/alpine", "latest", "sha256:first", firstSeen); err != nil {
		t.Fatalf("CreateObservation() error = %v", err)
	}
	if _, err := db.ApproveDigest(context.Background(), "docker.io", "library/alpine", "latest", "sha256:first", firstSeen, "alice", "reviewed", nil); err != nil {
		t.Fatalf("ApproveDigest() error = %v", err)
	}
	handler := Server{Engine: &engine}.Handler()

	resp := postAuthZReq(t, handler, PluginRequest{
		User:          "alice",
		RequestMethod: http.MethodPost,
		RequestURI:    "/v1.46/images/create?fromImage=alpine&tag=latest",
	})

	if !resp.Allow {
		t.Fatalf("Allow = false, want approved allow: %#v", resp)
	}
	if !strings.Contains(resp.Msg, "Manual approval: active") {
		t.Fatalf("Msg = %q, want manual approval context", resp.Msg)
	}
}

func TestAuthZReqAllowsDigestPinnedPull(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	engine, _, _ := newAuthZEngine(t, now, "unused")
	handler := Server{Engine: &engine}.Handler()

	resp := postAuthZReq(t, handler, PluginRequest{
		RequestMethod: http.MethodPost,
		RequestURI:    "/v1.46/images/create?fromImage=ghcr.io/example/app@sha256:abc123",
	})

	if !resp.Allow {
		t.Fatalf("Allow = false, want digest-pinned allow: %#v", resp)
	}
	if !strings.Contains(resp.Msg, "digest-pinned image allowed by policy") {
		t.Fatalf("Msg = %q, want digest-pinned reason", resp.Msg)
	}
}

func TestAuthZReqDeniesContainerCreateMutableImage(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	engine, db, _ := newAuthZEngine(t, now, "sha256:container")
	handler := Server{Engine: &engine}.Handler()

	resp := postAuthZReq(t, handler, PluginRequest{
		User:          "watchtower",
		RequestMethod: http.MethodPost,
		RequestURI:    "/v1.46/containers/create?name=app",
		RequestBody:   `{"Image":"alpine:latest"}`,
	})

	if resp.Allow {
		t.Fatalf("Allow = true, want container create denial: %#v", resp)
	}
	for _, want := range []string{
		"Pull blocked by Ribat.",
		"Image: docker.io/library/alpine:latest",
		"Resolved digest: sha256:container",
	} {
		if !strings.Contains(resp.Err, want) {
			t.Fatalf("Err = %q, want %q", resp.Err, want)
		}
	}
	obs, err := db.GetObservation(context.Background(), "docker.io", "library/alpine", "latest", "sha256:container")
	if err != nil {
		t.Fatalf("GetObservation() error = %v", err)
	}
	if obs == nil {
		t.Fatal("observation = nil, want container create image recorded")
	}
}

func TestAuthZReqDeniesSwarmServiceUpdateMutableImage(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	engine, db, _ := newAuthZEngine(t, now, "sha256:service")
	handler := Server{Engine: &engine}.Handler()

	resp := postAuthZReq(t, handler, PluginRequest{
		User:          "portainer",
		RequestMethod: http.MethodPost,
		RequestURI:    "/v1.46/services/web/update?version=7",
		RequestBody:   `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:stable"}}}`,
	})

	if resp.Allow {
		t.Fatalf("Allow = true, want service update denial: %#v", resp)
	}
	if !strings.Contains(resp.Err, "Image: docker.io/library/nginx:stable") {
		t.Fatalf("Err = %q, want normalized service image", resp.Err)
	}
	obs, err := db.GetObservation(context.Background(), "docker.io", "library/nginx", "stable", "sha256:service")
	if err != nil {
		t.Fatalf("GetObservation() error = %v", err)
	}
	if obs == nil {
		t.Fatal("observation = nil, want service update image recorded")
	}
}

func TestAuthZReqDeniesBuildPullAndAudits(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	db, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	handler := Server{
		Engine:    fakeEngine{},
		Decisions: db,
		Audit:     audit.NewLogger(auditPath),
		Now:       func() time.Time { return now },
	}.Handler()

	resp := postAuthZReq(t, handler, PluginRequest{
		User:          "builder",
		RequestMethod: http.MethodPost,
		RequestURI:    "/v1.46/build?pull=1&t=example/app",
	})

	if resp.Allow {
		t.Fatalf("Allow = true, want build --pull denial: %#v", resp)
	}
	if !strings.Contains(resp.Err, "docker build --pull is denied by Ribat") {
		t.Fatalf("Err = %q, want build pull denial reason", resp.Err)
	}
	count, err := db.CountDecisions(context.Background())
	if err != nil {
		t.Fatalf("CountDecisions() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("decision count = %d, want 1", count)
	}
	auditBody, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	for _, want := range []string{
		`"image_ref":"docker build"`,
		`"client_user":"builder"`,
		`"request_uri":"/v1.46/build?pull=1\u0026t=example/app"`,
		`"decision":"deny"`,
	} {
		if !bytes.Contains(auditBody, []byte(want)) {
			t.Fatalf("audit log = %s, want %s", auditBody, want)
		}
	}
}

func TestAuthZReqAllowsBuildWithoutPull(t *testing.T) {
	handler := Server{Engine: fakeEngine{}}.Handler()
	resp := postAuthZReq(t, handler, PluginRequest{
		RequestMethod: http.MethodPost,
		RequestURI:    "/v1.46/build?t=example/app",
	})

	if !resp.Allow {
		t.Fatalf("Allow = false, want build without --pull pass-through: %#v", resp)
	}
}

func TestPullImageRef(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		requestURI string
		wantRef    string
		wantOK     bool
	}{
		{
			name:       "pull query",
			method:     http.MethodPost,
			requestURI: "/v1.46/images/create?fromImage=alpine&tag=latest",
			wantRef:    "alpine:latest",
			wantOK:     true,
		},
		{
			name:       "tag already in image",
			method:     http.MethodPost,
			requestURI: "/v1.46/images/create?fromImage=nginx:stable&tag=ignored",
			wantRef:    "nginx:stable",
			wantOK:     true,
		},
		{
			name:       "digest pinned",
			method:     http.MethodPost,
			requestURI: "/v1.46/images/create?fromImage=ghcr.io/example/app@sha256:abc123&tag=latest",
			wantRef:    "ghcr.io/example/app@sha256:abc123",
			wantOK:     true,
		},
		{
			name:       "uncovered endpoint",
			method:     http.MethodPost,
			requestURI: "/v1.46/containers/json",
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRef, gotOK, err := pullImageRef(tt.method, tt.requestURI)
			if err != nil {
				t.Fatalf("pullImageRef() error = %v", err)
			}
			if gotOK != tt.wantOK {
				t.Fatalf("ok = %t, want %t", gotOK, tt.wantOK)
			}
			if gotRef != tt.wantRef {
				t.Fatalf("ref = %q, want %q", gotRef, tt.wantRef)
			}
		})
	}
}

func TestInspectRequestExtractsWorkflowImages(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		requestURI  string
		requestBody string
		wantKind    requestActionKind
		wantRef     string
	}{
		{
			name:       "compose pull images create",
			method:     http.MethodPost,
			requestURI: "/v1.46/images/create?fromImage=alpine&tag=latest",
			wantKind:   actionDecide,
			wantRef:    "alpine:latest",
		},
		{
			name:        "watchtower container create",
			method:      http.MethodPost,
			requestURI:  "/v1.46/containers/create",
			requestBody: `{"Image":"nginx:stable"}`,
			wantKind:    actionDecide,
			wantRef:     "nginx:stable",
		},
		{
			name:        "portainer service create",
			method:      http.MethodPost,
			requestURI:  "/v1.46/services/create",
			requestBody: `{"TaskTemplate":{"ContainerSpec":{"Image":"ghcr.io/example/app:main"}}}`,
			wantKind:    actionDecide,
			wantRef:     "ghcr.io/example/app:main",
		},
		{
			name:        "swarm service update",
			method:      http.MethodPost,
			requestURI:  "/v1.46/services/example/update?version=3",
			requestBody: `{"TaskTemplate":{"ContainerSpec":{"Image":"redis:7"}}}`,
			wantKind:    actionDecide,
			wantRef:     "redis:7",
		},
		{
			name:       "build pull",
			method:     http.MethodPost,
			requestURI: "/v1.46/build?pull=true",
			wantKind:   actionDeny,
		},
		{
			name:       "build without pull",
			method:     http.MethodPost,
			requestURI: "/v1.46/build",
			wantKind:   actionPass,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, err := inspectRequest(tt.method, tt.requestURI, tt.requestBody)
			if err != nil {
				t.Fatalf("inspectRequest() error = %v", err)
			}
			if action.kind != tt.wantKind {
				t.Fatalf("kind = %v, want %v", action.kind, tt.wantKind)
			}
			if tt.wantRef != "" {
				if len(action.imageRefs) != 1 {
					t.Fatalf("image refs = %#v, want one ref", action.imageRefs)
				}
				if action.imageRefs[0] != tt.wantRef {
					t.Fatalf("image ref = %q, want %q", action.imageRefs[0], tt.wantRef)
				}
			}
		})
	}
}

func postAuthZReq(t *testing.T, handler http.Handler, pluginReq PluginRequest) PluginResponse {
	t.Helper()
	body, err := json.Marshal(pluginReq)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/AuthZPlugin.AuthZReq", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	var resp PluginResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response %q: %v", rr.Body.String(), err)
	}
	return resp
}

func waitForSocket(t *testing.T, socketPath string, errCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			if err != nil && strings.Contains(err.Error(), "operation not permitted") {
				t.Skipf("unix socket listen not permitted in this sandbox: %v", err)
			}
			t.Fatalf("ListenAndServe() returned before socket was ready: %v", err)
		default:
		}
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %s was not ready", socketPath)
}

func newAuthZEngine(t *testing.T, now time.Time, digest string) (quarantine.Engine, *store.SQLiteStore, string) {
	t.Helper()
	db, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	return quarantine.Engine{
		Config:   testConfig(),
		Store:    db,
		Resolver: fakeResolver{digest: digest},
		Audit:    audit.NewLogger(auditPath),
		Now:      func() time.Time { return now },
	}, db, auditPath
}

func testConfig() policy.Config {
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

type fakeResolver struct {
	digest string
}

func (r fakeResolver) Resolve(_ context.Context, ref image.Reference) (registry.ManifestDigest, error) {
	return registry.ManifestDigest{
		Registry:   ref.Registry,
		Repository: ref.Repository,
		Tag:        ref.Tag,
		Digest:     r.digest,
	}, nil
}

type fakeEngine struct{}

func (fakeEngine) Decide(context.Context, quarantine.Request) (quarantine.Decision, error) {
	return quarantine.Decision{Allowed: true}, nil
}
