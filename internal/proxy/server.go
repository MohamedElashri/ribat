package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MohamedElashri/ribat/internal/image"
	"github.com/MohamedElashri/ribat/internal/quarantine"
	"github.com/MohamedElashri/ribat/internal/registry"
)

type DecisionEngine interface {
	Decide(context.Context, quarantine.Request) (quarantine.Decision, error)
}

type Server struct {
	Engine   DecisionEngine
	Resolver *registry.Resolver

	mu           sync.Mutex
	allowedBlobs map[string]struct{}
}

func ListenAndServe(ctx context.Context, listenAddr string, server Server) error {
	if listenAddr == "" {
		return errors.New("proxy listen address is required")
	}
	if server.Engine == nil {
		return errors.New("proxy decision engine is required")
	}
	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = httpServer.Shutdown(context.Background())
	}()
	err := httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Handler() http.Handler {
	s.ensureState()
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/", s.handleV2)
	mux.HandleFunc("/v2", s.handleV2)
	return mux
}

func (s *Server) handleV2(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	if r.URL.Path == "/v2" || r.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req, err := parseProxyRequest(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	switch req.kind {
	case proxyManifest:
		s.handleManifest(w, r, req)
	case proxyBlob:
		s.handleBlob(w, r, req)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request, req proxyRequest) {
	reference := normalizeManifestReference(req.reference)
	imageRef := proxyImageRef(req.registry, req.repository, reference)
	decision, err := s.Engine.Decide(r.Context(), quarantine.Request{
		ImageRef:      imageRef,
		RequestMethod: r.Method,
		RequestURI:    r.URL.RequestURI(),
	})
	if err != nil {
		http.Error(w, "ribat proxy decision failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !decision.Allowed {
		http.Error(w, proxyDecisionMessage(decision), http.StatusForbidden)
		return
	}

	ref, err := image.ParseReference(imageRef)
	if err != nil {
		http.Error(w, "invalid upstream image reference: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fetched, err := s.resolver().FetchManifest(r.Context(), ref, reference)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if fetched.MediaType != "" {
		w.Header().Set("Content-Type", fetched.MediaType)
	}
	if fetched.Digest != "" {
		w.Header().Set("Docker-Content-Digest", fetched.Digest)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(fetched.Body)))
	s.rememberManifestBlobs(req.registry, req.repository, fetched.Body)
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(fetched.Body)
	}
}

func (s *Server) handleBlob(w http.ResponseWriter, r *http.Request, req proxyRequest) {
	if !s.blobAllowed(req.registry, req.repository, req.reference) {
		http.Error(w, "blob denied by Ribat: no allowed manifest has exposed this blob digest", http.StatusForbidden)
		return
	}

	blob, err := s.resolver().FetchBlob(r.Context(), req.registry, req.repository, req.reference)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer blob.Body.Close()
	copyBlobHeaders(w.Header(), blob)
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, blob.Body)
	}
}

func (s *Server) resolver() *registry.Resolver {
	if s.Resolver != nil {
		return s.Resolver
	}
	return registry.NewResolver(nil)
}

func (s *Server) ensureState() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.allowedBlobs == nil {
		s.allowedBlobs = make(map[string]struct{})
	}
}

func (s *Server) rememberManifestBlobs(registryName, repository string, body []byte) {
	for _, digest := range manifestBlobDigests(body) {
		s.mu.Lock()
		s.allowedBlobs[blobKey(registryName, repository, digest)] = struct{}{}
		s.mu.Unlock()
	}
}

func (s *Server) blobAllowed(registryName, repository, digest string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.allowedBlobs[blobKey(registryName, repository, digest)]
	return ok
}

func blobKey(registryName, repository, digest string) string {
	return registryName + "\n" + repository + "\n" + digest
}

func manifestBlobDigests(body []byte) []string {
	var payload struct {
		Config *struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}
	var digests []string
	if payload.Config != nil && payload.Config.Digest != "" {
		digests = append(digests, payload.Config.Digest)
	}
	for _, layer := range payload.Layers {
		if layer.Digest != "" {
			digests = append(digests, layer.Digest)
		}
	}
	return digests
}

func copyBlobHeaders(dst http.Header, blob registry.Blob) {
	for _, key := range []string{"Content-Type", "Content-Length", "Docker-Content-Digest", "ETag"} {
		if value := blob.Header.Get(key); value != "" {
			dst.Set(key, value)
		}
	}
	if dst.Get("Content-Type") == "" && blob.MediaType != "" {
		dst.Set("Content-Type", blob.MediaType)
	}
	if dst.Get("Content-Length") == "" && blob.Size >= 0 {
		dst.Set("Content-Length", strconv.FormatInt(blob.Size, 10))
	}
	if dst.Get("Docker-Content-Digest") == "" {
		dst.Set("Docker-Content-Digest", blob.Digest)
	}
}

type proxyKind int

const (
	proxyUnknown proxyKind = iota
	proxyManifest
	proxyBlob
)

type proxyRequest struct {
	kind       proxyKind
	registry   string
	repository string
	reference  string
}

func parseProxyRequest(path string) (proxyRequest, error) {
	rest := strings.TrimPrefix(path, "/v2/")
	if rest == path || rest == "" {
		return proxyRequest{}, fmt.Errorf("unsupported registry proxy path %q", path)
	}
	if before, after, ok := strings.Cut(rest, "/manifests/"); ok {
		return parseRepositoryReference(before, after, proxyManifest)
	}
	if before, after, ok := strings.Cut(rest, "/blobs/"); ok {
		return parseRepositoryReference(before, after, proxyBlob)
	}
	return proxyRequest{}, fmt.Errorf("unsupported registry proxy path %q", path)
}

func parseRepositoryReference(repoPath, reference string, kind proxyKind) (proxyRequest, error) {
	repoPath = strings.Trim(repoPath, "/")
	reference = strings.Trim(reference, "/")
	if repoPath == "" || reference == "" {
		return proxyRequest{}, errors.New("registry proxy request is missing repository or reference")
	}
	registryName, repository, err := upstreamRepository(repoPath)
	if err != nil {
		return proxyRequest{}, err
	}
	return proxyRequest{
		kind:       kind,
		registry:   registryName,
		repository: repository,
		reference:  reference,
	}, nil
}

func upstreamRepository(repoPath string) (string, string, error) {
	parts := strings.Split(repoPath, "/")
	if len(parts) == 0 {
		return "", "", errors.New("repository path is required")
	}
	first := parts[0]
	if hasExplicitRegistry(first) {
		if len(parts) < 2 {
			return "", "", fmt.Errorf("proxied repository %q is missing an upstream repository path", repoPath)
		}
		return first, strings.Join(parts[1:], "/"), nil
	}
	if len(parts) == 1 {
		return "docker.io", "library/" + first, nil
	}
	return "docker.io", repoPath, nil
}

func hasExplicitRegistry(component string) bool {
	return strings.ContainsAny(component, ".:") || component == "localhost"
}

func proxyImageRef(registryName, repository, reference string) string {
	if strings.Contains(reference, ":") {
		return registryName + "/" + repository + "@" + reference
	}
	return registryName + "/" + repository + ":" + reference
}

func normalizeManifestReference(reference string) string {
	const (
		sha256PathPrefix = "sha256-"
		sha256HexLength  = 64
	)
	if len(reference) != len(sha256PathPrefix)+sha256HexLength || !strings.HasPrefix(reference, sha256PathPrefix) {
		return reference
	}
	hexPart := strings.TrimPrefix(reference, sha256PathPrefix)
	for _, r := range hexPart {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return reference
		}
	}
	return "sha256:" + hexPart
}

func proxyDecisionMessage(decision quarantine.Decision) string {
	var lines []string
	lines = append(lines, "Pull blocked by Ribat.", "", "Image: "+decision.ImageRef)
	if decision.Digest != "" {
		lines = append(lines, "Resolved digest: "+decision.Digest)
	}
	if decision.MatchedRule != "" {
		lines = append(lines, "Policy: "+decision.MatchedRule)
	}
	if decision.RequiredAge > 0 {
		lines = append(lines, "Required minimum age: "+decision.RequiredAge.String())
	}
	if decision.CurrentAge > 0 {
		lines = append(lines, "Current age: "+decision.CurrentAge.String())
	}
	if decision.NextAllowedAt != nil {
		lines = append(lines, "Next allowed pull: "+decision.NextAllowedAt.Format("2006-01-02 15:04:05 UTC"))
	}
	lines = append(lines, "Reason: "+decision.Reason)
	return strings.Join(lines, "\n")
}
