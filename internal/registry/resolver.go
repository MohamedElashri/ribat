package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MohamedElashri/ribat/internal/image"
)

const (
	MediaTypeDockerManifestV2   = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeOCIManifest        = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIImageIndex      = "application/vnd.oci.image.index.v1+json"
)

var ErrTagNotFound = errors.New("tag not found")

type Resolver struct {
	Client    *http.Client
	Endpoints map[string]string
}

type ManifestDigest struct {
	Registry   string
	Repository string
	Tag        string
	Digest     string
	MediaType  string
}

func NewResolver(client *http.Client) *Resolver {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Resolver{Client: client}
}

func (r *Resolver) Resolve(ctx context.Context, ref image.Reference) (ManifestDigest, error) {
	if ref.Tag == "" {
		return ManifestDigest{}, fmt.Errorf("image %s has no tag to resolve", ref.CanonicalRef)
	}

	endpoint, err := r.endpoint(ref.Registry)
	if err != nil {
		return ManifestDigest{}, err
	}
	manifestURL := endpoint + "/v2/" + ref.Repository + "/manifests/" + url.PathEscape(ref.Tag)

	resp, err := r.doManifestRequest(ctx, http.MethodHead, manifestURL, "")
	if err != nil {
		return ManifestDigest{}, err
	}
	if shouldFallbackToGet(resp) {
		closeBody(resp)
		resp, err = r.doManifestRequest(ctx, http.MethodGet, manifestURL, "")
		if err != nil {
			return ManifestDigest{}, err
		}
	}

	if resp.StatusCode == http.StatusUnauthorized {
		challenge, err := parseBearerChallenge(resp.Header.Get("WWW-Authenticate"))
		if err != nil {
			closeBody(resp)
			return ManifestDigest{}, fmt.Errorf("registry %s requires authentication but did not return a usable bearer challenge: %w", ref.Registry, err)
		}
		closeBody(resp)
		token, err := r.fetchBearerToken(ctx, challenge)
		if err != nil {
			return ManifestDigest{}, err
		}
		resp, err = r.doManifestRequest(ctx, http.MethodHead, manifestURL, token)
		if err != nil {
			return ManifestDigest{}, err
		}
		if shouldFallbackToGet(resp) {
			closeBody(resp)
			resp, err = r.doManifestRequest(ctx, http.MethodGet, manifestURL, token)
			if err != nil {
				return ManifestDigest{}, err
			}
		}
	}
	defer closeBody(resp)

	if resp.StatusCode == http.StatusNotFound {
		return ManifestDigest{}, fmt.Errorf("%w: %s", ErrTagNotFound, ref.CanonicalRef)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return ManifestDigest{}, fmt.Errorf("resolve registry digest for %s: registry returned HTTP %d", ref.CanonicalRef, resp.StatusCode)
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return ManifestDigest{}, fmt.Errorf("resolve registry digest for %s: registry response did not include Docker-Content-Digest", ref.CanonicalRef)
	}

	return ManifestDigest{
		Registry:   ref.Registry,
		Repository: ref.Repository,
		Tag:        ref.Tag,
		Digest:     digest,
		MediaType:  mediaType(resp.Header.Get("Content-Type")),
	}, nil
}

func (r *Resolver) endpoint(registry string) (string, error) {
	if r != nil && r.Endpoints != nil {
		if endpoint := r.Endpoints[registry]; endpoint != "" {
			return strings.TrimRight(endpoint, "/"), nil
		}
	}
	if registry == "docker.io" {
		return "https://registry-1.docker.io", nil
	}
	if registry == "" {
		return "", errors.New("registry is required")
	}
	return "https://" + registry, nil
}

func shouldFallbackToGet(resp *http.Response) bool {
	return resp.StatusCode == http.StatusMethodNotAllowed ||
		(resp.StatusCode == http.StatusNotFound && resp.Header.Get("Docker-Content-Digest") == "")
}

func (r *Resolver) doManifestRequest(ctx context.Context, method, manifestURL, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, manifestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create registry request: %w", err)
	}
	req.Header.Set("Accept", strings.Join([]string{
		MediaTypeOCIImageIndex,
		MediaTypeDockerManifestList,
		MediaTypeOCIManifest,
		MediaTypeDockerManifestV2,
	}, ", "))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("resolve registry digest: %w", err)
	}
	return resp, nil
}

type bearerChallenge struct {
	Realm   string
	Service string
	Scope   string
}

func parseBearerChallenge(header string) (bearerChallenge, error) {
	if header == "" {
		return bearerChallenge{}, errors.New("missing WWW-Authenticate header")
	}
	scheme, params, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return bearerChallenge{}, fmt.Errorf("unsupported challenge %q", header)
	}

	values := map[string]string{}
	for _, part := range splitChallengeParams(params) {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		values[strings.ToLower(key)] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	challenge := bearerChallenge{
		Realm:   values["realm"],
		Service: values["service"],
		Scope:   values["scope"],
	}
	if challenge.Realm == "" {
		return bearerChallenge{}, errors.New("bearer challenge missing realm")
	}
	return challenge, nil
}

func splitChallengeParams(input string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	escaped := false
	for _, r := range input {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			escaped = true
		case r == '"':
			inQuote = !inQuote
			current.WriteRune(r)
		case r == ',' && !inQuote:
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	parts = append(parts, current.String())
	return parts
}

func (r *Resolver) fetchBearerToken(ctx context.Context, challenge bearerChallenge) (string, error) {
	tokenURL, err := url.Parse(challenge.Realm)
	if err != nil {
		return "", fmt.Errorf("parse bearer token realm: %w", err)
	}
	q := tokenURL.Query()
	if challenge.Service != "" {
		q.Set("service", challenge.Service)
	}
	if challenge.Scope != "" {
		q.Set("scope", challenge.Scope)
	}
	tokenURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("create bearer token request: %w", err)
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch bearer token: %w", err)
	}
	defer closeBody(resp)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("fetch bearer token: token service returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read bearer token response: %w", err)
	}
	var payload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("parse bearer token response: %w", err)
	}
	token := payload.Token
	if token == "" {
		token = payload.AccessToken
	}
	if token == "" {
		return "", errors.New("bearer token response did not include token")
	}
	return token, nil
}

func mediaType(contentType string) string {
	value, _, _ := strings.Cut(contentType, ";")
	return strings.TrimSpace(value)
}

func closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}
