package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/MohamedElashri/ribat/internal/quarantine"
)

type DecisionEngine interface {
	Decide(context.Context, quarantine.Request) (quarantine.Decision, error)
}

type Server struct {
	Engine DecisionEngine
}

type PluginRequest struct {
	User            string            `json:"User"`
	UserAuthNMethod string            `json:"UserAuthNMethod"`
	RequestMethod   string            `json:"RequestMethod"`
	RequestURI      string            `json:"RequestURI"`
	RequestHeaders  map[string]string `json:"RequestHeaders"`
	RequestBody     string            `json:"RequestBody"`
}

type PluginResponse struct {
	Allow bool   `json:"Allow"`
	Msg   string `json:"Msg,omitempty"`
	Err   string `json:"Err,omitempty"`
}

func ListenAndServe(ctx context.Context, socketPath string, server Server) error {
	if socketPath == "" {
		return errors.New("authz socket path is required")
	}
	if server.Engine == nil {
		return errors.New("authz decision engine is required")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return fmt.Errorf("create authz socket directory: %w", err)
	}
	if err := os.RemoveAll(socketPath); err != nil {
		return fmt.Errorf("remove stale authz socket: %w", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on authz socket: %w", err)
	}
	defer listener.Close()

	httpServer := &http.Server{Handler: server.Handler()}
	go func() {
		<-ctx.Done()
		_ = httpServer.Shutdown(context.Background())
	}()

	err = httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/Plugin.Activate", s.handleActivate)
	mux.HandleFunc("/AuthZPlugin.AuthZReq", s.handleAuthZReq)
	mux.HandleFunc("/AuthZPlugin.AuthZRes", s.handleAuthZRes)
	return mux
}

func (s Server) handleActivate(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string][]string{"Implements": {"authz"}})
}

func (s Server) handleAuthZReq(w http.ResponseWriter, r *http.Request) {
	var req PluginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, PluginResponse{Allow: false, Err: "invalid authorization request: " + err.Error()})
		return
	}

	imageRef, ok, err := pullImageRef(req.RequestMethod, req.RequestURI)
	if err != nil {
		writeJSON(w, http.StatusOK, PluginResponse{Allow: false, Err: err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusOK, PluginResponse{Allow: true})
		return
	}

	decision, err := s.Engine.Decide(r.Context(), quarantine.Request{
		ImageRef:      imageRef,
		ClientUser:    req.User,
		RequestMethod: req.RequestMethod,
		RequestURI:    req.RequestURI,
	})
	if err != nil {
		writeJSON(w, http.StatusOK, PluginResponse{Allow: false, Err: "ribat authorization failed: " + err.Error()})
		return
	}
	response := PluginResponse{
		Allow: decision.Allowed,
		Msg:   decisionMessage(decision),
	}
	if !decision.Allowed {
		response.Err = response.Msg
		response.Msg = ""
	}
	writeJSON(w, http.StatusOK, response)
}

func (s Server) handleAuthZRes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, PluginResponse{Allow: true})
}

func pullImageRef(method, requestURI string) (string, bool, error) {
	if !strings.EqualFold(method, http.MethodPost) {
		return "", false, nil
	}
	u, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return "", false, fmt.Errorf("could not parse Docker request URI %q: %w", requestURI, err)
	}
	if !isImagesCreatePath(u.Path) {
		return "", false, nil
	}

	q := u.Query()
	fromImage := q.Get("fromImage")
	if fromImage == "" {
		return "", true, fmt.Errorf("Docker pull request %q is missing fromImage", requestURI)
	}
	tag := q.Get("tag")
	return combineImageAndTag(fromImage, tag), true, nil
}

func isImagesCreatePath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 3 && strings.HasPrefix(parts[0], "v") && parts[1] == "images" && parts[2] == "create"
}

func combineImageAndTag(fromImage, tag string) string {
	if tag == "" || strings.Contains(fromImage, "@") || hasTag(fromImage) {
		return fromImage
	}
	return fromImage + ":" + tag
}

func hasTag(ref string) bool {
	lastSlash := strings.LastIndexByte(ref, '/')
	lastColon := strings.LastIndexByte(ref, ':')
	return lastColon > lastSlash
}

func decisionMessage(decision quarantine.Decision) string {
	var lines []string
	if decision.Allowed {
		lines = append(lines, "Pull allowed by Ribat.")
	} else {
		lines = append(lines, "Pull blocked by Ribat.")
	}
	lines = append(lines, "", "Image: "+decision.ImageRef)
	if decision.Digest != "" {
		lines = append(lines, "Resolved digest: "+decision.Digest)
	}
	lines = append(lines, "Policy: "+decision.MatchedRule)
	if decision.FirstSeenAt != nil {
		lines = append(lines, "Digest first seen: "+decision.FirstSeenAt.Format("2006-01-02 15:04:05 UTC"))
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
	if decision.ManualApproval {
		lines = append(lines, "Manual approval: active")
	}
	if decision.Frozen {
		lines = append(lines, "Freeze: active")
	}
	lines = append(lines, "Reason: "+decision.Reason)
	return strings.Join(lines, "\n")
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
