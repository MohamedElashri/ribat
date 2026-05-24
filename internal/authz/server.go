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
	"time"

	"github.com/MohamedElashri/ribat/internal/audit"
	"github.com/MohamedElashri/ribat/internal/quarantine"
	"github.com/MohamedElashri/ribat/internal/store"
)

type DecisionEngine interface {
	Decide(context.Context, quarantine.Request) (quarantine.Decision, error)
}

type DecisionRecorder interface {
	RecordDecision(context.Context, store.DecisionRecord) error
}

type AuditRecorder interface {
	Record(audit.Event) error
}

type Server struct {
	Engine    DecisionEngine
	Decisions DecisionRecorder
	Audit     AuditRecorder
	Now       func() time.Time
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

	action, err := inspectRequest(req.RequestMethod, req.RequestURI, req.RequestBody)
	if err != nil {
		writeJSON(w, http.StatusOK, PluginResponse{Allow: false, Err: err.Error()})
		return
	}
	if action.kind == actionPass {
		writeJSON(w, http.StatusOK, PluginResponse{Allow: true})
		return
	}
	if action.kind == actionDeny {
		if err := s.recordSyntheticDeny(r.Context(), req, action.reason); err != nil {
			writeJSON(w, http.StatusOK, PluginResponse{Allow: false, Err: "ribat authorization failed: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, PluginResponse{Allow: false, Err: action.reason})
		return
	}

	var messages []string
	for _, imageRef := range action.imageRefs {
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
		message := decisionMessage(decision)
		if !decision.Allowed {
			writeJSON(w, http.StatusOK, PluginResponse{Allow: false, Err: message})
			return
		}
		messages = append(messages, message)
	}
	writeJSON(w, http.StatusOK, PluginResponse{Allow: true, Msg: strings.Join(messages, "\n\n")})
}

func (s Server) handleAuthZRes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, PluginResponse{Allow: true})
}

func pullImageRef(method, requestURI string) (string, bool, error) {
	action, err := inspectRequest(method, requestURI, "")
	if err != nil {
		return "", false, err
	}
	if action.kind != actionDecide || len(action.imageRefs) == 0 {
		return "", false, nil
	}
	return action.imageRefs[0], true, nil
}

type requestActionKind int

const (
	actionPass requestActionKind = iota
	actionDecide
	actionDeny
)

type requestAction struct {
	kind      requestActionKind
	imageRefs []string
	reason    string
}

func inspectRequest(method, requestURI, requestBody string) (requestAction, error) {
	if !strings.EqualFold(method, http.MethodPost) {
		return requestAction{kind: actionPass}, nil
	}
	u, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return requestAction{}, fmt.Errorf("could not parse Docker request URI %q: %w", requestURI, err)
	}

	switch {
	case isImagesCreatePath(u.Path):
		q := u.Query()
		fromImage := q.Get("fromImage")
		if fromImage == "" {
			return requestAction{kind: actionDeny}, fmt.Errorf("Docker pull request %q is missing fromImage", requestURI)
		}
		return requestAction{kind: actionDecide, imageRefs: []string{combineImageAndTag(fromImage, q.Get("tag"))}}, nil
	case isBuildPath(u.Path):
		if queryBool(u.Query().Get("pull")) {
			return requestAction{
				kind:   actionDeny,
				reason: "docker build --pull is denied by Ribat because Dockerfile base images cannot be verified from this authorization request; use digest-pinned base images and build without --pull or pre-approve the pull separately",
			}, nil
		}
		return requestAction{kind: actionPass}, nil
	case isContainersCreatePath(u.Path):
		imageRef, err := containerCreateImage(requestBody)
		if err != nil {
			return requestAction{}, err
		}
		return requestAction{kind: actionDecide, imageRefs: []string{imageRef}}, nil
	case isServicesCreatePath(u.Path) || isServicesUpdatePath(u.Path):
		imageRef, err := serviceImage(requestBody)
		if err != nil {
			return requestAction{}, err
		}
		return requestAction{kind: actionDecide, imageRefs: []string{imageRef}}, nil
	default:
		return requestAction{kind: actionPass}, nil
	}
}

func (s Server) recordSyntheticDeny(ctx context.Context, req PluginRequest, reason string) error {
	now := s.now()
	if s.Decisions != nil {
		if err := s.Decisions.RecordDecision(ctx, store.DecisionRecord{
			Timestamp:     now,
			ImageRef:      "docker build",
			Decision:      store.DecisionDeny,
			Reason:        reason,
			ClientUser:    req.User,
			RequestMethod: req.RequestMethod,
			RequestURI:    req.RequestURI,
		}); err != nil {
			return err
		}
	}
	if s.Audit != nil {
		return s.Audit.Record(audit.Event{
			Timestamp:     now,
			ImageRef:      "docker build",
			Decision:      store.DecisionDeny,
			Reason:        reason,
			ClientUser:    req.User,
			RequestMethod: req.RequestMethod,
			RequestURI:    req.RequestURI,
		})
	}
	return nil
}

func (s Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func isImagesCreatePath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 3 && strings.HasPrefix(parts[0], "v") && parts[1] == "images" && parts[2] == "create"
}

func isBuildPath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 2 && strings.HasPrefix(parts[0], "v") && parts[1] == "build"
}

func isContainersCreatePath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 3 && strings.HasPrefix(parts[0], "v") && parts[1] == "containers" && parts[2] == "create"
}

func isServicesCreatePath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 3 && strings.HasPrefix(parts[0], "v") && parts[1] == "services" && parts[2] == "create"
}

func isServicesUpdatePath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 4 && strings.HasPrefix(parts[0], "v") && parts[1] == "services" && parts[2] != "" && parts[3] == "update"
}

func queryBool(value string) bool {
	switch strings.ToLower(value) {
	case "1", "true", "t", "yes", "y":
		return true
	default:
		return false
	}
}

func containerCreateImage(body string) (string, error) {
	var req struct {
		Image string `json:"Image"`
	}
	if err := decodeRequestBody(body, &req, "container create"); err != nil {
		return "", err
	}
	if req.Image == "" {
		return "", errors.New("Docker container create request is missing Image")
	}
	return req.Image, nil
}

func serviceImage(body string) (string, error) {
	var req struct {
		TaskTemplate struct {
			ContainerSpec struct {
				Image string `json:"Image"`
			} `json:"ContainerSpec"`
		} `json:"TaskTemplate"`
	}
	if err := decodeRequestBody(body, &req, "service create/update"); err != nil {
		return "", err
	}
	imageRef := req.TaskTemplate.ContainerSpec.Image
	if imageRef == "" {
		return "", errors.New("Docker service create/update request is missing TaskTemplate.ContainerSpec.Image")
	}
	return imageRef, nil
}

func decodeRequestBody(body string, dst any, operation string) error {
	if strings.TrimSpace(body) == "" {
		return fmt.Errorf("Docker %s request is missing a request body", operation)
	}
	if err := json.Unmarshal([]byte(body), dst); err != nil {
		return fmt.Errorf("could not parse Docker %s request body: %w", operation, err)
	}
	return nil
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
