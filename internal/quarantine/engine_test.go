package quarantine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MohamedElashri/ribat/internal/audit"
	"github.com/MohamedElashri/ribat/internal/image"
	"github.com/MohamedElashri/ribat/internal/policy"
	"github.com/MohamedElashri/ribat/internal/registry"
	"github.com/MohamedElashri/ribat/internal/store"
)

func TestFirstSeenMutableDigestIsDeniedRecordedAndAudited(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	engine, db, auditPath := newTestEngine(t, "sha256:first", now, false)

	decision, err := engine.Decide(context.Background(), Request{ImageRef: "example.test/example/app:latest"})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision.Allowed {
		t.Fatal("decision allowed = true, want deny")
	}
	if !strings.Contains(decision.Reason, "entered quarantine") {
		t.Fatalf("reason = %q, want quarantine reason", decision.Reason)
	}
	obs, err := db.GetObservation(context.Background(), "example.test", "example/app", "latest", "sha256:first")
	if err != nil {
		t.Fatalf("GetObservation() error = %v", err)
	}
	if obs == nil {
		t.Fatal("observation = nil, want recorded digest")
	}
	assertDecisionCount(t, db, 1)
	assertAuditDecision(t, auditPath, "deny", "sha256:first")
}

func TestRepeatedAttemptBeforeRequiredAgeIsDenied(t *testing.T) {
	firstSeen := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	engine, db, _ := newTestEngine(t, "sha256:first", firstSeen.Add(time.Hour), true)
	if _, err := db.CreateObservation(context.Background(), "example.test", "example/app", "latest", "sha256:first", firstSeen); err != nil {
		t.Fatalf("CreateObservation() error = %v", err)
	}

	decision, err := engine.Decide(context.Background(), Request{ImageRef: "example.test/example/app:latest"})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision.Allowed {
		t.Fatal("decision allowed = true, want deny")
	}
	if decision.NextAllowedAt == nil {
		t.Fatal("next allowed = nil, want calculated value")
	}
}

func TestAttemptAfterAgeThresholdIsAllowed(t *testing.T) {
	firstSeen := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	engine, db, _ := newTestEngine(t, "sha256:first", firstSeen.Add(8*24*time.Hour), false)
	if _, err := db.CreateObservation(context.Background(), "example.test", "example/app", "latest", "sha256:first", firstSeen); err != nil {
		t.Fatalf("CreateObservation() error = %v", err)
	}

	decision, err := engine.Decide(context.Background(), Request{ImageRef: "example.test/example/app:latest"})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("decision allowed = false, reason = %q", decision.Reason)
	}
	obs, err := db.GetObservation(context.Background(), "example.test", "example/app", "latest", "sha256:first")
	if err != nil {
		t.Fatalf("GetObservation() error = %v", err)
	}
	if obs.LastAllowedAt == nil {
		t.Fatal("LastAllowedAt = nil, want allowed timestamp")
	}
}

func TestManualApprovalAllowsBeforeAgeThreshold(t *testing.T) {
	firstSeen := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	engine, db, _ := newTestEngine(t, "sha256:first", firstSeen.Add(time.Hour), false)
	if _, err := db.CreateObservation(context.Background(), "example.test", "example/app", "latest", "sha256:first", firstSeen); err != nil {
		t.Fatalf("CreateObservation() error = %v", err)
	}
	if _, err := db.ApproveDigest(context.Background(), "example.test", "example/app", "latest", "sha256:first", firstSeen.Add(time.Minute), "alice", "reviewed", nil); err != nil {
		t.Fatalf("ApproveDigest() error = %v", err)
	}

	decision, err := engine.Decide(context.Background(), Request{ImageRef: "example.test/example/app:latest"})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if !decision.Allowed || !decision.ManualApproval {
		t.Fatalf("decision = %#v, want manual approval allow", decision)
	}
}

func TestFreezeDeniesEvenApprovedDigest(t *testing.T) {
	firstSeen := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	engine, db, _ := newTestEngine(t, "sha256:first", firstSeen.Add(8*24*time.Hour), false)
	if _, err := db.CreateObservation(context.Background(), "example.test", "example/app", "latest", "sha256:first", firstSeen); err != nil {
		t.Fatalf("CreateObservation() error = %v", err)
	}
	if _, err := db.ApproveDigest(context.Background(), "example.test", "example/app", "latest", "sha256:first", firstSeen, "alice", "reviewed", nil); err != nil {
		t.Fatalf("ApproveDigest() error = %v", err)
	}
	if _, err := db.FreezeTag(context.Background(), "example.test", "example/app", "latest", "", firstSeen.Add(time.Minute), "bob", "incident", nil); err != nil {
		t.Fatalf("FreezeTag() error = %v", err)
	}

	decision, err := engine.Decide(context.Background(), Request{ImageRef: "example.test/example/app:latest"})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision.Allowed || !decision.Frozen {
		t.Fatalf("decision = %#v, want frozen deny", decision)
	}
}

func TestDigestPinnedImageAllowedByDefault(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	engine, _, _ := newTestEngine(t, "unused", now, false)

	decision, err := engine.Decide(context.Background(), Request{ImageRef: "example.test/example/app@sha256:pinned"})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("decision allowed = false, reason = %q", decision.Reason)
	}
}

func TestRegistryFailureDeniesByDefault(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	engine, _, _ := newTestEngine(t, "", now, false)
	engine.Resolver = fakeResolver{err: errors.New("registry offline")}

	decision, err := engine.Decide(context.Background(), Request{ImageRef: "example.test/example/app:latest"})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision.Allowed {
		t.Fatal("decision allowed = true, want deny")
	}
	if !strings.Contains(decision.Reason, "registry offline") {
		t.Fatalf("reason = %q, want resolver error", decision.Reason)
	}
}

func TestSignatureRequiredDeniesWhenVerifierUnavailable(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	engine, db, _ := newTestEngine(t, "sha256:first", now.Add(8*24*time.Hour), true)
	engine.Config.DefaultPolicy.Signatures.Cosign.Required = true
	if _, err := db.CreateObservation(context.Background(), "example.test", "example/app", "latest", "sha256:first", now); err != nil {
		t.Fatalf("CreateObservation() error = %v", err)
	}

	decision, err := engine.Decide(context.Background(), Request{ImageRef: "example.test/example/app:latest"})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision.Allowed {
		t.Fatal("decision allowed = true, want deny")
	}
	if !strings.Contains(decision.Reason, "cosign verification is required") {
		t.Fatalf("reason = %q, want signature requirement", decision.Reason)
	}
}

func newTestEngine(t *testing.T, digest string, now time.Time, noAudit bool) (Engine, *store.SQLiteStore, string) {
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

	auditPath := ""
	var recorder AuditRecorder
	if !noAudit {
		auditPath = filepath.Join(t.TempDir(), "audit.jsonl")
		recorder = audit.NewLogger(auditPath)
	}

	return Engine{
		Config:   testConfig(),
		Store:    db,
		Resolver: fakeResolver{digest: digest},
		Audit:    recorder,
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
	err    error
}

func (r fakeResolver) Resolve(_ context.Context, ref image.Reference) (registry.ManifestDigest, error) {
	if r.err != nil {
		return registry.ManifestDigest{}, r.err
	}
	return registry.ManifestDigest{
		Registry:   ref.Registry,
		Repository: ref.Repository,
		Tag:        ref.Tag,
		Digest:     r.digest,
	}, nil
}

func assertDecisionCount(t *testing.T, db *store.SQLiteStore, want int) {
	t.Helper()
	count, err := db.CountDecisions(context.Background())
	if err != nil {
		t.Fatalf("CountDecisions() error = %v", err)
	}
	if count != want {
		t.Fatalf("decision count = %d, want %d", count, want)
	}
}

func assertAuditDecision(t *testing.T, auditPath, wantDecision, wantDigest string) {
	t.Helper()
	body, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(body), `"decision":"`+wantDecision+`"`) {
		t.Fatalf("audit log = %s, want decision %q", body, wantDecision)
	}
	if !strings.Contains(string(body), `"digest":"`+wantDigest+`"`) {
		t.Fatalf("audit log = %s, want digest %q", body, wantDigest)
	}
}
