package store

import (
	"context"
	"testing"
	"time"
)

func TestObservationLifecycle(t *testing.T) {
	ctx := context.Background()
	db := newTestStore(t)
	firstSeen := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	lastSeen := firstSeen.Add(2 * time.Hour)

	obs, err := db.CreateObservation(ctx, "docker.io", "library/nginx", "latest", "sha256:first", firstSeen)
	if err != nil {
		t.Fatalf("CreateObservation() error = %v", err)
	}
	if obs.Status != ObservationStatusQuarantined {
		t.Fatalf("status = %q, want %q", obs.Status, ObservationStatusQuarantined)
	}
	if !obs.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("first seen = %s, want %s", obs.FirstSeenAt, firstSeen)
	}

	repeated, err := db.CreateObservation(ctx, "docker.io", "library/nginx", "latest", "sha256:first", lastSeen)
	if err != nil {
		t.Fatalf("CreateObservation(repeated) error = %v", err)
	}
	if !repeated.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("repeated first seen = %s, want preserved %s", repeated.FirstSeenAt, firstSeen)
	}

	if err := db.TouchObservation(ctx, obs.ID, lastSeen); err != nil {
		t.Fatalf("TouchObservation() error = %v", err)
	}
	touched, err := db.GetObservation(ctx, "docker.io", "library/nginx", "latest", "sha256:first")
	if err != nil {
		t.Fatalf("GetObservation() error = %v", err)
	}
	if !touched.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("touched first seen = %s, want preserved %s", touched.FirstSeenAt, firstSeen)
	}
	if !touched.LastSeenAt.Equal(lastSeen) {
		t.Fatalf("last seen = %s, want %s", touched.LastSeenAt, lastSeen)
	}
}

func TestDifferentDigestCreatesSeparateObservation(t *testing.T) {
	ctx := context.Background()
	db := newTestStore(t)
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)

	first, err := db.CreateObservation(ctx, "docker.io", "library/nginx", "latest", "sha256:first", now)
	if err != nil {
		t.Fatalf("CreateObservation(first) error = %v", err)
	}
	second, err := db.CreateObservation(ctx, "docker.io", "library/nginx", "latest", "sha256:second", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateObservation(second) error = %v", err)
	}
	if first.ID == second.ID {
		t.Fatalf("different digests used same observation id %d", first.ID)
	}

	observations, err := db.ListObservations(ctx, "docker.io", "library/nginx", "latest")
	if err != nil {
		t.Fatalf("ListObservations() error = %v", err)
	}
	if len(observations) != 2 {
		t.Fatalf("observations length = %d, want 2", len(observations))
	}
}

func TestApprovalIsDigestSpecific(t *testing.T) {
	ctx := context.Background()
	db := newTestStore(t)
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)

	if _, err := db.ApproveDigest(ctx, "docker.io", "library/nginx", "latest", "sha256:approved", now, "alice", "reviewed", nil); err != nil {
		t.Fatalf("ApproveDigest() error = %v", err)
	}
	approved, err := db.ActiveApproval(ctx, "docker.io", "library/nginx", "latest", "sha256:approved", now)
	if err != nil {
		t.Fatalf("ActiveApproval(approved) error = %v", err)
	}
	if approved == nil {
		t.Fatal("ActiveApproval(approved) = nil, want approval")
	}
	other, err := db.ActiveApproval(ctx, "docker.io", "library/nginx", "latest", "sha256:other", now)
	if err != nil {
		t.Fatalf("ActiveApproval(other) error = %v", err)
	}
	if other != nil {
		t.Fatalf("ActiveApproval(other) = %#v, want nil", other)
	}
}

func TestFreezeOverridesApproval(t *testing.T) {
	ctx := context.Background()
	db := newTestStore(t)
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)

	if _, err := db.ApproveDigest(ctx, "docker.io", "library/nginx", "latest", "sha256:approved", now, "alice", "reviewed", nil); err != nil {
		t.Fatalf("ApproveDigest() error = %v", err)
	}
	if _, err := db.FreezeTag(ctx, "docker.io", "library/nginx", "latest", "", now.Add(time.Minute), "bob", "incident", nil); err != nil {
		t.Fatalf("FreezeTag() error = %v", err)
	}
	approval, err := db.ActiveApproval(ctx, "docker.io", "library/nginx", "latest", "sha256:approved", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("ActiveApproval() error = %v", err)
	}
	freeze, err := db.ActiveFreeze(ctx, "docker.io", "library/nginx", "latest", "sha256:approved", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("ActiveFreeze() error = %v", err)
	}
	if approval == nil {
		t.Fatal("ActiveApproval() = nil, want approval")
	}
	if freeze == nil {
		t.Fatal("ActiveFreeze() = nil, want freeze")
	}
	override, err := db.LocalOverride(ctx, "docker.io", "library/nginx", "latest", "sha256:approved", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("LocalOverride() error = %v", err)
	}
	if override.Approval == nil || override.Freeze == nil {
		t.Fatalf("LocalOverride() = %#v, want approval and freeze", override)
	}
	if decision := override.Decision; decision != DecisionDeny {
		t.Fatalf("effective override = %q, want %q", decision, DecisionDeny)
	}
}

func TestBypassExpiresAndFreezeOverridesIt(t *testing.T) {
	ctx := context.Background()
	db := newTestStore(t)
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	expiresAt := now.Add(time.Hour)

	if _, err := db.BypassTag(ctx, "docker.io", "library/nginx", "latest", now, "alice", "incident", &expiresAt); err != nil {
		t.Fatalf("BypassTag() error = %v", err)
	}
	active, err := db.ActiveBypass(ctx, "docker.io", "library/nginx", "latest", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ActiveBypass(active) error = %v", err)
	}
	if active == nil {
		t.Fatal("ActiveBypass(active) = nil, want bypass")
	}
	expired, err := db.ActiveBypass(ctx, "docker.io", "library/nginx", "latest", now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("ActiveBypass(expired) error = %v", err)
	}
	if expired != nil {
		t.Fatalf("ActiveBypass(expired) = %#v, want nil", expired)
	}
	if _, err := db.FreezeTag(ctx, "docker.io", "library/nginx", "latest", "", now.Add(2*time.Minute), "bob", "compromise", nil); err != nil {
		t.Fatalf("FreezeTag() error = %v", err)
	}
	override, err := db.LocalOverride(ctx, "docker.io", "library/nginx", "latest", "sha256:first", now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("LocalOverride() error = %v", err)
	}
	if override.Bypass == nil || override.Freeze == nil {
		t.Fatalf("LocalOverride() = %#v, want bypass and freeze", override)
	}
	if override.Decision != DecisionDeny {
		t.Fatalf("LocalOverride decision = %q, want %q", override.Decision, DecisionDeny)
	}
}

func TestRecordDecision(t *testing.T) {
	ctx := context.Background()
	db := newTestStore(t)
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)

	err := db.RecordDecision(ctx, DecisionRecord{
		Timestamp:  now,
		ImageRef:   "docker.io/library/nginx:latest",
		Registry:   "docker.io",
		Repository: "library/nginx",
		Tag:        "latest",
		Digest:     "sha256:first",
		Decision:   DecisionDeny,
		Reason:     "new digest entered quarantine",
	})
	if err != nil {
		t.Fatalf("RecordDecision() error = %v", err)
	}

	var count int
	if err := db.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pull_decisions").Scan(&count); err != nil {
		t.Fatalf("count decisions: %v", err)
	}
	if count != 1 {
		t.Fatalf("decision count = %d, want 1", count)
	}
}

func TestCosignVerificationCacheUsesPolicyKey(t *testing.T) {
	ctx := context.Background()
	db := newTestStore(t)
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)

	err := db.RecordCosignVerification(ctx, CosignVerification{
		Registry:   "ghcr.io",
		Repository: "example/app",
		Digest:     "sha256:first",
		PolicyKey:  "sha256:policy-a",
		ImageRef:   "ghcr.io/example/app@sha256:first",
		VerifiedAt: now,
		Success:    true,
		Reason:     "ok",
	})
	if err != nil {
		t.Fatalf("RecordCosignVerification() error = %v", err)
	}
	cached, err := db.GetCosignVerification(ctx, "ghcr.io", "example/app", "sha256:first", "sha256:policy-a")
	if err != nil {
		t.Fatalf("GetCosignVerification() error = %v", err)
	}
	if cached == nil || !cached.Success || cached.Reason != "ok" {
		t.Fatalf("cached verification = %#v, want successful result", cached)
	}
	otherPolicy, err := db.GetCosignVerification(ctx, "ghcr.io", "example/app", "sha256:first", "sha256:policy-b")
	if err != nil {
		t.Fatalf("GetCosignVerification(other policy) error = %v", err)
	}
	if otherPolicy != nil {
		t.Fatalf("other policy cache = %#v, want nil", otherPolicy)
	}
}

func TestExportImportPreservesObservationsAndApprovals(t *testing.T) {
	ctx := context.Background()
	source := newTestStore(t)
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	expiresAt := now.Add(24 * time.Hour)

	if _, err := source.CreateObservation(ctx, "docker.io", "library/nginx", "latest", "sha256:first", now); err != nil {
		t.Fatalf("CreateObservation() error = %v", err)
	}
	if _, err := source.ApproveDigest(ctx, "docker.io", "library/nginx", "latest", "sha256:first", now, "alice", "reviewed", &expiresAt); err != nil {
		t.Fatalf("ApproveDigest() error = %v", err)
	}
	if err := source.RecordCosignVerification(ctx, CosignVerification{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Digest:     "sha256:first",
		PolicyKey:  "sha256:policy",
		ImageRef:   "docker.io/library/nginx@sha256:first",
		VerifiedAt: now,
		Success:    true,
		Reason:     "ok",
	}); err != nil {
		t.Fatalf("RecordCosignVerification() error = %v", err)
	}
	exported, err := source.ExportState(ctx)
	if err != nil {
		t.Fatalf("ExportState() error = %v", err)
	}

	target := newTestStore(t)
	if err := target.ImportState(ctx, exported); err != nil {
		t.Fatalf("ImportState() error = %v", err)
	}
	obs, err := target.GetObservation(ctx, "docker.io", "library/nginx", "latest", "sha256:first")
	if err != nil {
		t.Fatalf("GetObservation() error = %v", err)
	}
	if obs == nil {
		t.Fatal("imported observation = nil, want observation")
	}
	approval, err := target.ActiveApproval(ctx, "docker.io", "library/nginx", "latest", "sha256:first", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ActiveApproval() error = %v", err)
	}
	if approval == nil || approval.Reason != "reviewed" {
		t.Fatalf("imported approval = %#v, want reviewed approval", approval)
	}
	verification, err := target.GetCosignVerification(ctx, "docker.io", "library/nginx", "sha256:first", "sha256:policy")
	if err != nil {
		t.Fatalf("GetCosignVerification() error = %v", err)
	}
	if verification == nil || !verification.Success {
		t.Fatalf("imported cosign verification = %#v, want success", verification)
	}
}

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()

	db, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
	return db
}
