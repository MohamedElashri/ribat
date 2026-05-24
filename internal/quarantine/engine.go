package quarantine

import (
	"context"
	"fmt"
	"time"

	"github.com/MohamedElashri/ribat/internal/audit"
	"github.com/MohamedElashri/ribat/internal/image"
	"github.com/MohamedElashri/ribat/internal/policy"
	"github.com/MohamedElashri/ribat/internal/registry"
	"github.com/MohamedElashri/ribat/internal/store"
	"github.com/MohamedElashri/ribat/internal/verify"
)

type Resolver interface {
	Resolve(context.Context, image.Reference) (registry.ManifestDigest, error)
}

type AuditRecorder interface {
	Record(audit.Event) error
}

type CosignVerifier interface {
	Verify(context.Context, image.Reference, string, policy.CosignPolicy) (verify.CosignResult, error)
}

type Engine struct {
	Config   policy.Config
	Store    *store.SQLiteStore
	Resolver Resolver
	Verifier CosignVerifier
	Audit    AuditRecorder
	Now      func() time.Time
}

type Request struct {
	ImageRef      string
	ClientUser    string
	RequestMethod string
	RequestURI    string
}

type Decision struct {
	ImageRef       string
	Registry       string
	Repository     string
	Tag            string
	Digest         string
	Allowed        bool
	Reason         string
	MatchedRule    string
	FirstSeenAt    *time.Time
	CurrentAge     time.Duration
	RequiredAge    time.Duration
	NextAllowedAt  *time.Time
	ManualApproval bool
	Bypassed       bool
	Frozen         bool
	CosignVerified bool
	CosignCached   bool
}

func (e *Engine) Decide(ctx context.Context, req Request) (Decision, error) {
	if e.Store == nil {
		return Decision{}, fmt.Errorf("quarantine store is required")
	}

	ref, err := image.ParseReference(req.ImageRef)
	if err != nil {
		return Decision{}, err
	}
	result, err := e.Config.EffectivePolicyFor(ref)
	if err != nil {
		return Decision{}, err
	}
	now := e.now()
	decision := Decision{
		ImageRef:    ref.CanonicalRef,
		Registry:    ref.Registry,
		Repository:  ref.Repository,
		Tag:         ref.Tag,
		Digest:      ref.Digest,
		MatchedRule: result.MatchedRule,
		RequiredAge: result.Policy.MutableTags.MinDigestAge.Duration,
	}

	if ref.IsDigestPinned {
		if err := e.decideDigestPinned(ctx, ref, result.Policy, now, &decision); err != nil {
			return Decision{}, err
		}
		return decision, e.record(ctx, req, decision, now)
	}

	if result.Policy.MutableTags.Action == policy.ActionAllow {
		decision.Allowed = true
		decision.Reason = "mutable tag allowed by policy"
		return decision, e.record(ctx, req, decision, now)
	}
	if result.Policy.MutableTags.Action == policy.ActionDeny {
		decision.Reason = "mutable tag denied by policy"
		return decision, e.record(ctx, req, decision, now)
	}

	resolver := e.Resolver
	if resolver == nil {
		resolver = registry.NewResolver(nil)
	}
	resolved, err := resolver.Resolve(ctx, ref)
	if err != nil {
		if result.Policy.FailedRegistryResolution.Action == policy.ActionAllow {
			decision.Allowed = true
			decision.Reason = "registry resolution failed but policy allows fallback"
		} else {
			decision.Reason = fmt.Sprintf("could not resolve remote digest: %v", err)
		}
		return decision, e.record(ctx, req, decision, now)
	}
	decision.Digest = resolved.Digest

	override, err := e.Store.LocalOverride(ctx, ref.Registry, ref.Repository, ref.Tag, resolved.Digest, now)
	if err != nil {
		return Decision{}, err
	}
	if override.Decision == store.DecisionDeny {
		decision.Frozen = true
		decision.Reason = "tag or digest is frozen"
		return decision, e.record(ctx, req, decision, now)
	}

	obs, err := e.Store.GetObservation(ctx, ref.Registry, ref.Repository, ref.Tag, resolved.Digest)
	if err != nil {
		return Decision{}, err
	}
	if obs == nil {
		obs, err = e.Store.CreateObservation(ctx, ref.Registry, ref.Repository, ref.Tag, resolved.Digest, now)
		if err != nil {
			return Decision{}, err
		}
		decision.FirstSeenAt = &obs.FirstSeenAt
		if override.Decision == store.DecisionAllow || result.Policy.MutableTags.AllowFirstSeenPull {
			decision.ManualApproval = override.Approval != nil
			decision.Bypassed = override.Bypass != nil && override.Approval == nil
			e.allowWithVerification(ctx, result.Policy, now, obs, &decision)
			return decision, e.record(ctx, req, decision, now)
		}
		decision.Reason = "new digest observed for mutable tag; digest entered quarantine"
		decision.NextAllowedAt = timePtr(obs.FirstSeenAt.Add(result.Policy.MutableTags.MinDigestAge.Duration))
		return decision, e.record(ctx, req, decision, now)
	}

	if err := e.Store.TouchObservation(ctx, obs.ID, now); err != nil {
		return Decision{}, err
	}
	decision.FirstSeenAt = &obs.FirstSeenAt
	if override.Decision == store.DecisionAllow {
		decision.ManualApproval = override.Approval != nil
		decision.Bypassed = override.Bypass != nil && override.Approval == nil
		e.allowWithVerification(ctx, result.Policy, now, obs, &decision)
		return decision, e.record(ctx, req, decision, now)
	}

	age := now.Sub(obs.FirstSeenAt)
	decision.CurrentAge = age
	if age < result.Policy.MutableTags.MinDigestAge.Duration {
		decision.Reason = "digest is still in quarantine"
		decision.NextAllowedAt = timePtr(obs.FirstSeenAt.Add(result.Policy.MutableTags.MinDigestAge.Duration))
		return decision, e.record(ctx, req, decision, now)
	}

	e.allowWithVerification(ctx, result.Policy, now, obs, &decision)
	return decision, e.record(ctx, req, decision, now)
}

func (e *Engine) decideDigestPinned(ctx context.Context, ref image.Reference, p policy.EffectivePolicy, now time.Time, decision *Decision) error {
	override, err := e.Store.LocalOverride(ctx, ref.Registry, ref.Repository, ref.Tag, ref.Digest, now)
	if err != nil {
		return err
	}
	if override.Decision == store.DecisionDeny {
		decision.Frozen = true
		decision.Reason = "tag or digest is frozen"
		return nil
	}
	if p.DigestPinnedImages.Action == policy.ActionDeny {
		decision.Reason = "digest-pinned image denied by policy"
		return nil
	}
	if p.Signatures.Cosign.Required {
		if !e.verifyCosign(ctx, ref, ref.Digest, p.Signatures.Cosign, now, decision) {
			return nil
		}
	}
	decision.Allowed = true
	decision.ManualApproval = override.Approval != nil
	decision.Bypassed = override.Bypass != nil && override.Approval == nil
	decision.Reason = "digest-pinned image allowed by policy"
	return nil
}

func (e *Engine) allowWithVerification(ctx context.Context, p policy.EffectivePolicy, now time.Time, obs *store.Observation, decision *Decision) {
	ref := image.Reference{
		Registry:     decision.Registry,
		Repository:   decision.Repository,
		Tag:          decision.Tag,
		CanonicalRef: decision.ImageRef,
	}
	if p.Signatures.Cosign.Required && !e.verifyCosign(ctx, ref, decision.Digest, p.Signatures.Cosign, now, decision) {
		return
	}
	if err := e.Store.MarkObservationAllowed(ctx, obs.ID, now); err != nil {
		decision.Allowed = false
		decision.Reason = fmt.Sprintf("could not update allowed observation state: %v", err)
		return
	}
	decision.Allowed = true
	if decision.ManualApproval {
		decision.Reason = "digest manually approved"
		return
	}
	if decision.Bypassed {
		decision.Reason = "tag bypass active"
		return
	}
	if decision.CosignVerified {
		decision.Reason = "digest satisfies quarantine and cosign verification policy"
		return
	}
	decision.Reason = "digest satisfies quarantine policy"
}

func (e *Engine) verifyCosign(ctx context.Context, ref image.Reference, digest string, cfg policy.CosignPolicy, now time.Time, decision *Decision) bool {
	policyKey := verify.CosignPolicyKey(cfg)
	cached, err := e.Store.GetCosignVerification(ctx, ref.Registry, ref.Repository, digest, policyKey)
	if err != nil {
		decision.Allowed = false
		decision.Reason = fmt.Sprintf("could not read cosign verification cache: %v", err)
		return false
	}
	if cached != nil && cached.Success {
		decision.CosignVerified = true
		decision.CosignCached = true
		return true
	}

	verifier := e.Verifier
	if verifier == nil {
		defaultVerifier := verify.NewCosignVerifier("")
		verifier = defaultVerifier
	}
	result, err := verifier.Verify(ctx, ref, digest, cfg)
	if err != nil {
		decision.Allowed = false
		decision.Reason = fmt.Sprintf("cosign verification failed: %v", err)
		return false
	}
	record := store.CosignVerification{
		Registry:   ref.Registry,
		Repository: ref.Repository,
		Digest:     digest,
		PolicyKey:  policyKey,
		ImageRef:   verify.DigestReference(ref, digest),
		VerifiedAt: now,
		Success:    result.Success,
		Reason:     result.Reason,
	}
	if err := e.Store.RecordCosignVerification(ctx, record); err != nil {
		decision.Allowed = false
		decision.Reason = fmt.Sprintf("could not cache cosign verification result: %v", err)
		return false
	}
	if !result.Success {
		decision.Allowed = false
		if result.Reason == "" {
			decision.Reason = "cosign verification failed"
		} else {
			decision.Reason = "cosign verification failed: " + result.Reason
		}
		return false
	}
	decision.CosignVerified = true
	return true
}

func (e *Engine) record(ctx context.Context, req Request, decision Decision, now time.Time) error {
	record := store.DecisionRecord{
		Timestamp:     now,
		ImageRef:      decision.ImageRef,
		Registry:      decision.Registry,
		Repository:    decision.Repository,
		Tag:           decision.Tag,
		Digest:        decision.Digest,
		Decision:      store.DecisionDeny,
		Reason:        decision.Reason,
		ClientUser:    req.ClientUser,
		RequestMethod: req.RequestMethod,
		RequestURI:    req.RequestURI,
	}
	if decision.Allowed {
		record.Decision = store.DecisionAllow
	}
	if err := e.Store.RecordDecision(ctx, record); err != nil {
		return err
	}
	if e.Audit == nil {
		return nil
	}
	return e.Audit.Record(audit.Event{
		Timestamp:      now,
		ImageRef:       decision.ImageRef,
		Registry:       decision.Registry,
		Repository:     decision.Repository,
		Tag:            decision.Tag,
		Digest:         decision.Digest,
		Decision:       record.Decision,
		Reason:         decision.Reason,
		MatchedRule:    decision.MatchedRule,
		ClientUser:     req.ClientUser,
		RequestMethod:  req.RequestMethod,
		RequestURI:     req.RequestURI,
		CosignVerified: decision.CosignVerified,
		CosignCached:   decision.CosignCached,
	})
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func timePtr(t time.Time) *time.Time {
	return &t
}
