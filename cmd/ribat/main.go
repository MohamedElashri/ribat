package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/MohamedElashri/ribat/internal/audit"
	"github.com/MohamedElashri/ribat/internal/image"
	"github.com/MohamedElashri/ribat/internal/policy"
	"github.com/MohamedElashri/ribat/internal/quarantine"
	"github.com/MohamedElashri/ribat/internal/registry"
	"github.com/MohamedElashri/ribat/internal/store"
	"github.com/MohamedElashri/ribat/internal/version"
)

const usage = `ribat guards mutable Docker image tags until their resolved digests satisfy policy.

Usage:
  ribat version
  ribat inspect IMAGE
  ribat decide [--config PATH] IMAGE
  ribat policy check [--config PATH] IMAGE
  ribat status [--config PATH] IMAGE
  ribat help
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}

	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "ribat %s\n", version.String())
		return 0
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "decide":
		return runDecide(args[1:], stdout, stderr)
	case "policy":
		return runPolicy(args[1:], stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func runDecide(args []string, stdout, stderr io.Writer) int {
	configPath, imageRef, code := parseConfigAndImage(args, "decide", stderr)
	if code != 0 {
		return code
	}

	cfg, err := policy.LoadFile(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "could not load policy: %v\n", err)
		return 1
	}
	if cfg.State.Backend != "sqlite" {
		fmt.Fprintf(stderr, "unsupported state backend %q; only sqlite is supported\n", cfg.State.Backend)
		return 1
	}
	if cfg.State.Path == "" {
		fmt.Fprintln(stderr, "state.path is required for decide")
		return 1
	}

	db, err := store.OpenSQLite(cfg.State.Path)
	if err != nil {
		fmt.Fprintf(stderr, "could not open local state: %v\n", err)
		return 1
	}
	defer db.Close()

	engine := quarantine.Engine{
		Config:   cfg,
		Store:    db,
		Resolver: registry.NewResolver(nil),
		Audit:    audit.NewLogger(cfg.Audit.Path),
	}
	decision, err := engine.Decide(context.Background(), quarantine.Request{ImageRef: imageRef})
	if err != nil {
		fmt.Fprintf(stderr, "could not decide pull: %v\n", err)
		return 1
	}
	printDecision(stdout, decision)
	if decision.Allowed {
		return 0
	}
	return 1
}

func runInspect(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		if len(args) == 0 {
			fmt.Fprintln(stderr, "missing image reference for inspect")
		} else {
			fmt.Fprintf(stderr, "inspect accepts one image reference, got extra argument %q\n", args[1])
		}
		return 2
	}

	ref, err := image.ParseReference(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "invalid image reference: %v\n", err)
		return 2
	}
	if ref.IsDigestPinned {
		fmt.Fprintf(stdout, "Image: %s\n", ref.CanonicalRef)
		fmt.Fprintln(stdout, "Digest pinned: true")
		fmt.Fprintf(stdout, "Digest: %s\n", ref.Digest)
		return 0
	}

	resolver := registry.NewResolver(nil)
	resolved, err := resolver.Resolve(context.Background(), ref)
	if err != nil {
		fmt.Fprintf(stderr, "could not resolve remote digest for %s: %v\n", ref.CanonicalRef, err)
		return 1
	}
	fmt.Fprintf(stdout, "Image: %s\n", ref.CanonicalRef)
	fmt.Fprintf(stdout, "Remote digest: %s\n", resolved.Digest)
	if resolved.MediaType != "" {
		fmt.Fprintf(stdout, "Media type: %s\n", resolved.MediaType)
	}
	return 0
}

func runPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, "missing policy subcommand\n\n%s", usage)
		return 2
	}

	switch args[0] {
	case "check":
		return runPolicyCheck(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown policy subcommand %q\n\n%s", args[0], usage)
		return 2
	}
}

func runPolicyCheck(args []string, stdout, stderr io.Writer) int {
	configPath, imageRef, code := parseConfigAndImage(args, "policy check", stderr)
	if code != 0 {
		return code
	}

	ref, err := image.ParseReference(imageRef)
	if err != nil {
		fmt.Fprintf(stderr, "invalid image reference: %v\n", err)
		return 2
	}
	cfg, err := policy.LoadFile(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "could not load policy: %v\n", err)
		return 1
	}
	result, err := cfg.EffectivePolicyFor(ref)
	if err != nil {
		fmt.Fprintf(stderr, "could not match policy: %v\n", err)
		return 1
	}

	printPolicyCheck(stdout, ref, result)
	return 0
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	configPath, imageRef, code := parseConfigAndImage(args, "status", stderr)
	if code != 0 {
		return code
	}

	ref, err := image.ParseReference(imageRef)
	if err != nil {
		fmt.Fprintf(stderr, "invalid image reference: %v\n", err)
		return 2
	}
	cfg, err := policy.LoadFile(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "could not load policy: %v\n", err)
		return 1
	}
	if cfg.State.Backend != "sqlite" {
		fmt.Fprintf(stderr, "unsupported state backend %q; only sqlite is supported\n", cfg.State.Backend)
		return 1
	}
	if cfg.State.Path == "" {
		fmt.Fprintln(stderr, "state.path is required for status")
		return 1
	}
	if cfg.State.Path != ":memory:" {
		if _, err := os.Stat(cfg.State.Path); err != nil {
			fmt.Fprintf(stderr, "could not open local state: %v\n", err)
			return 1
		}
	}

	db, err := store.OpenSQLite(cfg.State.Path)
	if err != nil {
		fmt.Fprintf(stderr, "could not open local state: %v\n", err)
		return 1
	}
	defer db.Close()

	ctx := context.Background()
	var observations []store.Observation
	if ref.Digest != "" {
		obs, err := db.GetObservation(ctx, ref.Registry, ref.Repository, ref.Tag, ref.Digest)
		if err != nil {
			fmt.Fprintf(stderr, "could not read local state: %v\n", err)
			return 1
		}
		if obs != nil {
			observations = append(observations, *obs)
		}
	} else {
		observations, err = db.ListObservations(ctx, ref.Registry, ref.Repository, ref.Tag)
		if err != nil {
			fmt.Fprintf(stderr, "could not read local state: %v\n", err)
			return 1
		}
	}

	printStatus(stdout, ref, observations, db, time.Now().UTC())
	return 0
}

func parseConfigAndImage(args []string, command string, stderr io.Writer) (string, string, int) {
	configPath := defaultConfigPath()
	var imageRef string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--config":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "missing value for --config")
				return "", "", 2
			}
			configPath = args[i+1]
			i++
		default:
			if strings.HasPrefix(arg, "--config=") {
				configPath = strings.TrimPrefix(arg, "--config=")
				continue
			}
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(stderr, "unknown flag %q\n", arg)
				return "", "", 2
			}
			if imageRef != "" {
				fmt.Fprintf(stderr, "%s accepts one image reference, got extra argument %q\n", command, arg)
				return "", "", 2
			}
			imageRef = arg
		}
	}

	if imageRef == "" {
		fmt.Fprintf(stderr, "missing image reference for %s\n", command)
		return "", "", 2
	}

	return configPath, imageRef, 0
}

func printPolicyCheck(w io.Writer, ref image.Reference, result policy.MatchResult) {
	p := result.Policy
	fmt.Fprintf(w, "Image: %s\n", ref.CanonicalRef)
	fmt.Fprintf(w, "Matched rule: %s\n", result.MatchedRule)
	fmt.Fprintln(w, "Mutable tags:")
	fmt.Fprintf(w, "  action: %s\n", p.MutableTags.Action)
	fmt.Fprintf(w, "  min_digest_age: %s\n", p.MutableTags.MinDigestAge)
	fmt.Fprintf(w, "  allow_first_seen_pull: %t\n", p.MutableTags.AllowFirstSeenPull)
	fmt.Fprintln(w, "Digest pinned images:")
	fmt.Fprintf(w, "  action: %s\n", p.DigestPinnedImages.Action)
	fmt.Fprintln(w, "Failed registry resolution:")
	fmt.Fprintf(w, "  action: %s\n", p.FailedRegistryResolution.Action)
	fmt.Fprintln(w, "Failed signature check:")
	fmt.Fprintf(w, "  action: %s\n", p.FailedSignatureCheck.Action)
	fmt.Fprintln(w, "Signatures:")
	fmt.Fprintf(w, "  cosign.required: %t\n", p.Signatures.Cosign.Required)
}

func printDecision(w io.Writer, decision quarantine.Decision) {
	fmt.Fprintf(w, "Image: %s\n", decision.ImageRef)
	if decision.Digest != "" {
		fmt.Fprintf(w, "Resolved digest: %s\n", decision.Digest)
	}
	fmt.Fprintf(w, "Matched rule: %s\n", decision.MatchedRule)
	if decision.FirstSeenAt != nil {
		fmt.Fprintf(w, "Digest first seen: %s\n", decision.FirstSeenAt.Format(time.RFC3339))
	}
	if decision.RequiredAge > 0 {
		fmt.Fprintf(w, "Required minimum age: %s\n", policy.Duration{Duration: decision.RequiredAge})
	}
	if decision.CurrentAge > 0 {
		fmt.Fprintf(w, "Current age: %s\n", decision.CurrentAge.Round(time.Second))
	}
	if decision.NextAllowedAt != nil {
		fmt.Fprintf(w, "Next allowed pull: %s\n", decision.NextAllowedAt.Format(time.RFC3339))
	}
	if decision.Allowed {
		fmt.Fprintln(w, "Decision: ALLOW")
	} else {
		fmt.Fprintln(w, "Decision: DENY")
	}
	fmt.Fprintf(w, "Reason: %s\n", decision.Reason)
	if decision.ManualApproval {
		fmt.Fprintln(w, "Manual approval: active")
	}
	if decision.Frozen {
		fmt.Fprintln(w, "Freeze: active")
	}
}

func printStatus(w io.Writer, ref image.Reference, observations []store.Observation, db *store.SQLiteStore, now time.Time) {
	fmt.Fprintf(w, "Image: %s\n", ref.CanonicalRef)
	if len(observations) == 0 {
		fmt.Fprintln(w, "Local state: no observations")
		return
	}

	fmt.Fprintln(w, "Local state: observed")
	ctx := context.Background()
	for _, obs := range observations {
		override, err := db.LocalOverride(ctx, obs.Registry, obs.Repository, obs.Tag, obs.Digest, now)
		fmt.Fprintf(w, "- Digest: %s\n", obs.Digest)
		fmt.Fprintf(w, "  Status: %s\n", obs.Status)
		fmt.Fprintf(w, "  First seen: %s\n", obs.FirstSeenAt.Format(time.RFC3339))
		fmt.Fprintf(w, "  Last seen: %s\n", obs.LastSeenAt.Format(time.RFC3339))
		if err != nil {
			fmt.Fprintf(w, "  Local override: error: %v\n", err)
			continue
		}
		switch override.Decision {
		case store.DecisionDeny:
			fmt.Fprintln(w, "  Local override: deny (freeze)")
			if override.Freeze.Reason != "" {
				fmt.Fprintf(w, "  Freeze reason: %s\n", override.Freeze.Reason)
			}
		case store.DecisionAllow:
			fmt.Fprintln(w, "  Local override: allow (approval)")
			if override.Approval.Reason != "" {
				fmt.Fprintf(w, "  Approval reason: %s\n", override.Approval.Reason)
			}
		default:
			fmt.Fprintln(w, "  Local override: none")
		}
	}
}

func defaultConfigPath() string {
	if _, err := os.Stat("configs/ribat.example.yaml"); err == nil {
		return "configs/ribat.example.yaml"
	}
	return "/etc/ribat/config.yaml"
}
