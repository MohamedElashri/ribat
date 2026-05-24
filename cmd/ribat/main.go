package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/MohamedElashri/ribat/internal/audit"
	"github.com/MohamedElashri/ribat/internal/authz"
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
  ribat authz [--config PATH] --socket PATH
  ribat approve [--config PATH] IMAGE:TAG@DIGEST --ttl DURATION --reason TEXT
  ribat bypass [--config PATH] IMAGE:TAG --ttl DURATION --reason TEXT
  ribat freeze [--config PATH] IMAGE:TAG --reason TEXT
  ribat audit [--config PATH] [--image IMAGE] [--since DURATION]
  ribat export-state [--config PATH]
  ribat import-state [--config PATH] [--input PATH]
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
	case "authz":
		return runAuthz(args[1:], stdout, stderr)
	case "approve":
		return runApprove(args[1:], stdout, stderr)
	case "bypass":
		return runBypass(args[1:], stdout, stderr)
	case "freeze":
		return runFreeze(args[1:], stdout, stderr)
	case "audit":
		return runAudit(args[1:], stdout, stderr)
	case "export-state":
		return runExportState(args[1:], stdout, stderr)
	case "import-state":
		return runImportState(args[1:], stdout, stderr)
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

func runAuthz(args []string, stdout, stderr io.Writer) int {
	configPath := defaultConfigPath()
	var socketPath string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--config":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "missing value for --config")
				return 2
			}
			configPath = args[i+1]
			i++
		case "--socket":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "missing value for --socket")
				return 2
			}
			socketPath = args[i+1]
			i++
		default:
			if strings.HasPrefix(arg, "--config=") {
				configPath = strings.TrimPrefix(arg, "--config=")
				continue
			}
			if strings.HasPrefix(arg, "--socket=") {
				socketPath = strings.TrimPrefix(arg, "--socket=")
				continue
			}
			fmt.Fprintf(stderr, "unknown argument %q for authz\n", arg)
			return 2
		}
	}
	if socketPath == "" {
		fmt.Fprintln(stderr, "authz requires --socket PATH")
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
		fmt.Fprintln(stderr, "state.path is required for authz")
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
	fmt.Fprintf(stdout, "ribat authz listening on %s\n", socketPath)
	if err := authz.ListenAndServe(context.Background(), socketPath, authz.Server{Engine: &engine}); err != nil {
		fmt.Fprintf(stderr, "authz server failed: %v\n", err)
		return 1
	}
	return 0
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

func runApprove(args []string, stdout, stderr io.Writer) int {
	opts, code := parseOperationArgs(args, "approve", false, stderr)
	if code != 0 {
		return code
	}
	if opts.reason == "" {
		fmt.Fprintln(stderr, "approve requires --reason TEXT")
		return 2
	}
	ref, err := image.ParseReference(opts.imageRef)
	if err != nil {
		fmt.Fprintf(stderr, "invalid image reference: %v\n", err)
		return 2
	}
	if ref.Digest == "" || ref.Tag == "" {
		fmt.Fprintln(stderr, "approve requires IMAGE:TAG@DIGEST so the approved tag and digest are explicit")
		return 2
	}
	db, cfg, err := openConfiguredState(opts.configPath, "approve")
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	defer db.Close()

	now := time.Now().UTC()
	expiresAt := expiresFromTTL(now, opts.ttl)
	approval, err := db.ApproveDigest(context.Background(), ref.Registry, ref.Repository, ref.Tag, ref.Digest, now, opts.actor, opts.reason, expiresAt)
	if err != nil {
		fmt.Fprintf(stderr, "could not approve digest: %v\n", err)
		return 1
	}
	if err := logOperation(cfg, "approval", ref, ref.Digest, opts.actor, opts.reason, now); err != nil {
		fmt.Fprintf(stderr, "could not write audit event: %v\n", err)
		return 1
	}
	printApproval(stdout, ref, approval)
	return 0
}

func runBypass(args []string, stdout, stderr io.Writer) int {
	opts, code := parseOperationArgs(args, "bypass", true, stderr)
	if code != 0 {
		return code
	}
	if opts.reason == "" {
		fmt.Fprintln(stderr, "bypass requires --reason TEXT")
		return 2
	}
	ref, err := image.ParseReference(opts.imageRef)
	if err != nil {
		fmt.Fprintf(stderr, "invalid image reference: %v\n", err)
		return 2
	}
	if ref.IsDigestPinned {
		fmt.Fprintln(stderr, "bypass requires IMAGE:TAG, not a digest-pinned reference")
		return 2
	}
	db, cfg, err := openConfiguredState(opts.configPath, "bypass")
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	defer db.Close()

	now := time.Now().UTC()
	expiresAt := expiresFromTTL(now, opts.ttl)
	bypass, err := db.BypassTag(context.Background(), ref.Registry, ref.Repository, ref.Tag, now, opts.actor, opts.reason, expiresAt)
	if err != nil {
		fmt.Fprintf(stderr, "could not create bypass: %v\n", err)
		return 1
	}
	if err := logOperation(cfg, "bypass", ref, "", opts.actor, opts.reason, now); err != nil {
		fmt.Fprintf(stderr, "could not write audit event: %v\n", err)
		return 1
	}
	printBypass(stdout, ref, bypass)
	return 0
}

func runFreeze(args []string, stdout, stderr io.Writer) int {
	opts, code := parseOperationArgs(args, "freeze", false, stderr)
	if code != 0 {
		return code
	}
	if opts.reason == "" {
		fmt.Fprintln(stderr, "freeze requires --reason TEXT")
		return 2
	}
	ref, err := image.ParseReference(opts.imageRef)
	if err != nil {
		fmt.Fprintf(stderr, "invalid image reference: %v\n", err)
		return 2
	}
	if ref.Tag == "" {
		fmt.Fprintln(stderr, "freeze requires IMAGE:TAG")
		return 2
	}
	db, cfg, err := openConfiguredState(opts.configPath, "freeze")
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	defer db.Close()

	now := time.Now().UTC()
	expiresAt := expiresFromTTL(now, opts.ttl)
	freeze, err := db.FreezeTag(context.Background(), ref.Registry, ref.Repository, ref.Tag, ref.Digest, now, opts.actor, opts.reason, expiresAt)
	if err != nil {
		fmt.Fprintf(stderr, "could not freeze tag: %v\n", err)
		return 1
	}
	if err := logOperation(cfg, "freeze", ref, ref.Digest, opts.actor, opts.reason, now); err != nil {
		fmt.Fprintf(stderr, "could not write audit event: %v\n", err)
		return 1
	}
	printFreeze(stdout, ref, freeze)
	return 0
}

func runAudit(args []string, stdout, stderr io.Writer) int {
	opts, code := parseAuditArgs(args, stderr)
	if code != 0 {
		return code
	}
	cfg, err := policy.LoadFile(opts.configPath)
	if err != nil {
		fmt.Fprintf(stderr, "could not load policy: %v\n", err)
		return 1
	}
	if cfg.Audit.Path == "" {
		fmt.Fprintln(stderr, "audit.path is required for audit")
		return 1
	}
	file, err := os.Open(cfg.Audit.Path)
	if err != nil {
		fmt.Fprintf(stderr, "could not open audit log: %v\n", err)
		return 1
	}
	defer file.Close()

	var imageFilter *image.Reference
	if opts.imageRef != "" {
		ref, err := image.ParseReference(opts.imageRef)
		if err != nil {
			fmt.Fprintf(stderr, "invalid image reference: %v\n", err)
			return 2
		}
		imageFilter = &ref
	}
	var since *time.Time
	if opts.since != nil {
		cutoff := time.Now().UTC().Add(-opts.since.Duration)
		since = &cutoff
	}

	scanner := bufio.NewScanner(file)
	encoder := json.NewEncoder(stdout)
	for scanner.Scan() {
		var event audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			fmt.Fprintf(stderr, "could not parse audit log line: %v\n", err)
			return 1
		}
		if since != nil && event.Timestamp.Before(*since) {
			continue
		}
		if imageFilter != nil && !auditEventMatchesImage(event, *imageFilter) {
			continue
		}
		if err := encoder.Encode(event); err != nil {
			fmt.Fprintf(stderr, "could not write audit output: %v\n", err)
			return 1
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(stderr, "could not read audit log: %v\n", err)
		return 1
	}
	return 0
}

func runExportState(args []string, stdout, stderr io.Writer) int {
	configPath, code := parseConfigOnly(args, "export-state", stderr)
	if code != 0 {
		return code
	}
	db, cfg, err := openConfiguredState(configPath, "export-state")
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	defer db.Close()

	now := time.Now().UTC()
	if err := logOperation(cfg, "export-state", image.Reference{}, "", currentActor(), "state export requested", now); err != nil {
		fmt.Fprintf(stderr, "could not write audit event: %v\n", err)
		return 1
	}
	state, err := db.ExportState(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "could not export state: %v\n", err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(state); err != nil {
		fmt.Fprintf(stderr, "could not write state export: %v\n", err)
		return 1
	}
	return 0
}

func runImportState(args []string, stdout, stderr io.Writer) int {
	opts, code := parseImportArgs(args, stderr)
	if code != 0 {
		return code
	}
	db, cfg, err := openConfiguredState(opts.configPath, "import-state")
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	defer db.Close()

	var input io.Reader = os.Stdin
	var file *os.File
	if opts.inputPath != "" {
		file, err = os.Open(opts.inputPath)
		if err != nil {
			fmt.Fprintf(stderr, "could not open state import: %v\n", err)
			return 1
		}
		defer file.Close()
		input = file
	}
	var state store.ExportedState
	if err := json.NewDecoder(input).Decode(&state); err != nil {
		fmt.Fprintf(stderr, "could not decode state import: %v\n", err)
		return 1
	}
	if err := db.ImportState(context.Background(), state); err != nil {
		fmt.Fprintf(stderr, "could not import state: %v\n", err)
		return 1
	}
	now := time.Now().UTC()
	if err := logOperation(cfg, "import-state", image.Reference{}, "", currentActor(), "state import completed", now); err != nil {
		fmt.Fprintf(stderr, "could not write audit event: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Imported state: observations=%d approvals=%d freezes=%d bypasses=%d decisions=%d\n",
		len(state.Observations), len(state.Approvals), len(state.Freezes), len(state.Bypasses), len(state.Decisions))
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

type operationOptions struct {
	configPath string
	imageRef   string
	ttl        *policy.Duration
	reason     string
	actor      string
}

type auditOptions struct {
	configPath string
	imageRef   string
	since      *policy.Duration
}

type importOptions struct {
	configPath string
	inputPath  string
}

func parseOperationArgs(args []string, command string, requireTTL bool, stderr io.Writer) (operationOptions, int) {
	opts := operationOptions{
		configPath: defaultConfigPath(),
		actor:      currentActor(),
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--config":
			value, ok := nextArg(args, &i, "--config", stderr)
			if !ok {
				return operationOptions{}, 2
			}
			opts.configPath = value
		case "--ttl":
			value, ok := nextArg(args, &i, "--ttl", stderr)
			if !ok {
				return operationOptions{}, 2
			}
			ttl, err := policy.ParseDuration(value)
			if err != nil {
				fmt.Fprintf(stderr, "invalid --ttl: %v\n", err)
				return operationOptions{}, 2
			}
			if ttl.Duration <= 0 {
				fmt.Fprintln(stderr, "--ttl must be greater than zero")
				return operationOptions{}, 2
			}
			opts.ttl = &ttl
		case "--reason":
			value, ok := nextArg(args, &i, "--reason", stderr)
			if !ok {
				return operationOptions{}, 2
			}
			opts.reason = value
		case "--by":
			value, ok := nextArg(args, &i, "--by", stderr)
			if !ok {
				return operationOptions{}, 2
			}
			opts.actor = value
		default:
			if strings.HasPrefix(arg, "--config=") {
				opts.configPath = strings.TrimPrefix(arg, "--config=")
				continue
			}
			if strings.HasPrefix(arg, "--ttl=") {
				value := strings.TrimPrefix(arg, "--ttl=")
				ttl, err := policy.ParseDuration(value)
				if err != nil {
					fmt.Fprintf(stderr, "invalid --ttl: %v\n", err)
					return operationOptions{}, 2
				}
				if ttl.Duration <= 0 {
					fmt.Fprintln(stderr, "--ttl must be greater than zero")
					return operationOptions{}, 2
				}
				opts.ttl = &ttl
				continue
			}
			if strings.HasPrefix(arg, "--reason=") {
				opts.reason = strings.TrimPrefix(arg, "--reason=")
				continue
			}
			if strings.HasPrefix(arg, "--by=") {
				opts.actor = strings.TrimPrefix(arg, "--by=")
				continue
			}
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(stderr, "unknown flag %q\n", arg)
				return operationOptions{}, 2
			}
			if opts.imageRef != "" {
				fmt.Fprintf(stderr, "%s accepts one image reference, got extra argument %q\n", command, arg)
				return operationOptions{}, 2
			}
			opts.imageRef = arg
		}
	}
	if opts.imageRef == "" {
		fmt.Fprintf(stderr, "missing image reference for %s\n", command)
		return operationOptions{}, 2
	}
	if requireTTL && opts.ttl == nil {
		fmt.Fprintf(stderr, "%s requires --ttl DURATION\n", command)
		return operationOptions{}, 2
	}
	return opts, 0
}

func parseAuditArgs(args []string, stderr io.Writer) (auditOptions, int) {
	opts := auditOptions{configPath: defaultConfigPath()}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--config":
			value, ok := nextArg(args, &i, "--config", stderr)
			if !ok {
				return auditOptions{}, 2
			}
			opts.configPath = value
		case "--image":
			value, ok := nextArg(args, &i, "--image", stderr)
			if !ok {
				return auditOptions{}, 2
			}
			opts.imageRef = value
		case "--since":
			value, ok := nextArg(args, &i, "--since", stderr)
			if !ok {
				return auditOptions{}, 2
			}
			since, err := policy.ParseDuration(value)
			if err != nil {
				fmt.Fprintf(stderr, "invalid --since: %v\n", err)
				return auditOptions{}, 2
			}
			opts.since = &since
		default:
			if strings.HasPrefix(arg, "--config=") {
				opts.configPath = strings.TrimPrefix(arg, "--config=")
				continue
			}
			if strings.HasPrefix(arg, "--image=") {
				opts.imageRef = strings.TrimPrefix(arg, "--image=")
				continue
			}
			if strings.HasPrefix(arg, "--since=") {
				value := strings.TrimPrefix(arg, "--since=")
				since, err := policy.ParseDuration(value)
				if err != nil {
					fmt.Fprintf(stderr, "invalid --since: %v\n", err)
					return auditOptions{}, 2
				}
				opts.since = &since
				continue
			}
			fmt.Fprintf(stderr, "unknown argument %q for audit\n", arg)
			return auditOptions{}, 2
		}
	}
	return opts, 0
}

func parseConfigOnly(args []string, command string, stderr io.Writer) (string, int) {
	configPath := defaultConfigPath()
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--config":
			value, ok := nextArg(args, &i, "--config", stderr)
			if !ok {
				return "", 2
			}
			configPath = value
		default:
			if strings.HasPrefix(arg, "--config=") {
				configPath = strings.TrimPrefix(arg, "--config=")
				continue
			}
			fmt.Fprintf(stderr, "unknown argument %q for %s\n", arg, command)
			return "", 2
		}
	}
	return configPath, 0
}

func parseImportArgs(args []string, stderr io.Writer) (importOptions, int) {
	opts := importOptions{configPath: defaultConfigPath()}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--config":
			value, ok := nextArg(args, &i, "--config", stderr)
			if !ok {
				return importOptions{}, 2
			}
			opts.configPath = value
		case "--input":
			value, ok := nextArg(args, &i, "--input", stderr)
			if !ok {
				return importOptions{}, 2
			}
			opts.inputPath = value
		default:
			if strings.HasPrefix(arg, "--config=") {
				opts.configPath = strings.TrimPrefix(arg, "--config=")
				continue
			}
			if strings.HasPrefix(arg, "--input=") {
				opts.inputPath = strings.TrimPrefix(arg, "--input=")
				continue
			}
			fmt.Fprintf(stderr, "unknown argument %q for import-state\n", arg)
			return importOptions{}, 2
		}
	}
	return opts, 0
}

func nextArg(args []string, index *int, flag string, stderr io.Writer) (string, bool) {
	if *index+1 >= len(args) {
		fmt.Fprintf(stderr, "missing value for %s\n", flag)
		return "", false
	}
	*index = *index + 1
	return args[*index], true
}

func openConfiguredState(configPath, command string) (*store.SQLiteStore, policy.Config, error) {
	cfg, err := policy.LoadFile(configPath)
	if err != nil {
		return nil, policy.Config{}, fmt.Errorf("could not load policy: %w", err)
	}
	if cfg.State.Backend != "sqlite" {
		return nil, policy.Config{}, fmt.Errorf("unsupported state backend %q; only sqlite is supported", cfg.State.Backend)
	}
	if cfg.State.Path == "" {
		return nil, policy.Config{}, fmt.Errorf("state.path is required for %s", command)
	}
	db, err := store.OpenSQLite(cfg.State.Path)
	if err != nil {
		return nil, policy.Config{}, fmt.Errorf("could not open local state: %w", err)
	}
	return db, cfg, nil
}

func expiresFromTTL(now time.Time, ttl *policy.Duration) *time.Time {
	if ttl == nil {
		return nil
	}
	expiresAt := now.Add(ttl.Duration).UTC()
	return &expiresAt
}

func currentActor() string {
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	return "cli"
}

func logOperation(cfg policy.Config, operation string, ref image.Reference, digest, actor, reason string, now time.Time) error {
	event := audit.Event{
		Timestamp:  now,
		ImageRef:   ref.CanonicalRef,
		Registry:   ref.Registry,
		Repository: ref.Repository,
		Tag:        ref.Tag,
		Digest:     digest,
		Decision:   operation,
		Reason:     reason,
		ClientUser: actor,
	}
	if event.ImageRef == "" {
		event.ImageRef = "state"
	}
	return audit.NewLogger(cfg.Audit.Path).Record(event)
}

func auditEventMatchesImage(event audit.Event, filter image.Reference) bool {
	if event.Registry == "" && event.ImageRef != "" {
		ref, err := image.ParseReference(event.ImageRef)
		if err == nil {
			event.Registry = ref.Registry
			event.Repository = ref.Repository
			event.Tag = ref.Tag
			event.Digest = ref.Digest
		}
	}
	if event.Registry != filter.Registry || event.Repository != filter.Repository || event.Tag != filter.Tag {
		return false
	}
	if filter.Digest != "" && event.Digest != filter.Digest {
		return false
	}
	return true
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
	if decision.Bypassed {
		fmt.Fprintln(w, "Bypass: active")
	}
	if decision.Frozen {
		fmt.Fprintln(w, "Freeze: active")
	}
}

func printApproval(w io.Writer, ref image.Reference, approval *store.Approval) {
	fmt.Fprintf(w, "Approved: %s\n", ref.CanonicalRef)
	fmt.Fprintf(w, "Digest: %s\n", approval.Digest)
	fmt.Fprintf(w, "Approved at: %s\n", approval.ApprovedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Approved by: %s\n", approval.ApprovedBy)
	if approval.ExpiresAt != nil {
		fmt.Fprintf(w, "Expires at: %s\n", approval.ExpiresAt.Format(time.RFC3339))
	}
	if approval.Reason != "" {
		fmt.Fprintf(w, "Reason: %s\n", approval.Reason)
	}
}

func printBypass(w io.Writer, ref image.Reference, bypass *store.Bypass) {
	fmt.Fprintf(w, "Bypass active: %s\n", ref.CanonicalRef)
	fmt.Fprintf(w, "Created at: %s\n", bypass.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Created by: %s\n", bypass.CreatedBy)
	if bypass.ExpiresAt != nil {
		fmt.Fprintf(w, "Expires at: %s\n", bypass.ExpiresAt.Format(time.RFC3339))
	}
	if bypass.Reason != "" {
		fmt.Fprintf(w, "Reason: %s\n", bypass.Reason)
	}
}

func printFreeze(w io.Writer, ref image.Reference, freeze *store.Freeze) {
	fmt.Fprintf(w, "Freeze active: %s\n", ref.CanonicalRef)
	if freeze.Digest != "" {
		fmt.Fprintf(w, "Digest: %s\n", freeze.Digest)
	}
	fmt.Fprintf(w, "Created at: %s\n", freeze.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Created by: %s\n", freeze.CreatedBy)
	if freeze.ExpiresAt != nil {
		fmt.Fprintf(w, "Expires at: %s\n", freeze.ExpiresAt.Format(time.RFC3339))
	}
	if freeze.Reason != "" {
		fmt.Fprintf(w, "Reason: %s\n", freeze.Reason)
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
			if override.Approval != nil {
				fmt.Fprintln(w, "  Local override: allow (approval)")
			} else {
				fmt.Fprintln(w, "  Local override: allow (bypass)")
			}
			if override.Approval != nil && override.Approval.Reason != "" {
				fmt.Fprintf(w, "  Approval reason: %s\n", override.Approval.Reason)
			}
			if override.Bypass != nil && override.Bypass.Reason != "" {
				fmt.Fprintf(w, "  Bypass reason: %s\n", override.Bypass.Reason)
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
