package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/MohamedElashri/ribat/internal/image"
	"github.com/MohamedElashri/ribat/internal/policy"
	"github.com/MohamedElashri/ribat/internal/version"
)

const usage = `ribat guards mutable Docker image tags until their resolved digests satisfy policy.

Usage:
  ribat version
  ribat policy check [--config PATH] IMAGE
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
	case "policy":
		return runPolicy(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
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
	configPath := defaultConfigPath()
	var imageRef string

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
		default:
			if strings.HasPrefix(arg, "--config=") {
				configPath = strings.TrimPrefix(arg, "--config=")
				continue
			}
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(stderr, "unknown flag %q\n", arg)
				return 2
			}
			if imageRef != "" {
				fmt.Fprintf(stderr, "policy check accepts one image reference, got extra argument %q\n", arg)
				return 2
			}
			imageRef = arg
		}
	}

	if imageRef == "" {
		fmt.Fprintln(stderr, "missing image reference for policy check")
		return 2
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
}

func defaultConfigPath() string {
	if _, err := os.Stat("configs/ribat.example.yaml"); err == nil {
		return "configs/ribat.example.yaml"
	}
	return "/etc/ribat/config.yaml"
}
