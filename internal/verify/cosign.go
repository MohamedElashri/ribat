package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"

	"github.com/MohamedElashri/ribat/internal/image"
	"github.com/MohamedElashri/ribat/internal/policy"
)

type CosignResult struct {
	Success bool
	Reason  string
	Command []string
}

type CosignVerifier struct {
	Command string
}

func NewCosignVerifier(command string) CosignVerifier {
	if command == "" {
		command = "cosign"
	}
	return CosignVerifier{Command: command}
}

func (v CosignVerifier) Verify(ctx context.Context, ref image.Reference, digest string, cfg policy.CosignPolicy) (CosignResult, error) {
	command := v.Command
	if command == "" {
		command = "cosign"
	}
	args, err := CosignVerifyArgs(ref, digest, cfg)
	if err != nil {
		return CosignResult{}, err
	}
	cmd := exec.CommandContext(ctx, command, args...)
	output, err := cmd.CombinedOutput()
	fullCommand := append([]string{command}, args...)
	if err != nil {
		reason := strings.TrimSpace(string(output))
		if reason == "" {
			reason = err.Error()
		}
		return CosignResult{Success: false, Reason: reason, Command: fullCommand}, nil
	}
	return CosignResult{Success: true, Reason: "cosign verification succeeded", Command: fullCommand}, nil
}

func CosignVerifyArgs(ref image.Reference, digest string, cfg policy.CosignPolicy) ([]string, error) {
	if digest == "" {
		return nil, fmt.Errorf("digest is required for cosign verification")
	}
	mode := cfg.Mode
	if mode == "" && cfg.Key != "" {
		mode = "key"
	}
	if mode == "" {
		mode = "keyless"
	}

	args := []string{"verify"}
	switch mode {
	case "key":
		if cfg.Key == "" {
			return nil, fmt.Errorf("cosign key is required when mode is key")
		}
		args = append(args, "--key", cfg.Key)
	case "keyless":
		if cfg.Issuer != "" {
			args = append(args, "--certificate-oidc-issuer", cfg.Issuer)
		}
		if cfg.Identity != "" {
			args = append(args, "--certificate-identity", cfg.Identity)
		}
		if cfg.IdentityRegex != "" {
			args = append(args, "--certificate-identity-regexp", cfg.IdentityRegex)
		}
	default:
		return nil, fmt.Errorf("unsupported cosign mode %q", cfg.Mode)
	}
	args = append(args, DigestReference(ref, digest))
	return args, nil
}

func DigestReference(ref image.Reference, digest string) string {
	return ref.Registry + "/" + ref.Repository + "@" + digest
}

func CosignPolicyKey(cfg policy.CosignPolicy) string {
	normalized := strings.Join([]string{
		cfg.Mode,
		cfg.Key,
		cfg.Issuer,
		cfg.Identity,
		cfg.IdentityRegex,
	}, "\x00")
	sum := sha256.Sum256([]byte(normalized))
	return "sha256:" + hex.EncodeToString(sum[:])
}
