package policy

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/MohamedElashri/ribat/internal/image"
)

type MatchResult struct {
	Policy      EffectivePolicy
	MatchedRule string
}

func (c Config) EffectivePolicyFor(ref image.Reference) (MatchResult, error) {
	effective := c.DefaultPolicy
	matched := "default_policy"

	for _, rule := range c.Rules {
		ok, err := matchPattern(rule.Match, ref)
		if err != nil {
			return MatchResult{}, err
		}
		if !ok {
			continue
		}
		applyRule(&effective, rule)
		matched = rule.Match
		break
	}

	return MatchResult{Policy: effective, MatchedRule: matched}, nil
}

func applyRule(effective *EffectivePolicy, rule Rule) {
	if rule.MutableTags.Action != nil {
		effective.MutableTags.Action = *rule.MutableTags.Action
	}
	if rule.MutableTags.MinDigestAge != nil {
		effective.MutableTags.MinDigestAge = *rule.MutableTags.MinDigestAge
	}
	if rule.MutableTags.AllowFirstSeenPull != nil {
		effective.MutableTags.AllowFirstSeenPull = *rule.MutableTags.AllowFirstSeenPull
	}
	if rule.Signatures.Cosign.Required != nil {
		effective.Signatures.Cosign.Required = *rule.Signatures.Cosign.Required
	}
	if rule.Signatures.Cosign.Mode != nil {
		effective.Signatures.Cosign.Mode = *rule.Signatures.Cosign.Mode
	}
	if rule.Signatures.Cosign.Key != nil {
		effective.Signatures.Cosign.Key = *rule.Signatures.Cosign.Key
	}
	if rule.Signatures.Cosign.Issuer != nil {
		effective.Signatures.Cosign.Issuer = *rule.Signatures.Cosign.Issuer
	}
	if rule.Signatures.Cosign.Identity != nil {
		effective.Signatures.Cosign.Identity = *rule.Signatures.Cosign.Identity
	}
	if rule.Signatures.Cosign.IdentityRegex != nil {
		effective.Signatures.Cosign.IdentityRegex = *rule.Signatures.Cosign.IdentityRegex
	}
}

func matchPattern(pattern string, ref image.Reference) (bool, error) {
	if pattern == "*" {
		return true, nil
	}

	target := ref.CanonicalRef
	if ref.IsDigestPinned && ref.Tag == "" {
		target = ref.Registry + "/" + ref.Repository
	}
	if !strings.Contains(pattern, "/") && strings.Contains(pattern, ":") {
		_, tagPattern, _ := strings.Cut(pattern, ":")
		return wildcardMatch(tagPattern, ref.Tag)
	}

	return wildcardMatch(pattern, target)
}

func wildcardMatch(pattern, value string) (bool, error) {
	var builder strings.Builder
	builder.WriteString("^")
	for _, r := range pattern {
		if r == '*' {
			builder.WriteString(".*")
			continue
		}
		builder.WriteString(regexp.QuoteMeta(string(r)))
	}
	builder.WriteString("$")

	re, err := regexp.Compile(builder.String())
	if err != nil {
		return false, fmt.Errorf("invalid match pattern %q: %w", pattern, err)
	}
	return re.MatchString(value), nil
}
