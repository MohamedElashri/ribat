package policy

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	ActionAllow      = "allow"
	ActionDeny       = "deny"
	ActionQuarantine = "quarantine"
)

type Config struct {
	Version       int
	DefaultPolicy EffectivePolicy
	Rules         []Rule
	Audit         AuditConfig
	State         StateConfig
}

type EffectivePolicy struct {
	MutableTags              MutableTagPolicy
	DigestPinnedImages       ActionPolicy
	FailedRegistryResolution ActionPolicy
	FailedSignatureCheck     ActionPolicy
	Signatures               SignaturesPolicy
}

type MutableTagPolicy struct {
	Action             string
	MinDigestAge       Duration
	AllowFirstSeenPull bool
}

type ActionPolicy struct {
	Action string
}

type SignaturesPolicy struct {
	Cosign CosignPolicy
}

type CosignPolicy struct {
	Required      bool
	Mode          string
	Key           string
	Issuer        string
	Identity      string
	IdentityRegex string
}

type Rule struct {
	Match       string
	MutableTags RuleMutableTagPolicy
	Signatures  RuleSignaturesPolicy
}

type RuleMutableTagPolicy struct {
	Action             *string
	MinDigestAge       *Duration
	AllowFirstSeenPull *bool
}

type RuleSignaturesPolicy struct {
	Cosign RuleCosignPolicy
}

type RuleCosignPolicy struct {
	Required      *bool
	Mode          *string
	Key           *string
	Issuer        *string
	Identity      *string
	IdentityRegex *string
}

type AuditConfig struct {
	Path string
}

type StateConfig struct {
	Backend string
	Path    string
}

func LoadFile(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("load policy file %q: %w", path, err)
	}
	defer file.Close()

	cfg, err := Load(file)
	if err != nil {
		return Config{}, fmt.Errorf("load policy file %q: %w", path, err)
	}
	return cfg, nil
}

func Load(r io.Reader) (Config, error) {
	parser := yamlPolicyParser{
		paths: map[int]string{},
	}
	if err := parser.parse(r); err != nil {
		return Config{}, err
	}
	if err := parser.config.validate(); err != nil {
		return Config{}, err
	}
	return parser.config, nil
}

func (c Config) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("policy version must be 1, got %d", c.Version)
	}
	if err := validateAction("default_policy.mutable_tags.action", c.DefaultPolicy.MutableTags.Action, ActionQuarantine, ActionAllow, ActionDeny); err != nil {
		return err
	}
	if c.DefaultPolicy.MutableTags.MinDigestAge.Duration == 0 && c.DefaultPolicy.MutableTags.Action == ActionQuarantine {
		return fmt.Errorf("default_policy.mutable_tags.min_digest_age is required when action is quarantine")
	}
	if err := validateAction("default_policy.digest_pinned_images.action", c.DefaultPolicy.DigestPinnedImages.Action, ActionAllow, ActionDeny); err != nil {
		return err
	}
	if err := validateAction("default_policy.failed_registry_resolution.action", c.DefaultPolicy.FailedRegistryResolution.Action, ActionAllow, ActionDeny); err != nil {
		return err
	}
	if err := validateAction("default_policy.failed_signature_check.action", c.DefaultPolicy.FailedSignatureCheck.Action, ActionAllow, ActionDeny); err != nil {
		return err
	}
	for i, rule := range c.Rules {
		if rule.Match == "" {
			return fmt.Errorf("rules[%d].match is required", i)
		}
		if rule.MutableTags.Action != nil {
			if err := validateAction(fmt.Sprintf("rules[%d].mutable_tags.action", i), *rule.MutableTags.Action, ActionQuarantine, ActionAllow, ActionDeny); err != nil {
				return err
			}
		}
		if err := validateCosignPolicy(fmt.Sprintf("rules[%d].signatures.cosign", i), rule.Signatures.Cosign.effective(c.DefaultPolicy.Signatures.Cosign)); err != nil {
			return err
		}
	}
	if err := validateCosignPolicy("default_policy.signatures.cosign", c.DefaultPolicy.Signatures.Cosign); err != nil {
		return err
	}
	return nil
}

func validateCosignPolicy(path string, p CosignPolicy) error {
	if p.Mode != "" && p.Mode != "keyless" && p.Mode != "key" {
		return fmt.Errorf("%s.mode has unsupported value %q; allowed values: keyless, key", path, p.Mode)
	}
	if !p.Required {
		return nil
	}
	mode := p.Mode
	if mode == "" && p.Key != "" {
		mode = "key"
	}
	if mode == "key" && p.Key == "" {
		return fmt.Errorf("%s.key is required when mode is key", path)
	}
	if mode == "keyless" || mode == "" {
		if p.Identity == "" && p.IdentityRegex == "" {
			return fmt.Errorf("%s.identity or %s.identity_regex is required for keyless verification", path, path)
		}
		if p.Identity != "" && p.IdentityRegex != "" {
			return fmt.Errorf("%s.identity and %s.identity_regex are mutually exclusive", path, path)
		}
	}
	return nil
}

func (p RuleCosignPolicy) effective(base CosignPolicy) CosignPolicy {
	if p.Required != nil {
		base.Required = *p.Required
	}
	if p.Mode != nil {
		base.Mode = *p.Mode
	}
	if p.Key != nil {
		base.Key = *p.Key
	}
	if p.Issuer != nil {
		base.Issuer = *p.Issuer
	}
	if p.Identity != nil {
		base.Identity = *p.Identity
	}
	if p.IdentityRegex != nil {
		base.IdentityRegex = *p.IdentityRegex
	}
	return base
}

func validateAction(path, got string, allowed ...string) error {
	if got == "" {
		return fmt.Errorf("%s is required", path)
	}
	for _, value := range allowed {
		if got == value {
			return nil
		}
	}
	return fmt.Errorf("%s has unsupported action %q; allowed values: %s", path, got, strings.Join(allowed, ", "))
}

type yamlPolicyParser struct {
	config      Config
	paths       map[int]string
	currentRule int
}

func (p *yamlPolicyParser) parse(r io.Reader) error {
	p.currentRule = -1
	scanner := bufio.NewScanner(r)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		raw := stripComment(scanner.Text())
		if strings.TrimSpace(raw) == "" {
			continue
		}

		indent := leadingSpaces(raw)
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "- ") {
			if err := p.parseListItem(lineNumber, indent, strings.TrimSpace(trimmed[2:])); err != nil {
				return err
			}
			continue
		}

		key, value, err := splitYAMLKeyValue(lineNumber, trimmed)
		if err != nil {
			return err
		}
		p.clearDeeper(indent)
		if value == "" {
			p.paths[indent] = key
			continue
		}
		if indent == 0 {
			p.currentRule = -1
		}
		if err := p.setValue(lineNumber, indent, key, parseScalar(value)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	return nil
}

func (p *yamlPolicyParser) parseListItem(lineNumber, indent int, item string) error {
	parent := p.paths[indent-2]
	if parent != "rules" {
		return nil
	}
	p.config.Rules = append(p.config.Rules, Rule{})
	p.currentRule = len(p.config.Rules) - 1
	if item == "" {
		return nil
	}
	key, value, err := splitYAMLKeyValue(lineNumber, item)
	if err != nil {
		return err
	}
	return p.setRuleValue(lineNumber, indent+2, key, parseScalar(value))
}

func (p *yamlPolicyParser) setValue(lineNumber, indent int, key, value string) error {
	if p.currentRule >= 0 && indent > 2 {
		return p.setRuleValue(lineNumber, indent, key, value)
	}

	switch {
	case indent == 0 && key == "version":
		version, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("line %d: version must be an integer", lineNumber)
		}
		p.config.Version = version
	case p.paths[0] == "default_policy" && p.paths[2] == "mutable_tags":
		return setMutableTagValue(lineNumber, "default_policy.mutable_tags", key, value, &p.config.DefaultPolicy.MutableTags)
	case p.paths[0] == "default_policy" && p.paths[2] == "digest_pinned_images" && key == "action":
		p.config.DefaultPolicy.DigestPinnedImages.Action = value
	case p.paths[0] == "default_policy" && p.paths[2] == "failed_registry_resolution" && key == "action":
		p.config.DefaultPolicy.FailedRegistryResolution.Action = value
	case p.paths[0] == "default_policy" && p.paths[2] == "failed_signature_check" && key == "action":
		p.config.DefaultPolicy.FailedSignatureCheck.Action = value
	case p.paths[0] == "default_policy" && p.paths[2] == "signatures" && p.paths[4] == "cosign":
		return setCosignValue(lineNumber, "default_policy.signatures.cosign", key, value, &p.config.DefaultPolicy.Signatures.Cosign)
	case p.paths[0] == "audit" && key == "path":
		p.config.Audit.Path = value
	case p.paths[0] == "state" && key == "backend":
		p.config.State.Backend = value
	case p.paths[0] == "state" && key == "path":
		p.config.State.Path = value
	}
	return nil
}

func (p *yamlPolicyParser) setRuleValue(lineNumber, indent int, key, value string) error {
	rule := &p.config.Rules[p.currentRule]
	if key == "match" {
		rule.Match = value
		return nil
	}
	if p.paths[indent-2] == "mutable_tags" {
		return setRuleMutableTagValue(lineNumber, key, value, &rule.MutableTags)
	}
	if p.paths[indent-4] == "signatures" && p.paths[indent-2] == "cosign" {
		return setRuleCosignValue(lineNumber, key, value, &rule.Signatures.Cosign)
	}
	return nil
}

func setMutableTagValue(lineNumber int, path, key, value string, target *MutableTagPolicy) error {
	switch key {
	case "action":
		target.Action = value
	case "min_digest_age":
		duration, err := ParseDuration(value)
		if err != nil {
			return fmt.Errorf("line %d: %s.%s: %w", lineNumber, path, key, err)
		}
		target.MinDigestAge = duration
	case "allow_first_seen_pull":
		parsed, err := parseBool(value)
		if err != nil {
			return fmt.Errorf("line %d: %s.%s must be true or false", lineNumber, path, key)
		}
		target.AllowFirstSeenPull = parsed
	}
	return nil
}

func setRuleMutableTagValue(lineNumber int, key, value string, target *RuleMutableTagPolicy) error {
	switch key {
	case "action":
		target.Action = &value
	case "min_digest_age":
		duration, err := ParseDuration(value)
		if err != nil {
			return fmt.Errorf("line %d: rule mutable_tags.%s: %w", lineNumber, key, err)
		}
		target.MinDigestAge = &duration
	case "allow_first_seen_pull":
		parsed, err := parseBool(value)
		if err != nil {
			return fmt.Errorf("line %d: rule mutable_tags.%s must be true or false", lineNumber, key)
		}
		target.AllowFirstSeenPull = &parsed
	}
	return nil
}

func setCosignValue(lineNumber int, path, key, value string, target *CosignPolicy) error {
	switch key {
	case "required":
		parsed, err := parseBool(value)
		if err != nil {
			return fmt.Errorf("line %d: %s.required must be true or false", lineNumber, path)
		}
		target.Required = parsed
	case "mode":
		target.Mode = value
	case "key":
		target.Key = value
	case "issuer":
		target.Issuer = value
	case "identity":
		target.Identity = value
	case "identity_regex":
		target.IdentityRegex = value
	}
	return nil
}

func setRuleCosignValue(lineNumber int, key, value string, target *RuleCosignPolicy) error {
	switch key {
	case "required":
		parsed, err := parseBool(value)
		if err != nil {
			return fmt.Errorf("line %d: rule signatures.cosign.required must be true or false", lineNumber)
		}
		target.Required = &parsed
	case "mode":
		target.Mode = &value
	case "key":
		target.Key = &value
	case "issuer":
		target.Issuer = &value
	case "identity":
		target.Identity = &value
	case "identity_regex":
		target.IdentityRegex = &value
	}
	return nil
}

func (p *yamlPolicyParser) clearDeeper(indent int) {
	for existing := range p.paths {
		if existing >= indent {
			delete(p.paths, existing)
		}
	}
}

func splitYAMLKeyValue(lineNumber int, line string) (string, string, error) {
	before, after, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", fmt.Errorf("line %d: expected key: value", lineNumber)
	}
	key := strings.TrimSpace(before)
	if key == "" {
		return "", "", fmt.Errorf("line %d: YAML key is empty", lineNumber)
	}
	return key, strings.TrimSpace(after), nil
}

func stripComment(line string) string {
	inSingle := false
	inDouble := false
	for i, r := range line {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
	}
	return line
}

func leadingSpaces(line string) int {
	count := 0
	for _, r := range line {
		if r != ' ' {
			break
		}
		count++
	}
	return count
}

func parseScalar(value string) string {
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func parseBool(value string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("invalid bool")
	}
}
