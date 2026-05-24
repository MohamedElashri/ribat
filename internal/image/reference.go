package image

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	defaultRegistry = "docker.io"
	defaultTag      = "latest"
	officialPrefix  = "library/"
)

var (
	registryRe  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]+)?$`)
	componentRe = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	tagRe       = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	digestRe    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:[+._-][A-Za-z][A-Za-z0-9]*)*:[A-Za-z0-9=_-]+$`)
)

// Reference is a normalized Docker image reference.
type Reference struct {
	Registry       string
	Repository     string
	Tag            string
	Digest         string
	IsMutableTag   bool
	IsDigestPinned bool
	CanonicalRef   string
}

// ParseReference parses a Docker image reference and normalizes Docker Hub
// defaults such as "nginx" into "docker.io/library/nginx:latest".
func ParseReference(input string) (Reference, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return Reference{}, errors.New("image reference is empty")
	}
	if raw != input || strings.ContainsAny(raw, " \t\r\n") {
		return Reference{}, fmt.Errorf("image reference %q must not contain whitespace", input)
	}
	if strings.Contains(raw, "://") {
		return Reference{}, fmt.Errorf("image reference %q must not include a URL scheme", input)
	}

	namePart, digest, err := splitDigest(raw)
	if err != nil {
		return Reference{}, err
	}
	if namePart == "" {
		return Reference{}, fmt.Errorf("image reference %q is missing repository name", input)
	}

	namePart, tag, err := splitTag(namePart)
	if err != nil {
		return Reference{}, err
	}
	if digest == "" && tag == "" {
		tag = defaultTag
	}

	registry, repository, err := normalizeName(namePart)
	if err != nil {
		return Reference{}, err
	}
	if tag != "" && !tagRe.MatchString(tag) {
		return Reference{}, fmt.Errorf("image reference %q has malformed tag %q", input, tag)
	}
	if digest != "" && !digestRe.MatchString(digest) {
		return Reference{}, fmt.Errorf("image reference %q has malformed digest %q", input, digest)
	}

	ref := Reference{
		Registry:       registry,
		Repository:     repository,
		Tag:            tag,
		Digest:         digest,
		IsDigestPinned: digest != "",
	}
	ref.IsMutableTag = !ref.IsDigestPinned
	ref.CanonicalRef = ref.canonical()

	return ref, nil
}

func splitDigest(ref string) (namePart, digest string, err error) {
	parts := strings.Split(ref, "@")
	switch len(parts) {
	case 1:
		return ref, "", nil
	case 2:
		if parts[1] == "" {
			return "", "", fmt.Errorf("image reference %q has an empty digest", ref)
		}
		return parts[0], parts[1], nil
	default:
		return "", "", fmt.Errorf("image reference %q has multiple digest separators", ref)
	}
}

func splitTag(namePart string) (name, tag string, err error) {
	lastSlash := strings.LastIndexByte(namePart, '/')
	lastColon := strings.LastIndexByte(namePart, ':')
	if lastColon <= lastSlash {
		return namePart, "", nil
	}
	if lastColon == len(namePart)-1 {
		return "", "", fmt.Errorf("image reference %q has an empty tag", namePart)
	}
	return namePart[:lastColon], namePart[lastColon+1:], nil
}

func normalizeName(name string) (registry, repository string, err error) {
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.Contains(name, "//") {
		return "", "", fmt.Errorf("image repository %q has an empty path component", name)
	}

	parts := strings.Split(name, "/")
	first := parts[0]
	if hasExplicitRegistry(first) {
		registry = first
		repository = strings.Join(parts[1:], "/")
		if repository == "" {
			return "", "", fmt.Errorf("image repository %q is missing a repository path", name)
		}
	} else {
		registry = defaultRegistry
		repository = name
		if len(parts) == 1 {
			repository = officialPrefix + repository
		}
	}

	if !registryRe.MatchString(registry) {
		return "", "", fmt.Errorf("image registry %q is malformed", registry)
	}
	if strings.Contains(repository, ":") {
		return "", "", fmt.Errorf("image repository %q must not contain a port or tag", repository)
	}
	for _, component := range strings.Split(repository, "/") {
		if component == "" {
			return "", "", fmt.Errorf("image repository %q has an empty path component", repository)
		}
		if !componentRe.MatchString(component) {
			return "", "", fmt.Errorf("image repository component %q is malformed", component)
		}
	}

	return registry, repository, nil
}

func hasExplicitRegistry(firstComponent string) bool {
	return strings.ContainsAny(firstComponent, ".:") || firstComponent == "localhost"
}

func (r Reference) canonical() string {
	base := r.Registry + "/" + r.Repository
	if r.Tag != "" {
		base += ":" + r.Tag
	}
	if r.Digest != "" {
		base += "@" + r.Digest
	}
	return base
}
