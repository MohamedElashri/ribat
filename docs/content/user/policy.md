+++
title = "Policy"
description = "Configure mutable-tag quarantine, digest-pinned behavior, registry failures, and Cosign verification."
weight = 40
template = "page"
+++

Ribat policy is stored in YAML. The example policy at `configs/ribat.example.yaml` is conservative: mutable tags enter quarantine, digest-pinned images are allowed, registry failures deny, and signature failures deny.

## First-Seen Denial

The first time Ribat sees a mutable tag resolve to a digest, it records the tuple:

```text
registry + repository + tag + digest
```

Then it denies the pull unless `allow_first_seen_pull` is explicitly enabled for the matching policy.

Example:

```text
docker.io/library/alpine:latest -> sha256:first
```

If `sha256:first` is new and the matching policy requires `14d`, the pull is denied until 14 days after the first observation. If `latest` later points to `sha256:second`, that second digest starts its own quarantine clock.

## Matching

Rules are evaluated in order. The first matching rule overrides fields from `default_policy`; if no rule matches, the default policy applies.

```yaml
rules:
  - match: "*:latest"
    mutable_tags:
      min_digest_age: 14d

  - match: "docker.io/library/alpine:*"
    mutable_tags:
      min_digest_age: 3d

  - match: "ghcr.io/example/app:*"
    mutable_tags:
      min_digest_age: 7d
```

Docker Hub shorthand is normalized before matching. For example, `nginx:latest` becomes `docker.io/library/nginx:latest`.

## Mutable Tags

```yaml
default_policy:
  mutable_tags:
    action: quarantine
    min_digest_age: 7d
    allow_first_seen_pull: false
```

Supported actions:

* `quarantine`: record new digests and allow only after the minimum age;
* `deny`: always deny mutable tags covered by this policy;
* `allow`: allow mutable tags covered by this policy.

Use `allow` and `allow_first_seen_pull: true` carefully; both reduce protection against fast mutable-tag compromise.

## Digest-Pinned Images

```yaml
default_policy:
  digest_pinned_images:
    action: allow
```

Digest-pinned references are deterministic and are allowed by default. They can still be denied by an active freeze or by required signature verification failure.

## Registry Failures

```yaml
default_policy:
  failed_registry_resolution:
    action: deny
```

The safe default is to deny when Ribat cannot resolve a mutable tag to a registry digest. Allowing resolution failures weakens the core invariant because Ribat cannot know which digest Docker would pull.

## Cosign Verification

Ribat verifies digest references, not mutable tag references. It resolves the mutable tag first, then runs Cosign against the resolved digest.

Keyless example:

```yaml
rules:
  - match: "ghcr.io/example/app:*"
    signatures:
      cosign:
        required: true
        mode: keyless
        issuer: "https://token.actions.githubusercontent.com"
        identity_regex: "^https://github.com/example/app/.github/workflows/release.yml@refs/tags/v.*$"
```

Key example:

```yaml
rules:
  - match: "registry.example.com/team/app:*"
    signatures:
      cosign:
        required: true
        mode: key
        key: "/etc/ribat/cosign.pub"
```

When Cosign is required, the host running Ribat must have `cosign` available on `PATH`.
