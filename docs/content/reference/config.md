+++
title = "Config Reference"
description = "Policy, state, audit, and verification fields."
weight = 20
template = "page"
+++

Ribat configuration is YAML. The config file defines the default policy, ordered policy rules, state path, and audit log path.

## File Location

Commands use this default config path:

| Context | Default |
| --- | --- |
| Source checkout with `configs/ribat.example.yaml` present | `configs/ribat.example.yaml` |
| Installed host | `/etc/ribat/config.yaml` |

Pass `--config PATH` to use a different file.

## Minimal Example

```yaml
version: 1

default_policy:
  mutable_tags:
    action: quarantine
    min_digest_age: 7d
    allow_first_seen_pull: false

  digest_pinned_images:
    action: allow

  failed_registry_resolution:
    action: deny

  failed_signature_check:
    action: deny

  signatures:
    cosign:
      required: false

audit:
  path: "/var/log/ribat/audit.jsonl"

state:
  backend: sqlite
  path: "/var/lib/ribat/state.db"
```

## Top-Level Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `version` | integer | yes | Config schema version. Must be `1`. |
| `default_policy` | object | yes | Baseline policy applied when no rule overrides a field. |
| `rules` | list | no | Ordered policy overlays matched against normalized image references. |
| `audit` | object | yes for modes that write audit logs | JSONL audit output configuration. |
| `state` | object | yes for decisions and operations | Local state backend configuration. |

## `default_policy.mutable_tags`

Controls mutable tag behavior.

```yaml
default_policy:
  mutable_tags:
    action: quarantine
    min_digest_age: 7d
    allow_first_seen_pull: false
```

| Field | Type | Required | Values | Description |
| --- | --- | --- | --- | --- |
| `action` | string | yes | `quarantine`, `allow`, `deny` | Main behavior for mutable tags. |
| `min_digest_age` | duration | yes when `action` is `quarantine` | Example: `1h`, `24h`, `7d` | Required age before a known digest can be allowed. |
| `allow_first_seen_pull` | boolean | no | `true`, `false` | Allows a newly observed digest immediately. Keep `false` for default-deny behavior. |

Actions:

| Action | Behavior |
| --- | --- |
| `quarantine` | Record new tag and digest tuples, deny first-seen digests, allow after age and verification policy pass. |
| `deny` | Deny mutable tags covered by this policy. |
| `allow` | Allow mutable tags covered by this policy. This weakens the delayed-trust model. |

## `default_policy.digest_pinned_images`

Controls digest-pinned references such as `ghcr.io/example/app@sha256:abc123`.

```yaml
default_policy:
  digest_pinned_images:
    action: allow
```

| Field | Type | Required | Values | Description |
| --- | --- | --- | --- | --- |
| `action` | string | yes | `allow`, `deny` | Whether digest-pinned image references are allowed by policy. |

Digest-pinned images can still be denied by an active freeze or by required Cosign verification failure.

## `default_policy.failed_registry_resolution`

Controls what happens when Ribat cannot resolve a mutable tag to a registry digest.

```yaml
default_policy:
  failed_registry_resolution:
    action: deny
```

| Field | Type | Required | Values | Description |
| --- | --- | --- | --- | --- |
| `action` | string | yes | `allow`, `deny` | Whether to allow if remote digest resolution fails. |

Use `deny` unless you intentionally want fail-open behavior. Ribat cannot preserve the core invariant when it cannot know which digest Docker would pull.

## `default_policy.failed_signature_check`

Controls signature verification failure behavior.

```yaml
default_policy:
  failed_signature_check:
    action: deny
```

| Field | Type | Required | Values | Description |
| --- | --- | --- | --- | --- |
| `action` | string | yes | `allow`, `deny` | Whether required signature failures are allowed. |

The safe value is `deny`.

## `default_policy.signatures.cosign`

Configures optional Cosign verification.

```yaml
default_policy:
  signatures:
    cosign:
      required: false
```

| Field | Type | Required | Values | Description |
| --- | --- | --- | --- | --- |
| `required` | boolean | no | `true`, `false` | Require Cosign verification before allow decisions. |
| `mode` | string | when needed | `keyless`, `key` | Verification mode. If omitted and `key` is set, key mode is inferred. |
| `key` | string | yes when `mode` is `key` | filesystem path | Public key path for key-based verification. |
| `issuer` | string | no | URL or issuer string | Expected keyless certificate issuer. |
| `identity` | string | one of `identity` or `identity_regex` when keyless verification is required | exact identity | Exact keyless identity. |
| `identity_regex` | string | one of `identity` or `identity_regex` when keyless verification is required | regular expression | Regex for accepted keyless identities. |

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

Ribat verifies digest references, not mutable tag references. The host running Ribat must have `cosign` available on `PATH`.

## `rules`

Rules are evaluated in order. The first matching rule overlays fields from `default_policy`.

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
    signatures:
      cosign:
        required: true
        mode: keyless
        issuer: "https://token.actions.githubusercontent.com"
        identity_regex: "^https://github.com/example/app/.github/workflows/release.yml@refs/tags/v.*$"
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `match` | string | yes | Image match pattern. Evaluated against normalized references. |
| `mutable_tags` | object | no | Rule-level overrides for mutable-tag policy. |
| `signatures.cosign` | object | no | Rule-level overrides for Cosign policy. |

Supported rule-level `mutable_tags` fields:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | string | no | Overrides mutable-tag action. |
| `min_digest_age` | duration | no | Overrides required digest age. |
| `allow_first_seen_pull` | boolean | no | Overrides first-seen behavior. |

Docker Hub shorthand is normalized before matching. For example, `nginx:latest` is matched as `docker.io/library/nginx:latest`.

## `audit`

Configures JSONL audit output.

```yaml
audit:
  path: "/var/log/ribat/audit.jsonl"
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `path` | string | yes for audit logging | JSONL audit log path. |

Audit events include decisions, approvals, bypasses, freezes, import/export events, Docker request metadata when available, and verification-related status.

## `state`

Configures local state.

```yaml
state:
  backend: sqlite
  path: "/var/lib/ribat/state.db"
```

| Field | Type | Required | Values | Description |
| --- | --- | --- | --- | --- |
| `backend` | string | yes | `sqlite` | State backend. Only SQLite is currently supported. |
| `path` | string | yes | filesystem path or `:memory:` for tests | SQLite database path. |

The database stores observations, decisions, approvals, freezes, bypasses, and Cosign verification cache rows.

## Duration Values

Durations use compact units:

| Example | Meaning |
| --- | --- |
| `30m` | 30 minutes |
| `1h` | 1 hour |
| `24h` | 24 hours |
| `3d` | 3 days |
| `14d` | 14 days |

Use days for quarantine policy and shorter durations for emergency approvals or bypasses.
