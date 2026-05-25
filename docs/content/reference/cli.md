+++
title = "CLI Reference"
description = "Command syntax, arguments, options, examples, and exit behavior for the ribat binary."
weight = 10
template = "page"
+++

This page documents the `ribat` command line interface as implemented by the binary.

## Conventions

Command syntax uses:

* `UPPERCASE` for positional arguments.
* `[ ... ]` for optional arguments.
* `--flag VALUE` for options that take a value.

Most options also accept the `--flag=VALUE` form.

The default config path is context-sensitive:

* `configs/ribat.example.yaml` when that file exists in the current working directory.
* `/etc/ribat/config.yaml` otherwise.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded. For `decide`, the image was allowed. |
| `1` | Runtime or policy failure. For `decide`, the image was denied. |
| `2` | Invalid command-line usage. |

## Command Summary

| Command | Purpose |
| --- | --- |
| `ribat version` | Print version metadata. |
| `ribat inspect IMAGE` | Resolve a remote tag without writing quarantine state. |
| `ribat decide [--config PATH] IMAGE` | Run the full policy decision and write state/audit records. |
| `ribat authz [--config PATH] --socket PATH` | Start Docker authorization plugin mode. |
| `ribat proxy [--config PATH] --listen ADDRESS` | Start local registry proxy mode. |
| `ribat approve [--config PATH] IMAGE:TAG@DIGEST --ttl DURATION --reason TEXT [--by ACTOR]` | Approve one digest for one tag. |
| `ribat bypass [--config PATH] IMAGE:TAG --ttl DURATION --reason TEXT [--by ACTOR]` | Temporarily bypass quarantine age for one tag. |
| `ribat freeze [--config PATH] IMAGE:TAG[@DIGEST] --reason TEXT [--ttl DURATION] [--by ACTOR]` | Deny a tag, or a tag plus digest. |
| `ribat audit [--config PATH] [--image IMAGE] [--since DURATION]` | Read and filter JSONL audit events. |
| `ribat export-state [--config PATH]` | Export SQLite state as JSON. |
| `ribat import-state [--config PATH] [--input PATH]` | Import exported state from a file or stdin. |
| `ribat policy check [--config PATH] IMAGE` | Show the effective policy for an image. |
| `ribat status [--config PATH] IMAGE` | Show local observations and overrides for an image. |
| `ribat help` | Print command help. |

## Image Arguments

Ribat accepts Docker-style image references:

```text
nginx
nginx:latest
library/nginx:1.27
docker.io/library/nginx:1.27
ghcr.io/example/app:main
ghcr.io/example/app@sha256:abc123
docker.io/library/alpine:latest@sha256:abc123
```

Docker Hub shorthand is normalized before policy matching. For example, `nginx:latest` becomes `docker.io/library/nginx:latest`.

`approve` requires `IMAGE:TAG@DIGEST` so the approved tag and digest are both explicit.

`bypass` requires `IMAGE:TAG` and rejects digest-pinned references.

`freeze` accepts `IMAGE:TAG` for a tag-level freeze and `IMAGE:TAG@DIGEST` for a digest-specific freeze.

## `version`

Print the Ribat version string.

```text
ribat version
```

Example:

```bash
ribat version
```

Typical output:

```text
ribat v0.1.0
```

## `inspect`

Resolve a remote tag and print digest information without updating local quarantine state.

```text
ribat inspect IMAGE
```

Arguments:

| Argument | Required | Description |
| --- | --- | --- |
| `IMAGE` | yes | Image reference to inspect. |

Examples:

```bash
ribat inspect docker.io/library/alpine:latest
ribat inspect ghcr.io/example/app@sha256:abc123
```

Notes:

* Mutable tags are resolved through the registry.
* Digest-pinned references are parsed locally and do not need registry resolution.
* `inspect` does not write observations, decisions, or audit events.

## `decide`

Run the full policy decision for an image. This is the local equivalent of the decision Ribat makes in AuthZ and proxy modes.

```text
ribat decide [--config PATH] IMAGE
```

Arguments:

| Argument | Required | Description |
| --- | --- | --- |
| `IMAGE` | yes | Image reference to evaluate. |

Options:

| Option | Argument | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--config` | `PATH` | no | default config path | Policy file to load. |

Example:

```bash
ribat decide --config /etc/ribat/config.yaml docker.io/library/alpine:latest
```

Typical denial output:

```text
Image: docker.io/library/alpine:latest
Resolved digest: sha256:abc123...
Matched rule: *:latest
Digest first seen: 2026-05-25T10:00:00Z
Required minimum age: 14d
Next allowed pull: 2026-06-08T10:00:00Z
Decision: DENY
Reason: new digest observed for mutable tag; digest entered quarantine
```

Side effects:

* opens the SQLite state database;
* may create or update a tag observation;
* records a pull decision;
* writes an audit event when `audit.path` is configured.

## `authz`

Start Docker authorization plugin mode.

```text
ribat authz [--config PATH] --socket PATH
```

Options:

| Option | Argument | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--config` | `PATH` | no | default config path | Policy file to load. |
| `--socket` | `PATH` | yes | none | Unix socket path exposed to Docker. |

Example:

```bash
ribat authz --config /etc/ribat/config.yaml --socket /run/docker/plugins/ribat.sock
```

Docker daemon configuration:

```json
{
  "authorization-plugins": ["ribat"]
}
```

AuthZ mode gates Docker pull, container create, service create, and service update requests. `docker build --pull` is denied conservatively.

For full installation steps, including the systemd service, plugin socket verification, Docker daemon configuration, and rollback, see [Installation](@/user/installation.md#enable-authz-mode).

## `proxy`

Start local registry proxy mode.

```text
ribat proxy [--config PATH] --listen ADDRESS
```

Options:

| Option | Argument | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--config` | `PATH` | no | default config path | Policy file to load. |
| `--listen` | `ADDRESS` | yes | none | TCP address for the local Registry HTTP API gate. |

Example:

```bash
ribat proxy --config /etc/ribat/config.yaml --listen 127.0.0.1:5000
```

Pull through the proxy by encoding the upstream registry in the repository path:

```bash
docker pull 127.0.0.1:5000/docker.io/library/alpine:latest
docker pull 127.0.0.1:5000/ghcr.io/example/app:main
```

Proxy mode uses the same quarantine engine, policy, state, audit, approvals, bypasses, freezes, and Cosign verification as AuthZ mode.

## `approve`

Create a digest-specific approval.

```text
ribat approve [--config PATH] IMAGE:TAG@DIGEST --ttl DURATION --reason TEXT [--by ACTOR]
```

Arguments:

| Argument | Required | Description |
| --- | --- | --- |
| `IMAGE:TAG@DIGEST` | yes | Tag and digest tuple to approve. |

Options:

| Option | Argument | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--config` | `PATH` | no | default config path | Policy file containing state and audit paths. |
| `--ttl` | `DURATION` | no | no expiry | Approval lifetime. Must be greater than zero when provided. |
| `--reason` | `TEXT` | yes | none | Human-readable audit reason. |
| `--by` | `ACTOR` | no | `$USER`, or `cli` | Actor recorded in state and audit events. |

Example:

```bash
ribat approve --config /etc/ribat/config.yaml \
  docker.io/library/alpine:latest@sha256:abc123 \
  --ttl 24h \
  --reason "reviewed upstream release" \
  --by alice
```

Security notes:

* Approval applies only to that exact tag and digest.
* If the tag moves to a new digest, the new digest must age normally or receive its own approval.
* Approval does not override an active freeze.
* Approval does not bypass required Cosign verification.

## `bypass`

Create a temporary tag-level quarantine-age bypass.

```text
ribat bypass [--config PATH] IMAGE:TAG --ttl DURATION --reason TEXT [--by ACTOR]
```

Arguments:

| Argument | Required | Description |
| --- | --- | --- |
| `IMAGE:TAG` | yes | Mutable tag to bypass. Digest-pinned references are rejected. |

Options:

| Option | Argument | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--config` | `PATH` | no | default config path | Policy file containing state and audit paths. |
| `--ttl` | `DURATION` | yes | none | Bypass lifetime. Must be greater than zero. |
| `--reason` | `TEXT` | yes | none | Human-readable audit reason. |
| `--by` | `ACTOR` | no | `$USER`, or `cli` | Actor recorded in state and audit events. |

Example:

```bash
ribat bypass --config /etc/ribat/config.yaml \
  docker.io/library/alpine:latest \
  --ttl 1h \
  --reason "production incident" \
  --by sre-oncall
```

Security notes:

* Bypass skips quarantine age only.
* Bypass does not override freezes.
* Bypass does not bypass required Cosign verification.

## `freeze`

Create a freeze that denies a tag, or one digest behind a tag.

```text
ribat freeze [--config PATH] IMAGE:TAG[@DIGEST] [--ttl DURATION] --reason TEXT [--by ACTOR]
```

Arguments:

| Argument | Required | Description |
| --- | --- | --- |
| `IMAGE:TAG[@DIGEST]` | yes | Tag to freeze, optionally narrowed to one digest. |

Options:

| Option | Argument | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--config` | `PATH` | no | default config path | Policy file containing state and audit paths. |
| `--ttl` | `DURATION` | no | no expiry | Freeze lifetime. Must be greater than zero when provided. |
| `--reason` | `TEXT` | yes | none | Human-readable audit reason. |
| `--by` | `ACTOR` | no | `$USER`, or `cli` | Actor recorded in state and audit events. |

Examples:

```bash
ribat freeze --config /etc/ribat/config.yaml \
  docker.io/library/alpine:latest \
  --reason "upstream compromise suspected"
```

```bash
ribat freeze --config /etc/ribat/config.yaml \
  docker.io/library/alpine:latest@sha256:abc123 \
  --ttl 12h \
  --reason "bad digest under investigation" \
  --by security
```

Security notes:

* Freeze has the strongest local override precedence.
* Freeze blocks approvals and bypasses.
* A tag-level freeze blocks every digest currently or later observed for that tag.

## `audit`

Read the configured JSONL audit log and optionally filter events.

```text
ribat audit [--config PATH] [--image IMAGE] [--since DURATION]
```

Options:

| Option | Argument | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--config` | `PATH` | no | default config path | Policy file containing `audit.path`. |
| `--image` | `IMAGE` | no | all images | Filter events to one normalized image reference. |
| `--since` | `DURATION` | no | all events | Show events newer than now minus the duration. |

Examples:

```bash
ribat audit --config /etc/ribat/config.yaml
```

```bash
ribat audit --config /etc/ribat/config.yaml \
  --image docker.io/library/alpine:latest \
  --since 7d
```

Output is JSONL, one event per line.

## `export-state`

Export SQLite state as JSON.

```text
ribat export-state [--config PATH]
```

Options:

| Option | Argument | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--config` | `PATH` | no | default config path | Policy file containing `state.path`. |

Example:

```bash
ribat export-state --config /etc/ribat/config.yaml > ribat-state.json
```

Side effects:

* Writes an `export-state` audit event when `audit.path` is configured.
* Does not change observations, approvals, bypasses, freezes, or decisions.

## `import-state`

Import state from a JSON export.

```text
ribat import-state [--config PATH] [--input PATH]
```

Options:

| Option | Argument | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--config` | `PATH` | no | default config path | Policy file containing `state.path`. |
| `--input` | `PATH` | no | stdin | JSON file produced by `export-state`. |

Examples:

```bash
ribat import-state --config /etc/ribat/config.yaml --input ribat-state.json
```

```bash
cat ribat-state.json | ribat import-state --config /etc/ribat/config.yaml
```

Import merges rows into the target database with replace semantics for matching IDs. It does not wipe unrelated existing state.

## `policy check`

Show the effective policy for an image without contacting the registry or writing state.

```text
ribat policy check [--config PATH] IMAGE
```

Arguments:

| Argument | Required | Description |
| --- | --- | --- |
| `IMAGE` | yes | Image reference to match against policy. |

Options:

| Option | Argument | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--config` | `PATH` | no | default config path | Policy file to load. |

Example:

```bash
ribat policy check --config /etc/ribat/config.yaml docker.io/library/alpine:latest
```

Use this command when validating rule order and policy overlays.

## `status`

Show local observations and active local overrides for an image.

```text
ribat status [--config PATH] IMAGE
```

Arguments:

| Argument | Required | Description |
| --- | --- | --- |
| `IMAGE` | yes | Image reference to look up in local SQLite state. |

Options:

| Option | Argument | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--config` | `PATH` | no | default config path | Policy file containing `state.path`. |

Examples:

```bash
ribat status --config /etc/ribat/config.yaml docker.io/library/alpine:latest
ribat status --config /etc/ribat/config.yaml docker.io/library/alpine:latest@sha256:abc123
```

Notes:

* `status` does not resolve the remote registry tag.
* Without a digest, it lists local observations for the tag.
* With a digest, it narrows the lookup to that exact observation.

## `help`

Print command usage.

```text
ribat help
ribat --help
ribat -h
```
