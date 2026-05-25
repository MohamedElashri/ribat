+++
title = "Operations"
description = "Approve, bypass, freeze, audit, export, and import Ribat state."
weight = 50
template = "page"
+++

These commands are used after Ribat is installed.

For exact command syntax, every option, and exit behavior, see the [CLI reference](@/reference/cli.md).

## Inspect And Decide

Resolve a tag without updating quarantine state:

```bash
ribat inspect docker.io/library/alpine:latest
```

Make a full policy decision and write state and audit events:

```bash
ribat decide --config /etc/ribat/config.yaml docker.io/library/alpine:latest
```

## Approval

Approvals are digest-specific. Use them when a quarantined digest has been reviewed and should be allowed before the age window expires.

Syntax:

```text
ribat approve [--config PATH] IMAGE:TAG@DIGEST --ttl DURATION --reason TEXT [--by ACTOR]
```

Options:

| Option | Argument | Required | Description |
| --- | --- | --- | --- |
| `--config` | `PATH` | no | Policy file containing state and audit paths. |
| `--ttl` | `DURATION` | no | Approval lifetime. Omit for no expiry. |
| `--reason` | `TEXT` | yes | Reason stored in state and audit events. |
| `--by` | `ACTOR` | no | Actor recorded for the operation. Defaults to `$USER` or `cli`. |

```bash
ribat approve --config /etc/ribat/config.yaml \
  docker.io/library/alpine:latest@sha256:abc123 \
  --ttl 24h \
  --reason "reviewed upstream release"
```

An approval does not allow a different digest for the same tag. If the tag moves, the new digest must age normally or receive its own approval.

## Bypass

Bypasses are tag-level and TTL-bound. They are intended for short incidents where age quarantine needs to be skipped temporarily.

Syntax:

```text
ribat bypass [--config PATH] IMAGE:TAG --ttl DURATION --reason TEXT [--by ACTOR]
```

Options:

| Option | Argument | Required | Description |
| --- | --- | --- | --- |
| `--config` | `PATH` | no | Policy file containing state and audit paths. |
| `--ttl` | `DURATION` | yes | Bypass lifetime. |
| `--reason` | `TEXT` | yes | Reason stored in state and audit events. |
| `--by` | `ACTOR` | no | Actor recorded for the operation. Defaults to `$USER` or `cli`. |

```bash
ribat bypass --config /etc/ribat/config.yaml \
  docker.io/library/alpine:latest \
  --ttl 1h \
  --reason "production incident"
```

Bypasses do not override freezes and do not bypass required Cosign verification.

## Freeze

Freezes deny a tag, or a tag plus digest, until removed from state or expired by TTL. Omit `--ttl` for an indefinite freeze.

Syntax:

```text
ribat freeze [--config PATH] IMAGE:TAG[@DIGEST] [--ttl DURATION] --reason TEXT [--by ACTOR]
```

Options:

| Option | Argument | Required | Description |
| --- | --- | --- | --- |
| `--config` | `PATH` | no | Policy file containing state and audit paths. |
| `--ttl` | `DURATION` | no | Freeze lifetime. Omit for no expiry. |
| `--reason` | `TEXT` | yes | Reason stored in state and audit events. |
| `--by` | `ACTOR` | no | Actor recorded for the operation. Defaults to `$USER` or `cli`. |

```bash
ribat freeze --config /etc/ribat/config.yaml \
  docker.io/library/alpine:latest \
  --reason "upstream compromise suspected"
```

Freeze precedence is strongest: freeze beats approval and bypass.

## Status

Show local observations and active overrides:

```bash
ribat status --config /etc/ribat/config.yaml docker.io/library/alpine:latest
```

`status` reads local SQLite state. It does not resolve the remote registry tag.

## Audit

Filter JSONL audit events by image and age:

```bash
ribat audit --config /etc/ribat/config.yaml \
  --image docker.io/library/alpine:latest \
  --since 7d
```

Use the audit log to answer what was allowed or denied, why, and which Docker request triggered the decision.

## Export And Import

Export state:

```bash
ribat export-state --config /etc/ribat/config.yaml > ribat-state.json
```

Import state:

```bash
ribat import-state --config /etc/ribat/config.yaml --input ribat-state.json
```

Import merges rows into the target database. It does not wipe unrelated existing state.
