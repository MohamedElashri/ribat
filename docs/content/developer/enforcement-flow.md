+++
title = "Enforcement Flow"
description = "How Ribat decides whether a pull is allowed."
weight = 20
template = "page"
+++

The core invariant is:

```text
A Docker pull of a mutable tag must not be allowed unless the currently resolved digest satisfies the configured age and verification policy.
```

## Mutable Tag Flow

1. Parse and normalize the image reference.
2. Match the effective policy.
3. Resolve the mutable tag to the current remote digest.
4. Check active local overrides.
5. If the tag and digest tuple is unknown, create an observation and deny unless policy explicitly allows first-seen pulls or a digest-specific approval exists.
6. If the digest is known but too young, deny.
7. If the digest is old enough, or approved or bypassed, run required verification.
8. If verification passes, mark the observation allowed and return allow.
9. Record a SQLite decision and JSONL audit event.

## Override Precedence

Freeze has the highest precedence and denies before approval or bypass.

Approval is digest-specific. It can allow a reviewed digest before the age window expires.

Bypass is tag-level and TTL-bound. It can skip quarantine age, but it does not bypass freezes or required Cosign verification.

## Digest-Pinned Flow

Digest-pinned references do not need remote tag resolution. They are allowed or denied by the digest-pinned policy, active freezes, and required verification.

## Build Pulls

`docker build --pull` is denied conservatively in AuthZ mode because the Docker authorization request does not provide enough trusted Dockerfile base-image context for Ribat to prove every pulled base image is safe.
