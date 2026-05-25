+++
title = "Storage"
description = "SQLite tables, observation keys, state export, and audit records."
weight = 30
template = "page"
+++

SQLite is the first supported state backend. The critical observation key is:

```text
registry + repository + tag + digest
```

Do not collapse this to `registry + repository + tag`; one mutable tag can point to many digests over time.

## Tables

`tag_observations` stores first and last seen timestamps for each tag and digest tuple.

`pull_decisions` stores allow and deny decisions, including Docker request metadata when available.

`approvals` stores digest-specific administrative approvals.

`freezes` stores tag-level or digest-specific denies.

`bypasses` stores tag-level TTL-bound quarantine-age overrides.

`cosign_verifications` caches verification results by digest plus the effective Cosign policy key. The policy key matters because a digest verified under a broad identity policy must not satisfy a later stricter identity policy.

## Export And Import

`ribat export-state` writes observations, decisions, approvals, freezes, bypasses, and Cosign cache rows as JSON.

`ribat import-state` merges exported rows into the target database with `INSERT OR REPLACE`. It does not wipe unrelated local state.

## Audit

Audit events are JSONL. Every allow, deny, administrative operation, and verification-relevant outcome should be auditable.
