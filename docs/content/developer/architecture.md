+++
title = "Architecture"
description = "The main packages and how they fit together."
weight = 10
template = "page"
+++

Ribat is one Go binary with multiple modes that share the same policy and quarantine engine.

## Package Map

```text
cmd/ribat/              CLI entrypoint and command wiring
internal/image/         Docker reference parsing and normalization
internal/policy/        YAML policy loading, validation, rule matching, durations
internal/registry/      Registry manifest resolution and proxy fetch helpers
internal/quarantine/    Core allow/deny engine
internal/store/         SQLite schema and persistence APIs
internal/audit/         JSONL audit event writer
internal/authz/         Docker authorization plugin server and request parsing
internal/proxy/         Local Registry HTTP API gate
internal/verify/        Cosign subprocess verifier and policy fingerprinting
internal/version/       Build metadata
tests/integration/      Local registry and opt-in Docker Hub integration coverage
```

## One Engine

AuthZ mode and proxy mode both call `internal/quarantine.Engine`. Do not fork policy logic into a transport-specific implementation. If a behavior affects allow or deny decisions, it belongs in the shared engine or in helpers called by the shared engine.

## Default Deployment

The default deployment is Docker authorization plugin mode:

```text
Docker Engine -> AuthZ request -> Ribat -> registry resolver -> quarantine engine -> allow or deny
```

Proxy mode is optional and stronger for deployments that can pull through a local Registry API gate:

```text
Docker Engine -> local Ribat proxy -> upstream registry
```
