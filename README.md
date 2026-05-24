# Ribat

Ribat is a Docker image update gate for mutable tags such as `latest`, `stable`, and rolling release tags. It is designed to observe the digest a tag resolves to, keep new digests in quarantine for a configured age, and only allow pulls after the policy is satisfied.

The current implementation includes a Go command-line application, local quarantine state, registry digest resolution, Docker authorization plugin mode with common updater workflow hardening, registry proxy mode, operations commands, a subprocess-based Cosign verification backend, and systemd installation artifacts.

## Usage
```bash
go run ./cmd/ribat version
go run ./cmd/ribat inspect docker.io/library/alpine:latest
go run ./cmd/ribat decide --config /path/to/ribat.yaml docker.io/library/alpine:latest
go run ./cmd/ribat approve --config /path/to/ribat.yaml docker.io/library/alpine:latest@sha256:abc123 --ttl 24h --reason "reviewed upstream release"
go run ./cmd/ribat bypass --config /path/to/ribat.yaml docker.io/library/alpine:latest --ttl 1h --reason "production incident"
go run ./cmd/ribat freeze --config /path/to/ribat.yaml docker.io/library/alpine:latest --reason "upstream compromise suspected"
go run ./cmd/ribat audit --config /path/to/ribat.yaml --image docker.io/library/alpine:latest --since 7d
go run ./cmd/ribat authz --config /path/to/ribat.yaml --socket /run/docker/plugins/ribat.sock
go run ./cmd/ribat proxy --config /path/to/ribat.yaml --listen 127.0.0.1:5000
go test ./...
```

Proxy mode exposes a local Registry HTTP API gate. Pull through it by placing the upstream registry in the proxied repository path, for example `127.0.0.1:5000/docker.io/library/alpine:latest` or `127.0.0.1:5000/ghcr.io/example/app:main`.

AuthZ mode checks Docker pull, container create, service create, and service update requests. It denies `docker build --pull` conservatively because the current authorization request does not provide enough trusted Dockerfile base-image context for Ribat to prove that all bases are safe.

## Configuration

An example policy is available at `configs/ribat.example.yaml`.

Cosign verification can be required per policy rule. Ribat verifies the resolved digest reference, caches successful verification results locally, and denies fail-closed if verification fails.

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

## Installation

Systemd packaging and Docker daemon configuration notes are available in `docs/install.md`.
