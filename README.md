# Ribat

Ribat is a Docker image update gate for mutable tags such as `latest`, `stable`, and rolling release tags. It observes the digest a tag resolves to, keeps new digests in quarantine for a configured age, and only allows pulls after the policy is satisfied.

The security idea is simple: a mutable tag is not trusted just because the registry says it changed. When `nginx:latest` starts pointing at a new digest, Ribat records that digest, denies the first pull, and waits for the configured quarantine window before allowing it.

Ribat currently includes:

* Docker authorization plugin mode for normal Docker hosts.
* Optional local registry proxy mode.
* SQLite quarantine state and JSONL audit logs.
* Approval, bypass, freeze, audit, export, and import commands.
* Optional subprocess-based Cosign verification.
* systemd installation artifacts and release binaries.

## Quick Start

Run a local decision with the example policy:

```bash
go run ./cmd/ribat version
go run ./cmd/ribat inspect docker.io/library/alpine:latest
go run ./cmd/ribat decide --config /path/to/ribat.yaml docker.io/library/alpine:latest
```

Install on a Docker host:

```bash
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now ribat.service
```

Then merge the authorization plugin setting from `packaging/docker/daemon-ribat.json` into `/etc/docker/daemon.json` and restart Docker.

## Example Denial

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

## Configuration

Example policies are available in `configs/`:

* `configs/ribat.example.yaml` for conservative defaults.
* `configs/ribat.strict.yaml` for a stricter default that quarantines all mutable tags for 14 days.
* `configs/ribat.cosign.example.yaml` for keyless Cosign verification examples.

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

## Modes

AuthZ mode checks Docker pull, container create, service create, and service update requests. It denies `docker build --pull` conservatively because Docker authorization requests do not currently give Ribat enough trusted Dockerfile base-image context to prove every pulled base image is safe.

Proxy mode exposes a local Registry HTTP API gate. Pull through it by placing the upstream registry in the proxied repository path, for example `127.0.0.1:5000/docker.io/library/alpine:latest` or `127.0.0.1:5000/ghcr.io/example/app:main`.

## Operations

```bash
ribat approve --config /etc/ribat/config.yaml docker.io/library/alpine:latest@sha256:abc123 --ttl 24h --reason "reviewed upstream release"
ribat bypass --config /etc/ribat/config.yaml docker.io/library/alpine:latest --ttl 1h --reason "production incident"
ribat freeze --config /etc/ribat/config.yaml docker.io/library/alpine:latest --reason "upstream compromise suspected"
ribat audit --config /etc/ribat/config.yaml --image docker.io/library/alpine:latest --since 7d
ribat export-state --config /etc/ribat/config.yaml
```

## Testing

Run the default test suite:

```bash
go test ./...
```

The default suite includes deterministic local Registry API integration coverage. Live Docker Hub validation is opt-in:

```bash
RIBAT_INTEGRATION_TESTS=1 go test ./tests/integration
```

## Documentation

* `docs/threat-model.md`
* `docs/install.md`
* `docs/policy.md`
* `docs/operations.md`
* `docs/troubleshooting.md`
