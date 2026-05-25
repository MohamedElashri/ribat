+++
title = "Testing"
description = "Default tests, integration tests, and live Docker validation."
weight = 40
template = "page"
+++

Run the default suite:

```bash
go test ./...
```

If the normal Go cache is not writable:

```bash
GOCACHE="$PWD/.gocache" go test ./...
```

## Local Integration Tests

The default suite includes deterministic local Registry API integration coverage in `tests/integration`. It uses in-process fixtures and does not require network access.

## Live Docker Hub Integration

Live Docker Hub validation is opt-in:

```bash
RIBAT_INTEGRATION_TESTS=1 go test ./tests/integration
```

It validates live digest resolution and first-seen quarantine recording.

## Live Docker Engine Validation

Run on a Docker host:

```bash
make test-docker-live
```

The script builds `bin/ribat`, starts a temporary proxy, validates first-seen denial through Docker Engine, approves the resolved digest, validates an allowed pull, and checks audit output.

Add a non-DockerHub proxy check:

```bash
RIBAT_VALIDATE_GHCR=1 make test-docker-live
```

Add live Cosign verification with a known signed image:

```bash
RIBAT_VALIDATE_COSIGN=1 \
RIBAT_COSIGN_IMAGE=ghcr.io/example/signed-app:v1.2.3 \
RIBAT_COSIGN_IDENTITY_REGEX='^https://github.com/example/signed-app/.github/workflows/release.yml@refs/tags/v.*$' \
make test-docker-live
```

Add an installed AuthZ smoke check:

```bash
RIBAT_VALIDATE_INSTALLED_AUTHZ=1 make test-docker-live
```

This check assumes Docker is already configured to use Ribat. It does not edit Docker daemon configuration.

## Installed Host AuthZ Validation

The invasive host lifecycle test installs Ribat service files, edits Docker daemon configuration, restarts Docker, verifies real AuthZ denial and approval through Docker Engine, checks service restart/log access, and restores Docker configuration.

Run only on a disposable Docker host or during a planned maintenance window:

```bash
RIBAT_HOST_LIVE_TESTS=1 \
RIBAT_HOST_LIVE_MUTATE_DOCKER=1 \
make test-host-authz-live
```

Set `RIBAT_HOST_INSTALL_MODE=source` to validate the `sudo make install` path. The default validates the release-installer host install path.

## Documentation Site

Build the docs site:

```bash
make docs-build
```

Serve it locally:

```bash
make docs-serve
```
