+++
title = "Live Validation"
description = "Run opt-in Docker Engine validation against Ribat."
weight = 70
template = "page"
+++

The default `go test ./...` suite stays network-free and does not require Docker. Live validation is opt-in and intended for a real Docker host.

## Docker Engine Proxy Validation

Run:

```bash
make test-docker-live
```

The target builds `bin/ribat`, creates temporary policy, state, and audit files under `/tmp`, starts `ribat proxy` on `127.0.0.1:5055`, and uses Docker Engine to pull through the proxy.

The validation checks:

* a first-seen mutable tag pull is denied;
* the resolved digest is recorded in SQLite state;
* a digest-specific approval allows the same proxy pull;
* the audit log contains both deny and allow decisions.

The default image is `docker.io/library/alpine:latest`. Override it if needed:

```bash
RIBAT_LIVE_TEST_IMAGE=docker.io/library/busybox:latest make test-docker-live
```

Override the local proxy address when the default port is busy:

```bash
RIBAT_PROXY_ADDR=127.0.0.1:5056 make test-docker-live
```

## Non-DockerHub Proxy Validation

Add a GHCR pull-through check:

```bash
RIBAT_VALIDATE_GHCR=1 make test-docker-live
```

The default GHCR image is `ghcr.io/stefanprodan/podinfo:latest`. Override it with:

```bash
RIBAT_VALIDATE_GHCR=1 \
RIBAT_GHCR_TEST_IMAGE=ghcr.io/example/app:latest \
make test-docker-live
```

## Cosign Live Validation

Cosign validation is opt-in because it requires the `cosign` command and a known signed image with a strict expected identity.

```bash
RIBAT_VALIDATE_COSIGN=1 \
RIBAT_COSIGN_IMAGE=ghcr.io/example/signed-app:v1.2.3 \
RIBAT_COSIGN_ISSUER=https://token.actions.githubusercontent.com \
RIBAT_COSIGN_IDENTITY_REGEX='^https://github.com/example/signed-app/.github/workflows/release.yml@refs/tags/v.*$' \
make test-docker-live
```

The script resolves the image digest, verifies that Ribat allows the digest-pinned image when Cosign verification matches, then verifies that an impossible identity denies the same digest.

## Installed AuthZ Smoke Check

The script does not edit Docker daemon configuration. To validate an already installed Docker authorization plugin, enable the optional check:

```bash
RIBAT_VALIDATE_INSTALLED_AUTHZ=1 make test-docker-live
```

This checks `/run/docker/plugins/ribat.sock` with `Plugin.Activate` and expects a Docker pull to be denied by Ribat. Use a fresh mutable tag for deterministic results:

```bash
RIBAT_VALIDATE_INSTALLED_AUTHZ=1 \
RIBAT_AUTHZ_TEST_IMAGE=docker.io/library/alpine:latest \
make test-docker-live
```

If the installed policy already allows the selected digest, choose another mutable tag or run only the proxy validation.

## Installed AuthZ Host Lifecycle

The full host lifecycle test is intentionally separate and guarded because it installs host files, edits Docker daemon configuration, restarts Docker, and then rolls the host back.

Run only on a disposable Docker host or during a planned maintenance window:

```bash
RIBAT_HOST_LIVE_TESTS=1 \
RIBAT_HOST_LIVE_MUTATE_DOCKER=1 \
make test-host-authz-live
```

The host lifecycle script checks:

* release-installer or source installation of `ribat.service`;
* `systemctl enable --now ribat.service`;
* `/run/docker/plugins/ribat.sock` activation;
* Docker `authorization-plugins` wiring;
* real `docker pull` denial through Docker AuthZ;
* digest approval followed by a real allowed `docker pull`;
* service restart and `journalctl` access;
* rollback of Docker daemon configuration and systemd drop-in.

Use `RIBAT_HOST_INSTALL_MODE=source` to test `sudo make install` instead of the release installer.
