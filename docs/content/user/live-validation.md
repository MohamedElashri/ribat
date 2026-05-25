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
