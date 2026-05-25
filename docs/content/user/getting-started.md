+++
title = "Getting Started"
description = "Learn the Ribat model and run the first local commands."
weight = 10
template = "page"
+++

Ribat is a Docker image update gate for mutable tags. It is designed for images referenced as `latest`, `stable`, `main`, or rolling version tags where the tag can move to a new digest at any time.

## The Model

Ribat does not rate-limit pulls. It gates the digest behind the tag.

**Weak model**: do not pull app:latest more than once every 7 days.
**Ribat model**: do not pull app:latest if its current digest was first seen less than 7 days ago.


When `docker.io/library/alpine:latest` resolves to a digest Ribat has not seen before, Ribat records:

```text
registry + repository + tag + digest
```

Then it denies the pull unless policy explicitly allows first-seen pulls. Once the digest has aged for the configured minimum age, and any required verification passes, Ribat allows it.

## Install The Binary

Install the latest prebuilt release on Linux or macOS:

```bash
curl -fsSL https://melashri.net/ribat/install.sh | sh
```

For a system-wide install:

```bash
curl -fsSL https://melashri.net/ribat/install.sh | RIBAT_INSTALL_SYSTEM=1 sh
```

Use the default user-local install for CLI experiments. Use `RIBAT_INSTALL_SYSTEM=1` when the binary should be available to the systemd service for Docker AuthZ enforcement.

To install a specific version:

```bash
curl -fsSL https://melashri.net/ribat/install.sh | RIBAT_VERSION=v0.1.0 sh
```

After installation:

```bash
ribat version
```

## Try Local Commands

With a source checkout, or after installing the binary and pointing `--config` at a policy file:

```bash
ribat inspect docker.io/library/alpine:latest
ribat decide --config configs/ribat.example.yaml docker.io/library/alpine:latest
```

`inspect` resolves a tag and prints the remote digest without updating quarantine state. `decide` runs the policy engine and writes state and audit events.

## Install On A Docker Host

Docker host enforcement requires root because it installs systemd files, writes `/etc/ribat`, creates state and log directories, exposes `/run/docker/plugins/ribat.sock`, and requires Docker daemon configuration.

For normal hosts, install Ribat as a Docker authorization plugin:

```bash
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now ribat.service
```

Then merge `packaging/docker/daemon-ribat.json` into `/etc/docker/daemon.json` and restart Docker.

Read the [AuthZ installation steps](@/user/installation.md#enable-authz-mode) before enabling it on a production host.
