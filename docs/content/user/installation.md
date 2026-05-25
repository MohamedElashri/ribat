+++
title = "Installation"
description = "Install Ribat from prebuilt releases or source, then enable Docker authorization plugin mode."
weight = 20
template = "page"
+++

Ribat has two installation layers:

1. install the `ribat` binary;
2. configure the host service and Docker authorization plugin when you want Ribat to guard Docker Engine pulls.

Use the release installer for normal binary installation. Use the source build when developing Ribat or when you want to install the systemd packaging directly from a checkout.

## Privileges

Binary installation does not need root when you install into a user directory such as `$HOME/.local/bin`.

Docker enforcement does need root privileges. AuthZ mode uses system paths such as `/usr/local/bin`, `/etc/ribat`, `/var/lib/ribat`, `/var/log/ribat`, and `/run/docker/plugins/ribat.sock`, and enabling it requires editing Docker daemon configuration and restarting Docker.

Use this split in practice:

| Goal | Root required? | Recommended path |
| --- | --- | --- |
| Try `ribat inspect`, `ribat policy check`, or local `decide` commands | no | `curl -fsSL https://melashri.net/ribat/install.sh \| sh` |
| Install the binary for all users | yes, unless `/usr/local/bin` is writable | `curl -fsSL https://melashri.net/ribat/install.sh \| RIBAT_INSTALL_SYSTEM=1 sh` |
| Enable Docker AuthZ enforcement | yes | install system files, enable `ribat.service`, update `/etc/docker/daemon.json`, restart Docker |

Do not run the whole installer as root unless you intentionally want a root-owned install. Prefer `RIBAT_INSTALL_SYSTEM=1`; the script uses `sudo` only for the final copy when needed.

## Supported Platforms

Release archives are published for:

| OS | Architectures |
| --- | --- |
| Linux | `amd64`, `arm64` |
| macOS | `amd64`, `arm64` |
| Windows | `amd64` archive is published, but the shell installer does not support Windows |

Release archives are named:

```text
ribat_v0.1.0_linux_amd64.tar.gz
ribat_v0.1.0_linux_arm64.tar.gz
ribat_v0.1.0_darwin_amd64.tar.gz
ribat_v0.1.0_darwin_arm64.tar.gz
ribat_v0.1.0_windows_amd64.tar.gz
```

Each release also publishes `checksums.txt`.

## Install With Curl

On Linux or macOS, install the latest release:

```bash
curl -fsSL https://melashri.net/ribat/install.sh | sh
```

The installer:

* detects your OS and CPU architecture;
* resolves the latest GitHub release unless `RIBAT_VERSION` is set;
* downloads the matching release archive;
* verifies the archive against `checksums.txt`;
* installs `ribat` into `$HOME/.local/bin` by default.

Confirm the install:

```bash
ribat version
```

### Installer Options

| Environment variable | Default | Description |
| --- | --- | --- |
| `RIBAT_VERSION` | `latest` | Release tag to install. Accepts `v0.1.0` or `0.1.0`. |
| `RIBAT_INSTALL_DIR` | `$XDG_BIN_HOME`, then `$HOME/.local/bin` | Destination directory for user installs. |
| `RIBAT_INSTALL_SYSTEM` | `0` | Set to `1` or `true` to install into `/usr/local/bin`, using `sudo` when needed. |

Examples:

```bash
curl -fsSL https://melashri.net/ribat/install.sh | RIBAT_VERSION=v0.1.0 sh
```

```bash
curl -fsSL https://melashri.net/ribat/install.sh | RIBAT_INSTALL_DIR="$HOME/bin" sh
```

```bash
curl -fsSL https://melashri.net/ribat/install.sh | RIBAT_INSTALL_SYSTEM=1 sh
```

Use the system-wide install when the binary will be launched by the systemd service at `/usr/local/bin/ribat`.

## Manual Archive Install

Download the release archive and checksum file from GitHub Releases.

Example for Linux x86_64:

```bash
TAG=v0.1.0
ARCHIVE="ribat_${TAG}_linux_amd64.tar.gz"
curl -fL -o "$ARCHIVE" "https://github.com/MohamedElashri/ribat/releases/download/${TAG}/${ARCHIVE}"
curl -fsSL -o checksums.txt "https://github.com/MohamedElashri/ribat/releases/download/${TAG}/checksums.txt"
grep "  ${ARCHIVE}$" checksums.txt | sha256sum -c -
tar -xzf "$ARCHIVE"
sudo install -m 0755 ribat /usr/local/bin/ribat
ribat version
```

Use `darwin_arm64`, `darwin_amd64`, `linux_arm64`, or `windows_amd64` for other release archives.

## Build From Source

Use this path when developing Ribat or installing systemd packaging from a checkout.

Requirements:

* Go, using the version declared in `go.mod`;
* `make`;
* systemd and Docker for host integration.

Build and test:

```bash
go test ./...
make build
./bin/ribat version
```

Install from source:

```bash
sudo make install
```

This installs:

```text
/usr/local/bin/ribat
/etc/ribat/config.yaml
/var/lib/ribat/
/var/log/ribat/
/etc/systemd/system/ribat.service
```

## Host Paths

Ribat uses these host paths by convention:

```text
/etc/ribat/config.yaml
/var/lib/ribat/state.db
/var/log/ribat/audit.jsonl
/run/docker/plugins/ribat.sock
```

The SQLite state file lives under `/var/lib/ribat`, so restarting Docker or Ribat does not clear quarantine observations, approvals, bypasses, or freezes.

## Enable AuthZ Mode

AuthZ mode is the host enforcement path and should be configured as root.

### 1. Install The Service Files

If you are installing from a source checkout, run:

```bash
sudo make install
```

This installs the binary, default config, state/log directories, and `ribat.service`.

If you installed only the prebuilt binary with `install.sh`, you still need the service unit and config files from this repository before enabling AuthZ mode. Until release archives include packaging files, use a checkout for host service installation:

```bash
git clone https://github.com/MohamedElashri/ribat.git
cd ribat
sudo make install
```

`make install` keeps an existing `/etc/ribat/config.yaml` in place.

### 2. Review Policy

Open `/etc/ribat/config.yaml` before enabling Docker enforcement:

```bash
sudo editor /etc/ribat/config.yaml
```

The default policy is conservative: first-seen mutable-tag digests are denied and recorded.

### 3. Start Ribat

Start the Ribat authorization plugin service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ribat.service
```

Check that Docker can discover the authorization plugin endpoint:

```bash
sudo curl --unix-socket /run/docker/plugins/ribat.sock -X POST http://localhost/Plugin.Activate
```

The response should include `authz`.

### 4. Configure Docker

Merge this setting into `/etc/docker/daemon.json`:

```json
{
  "authorization-plugins": ["ribat"]
}
```

An example file is available at `packaging/docker/daemon-ribat.json`. If your Docker daemon already has a `daemon.json`, merge the `authorization-plugins` key instead of replacing the whole file.

Install the optional Docker systemd drop-in so Docker starts after Ribat:

```bash
sudo make install-docker-dropin
sudo systemctl daemon-reload
sudo systemctl restart docker
```

After Docker restarts, first-seen mutable-tag pulls should be denied and recorded according to `/etc/ribat/config.yaml`.

### 5. Verify Docker Sees The Plugin

Check Docker daemon information:

```bash
docker info --format '{{json .SecurityOptions}}'
```

The output should include an authorization plugin entry for Ribat.

You can also confirm that the socket still responds:

```bash
sudo curl --unix-socket /run/docker/plugins/ribat.sock -X POST http://localhost/Plugin.Activate
```

### 6. Verify Enforcement

Run a local decision:

```bash
sudo ribat decide --config /etc/ribat/config.yaml docker.io/library/alpine:latest
```

The first decision for a new mutable-tag digest should usually be `DENY` with a reason that says the digest entered quarantine.

On a Docker host, run the live validation harness:

```bash
make test-docker-live
```

Or test a normal Docker pull:

```bash
docker pull docker.io/library/alpine:latest
```

For a first-seen mutable-tag digest, Docker should show a Ribat denial message. Use `ribat status` and `ribat audit` to inspect what happened:

```bash
sudo ribat status --config /etc/ribat/config.yaml docker.io/library/alpine:latest
sudo ribat audit --config /etc/ribat/config.yaml --image docker.io/library/alpine:latest --since 24h
```

## Disable

To disable Ribat without deleting state:

```bash
sudo systemctl stop docker
```

Remove `ribat` from the `authorization-plugins` list in `/etc/docker/daemon.json`.

If you installed the Docker drop-in, remove it:

```bash
sudo rm -f /etc/systemd/system/docker.service.d/10-ribat.conf
sudo systemctl daemon-reload
```

Then restart Docker and stop Ribat:

```bash
sudo systemctl start docker
sudo systemctl disable --now ribat.service
```

## Rollback

Use this rollback when Docker cannot start or pulls are blocked unexpectedly:

```bash
sudo systemctl stop docker
sudo rm -f /etc/systemd/system/docker.service.d/10-ribat.conf
```

Edit `/etc/docker/daemon.json` and remove `ribat` from `authorization-plugins`.

Then reload systemd daemon and start Docker:

```bash
sudo systemctl daemon-reload
sudo systemctl start docker
```

The rollback leaves `/var/lib/ribat/state.db` and `/var/log/ribat/audit.jsonl` in place for inspection. Remove the service and binary only after Docker is healthy:

```bash
sudo make uninstall
```
