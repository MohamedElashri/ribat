# Ribat

Ribat is a Docker image update gate for mutable tags such as `latest`, `stable`, and rolling release tags.

When a tag resolves to a digest Ribat has not seen before, that digest enters quarantine. Pulls are allowed only after the configured age and optional verification policy are satisfied.

## Quick Start

Install the latest release on Linux or macOS:

```bash
curl -fsSL https://melashri.net/ribat/install.sh | sh
```

Or run from a source checkout:

```bash
go run ./cmd/ribat version
go run ./cmd/ribat inspect docker.io/library/alpine:latest
go run ./cmd/ribat decide --config configs/ribat.example.yaml docker.io/library/alpine:latest
```

Install on a Docker host with:

```bash
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now ribat.service
```

Then merge the authorization plugin setting from `packaging/docker/daemon-ribat.json` into `/etc/docker/daemon.json` and restart Docker.

Run tests with:

```bash
go test ./...
```

## Documentation

Full documentation is published at [docs](https://melashri.net/ribat/)

The source for the docs site lives under `docs/` and is built with [Nida](https://github.com/MohamedElashri/nida):

```bash
make docs-build
make docs-serve
```
