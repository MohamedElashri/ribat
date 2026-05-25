+++
title = "Release Workflow"
description = "How maintainers validate and publish Ribat releases."
weight = 50
template = "page"
+++

Ribat release artifacts are built by `.github/workflows/release.yml` on version tags and manual dispatch.

## Version Tags

Use tags such as:

```text
v0.1.0
v0.1.1
v0.2.0-rc.1
```

## Local Preflight

Run:

```bash
go test ./...
make docs-build
make -n release-snapshot VERSION=v0.0.0-test RELEASE_TARGETS=linux/amd64 SOURCE_DATE_EPOCH=1700000000
```

On a Docker host, also run:

```bash
make test-docker-live
```

On a host with the AuthZ plugin installed:

```bash
RIBAT_VALIDATE_INSTALLED_AUTHZ=1 make test-docker-live
```

## Release Artifacts

`make release-snapshot` and the release workflow build versioned tarballs for Linux, Darwin, and Windows targets. Builds use:

```text
-trimpath
-buildvcs=false
-buildid=
```

The workflow writes `checksums.txt` and publishes the files to a GitHub Release.

The public installer at `https://melashri.net/ribat/install.sh` downloads these archives and verifies them against `checksums.txt`. Keep archive naming compatible with:

```text
ribat_${TAG}_${os}_${arch}.tar.gz
```

where `TAG` includes the leading `v`, such as `v0.1.0`.

## GitHub Pages

Documentation is published separately by `.github/workflows/pages.yml` when docs, templates, static assets, source, or workflow files change on `main`.
