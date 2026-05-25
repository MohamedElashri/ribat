+++
title = "Proxy Mode"
description = "Use Ribat as a local Registry HTTP API gate."
weight = 60
template = "page"
+++

Proxy mode is an optional stronger deployment shape. Docker pulls through a local Registry HTTP API endpoint, and Ribat gates manifest and blob access.

Start a proxy:

```bash
ribat proxy --config /etc/ribat/config.yaml --listen 127.0.0.1:5000
```

Pull through the proxy by placing the upstream registry in the proxied repository path:

```bash
docker pull 127.0.0.1:5000/docker.io/library/alpine:latest
docker pull 127.0.0.1:5000/ghcr.io/example/app:main
```

Docker Hub remains the default for repository paths without an explicit upstream registry, matching normal image-reference normalization.

## Enforcement

Manifest requests go through the same quarantine engine used by AuthZ mode. That means proxy mode shares policy, SQLite state, approvals, bypasses, freezes, audit logging, and Cosign verification.

Blob requests are denied until an allowed manifest response exposes the blob digest. This prevents a client from fetching layers for a manifest that Ribat denied.

## Current Limits

Proxy mode supports the basic manifest and blob paths needed for pull enforcement. It does not implement uploads, catalog, tag listing, persistent blob caching, registry credential forwarding, range requests, or platform-specific child-manifest selection yet.
