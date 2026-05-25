+++
title = "Security Model"
description = "What Ribat protects, what it does not protect, and how default-deny behavior works."
weight = 30
template = "page"
+++

Ribat protects Docker hosts from adopting newly published mutable-tag digests too quickly. It is designed for systems that pull images by tags such as `latest`, `stable`, `main`, or rolling version tags.

## Security Invariant

A Docker pull of a mutable tag must not be allowed unless the currently resolved digest satisfies the configured age and verification policy.

This means Ribat evaluates the digest the tag points to now, not just the tag string. A tag can point to many digests over time, and each digest gets its own first-seen timestamp.

## In Scope

Ribat is intended to reduce risk from:

* compromised upstream maintainer accounts;
* compromised registry accounts;
* poisoned images pushed to otherwise trusted repositories;
* fast-moving mutable tags such as `latest`, `stable`, `main`, and `v1`;
* auto-updaters that pull immediately after a tag changes;
* Watchtower, Portainer, Docker Compose, cron-based pulls, and Swarm updates that use Docker Engine.

## Out Of Scope

Ribat does not fully protect against:

* a root user disabling Ribat;
* a malicious or compromised Docker daemon;
* pulls performed by another runtime outside Docker Engine, such as direct `containerd`, `nerdctl`, or `ctr` use;
* images that were already allowed or running before Ribat was installed;
* malicious digests that have aged past the quarantine window;
* trusted maintainers intentionally signing malicious images;
* vulnerability scanning. Ribat is an update gate, not a scanner.

## Default-Deny Behavior

Ribat is conservative by default:

* first-seen mutable-tag digests are recorded and denied;
* registry resolution failures are denied;
* required signature verification failures are denied;
* freezes override approvals and bypasses;
* bypasses do not bypass required Cosign verification;
* `docker build --pull` is denied until Ribat can prove base-image safety.

## Remaining Risk

Quarantine windows reduce the chance of immediate compromise, but they are not a guarantee that an aged digest is benign. For high-trust repositories, combine Ribat with digest pinning, Cosign verification, vulnerability scanning, and normal release review.
