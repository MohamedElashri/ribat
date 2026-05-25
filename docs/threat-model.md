# Ribat Threat Model

Ribat protects Docker hosts from adopting newly published mutable-tag digests too quickly. It is designed for systems that pull images by tags such as `latest`, `stable`, `main`, or rolling version tags.

## Security Invariant

A Docker pull of a mutable tag must not be allowed unless the currently resolved digest satisfies the configured age and verification policy.

This means Ribat evaluates the digest the tag points to now, not just the tag string. A tag can point to many digests over time, and each digest gets its own first-seen timestamp.

## In Scope

Ribat is intended to reduce risk from:

* Compromised upstream maintainer accounts.
* Compromised registry accounts.
* Poisoned images pushed to otherwise trusted repositories.
* Fast-moving mutable tags such as `latest`, `stable`, `main`, and `v1`.
* Auto-updaters that pull immediately after a tag changes.
* Watchtower, Portainer, Docker Compose, cron-based pulls, and Swarm updates that use Docker Engine.

## Out Of Scope

Ribat does not fully protect against:

* A root user disabling Ribat.
* A malicious or compromised Docker daemon.
* Pulls performed by another runtime outside Docker Engine, such as direct `containerd`, `nerdctl`, or `ctr` use.
* Images that were already allowed or running before Ribat was installed.
* Malicious digests that have aged past the quarantine window.
* Trusted maintainers intentionally signing malicious images.
* Vulnerability scanning. Ribat is an update gate, not a scanner.

## Default-Deny Behavior

Ribat is conservative by default:

* First-seen mutable-tag digests are recorded and denied.
* Registry resolution failures are denied.
* Required signature verification failures are denied.
* Freezes override approvals and bypasses.
* Bypasses do not bypass required Cosign verification.
* `docker build --pull` is denied until Ribat can prove base-image safety.

## Auditability

Ribat records allow, deny, approval, bypass, freeze, import, export, and verification-relevant events. The initial audit format is JSONL so operators can inspect it with normal command-line tools and ship it to existing log systems.

## Remaining Risk

Quarantine windows reduce the chance of immediate compromise, but they are not a guarantee that an aged digest is benign. For high-trust repositories, combine Ribat with digest pinning, Cosign verification, vulnerability scanning, and normal release review.
