+++
title = "Ribat Docs"
description = "User and developer documentation for Ribat, a delayed-trust gate for Docker image updates."
sort_by = "weight"
+++

Ribat protects Docker hosts from adopting newly published mutable-tag digests too quickly.

The central rule is simple: when a mutable tag such as `latest`, `stable`, or `main` points to a new digest, that digest is recorded and quarantined until it satisfies the configured age and verification policy.

Use the User docs to install and operate Ribat. Use the Developer docs to understand the enforcement path, storage model, validation harness, and documentation publishing workflow.
