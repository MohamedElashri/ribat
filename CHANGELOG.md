# Changelog

All notable changes to Ribat are documented in this file.

This project follows semantic versioning. Versions before `v1.0.0` may still refine operational defaults and deployment packaging, but patch releases should remain focused on fixes and documentation corrections.

## [0.1.1] - 2026-05-25

### Fixed

- Fixed proxy-mode pulls through Docker Engine when Docker requests digest-addressed manifests using the `sha256-<hex>` URL path form. Ribat now normalizes that path form back to `sha256:<hex>` before policy evaluation and upstream manifest fetches.
- Hardened the live Docker validation script so first-seen proxy denial is confirmed through the audit log even when Docker only surfaces a generic `403 Forbidden` error.

## [0.1.0] - 2026-05-25

### Added

- First public release of Ribat.
- Mutable-tag quarantine engine with first-seen digest recording, minimum-age enforcement, digest-specific approvals, tag-level bypasses, freezes, SQLite persistence, JSONL audit logging, export, and import.
- Docker authorization plugin mode for enforcing Ribat decisions from Docker Engine.
- Local registry proxy mode for pull enforcement through a Registry HTTP API gate.
- Registry digest resolution for Docker Hub and explicit registries, including Docker Hub shorthand normalization.
- Digest-pinned image policy handling.
- Optional Cosign verification policy support.
- CLI commands for `inspect`, `decide`, `status`, `approve`, `bypass`, `freeze`, `audit`, `export-state`, `import-state`, `policy check`, `authz`, and `proxy`.
- Systemd packaging, Docker daemon configuration examples, release archives for Linux, macOS, and Windows targets, checksum generation, and a public shell installer.
- Documentation site built with Nida, including user, reference, and developer documentation.
- CI, release, GitHub Pages, integration, and opt-in live Docker validation workflows.
