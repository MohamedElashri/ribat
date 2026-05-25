+++
title = "Docs Site"
description = "How Ribat documentation is organized, built with Nida, and published."
weight = 60
template = "page"
+++

Ribat's documentation site follows the same shape as the Nida documentation site.

```text
docs/
  config.toml
  content/
    user/
    reference/
    developer/
  templates/
  static/
  public/       generated, ignored by git
```

## Sections

User docs are for operators installing and running Ribat.

Reference docs are for exact CLI and configuration details.

Developer docs are for contributors and maintainers working on internals, tests, releases, and documentation.

## Local Build

If a sibling Nida checkout exists at `../nida`, the Makefile uses it:

```bash
make docs-build
make docs-serve
```

If not, the Makefile falls back to:

```bash
go run github.com/MohamedElashri/nida/cmd/nida@main build --site ./docs
```

## GitHub Actions

`.github/workflows/pages.yml` checks out Ribat, checks out `MohamedElashri/nida` into `.docs-tools/nida`, builds this site with Nida, uploads `docs/public`, and deploys it to GitHub Pages.

The workflow is intentionally path-filtered. It runs on pushes to `main` only when `docs/**` or `.github/workflows/pages.yml` changes, plus manual `workflow_dispatch` runs. Changes to `cmd/**`, `internal/**`, `configs/**`, `scripts/**`, `README.md`, or `Makefile` should not spend Pages minutes unless they also change docs.

This keeps Ribat's repository free of generated HTML while still using the same static-site generator and templates as Nida's own docs.
