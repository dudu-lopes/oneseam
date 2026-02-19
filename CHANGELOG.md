<!-- Copyright (c) 2026 ONESEAM Contributors. SPDX-License-Identifier: AGPL-3.0-or-later -->

# Changelog

All notable changes to this project are documented in this file.

The format is inspired by Keep a Changelog and this project follows semantic versioning.

## [3.1.0] - 2026-02-19
### Added
- Simplified trader-first CLI as default mode.
- Blind matching integration for private overlap detection.
- Repository governance files (`DISCLAIMER.md`, `CODE_OF_CONDUCT.md`, `docs/*`).
- Linux helper scripts (`scripts/run_node.sh`, `scripts/setup.sh`).
- Packaging bootstrap files (`.env.example`, `setup.py`).

### Changed
- Repository structure standardized for production presentation.
- Security policy moved to `docs/SECURITY.md`.

### Removed
- Legacy OTC/EVM artifact files from active repository surface.

## [3.0.0] - 2026-02-19
### Added
- Dark-pool oriented v2 API and non-custodial swap coordination flow.
- JWT/RBAC/rate-limit hardening and immutable audit-chain foundations.
