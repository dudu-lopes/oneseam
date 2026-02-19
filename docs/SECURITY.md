<!-- Copyright (c) 2026 Eduardo de Figueiredo. SPDX-License-Identifier: AGPL-3.0-or-later -->

# Security Policy

## Supported Scope
Security reports are accepted for:
- `oneseam.py`
- `oneseam_blind_matching.py`
- `oneseam_simple_cli.py`
- API `/v2/*` dark-pool flow
- shard integrity, wallet attestation, and audit-chain logic

## Reporting a Vulnerability
Do not open public issues for active vulnerabilities.

Share privately with maintainers including:
- affected version/commit
- reproduction steps
- impact assessment
- suggested mitigation (optional)

## Production Security Baseline
- Enable TLS/mTLS in production.
- Disable legacy API keys (`allow_legacy_api_keys: false`).
- Keep `legacy_otc_api_enabled: false`.
- Require wallet attestation and proof validation where applicable.
- Never commit private keys, JWT secrets, or production certificates.
