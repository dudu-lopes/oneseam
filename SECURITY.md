# Security Policy

## Supported Scope
Security reports are accepted for:
- `oneseam.py`
- `oneseam_blind_matching.py`
- `oneseam_simple_cli.py`
- API `/v2/*` dark-pool flow
- signing, shard integrity, and audit-chain logic

## Reporting a Vulnerability
Do not open public issues for active vulnerabilities.

Report privately with:
- affected version/commit
- clear reproduction steps
- impact assessment
- optional mitigation

Until a dedicated security contact is published, use a private channel with repository maintainers.

## Hard Requirements for Deployments
- mTLS/TLS enabled in production.
- JWT verification keys configured (`allow_legacy_api_keys: false`).
- wallet attestation enabled for proof submission.
- no private keys committed to repository.

