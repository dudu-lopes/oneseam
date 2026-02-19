<!-- Copyright (c) 2026 ONESEAM Contributors. SPDX-License-Identifier: AGPL-3.0-or-later -->

# API (v2)

Base path: `/v2`

## Intents
- `POST /v2/intents/prepare-signature`
- `POST /v2/intents`
- `GET /v2/intents/{intent_id}`
- `POST /v2/intents/{intent_id}/cancel`

## Matches and Session
- `GET /v2/matches/{match_id}`
- `POST /v2/matches/{match_id}/session/open`
- `POST /v2/matches/{match_id}/swap/start`

## Swap and HTLC proofs
- `POST /v2/swaps/{swap_id}/htlc/proof/prepare-signature`
- `POST /v2/swaps/{swap_id}/htlc/proof`
- `GET /v2/swaps/{swap_id}`

## Fee
- `POST /v2/swaps/{swap_id}/fee/invoice`
- `POST /v2/swaps/{swap_id}/fee/confirm`

## Authentication
- JWT Bearer tokens are supported.
- RBAC scopes and role checks are enforced per endpoint.

## Response pattern
- Success: JSON object with domain payload.
- Failure: JSON object with standardized error fields (`error_code`, `request_id`).

## Notes
- Wallet attestation and proof verification behavior are controlled by `oneseam_config.yaml`.
- Legacy OTC v1 endpoints are deprecated and should remain disabled in production.
