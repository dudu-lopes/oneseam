<!-- Copyright (c) 2026 Eduardo de Figueiredo. SPDX-License-Identifier: BUSL-1.1 -->

# ONESEAM Intent Dark Pool

ONESEAM is an **intent dark-pool**: a **Bitcoin-native** non-custodial P2P coordination network for:
- private order discovery
- private matching
- HTLC settlement coordination (BTC + Lightning first)

Orders are published as encrypted intents and sharded across the P2P network.
The platform does not custody funds and does not sign end-user transactions on the backend.

## Competitive Differentiators
- **Intent dark-pool model:** no public order book and no single node can reconstruct a full order.
- **Bitcoin-native settlement:** BTC + Lightning first, with HTLC coordination and wallet-to-wallet execution.
- **Non-custodial by design:** the platform never holds funds or signs transactions.
- **Privacy-first matching:** blind commitments and bucketed overlap detection reduce information leakage.
- **Auditability without disclosure:** immutable audit chain for actions without exposing private order data.

## Quick Start
```bash
pip install -r requirements.txt
python oneseam.py
```

Advanced CLI:
```bash
python oneseam.py --advanced
```

API mode:
```bash
python oneseam.py api
```

## Simplified Trader CLI (default)
- `1. Post Order`
- `2. My Orders` (active orders + match notifications + match confirmation)
- `3. Exit`
- `0. Node Status`

## API v2
- `POST /v2/intents/prepare-signature`
- `POST /v2/intents`
- `GET /v2/intents/{intent_id}`
- `POST /v2/intents/{intent_id}/cancel`
- `GET /v2/matches/{match_id}`
- `POST /v2/matches/{match_id}/session/open`
- `POST /v2/matches/{match_id}/swap/start`
- `POST /v2/swaps/{swap_id}/htlc/proof/prepare-signature`
- `POST /v2/swaps/{swap_id}/htlc/proof`
- `GET /v2/swaps/{swap_id}`
- `POST /v2/swaps/{swap_id}/fee/invoice`
- `POST /v2/swaps/{swap_id}/fee/confirm`

## Documentation
- Architecture: `docs/ARCHITECTURE.md`
- Installation: `docs/INSTALLATION.md`
- API reference: `docs/API.md`

## Core Repository Layout
- `oneseam.py`
- `oneseam_blind_matching.py`
- `oneseam_simple_cli.py`
- `oneseam_config.yaml`
- `shard_signing_pub.pem`

## Security and Production Notes
- Set `production_mode: true` in production.
- Set `legacy_otc_api_enabled: false`.
- Use TLS/mTLS and JWT-only auth (`allow_legacy_api_keys: false`).
- Never commit private keys, tokens, or production certificates.

## License
ONESEAM is source-available software released under the Business Source License 1.1 (BSL 1.1).
See `LICENSE` for full terms.
