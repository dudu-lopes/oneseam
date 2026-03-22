<!-- Copyright (c) 2026 Eduardo de Figueiredo. SPDX-License-Identifier: BUSL-1.1 -->

# ONESEAM Intent Dark Pool — trade your BTC without sowing your hands

ONESEAM is an **intent dark-pool**: a **Bitcoin-native** non-custodial P2P coordination network for:
- private order discovery
- private matching
- HTLC settlement coordination (BTC + Lightning first)

Orders are published as encrypted intents and sharded across the P2P network.
The platform does not custody funds and does not sign end-user transactions on the backend.

## Competitive Differentiators
- **Intent dark-pool model:** no public order book and no single node can reconstruct a full order.
- **Bitcoin-native settlement:** BTC + Lightning first, with HTLC coordination and wallet-to-wallet execution.
- **Batch matching with shared preimage:** fragmented fills across multiple counterparties settle atomically.
- **Non-custodial by design:** the platform never holds funds or signs transactions.
- **Privacy-first matching:** blind commitments and bucketed overlap detection reduce information leakage.
- **DHT intent discovery:** slot-indexed commitments enable private discovery without exposing full orders.
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

## DHT Intent Discovery (Blind Slot Index)
ONESEAM uses a dedicated DHT layer for **intent discovery only**. Each intent is converted into a blind commitment
and indexed by **slot tokens** (price bucket + amount bucket + side). Nodes query the DHT by slot keys and receive
only the **commitment id + holder node**, then fetch shards/manifests to verify overlap privately.
This preserves dark-pool privacy while improving discovery across the network.

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
- `batch_allow_partial: true` enables partial fills when full liquidity is not available.

## Desktop App (Tauri)
The desktop app bundles the Python backend as a native binary, so end users do **not** need Python or Node.

### Windows Installer (ready)
- Installer location: `releases/ONESEAM_1.0.0_x64-setup.exe`
- This is a click-to-install `.exe` for end users.

### Build on Windows (for maintainers)
```bash
cd oneseam-desktop
npm install
npm run build
```

### Build on macOS (for maintainers)
```bash
cd oneseam-desktop
npm install
npm run build
```
The `.dmg` output will be under:
`oneseam-desktop/src-tauri/target/release/bundle/dmg/`

## License
ONESEAM is source-available software released under the Business Source License 1.1 (BSL 1.1).
See `LICENSE` for full terms.
