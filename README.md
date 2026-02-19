# ONESEAM Dark Pool

ONESEAM is a non-custodial P2P coordination network for:
- private order discovery
- private matching
- HTLC settlement coordination (BTC + Lightning first)

The platform does not custody funds and does not sign end-user transactions on the backend.

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
- `2. Check Matches`
- `3. Accept Match & Swap`
- `4. My Orders`
- `5. Help`
- `6. Exit`
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
- Security policy: `docs/SECURITY.md`
- Production checklist: `docs/PRODUCTION_FILES.md`

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
ONESEAM is open-source software released under the GNU AGPL-3.0 license.
See `LICENSE` for full terms.
