# ONESEAM DarkPool

A non-custodial P2P infrastructure for private order discovery, private matching, and HTLC settlement coordination (BTC + Lightning first).

The platform **does not custody funds** and **does not sign user transactions** on the backend.

## Core Project Files
- `oneseam.py` (main entrypoint)
- `oneseam_blind_matching.py` (price-slot commitment engine for blind matching)
- `oneseam_config.yaml` (active configuration)
- `requirements.txt`
- `README.md`

## Recommended Production Structure
- `config/production.example.yaml` (configuration template)
- `docs/PRODUCTION_FILES.md` (file checklist)
- `scripts/run_api.ps1`
- `scripts/run_cli.ps1`
- `scripts/check_ready.ps1`
- `certs/` (real certificates in deployment)
- `secrets/` (local deployment secrets)

## Install
```bash
pip install -r requirements.txt
```

## Run
CLI:
```bash
python oneseam.py
```

API:
```bash
python oneseam.py api
```

Admin/Technical UI (hidden by default):
```bash
python oneseam.py --admin-ui
```

## Wallet UX (CLI)
Optional: enable auto-signing in CLI without manually copying the message:

```bash
export ONESEAM_WALLET_PRIVATE_KEY=0x...
```

If the action wallet matches the environment key, the signature is applied automatically.

## Trader Flow (Condensed CLI)
Operator main menu:
- `1. Node Status`
- `2. Commit Trade Intent (for matching)`
- `3. Accept Trade (from match)`
- `4. Exit`

Technical functions are kept outside the primary flow (admin mode).

## API v2 (DarkPool)
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

## Blind Match (privacy-preserving)
- The system uses `price slot` commitments for phase-A filtering without exposing clear-text price ranges.
- Final overlap is still mathematically validated in the backend (phase B) before opening session/swap.
- Public commitments (hashes) can be sharded and distributed to the `blind_orderbook` destination.

Main configuration keys in `oneseam_config.yaml`:
- `blind_matching_enabled`
- `blind_price_slot_size`
- `blind_max_price_slots`
- `blind_global_salt`
- `blind_commitment_destination`

## Real Production (OTC Desk)
In `oneseam_config.yaml`:
- `production_mode: true`
- `legacy_otc_api_enabled: false`
- REST TLS enabled + JWT only (`allow_legacy_api_keys: false`)
- P2P TLS + mTLS enabled
- `wallet_attestation_required: true`
- `proof_wallet_attestation_required: true`
- `proof_server_side_verification_required: true`
- Configure verifier:
  - `proof_verifier_url` (external BTC/LN verifier), or
  - `btc_rpc_url` for BTC-side verification

Validate readiness before opening:
```bash
powershell -ExecutionPolicy Bypass -File scripts/check_ready.ps1 -BaseUrl http://127.0.0.1:8000
```

## Required Files for a Real Desk
See the full checklist in `docs/PRODUCTION_FILES.md`.

Short summary:
- required in repo: code + config + scripts + docs
- required in environment: real certs, JWT public keys, verifier/BTC RPC secrets
- never version production private keys and tokens
