# Oneseam OTC

P2P OTC trading infrastructure with zero-knowledge privacy.

## Product Scope

Oneseam OTC is focused on **RFQ/Trade lifecycle and non-custodial escrow orchestration**.
The platform preserves the core decentralized transport:

- UDP P2P discovery + seed bootstrap
- Shamir Secret Sharing (k-of-n)
- Byzantine quorum reconstruction
- Ed25519 shard signatures
- SQLite/PostgreSQL storage
- REST API + CLI

## Current Domain Model

- `RFQ`: maker proposes OTC terms (`base/quote`, size, expiry)
- `Trade`: bilateral agreement (`buyer/seller`, wallets, fee bps)
- `Escrow`: on-chain lifecycle tracked by externally submitted transaction hashes (`tx_hash`)

## Installation

```bash
pip install -r requirements.txt
```

## Main Files

- `oneseam_enterprise.py` - runtime (P2P, OTC domain, REST, CLI, storage)
- `oneseam_config.yaml` - node and OTC/EVM config
- `requirements.txt` - dependencies
- `tests/test_security.py` - auth and audit tests

## Configuration

Edit `oneseam_config.yaml`.

### Core

```yaml
node_port: 5001
broadcast_port: 5002
db_backend: "sqlite"   # sqlite | postgres
quorum_k: 2
quorum_n: 3
```

### OTC

```yaml
otc_enabled: true
wallet_binding_required: true
allowed_base_assets: ["BTC", "ETH", "SOL"]
allowed_quote_assets: ["USDT", "USDC", "USD"]
otc_default_fee_bps: 20
otc_max_trade_notional: 10000000
```

### EVM Escrow (Non-Custodial)

```yaml
evm_rpc_url: ""
evm_chain_id: 11155111
escrow_factory_address: ""
escrow_confirmations_required: 1
escrow_verify_on_submit: false
```

### Security

```yaml
tls_enabled: false
jwt_public_keys: []
allow_legacy_api_keys: true
p2p_tls_enabled: false
shard_signature_required: true
```

## Run

### CLI mode

```bash
python oneseam_enterprise.py
```

### REST mode

```bash
python oneseam_enterprise.py api
```

### Local test with two terminals (same machine)

```bash
# Terminal 1
python oneseam_enterprise.py --local-test

# Terminal 2
python oneseam_enterprise.py --local-test
```

Each process gets an ephemeral node id in local-test mode.

## REST API (Public Surface)

- `GET /health`
- `GET /ready`
- `GET /metrics`
- `POST /v1/otc/wallet/bind`
- `POST /v1/otc/rfqs`
- `GET /v1/otc/rfqs/{rfq_id}`
- `POST /v1/otc/rfqs/{rfq_id}/accept`
- `POST /v1/otc/trades`
- `GET /v1/otc/trades/{trade_id}`
- `POST /v1/otc/trades/{trade_id}/escrow/create`
- `POST /v1/otc/trades/{trade_id}/settle`
- `POST /v1/otc/trades/{trade_id}/refund`
- `GET /v1/otc/fees`

Auth: `Authorization: Bearer <JWT>`.

Recommended scopes:
- `otc:rfq:write`, `otc:rfq:read`
- `otc:trade:write`, `otc:trade:read`
- `otc:settle`

For non-custodial escrow operations, submit externally signed tx hashes:

```json
{
  "tx_hash": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "escrow_trade_ref": "optional_contract_trade_id"
}
```

## Notes

- Legacy financial-messaging and USD metering endpoints are removed from public API and CLI.
- Existing sharding/quorum/P2P infrastructure remains active.
- Non-custodial mode: the node does not sign transactions and does not custody private keys.
- Escrow/settle/refund endpoints require externally signed `tx_hash`.
