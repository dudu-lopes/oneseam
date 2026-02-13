# Oneseam OTC

P2P OTC trading infrastructure with zero-knowledge privacy and strict non-custodial smart contract settlement flow.

## Scope

Oneseam keeps the decentralized transport core and applies it to OTC lifecycle:

- P2P discovery (`UDP` + seed bootstrap)
- Shamir Secret Sharing and Byzantine quorum
- Ed25519 shard signatures
- SQLite/PostgreSQL persistence
- REST API + CLI
- Non-custodial EVM escrow orchestration (Sepolia default)

Server never stores private keys and never signs or broadcasts client transactions.

## Main Files

- `oneseam_enterprise.py`: runtime (P2P, OTC domain, REST, CLI, storage)
- `oneseam_config.yaml`: node, OTC and EVM config
- `contracts/OTCEscrow.sol`: escrow contract source
- `contracts/abi/OTCEscrow.json`: contract ABI consumed by backend
- `requirements.txt`: Python dependencies
- `tests/test_security.py`: security and audit tests

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Edit `oneseam_config.yaml`.

### Core

```yaml
node_port: 5001
broadcast_port: 5002
db_backend: "sqlite"   # sqlite | postgres
db_path: "oneseam.db"
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
escrow_contract_address: ""
escrow_contract_abi_path: "contracts/abi/OTCEscrow.json"
escrow_confirmations_required: 1
escrow_verify_on_submit: true
escrow_prepare_ttl_seconds: 600
escrow_event_strict_validation: true
escrow_reconcile_interval_seconds: 20
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

### Local test on one machine

```bash
# Terminal 1
python oneseam_enterprise.py --local-test

# Terminal 2
python oneseam_enterprise.py --local-test
```

Each process gets an ephemeral node ID in local-test mode.

## REST API (Public Surface)

- `POST /v1/otc/wallet/bind`
- `POST /v1/otc/rfqs`
- `GET /v1/otc/rfqs/{rfq_id}`
- `POST /v1/otc/rfqs/{rfq_id}/accept`
- `POST /v1/otc/trades`
- `GET /v1/otc/trades/{trade_id}`
- `POST /v1/otc/trades/{trade_id}/escrow/prepare`
- `POST /v1/otc/trades/{trade_id}/settle/prepare`
- `POST /v1/otc/trades/{trade_id}/refund/prepare`
- `POST /v1/otc/trades/{trade_id}/escrow/create`
- `POST /v1/otc/trades/{trade_id}/settle`
- `POST /v1/otc/trades/{trade_id}/refund`
- `GET /v1/otc/fees`

Auth: `Authorization: Bearer <JWT>`.

## Non-Custodial Flow

1. Create/accept RFQ and create trade.
2. Call a `*/prepare` endpoint to get unsigned transaction payload:

```json
{
  "prepared_transaction": {
    "intent_id": "intent_...",
    "to": "0x...",
    "data": "0x...",
    "value": "0",
    "chain_id": 11155111,
    "gas_hint": { "limit": 350000 },
    "action": "escrow_create",
    "trade_id": "trade_...",
    "expires_at": 1730000000000
  }
}
```

3. Sign and broadcast transaction using external wallet/infrastructure.
4. Submit `tx_hash` to action endpoint (`escrow/create`, `settle`, `refund`).
5. Backend verifies receipt, confirmations, contract address, expected event and trade linkage before state transition.

Submit payload:

```json
{
  "tx_hash": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "intent_id": "intent_...",
  "escrow_trade_ref": "optional"
}
```

## Verification Error Codes

- `tx_not_found`
- `tx_not_confirmed`
- `tx_reverted`
- `wrong_contract`
- `wrong_event`
- `trade_mismatch`
- `tx_hash_reused`

## Notes

- Public surface is OTC-only.
- Legacy financial messaging endpoints are not part of OTC API surface.
- Billing is fee-per-trade (`bps`) instead of USD metering per instruction.
