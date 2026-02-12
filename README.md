# Oneseam Enterprise

Enterprise-grade resilient cryptographic messaging infrastructure for financial settlement instructions.

## Overview

Oneseam operates exclusively on **transaction instructions (financial messages)**, not on assets or monetary values. Settlement occurs locally within participating institutions, in compliance with regulatory and data sovereignty requirements.

### Key Features

- **Zero-knowledge transport**: Each instruction is fragmented into cryptographically independent shards via Shamir Secret Sharing. No intermediate node has access to the complete instruction during transport.

- **Byzantine fault-tolerant**: Configurable k-of-n quorum (e.g., 2-of-3, 4-of-7).

- **On-grid / Off-grid**: Operates over traditional internet (on-grid) and mesh networks (off-grid) for infrastructure degradation scenarios.

- **Access Release Token (ART)**: Cryptographic mechanism for billing proof and message access authorization.

- **Data sovereignty**: Region-aware routing for GDPR, LGPD, and jurisdictional compliance.

- **Transport security**: TLS for REST, optional mTLS for REST and P2P.

- **Shard integrity**: Optional Ed25519 shard signing with verification.

- **Audit trail**: Immutable hash-chained audit log stored in the DB.

## The SEAM Protocol

**SEAM (Settlement Evidence & Agreement Message)** is the logical layer that transforms Oneseam from encrypted messaging into economic infrastructure.

Instead of transferring money, SEAM creates a **verifiable distributed financial obligation**. When an instruction is created, it receives:

- Unique cryptographic ID
- Immutable timestamp
- Cryptographic integrity hash
- Multi-node witness via shard distribution

Multiple independent nodes witness the instruction's existence. Only a quorum can reconstruct it. **No single company, server, or bank needs to be trusted in isolation** - the network itself proves the commitment was issued.

### Economic Function

SEAM operates as a **programmable letter of credit**. The receiving party gains an **auditable economic asset** before payment occurs. This proof enables production, delivery, or financing based on the commitment, without requiring a central intermediary to guarantee the financial promise.

**Example use case:**
```
Supplier receives SEAM instruction: "Pay $500k upon delivery"
-> Supplier uses SEAM as collateral to secure working capital loan
-> Supplier manufactures goods
-> Delivery triggers settlement (local, within institutions)
-> SEAM obligation fulfilled
```

The instruction itself becomes tradeable, financeable, and programmable - without moving funds through Oneseam.

## Architecture
```
Origin Institution                    Destination Institution
       |                                       |
       |  Fragment (SSS)                       |  Collect shards dynamically
       |  Distribute shards P2P                |  Reconstruct at quorum
       |  --------------------------------->  |  Validate & execute locally
       |  (on-grid + off-grid)                 |
```

- **No custody of funds** - Messages only
- **No payment processing** - Instruction delivery infrastructure
- **No financial intermediary** - Peer-to-peer messaging fabric

## Installation
```bash
pip install -r requirements.txt
```

## Main Repository Files
- `oneseam_enterprise.py` - Core runtime (P2P, REST, storage, security, CLI)
- `oneseam_config.yaml` - Node configuration
- `requirements.txt` - Python dependencies
- `README.md` - Product and operational documentation
- `tests/test_security.py` - Security-focused tests
- `verify_env.py` - Environment validation helper
- `clean_storage.py` - Local cleanup helper

## Configuration

Edit `oneseam_config.yaml`:
```yaml
quorum_k: 2          # Minimum shards for reconstruction
quorum_n: 3          # Total shards
transport_mode: HYBRID   # ON_GRID | OFF_GRID | HYBRID
region: "EU"         # Data sovereignty region
```

### Storage (DB)
```yaml
db_backend: "sqlite"   # sqlite | postgres
db_path: "oneseam.db"
db_dsn: ""             # postgres DSN if backend=postgres
```

### Bootstrap / NAT
```yaml
seed_nodes: ["1.2.3.4:5001"]
upnp_enabled: false
```

### Local Test (Single Machine)
```yaml
local_test_port_scan_size: 20
local_test_discovery_interval: 2.0
local_test_registry_dir: ".oneseam_local"
local_test_registry_ttl_seconds: 90
```

### Security (REST API)
```yaml
tls_enabled: true
tls_cert_path: "/path/to/cert.pem"
tls_key_path: "/path/to/key.pem"
mtls_ca_path: "/path/to/ca.pem"   # optional

jwt_issuer: "oneseam"
jwt_audience: "oneseam-api"
jwt_public_keys:
  - "/path/to/jwt_public_key.pem"
```

### Security (P2P)
```yaml
p2p_tls_enabled: true
p2p_tls_cert_path: "/path/to/cert.pem"
p2p_tls_key_path: "/path/to/key.pem"
p2p_mtls_ca_path: "/path/to/ca.pem"
p2p_mtls_required: true
```

### Shard Signing
```yaml
shard_signature_required: true
shard_signing_private_key: "shard_signing_priv.pem"
shard_signing_public_key: "shard_signing_pub.pem"
trusted_node_pubkeys: {}  # {NODE_ID: "-----BEGIN PUBLIC KEY-----..."}
```

## Usage

### CLI Mode
```bash
python oneseam_enterprise.py
```

### REST API Mode
```bash
python oneseam_enterprise.py api
```

### Local P2P Test (Same Computer)
```bash
# Terminal 1
python oneseam_enterprise.py --local-test

# Terminal 2 (same command, different ephemeral node ID)
python oneseam_enterprise.py --local-test
```

Notes:
- In `--local-test`, each process gets a different ephemeral `node_id`.
- If the default P2P port is busy, the node auto-selects the next free local port.
- Nodes discover each other on `127.0.0.1` automatically in local test mode via a local registry.

**Endpoints:**
- `GET /health` - Health check
- `GET /ready` - Readiness check
- `GET /metrics` - Metrics snapshot (if enabled)
- `POST /v1/seam/payment_obligation` - Create SEAM payment obligation
- `POST /v1/instructions` - Submit instruction
- `GET /v1/instructions/<id>` - Retrieve / reconstruct instruction
- `POST /v1/instructions/<id>/release` - Generate Access Release Token (ART)
- `GET /v1/billing` - Billing report

**Authentication:** `Authorization: Bearer <JWT>` (default). `X-API-Key` is deprecated.

## Business Model

Enterprise-first: software licensing, support, and per-instruction volume billing ($0.02 per reconstructed instruction) via cryptographic access release mechanism.

## Dependencies

- `cryptography` - AES-256-GCM payload encryption
- `pycryptodome` - Shamir Secret Sharing (zero-knowledge sharding)
- `aiohttp` - REST API
- `pyyaml` - Configuration
- `PyJWT` - JWT authentication
- `pydantic` - Schema validation
- `psycopg2-binary` - PostgreSQL backend (optional)
- `miniupnpc` - NAT traversal (optional)

## License

Proprietary - Oneseam Enterprise
