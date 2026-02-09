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

## The SEAM Protocol

**SEAM (Settlement Evidence & Agreement Message)** is the logical layer that transforms Oneseam from encrypted messaging into economic infrastructure.

Instead of transferring money, SEAM creates a **verifiable distributed financial obligation**. When an instruction is created, it receives:

- Unique cryptographic ID
- Immutable timestamp
- Cryptographic integrity hash
- Multi-node witness via shard distribution

Multiple independent nodes witness the instruction's existence. Only a quorum can reconstruct it. **No single company, server, or bank needs to be trusted in isolation** — the network itself proves the commitment was issued.

### Economic Function

SEAM operates as a **programmable letter of credit**. The receiving party gains an **auditable economic asset** before payment occurs. This proof enables production, delivery, or financing based on the commitment, without requiring a central intermediary to guarantee the financial promise.

**Example use case:**
```
Supplier receives SEAM instruction: "Pay $500k upon delivery"
→ Supplier uses SEAM as collateral to secure working capital loan
→ Supplier manufactures goods
→ Delivery triggers settlement (local, within institutions)
→ SEAM obligation fulfilled
```

The instruction itself becomes tradeable, financeable, and programmable — without moving funds through Oneseam.

## Architecture
```
Origin Institution                    Destination Institution
       |                                       |
       |  Fragment (SSS)                       |  Collect shards dynamically
       |  Distribute shards P2P                |  Reconstruct at quorum
       |  --------------------------------->  |  Validate & execute locally
       |  (on-grid + off-grid)                 |
```

- **No custody of funds** – Messages only
- **No payment processing** – Instruction delivery infrastructure
- **No financial intermediary** – Peer-to-peer messaging fabric

## Installation
```bash
pip install -r requirements.txt
```

## Configuration

Edit `oneseam_config.yaml`:
```yaml
quorum_k: 2          # Minimum shards for reconstruction
quorum_n: 3          # Total shards
transport_mode: HYBRID   # ON_GRID | OFF_GRID | HYBRID
region: "EU"         # Data sovereignty region
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

**Endpoints:**
- `POST /v1/instructions` – Submit instruction
- `GET /v1/instructions/<id>` – Retrieve / reconstruct instruction
- `POST /v1/instructions/<id>/release` – Generate Access Release Token (ART)
- `GET /v1/billing` – Billing report

**Authentication:** `X-API-Key` header

## Business Model

Enterprise-first: software licensing, support, and per-instruction volume billing ($0.02 per reconstructed instruction) via cryptographic access release mechanism.

## Dependencies

- `cryptography` – AES-256-GCM payload encryption
- `pycryptodome` – Shamir Secret Sharing (zero-knowledge sharding)
- `flask` – REST API
- `pyyaml` – Configuration

## License

Proprietary – Oneseam Enterprise
