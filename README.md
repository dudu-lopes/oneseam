<!-- Copyright (c) 2026 Eduardo de Figueiredo. SPDX-License-Identifier: BUSL-1.1 -->

# ONESEAM — Trade BTC without showing your hands

ONESEAM is a **Bitcoin‑native**, **non‑custodial** dark‑pool network that helps buyers and sellers match privately and coordinate HTLC settlement without revealing their full orders or custodying funds.

**What it does (simple):**
- Lets you post a private order (intent)
- Finds compatible matches without exposing your price range
- Coordinates a wallet‑to‑wallet BTC + Lightning swap

## Use It (Desktop App)
Download and run the installer:
- `releases/ONESEAM_1.0.0_x64-setup.exe`

Checksum (SHA256):
- `CB5F235F4B02FECF73C30482122DCCD2F3DBDB1C06108D71B1513640F4CFEB77`

## Run From Source (optional)
```bash
pip install -r requirements.txt
python oneseam.py
```

## Basic CLI (default)
- `1. Post Order`
- `2. My Orders`
- `3. Exit`
- `0. Node Status`

## License
ONESEAM is source‑available software released under the Business Source License 1.1 (BSL 1.1).
See `LICENSE` for full terms.
