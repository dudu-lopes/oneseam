<!-- Copyright (c) 2026 ONESEAM Contributors. SPDX-License-Identifier: AGPL-3.0-or-later -->

# Installation

## 1) Prerequisites
- Python 3.12+
- Git
- OpenSSL certificates for production TLS/mTLS

## 2) Clone and install
```bash
git clone https://github.com/dudu-lopes/oneseam.git
cd oneseam
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows PowerShell:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 3) Configure node
- Copy and edit `oneseam_config.yaml`.
- For production, keep:
  - `production_mode: true`
  - `legacy_otc_api_enabled: false`
  - `allow_legacy_api_keys: false`

## 4) Run
CLI:
```bash
python oneseam.py
```

API:
```bash
python oneseam.py api
```

## 5) Optional scripts
Linux/macOS:
```bash
bash scripts/setup.sh
bash scripts/run_node.sh
```

Windows:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_cli.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_api.ps1
```
