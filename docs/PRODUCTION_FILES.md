# ONESEAM - Required Files

## 1) Core project files
- `oneseam.py`
- `oneseam_config.yaml`
- `requirements.txt`
- `README.md`

## 2) Runtime-generated files (do not version with secrets)
- `oneseam.db` (if sqlite)
- `node_id.txt`
- `oneseam_keys.json`
- `oneseam_storage/`

## 3) Production files (must exist in real deployment)
- REST TLS cert/key:
  - `certs/rest/server.crt`
  - `certs/rest/server.key`
  - `certs/rest/ca.crt` (if mTLS on REST)
- P2P TLS/mTLS certs:
  - `certs/p2p/server.crt`
  - `certs/p2p/server.key`
  - `certs/p2p/ca.crt`
- JWT verification keys:
  - `certs/jwt/jwt_pub.pem` (or multiple keys)
- Proof verifier integration:
  - `proof_verifier_url` and `proof_verifier_auth_token` in config
  - optional BTC RPC credentials (`btc_rpc_*`) for BTC-side verification

## 4) Developer and operations helpers
- `config/production.example.yaml`
- `scripts/run_api.ps1`
- `scripts/run_cli.ps1`
- `scripts/check_ready.ps1`

## 5) Presentation/demo package (recommended)
- Keep in repo:
  - `oneseam.py`
  - `oneseam_config.yaml`
  - `requirements.txt`
  - `README.md`
  - `tests/`
  - `scripts/`
  - `config/production.example.yaml`
  - `docs/PRODUCTION_FILES.md`
- Exclude from repo:
  - real private keys
  - real tokens/passwords
  - production cert private keys
