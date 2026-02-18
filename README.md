# ONESEAM DarkPool

Infraestrutura P2P non-custodial para descoberta privada de ordens, matching privado e coordenacao de settlement via HTLC (BTC + Lightning first).

A plataforma **nao custodia fundos** e **nao assina transacoes do usuario** no backend.

## Arquivos principais do projeto
- `oneseam.py` (entrypoint principal)
- `oneseam_blind_matching.py` (motor de commitments por price slot para blind match)
- `oneseam_config.yaml` (config ativa)
- `requirements.txt`
- `README.md`

## Estrutura recomendada para producao
- `config/production.example.yaml` (modelo de configuracao)
- `docs/PRODUCTION_FILES.md` (checklist de arquivos)
- `scripts/run_api.ps1`
- `scripts/run_cli.ps1`
- `scripts/check_ready.ps1`
- `certs/` (certificados reais no deploy)
- `secrets/` (segredos locais no deploy)

## Instalar
```bash
pip install -r requirements.txt
```

## Rodar
CLI:
```bash
python oneseam.py
```

API:
```bash
python oneseam.py api
```


## UX simples de wallet (CLI)
Opcionalmente, para auto-assinar no CLI sem copiar mensagem manualmente:

```bash
export ONESEAM_WALLET_PRIVATE_KEY=0x...
```

Se a wallet da acao bater com a chave do ambiente, a assinatura e aplicada automaticamente.

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
- O sistema usa commitments por `price slots` para filtro de match sem expor faixa de preco em claro na fase A.
- O overlap final continua validado matematicamente no backend (fase B) antes de abrir sessao/swap.
- Commitment publico (hashes) pode ser shardado e distribuido no destino `blind_orderbook`.

Configuracao principal em `oneseam_config.yaml`:
- `blind_matching_enabled`
- `blind_price_slot_size`
- `blind_max_price_slots`
- `blind_global_salt`
- `blind_commitment_destination`

## Producao real (mesa OTC)
No `oneseam_config.yaml`:
- `production_mode: true`
- `legacy_otc_api_enabled: false`
- TLS REST ativo + JWT only (`allow_legacy_api_keys: false`)
- P2P TLS + mTLS ativos
- `wallet_attestation_required: true`
- `proof_wallet_attestation_required: true`
- `proof_server_side_verification_required: true`
- Configurar verificador:
  - `proof_verifier_url` (BTC/LN verifier externo), ou
  - `btc_rpc_url` para verificacao BTC-side

Valide readiness antes de abrir:
```bash
powershell -ExecutionPolicy Bypass -File scripts/check_ready.ps1 -BaseUrl http://127.0.0.1:8000
```

## Arquivos necessarios para mesa real
Veja checklist completo em `docs/PRODUCTION_FILES.md`.

Resumo curto:
- necessarios em repo: codigo + config + scripts + docs
- necessarios no ambiente: certs reais, JWT pubkeys, segredos de verificador/BTC RPC
- nunca versionar chaves privadas e tokens de producao
