<!-- Copyright (c) 2026 Eduardo de Figueiredo. SPDX-License-Identifier: AGPL-3.0-or-later -->

# Contributing to ONESEAM

## Scope
This repository is focused on non-custodial dark-pool style OTC coordination:
- private order discovery
- private matching
- settlement coordination (no custody)

Changes that introduce custody behavior are out of scope.

## Development Setup
```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r requirements.txt
```

## Local Validation
```bash
python -m py_compile oneseam.py oneseam_simple_cli.py oneseam_blind_matching.py
```

## Pull Request Rules
- Keep changes small and focused.
- Include clear reproduction/validation steps for behavior changes.
- Update `README.md` and `oneseam_config.yaml` examples when config/API changes.
- Never commit private keys, secrets, or real production certificates.
- Follow `CODE_OF_CONDUCT.md`.
- For vulnerabilities, follow `docs/SECURITY.md`.

## Commit Message Style
Use concise prefixes:
- `feat:`
- `fix:`
- `chore:`
- `docs:`
- `test:`
