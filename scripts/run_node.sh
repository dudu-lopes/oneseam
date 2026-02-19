#!/usr/bin/env bash
# Copyright (c) 2026 ONESEAM Contributors.
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python oneseam.py
