# Copyright (c) 2026 ONESEAM Contributors.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Simple API usage example for ONESEAM v2.

This script demonstrates:
1) preparing intent signature payload
2) creating a trade intent
3) fetching intent status

It is intentionally minimal and expects a locally running API.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

API_BASE = os.getenv("ONESEAM_API_BASE", "http://127.0.0.1:8000")


def post(path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url=f"{API_BASE}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as res:
        return json.loads(res.read().decode("utf-8"))


def get(path: str) -> dict:
    req = urllib.request.Request(url=f"{API_BASE}{path}", method="GET")
    with urllib.request.urlopen(req, timeout=10) as res:
        return json.loads(res.read().decode("utf-8"))


def main() -> None:
    payload = {
        "maker_wallet": "0x0000000000000000000000000000000000000001",
        "sell_asset": "BTC",
        "buy_asset": "USDT",
        "amount": 0.1,
        "price_min": 50000.0,
        "price_max": 52000.0,
        "expiration": 4102444800000,
        "wallet_nonce": "example_nonce_001",
    }

    try:
        prepared = post("/v2/intents/prepare-signature", payload)
        print("prepare-signature:\n", json.dumps(prepared, indent=2))

        print("\nCreate intent skipped: wallet_signature is required in production flow.")
        print("Use the returned message for real wallet signing, then call POST /v2/intents.")

        if prepared.get("intent_id"):
            status = get(f"/v2/intents/{prepared['intent_id']}")
            print("\nintent status:\n", json.dumps(status, indent=2))
    except urllib.error.HTTPError as exc:
        print("HTTP error:", exc.code, exc.read().decode("utf-8", errors="ignore"))
    except Exception as exc:
        print("Error:", str(exc))


if __name__ == "__main__":
    main()
