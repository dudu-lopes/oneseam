# Copyright (c) 2026 Eduardo de Figueiredo.
# SPDX-License-Identifier: BUSL-1.1

"""
ONESEAM blind matching primitives.

This module provides deterministic price-slot commitments so nodes can
perform phase-A candidate matching using token overlap without exposing
raw user price ranges.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any


DEFAULT_GLOBAL_SALT = "ONESEAM_BLIND_MATCHING_V1_PRICE_SLOTS"


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_pair(asset_a: str, asset_b: str) -> tuple[str, str]:
    a = str(asset_a or "").strip().upper()
    b = str(asset_b or "").strip().upper()
    if not a or not b or a == b:
        raise ValueError("invalid_asset_pair")
    first, second = sorted((a, b))
    return first, second


def _to_positive_float(value: Any, error_code: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise ValueError(error_code)
    return parsed


def _normalize_price_range_to_canonical(
    sell_asset: str,
    buy_asset: str,
    price_min: float,
    price_max: float,
) -> tuple[float, float, str, str]:
    """
    Normalize to canonical quote/base units for deterministic token generation.

    Returns:
        (normalized_min, normalized_max, canonical_base, canonical_quote)
    """
    pair_base, pair_quote = canonical_pair(sell_asset, buy_asset)
    p_low = min(price_min, price_max)
    p_high = max(price_min, price_max)
    if p_low <= 0 or p_high <= 0:
        raise ValueError("invalid_price_range")

    sell = str(sell_asset).strip().upper()
    buy = str(buy_asset).strip().upper()
    if sell == pair_base and buy == pair_quote:
        return p_low, p_high, pair_base, pair_quote
    if sell == pair_quote and buy == pair_base:
        inv_low = min(1.0 / p_high, 1.0 / p_low)
        inv_high = max(1.0 / p_high, 1.0 / p_low)
        return inv_low, inv_high, pair_base, pair_quote
    raise ValueError("invalid_pair_direction")


def _bucket_range(min_value: float, max_value: float, step: float) -> tuple[int, int]:
    if step <= 0:
        raise ValueError("invalid_slot_size")
    left = int(math.floor(min_value / step))
    right = int(math.floor(max_value / step))
    return min(left, right), max(left, right)


def _slot_token(slot_id: str, pair_hash: str, global_salt: str) -> str:
    return _hash_text(f"{slot_id}|{pair_hash}|{global_salt}")


def build_blind_commitment_meta(
    intent: dict[str, Any],
    *,
    slot_size: float,
    amount_bucket_size: float,
    global_salt: str = DEFAULT_GLOBAL_SALT,
    max_slots: int = 4096,
) -> dict[str, Any]:
    sell_asset = str(intent.get("sell_asset", "")).strip().upper()
    buy_asset = str(intent.get("buy_asset", "")).strip().upper()
    amount = _to_positive_float(intent.get("amount", 0.0), "amount_must_be_positive")
    price_min = _to_positive_float(intent.get("price_min", 0.0), "invalid_price_range")
    price_max = _to_positive_float(intent.get("price_max", 0.0), "invalid_price_range")
    normalized_min, normalized_max, pair_base, pair_quote = _normalize_price_range_to_canonical(
        sell_asset, buy_asset, price_min, price_max
    )

    canonical_pair_id = f"{pair_base}/{pair_quote}"
    direction = f"{sell_asset}->{buy_asset}"
    pair_hash = _hash_text(f"pair:{canonical_pair_id}|{global_salt}")
    side_hash = _hash_text(f"side:{direction}|{global_salt}")

    slot_min, slot_max = _bucket_range(normalized_min, normalized_max, float(slot_size))
    slot_count = (slot_max - slot_min) + 1
    if slot_count <= 0:
        raise ValueError("invalid_slot_count")
    if slot_count > int(max_slots):
        raise ValueError("blind_slot_range_too_wide")

    slot_tokens: list[str] = []
    for slot_id in range(slot_min, slot_max + 1):
        slot_tokens.append(_slot_token(f"S{slot_id}", pair_hash, global_salt))

    if amount_bucket_size <= 0:
        raise ValueError("invalid_amount_bucket_size")
    amount_bucket = int(math.floor(amount / float(amount_bucket_size)))
    amount_hash = _hash_text(f"amount:{amount_bucket}|{global_salt}")

    return {
        "blind_matching_version": "blind_v1",
        "blind_pair_hash": pair_hash,
        "blind_side_hash": side_hash,
        "blind_slot_size": float(slot_size),
        "blind_slot_min": slot_min,
        "blind_slot_max": slot_max,
        "blind_slot_token_count": slot_count,
        "blind_slot_tokens": slot_tokens,
        "blind_amount_bucket": amount_bucket,
        "blind_amount_hash": amount_hash,
    }


def blind_overlap_tokens(meta_a: dict[str, Any], meta_b: dict[str, Any]) -> list[str] | None:
    """
    Returns:
      - None if blind metadata is missing/incomplete
      - [] if complete but not compatible
      - [token, ...] when there is a blind overlap
    """
    if not isinstance(meta_a, dict) or not isinstance(meta_b, dict):
        return None
    a_tokens = meta_a.get("blind_slot_tokens")
    b_tokens = meta_b.get("blind_slot_tokens")
    a_pair_hash = str(meta_a.get("blind_pair_hash", "")).strip()
    b_pair_hash = str(meta_b.get("blind_pair_hash", "")).strip()
    a_side_hash = str(meta_a.get("blind_side_hash", "")).strip()
    b_side_hash = str(meta_b.get("blind_side_hash", "")).strip()
    if not isinstance(a_tokens, list) or not isinstance(b_tokens, list):
        return None
    if not a_pair_hash or not b_pair_hash or not a_side_hash or not b_side_hash:
        return None
    if a_pair_hash != b_pair_hash:
        return []
    if a_side_hash == b_side_hash:
        return []
    return sorted({str(x) for x in a_tokens} & {str(x) for x in b_tokens})


def build_public_blind_commitment(intent: dict[str, Any], commitment_meta: dict[str, Any]) -> dict[str, Any]:
    """
    Build a minimal public commitment payload for network distribution.
    """
    return {
        "kind": "trade_intent_blind_commitment",
        "version": str(commitment_meta.get("blind_matching_version", "blind_v1")),
        "intent_id": str(intent.get("intent_id", "")),
        "maker_client_id": str(intent.get("maker_client_id", "")),
        "blind_pair_hash": str(commitment_meta.get("blind_pair_hash", "")),
        "blind_side_hash": str(commitment_meta.get("blind_side_hash", "")),
        "blind_amount_hash": str(commitment_meta.get("blind_amount_hash", "")),
        "blind_slot_tokens": list(commitment_meta.get("blind_slot_tokens") or []),
        "blind_slot_token_count": int(commitment_meta.get("blind_slot_token_count", 0)),
        "expiration": int(intent.get("expiration", 0)),
    }
