# Copyright (c) 2026 Eduardo de Figueiredo.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
ONESEAM simplified CLI (default user experience).

This module intentionally hides low-level protocol internals and presents
an operator-friendly workflow:
1) Post Order
2) Check Matches
3) Accept Match & Swap
4) My Orders
5) Help
6) Exit

It depends on an adapter object provided by oneseam.py.
"""

from __future__ import annotations

import time
from typing import Any


def _ask_non_empty(prompt: str) -> str:
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print('[!] Value is required.')


def _ask_float(prompt: str) -> float:
    while True:
        raw = input(prompt).strip()
        try:
            return float(raw)
        except ValueError:
            print('[!] Invalid number.')


def _ask_int(prompt: str, default: int | None = None) -> int:
    while True:
        raw = input(prompt).strip()
        if not raw and default is not None:
            return int(default)
        try:
            return int(raw)
        except ValueError:
            print('[!] Invalid integer.')


def _find_item_by_id(items: list[dict[str, Any]], field_name: str, field_value: str) -> dict[str, Any] | None:
    for item in items:
        if item.get(field_name) == field_value:
            return item
    return None


def _status_banner() -> None:
    print('\n' + '=' * 58)
    print('  ONESEAM SIMPLE CLI')
    print('=' * 58)
    print('  0. Node Status')
    print('  1. Post Order')
    print('  2. My Orders')
    print('  3. Exit')
    print('=' * 58)


def _select_expiry_ms() -> int:
    print('\nOrder expires in:')
    print('  1. 15 minutes')
    print('  2. 1 hour')
    print('  3. 24 hours')
    choice = input('Select [1]: ').strip() or '1'
    expiry_seconds = {'1': 900, '2': 3600, '3': 86400}.get(choice, 900)
    return int(time.time() * 1000) + (expiry_seconds * 1000)


def _post_order_flow(adapter: Any):
    print('\n' + '-' * 58)
    print('POST ORDER')
    print('-' * 58)

    client_id = _ask_non_empty('Client ID: ')
    wallet = _ask_non_empty('Wallet address: ')

    print('\nSide:')
    print('  1. Sell')
    print('  2. Buy')
    side = input('Select [1]: ').strip() or '1'

    if side == '1':
        sell_asset = _ask_non_empty('Sell asset (e.g. BTC): ').upper()
        buy_asset = _ask_non_empty('Buy asset (e.g. USDT): ').upper()
        amount = _ask_float(f'Amount to sell ({sell_asset}): ')
        print(f'Price range ({buy_asset} per {sell_asset}):')
    else:
        buy_asset = _ask_non_empty('Asset to buy (e.g. BTC): ').upper()
        sell_asset = _ask_non_empty('Asset to pay (e.g. USDT): ').upper()
        amount = _ask_float(f'Max budget to spend ({sell_asset}): ')
        print(f'Price range ({sell_asset} per {buy_asset}):')

    price_min = _ask_float('  Min price: ')
    price_max = _ask_float('  Max price: ')
    expiration = _select_expiry_ms()

    payload = {
        'maker_wallet': wallet,
        'sell_asset': sell_asset,
        'buy_asset': buy_asset,
        'amount': amount,
        'price_min': price_min,
        'price_max': price_max,
        'expiration': expiration,
        'wallet_nonce': f"simple_cli_{int(time.time())}"
    }
    actor_ctx = {'client_id': client_id}
    intent = adapter.post_order(payload, actor_ctx)

    print('\n[OK] Order posted.')
    print(f"Intent ID: {intent.get('intent_id', '')}")
    matches = intent.get('matches_detected') or []
    if matches:
        print(f"Matches detected: {', '.join(matches)}")
        print("Tip: run '2. My Orders' to review and confirm matches.")
    else:
        print("No immediate match. Monitor in '2. My Orders'.")


def _check_matches_flow(adapter: Any):
    print('\n' + '-' * 58)
    print('CHECK MATCHES')
    print('-' * 58)
    client_id = _ask_non_empty('Client ID: ')
    actor_ctx = {'client_id': client_id}
    matches = adapter.list_matches(actor_ctx)
    if not matches:
        print('No matches found.')
        return
    print(f"Found {len(matches)} match(es):")
    for idx, item in enumerate(matches, start=1):
        print(f"  [{idx}] {item.get('match_id','')}")
        print(f"      Side: {item.get('you_side','')}")
        print(f"      You: {item.get('you_sell_asset','')} -> {item.get('you_buy_asset','')} | amount={item.get('you_amount','')}")
        print(f"      Price overlap: {item.get('overlap_min','')} - {item.get('overlap_max','')}")
        print(f"      Suggested price: {item.get('suggested_price','')}")
        print(f"      Readiness: {item.get('readiness','')}")


def _guided_swap_loop(
    adapter: Any,
    actor_ctx: dict[str, Any],
    match_id: str,
    swap_id: str,
    session: dict[str, Any] | None = None,
) -> None:
    while True:
        orders = adapter.list_orders(actor_ctx)
        match = _find_item_by_id(orders.get('matches', []), 'match_id', match_id)
        swap = _find_item_by_id(orders.get('swaps', []), 'swap_id', swap_id)
        if not swap:
            print('[INFO] Swap no longer available.')
            return
        fee_invoice = (orders.get('fee_invoices') or {}).get(swap_id)

        print('\n' + '-' * 58)
        print(f"SWAP STATUS: {swap.get('state','')}")
        print(f"Swap ID: {swap_id}")
        print(f"Match ID: {match_id}")
        if fee_invoice:
            print(f"Fee: {fee_invoice.get('fee_amount','')} {fee_invoice.get('fee_asset','')} | status={fee_invoice.get('payment_status','')}")

        actions = adapter.compute_next_actions(
            intent=None,
            match=match,
            session=session,
            swap=swap,
            fee_invoice=fee_invoice,
            actor_ctx=actor_ctx
        )
        if not actions:
            print('[OK] No pending actions.')
            return

        recommended = actions[0]
        print(f"Recommended: {recommended.get('label','')} ({recommended.get('code','')})")
        if recommended.get('auto') and not recommended.get('risky'):
            auto_run = input('Run recommended action now? (y/n): ').strip().lower()
            if auto_run == 'y':
                adapter.execute_next_action(recommended, actor_ctx, source='simple_cli')
                continue

        print('Available actions:')
        for idx, act in enumerate(actions, start=1):
            risk = 'RISK' if act.get('risky') else 'SAFE'
            print(f"  {idx}. {act.get('label','')} [{risk}]")
        print(f"  {len(actions) + 1}. Back")
        chosen = input('Select option: ').strip()
        if chosen == str(len(actions) + 1):
            return
        try:
            selected = actions[int(chosen) - 1]
        except (ValueError, IndexError):
            print('[!] Invalid option.')
            continue
        adapter.execute_next_action(selected, actor_ctx, source='simple_cli')


def _accept_match_and_swap_flow(adapter: Any):
    print('\n' + '-' * 58)
    print('ACCEPT MATCH & SWAP')
    print('-' * 58)
    client_id = _ask_non_empty('Client ID: ')
    actor_ctx = {'client_id': client_id}
    matches = adapter.list_matches(actor_ctx)
    if not matches:
        print('No matches available.')
        return
    for idx, item in enumerate(matches, start=1):
        print(f"  [{idx}] {item.get('match_id','')} | readiness={item.get('readiness','')}")
        print(f"      You: {item.get('you_sell_asset','')} -> {item.get('you_buy_asset','')} | amount={item.get('you_amount','')}")
        print(f"      Price overlap: {item.get('overlap_min','')} - {item.get('overlap_max','')}")

    raw = input('Select match number or enter match_id: ').strip()
    selected_match_id = ''
    if raw.isdigit():
        pick = int(raw)
        if pick < 1 or pick > len(matches):
            print('[!] Invalid option.')
            return
        selected_match_id = matches[pick - 1].get('match_id', '')
    else:
        selected_match_id = raw
    if not selected_match_id:
        print('[!] Match ID is required.')
        return
    confirm = input(f'Accept match {selected_match_id} and start swap? (y/n): ').strip().lower()
    if confirm != 'y':
        return
    result = adapter.accept_match_and_start(selected_match_id, actor_ctx)
    session = result.get('session') or {}
    swap = result.get('swap') or {}
    swap_id = swap.get('swap_id', '')
    print('[OK] Match accepted.')
    print(f"Session ID: {session.get('session_id','')}")
    print(f"Swap ID: {swap_id}")
    if swap_id:
        _guided_swap_loop(adapter, actor_ctx, selected_match_id, swap_id, session=session)


def _my_orders_flow(adapter: Any):
    print('\n' + '-' * 58)
    print('MY ORDERS')
    print('-' * 58)
    client_id = _ask_non_empty('Client ID: ')
    actor_ctx = {'client_id': client_id}
    orders = adapter.list_orders(actor_ctx)
    intents = orders.get('intents') or []
    matches = orders.get('matches') or []
    swaps = orders.get('swaps') or []
    fee_invoices = orders.get('fee_invoices') or {}
    terminal_intent_statuses = {'CANCELLED', 'EXPIRED', 'SETTLED', 'COMPLETED'}
    active_intents = [x for x in intents if str(x.get('status', '')).upper() not in terminal_intent_statuses]
    print(f"Active orders: {len(active_intents)} | Matches: {len(matches)} | Swaps: {len(swaps)}")
    for item in active_intents[:20]:
        print(f"  - intent {item.get('intent_id','')} | {item.get('sell_asset','')}->{item.get('buy_asset','')} | {item.get('status','')}")
    print('\nMatches:')
    for idx, item in enumerate(matches[:20], start=1):
        print(f"  [{idx}] {item.get('match_id','')} | readiness={item.get('readiness','')} | status={item.get('status','')}")
        print(f"      You: {item.get('you_sell_asset','')} -> {item.get('you_buy_asset','')} | amount={item.get('you_amount','')}")
        print(f"      Price overlap: {item.get('overlap_min','')} - {item.get('overlap_max','')}")
    print('\nSwaps:')
    for item in swaps[:20]:
        invoice = fee_invoices.get(item.get('swap_id', ''), None)
        invoice_status = (invoice or {}).get('payment_status', 'none')
        print(f"  - swap {item.get('swap_id','')} | state={item.get('state','')} | fee={invoice_status}")

    if matches:
        confirm_match = input('Confirm and start a match now? (y/n): ').strip().lower()
        if confirm_match == 'y':
            raw = input('Select match number or enter match_id: ').strip()
            selected_match_id = ''
            if raw.isdigit():
                pick = int(raw)
                if 1 <= pick <= len(matches):
                    selected_match_id = matches[pick - 1].get('match_id', '')
            else:
                selected_match_id = raw
            if selected_match_id:
                result = adapter.accept_match_and_start(selected_match_id, actor_ctx)
                session = result.get('session') or {}
                swap = result.get('swap') or {}
                swap_id = swap.get('swap_id', '')
                print(f"[OK] Match confirmed: {selected_match_id}")
                print(f"Session ID: {session.get('session_id','')}")
                print(f"Swap ID: {swap_id}")
                if swap_id:
                    _guided_swap_loop(adapter, actor_ctx, selected_match_id, swap_id, session=session)
                return
            print('[!] Invalid match selection.')

    open_swap = input('Open a swap for guided actions (swap_id, optional): ').strip()
    if not open_swap:
        return
    match_id = ''
    for swap in swaps:
        if swap.get('swap_id') == open_swap:
            match_id = swap.get('match_id', '')
            break
    _guided_swap_loop(adapter, actor_ctx, match_id, open_swap, session=None)


def _help_flow():
    print('\n' + '-' * 58)
    print('HELP')
    print('-' * 58)
    print('1) Post Order: submit a private intent with price range and expiry.')
    print('2) Check Matches: list compatible matches found by the network.')
    print('3) Accept Match & Swap: opens session, starts HTLC flow, and guides next actions.')
    print('4) My Orders: view intents, matches, swaps, and fee state.')
    print('5) Safety: irreversible actions (claim/refund/fee confirm) always require explicit confirmation.')
    print('0) Node Status: quick health/status access.')
    print('-' * 58)


def run_simple_cli(adapter: Any):
    """
    Main loop for simplified CLI.
    Adapter methods are resolved from oneseam.py.
    """
    while True:
        _status_banner()
        choice = input('Select option: ').strip()
        handlers = {
            '0': adapter.node_status,
            '1': lambda: _post_order_flow(adapter),
            '2': lambda: _my_orders_flow(adapter),
        }
        try:
            if choice == '3':
                print('[SHUTDOWN] Stopping node...')
                raise SystemExit(0)
            handler = handlers.get(choice)
            if handler is None:
                print('[!] Invalid option.')
                continue
            handler()
        except KeyboardInterrupt:
            print('\n[SHUTDOWN] Interrupted by user.')
            raise SystemExit(0)
        except SystemExit:
            raise
        except Exception as e:  # noqa: BLE001 - CLI boundary should never crash on adapter/runtime errors.
            print(f'[X] Operation failed: {e}')
