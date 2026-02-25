# Copyright (c) 2026 Eduardo de Figueiredo.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
ONESEAM simplified CLI (default user experience).

This module intentionally hides low-level protocol internals and presents
an operator-friendly workflow:
0) Node Status
1) Post Order
2) My Orders
3) Exit

It depends on an adapter object provided by oneseam.py.
"""

from __future__ import annotations

import time
from typing import Any

MAX_LIST_ITEMS = 8


def _ask_non_empty(prompt: str) -> str:
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print('Value is required.')


def _ask_float(prompt: str) -> float:
    while True:
        raw = input(prompt).strip()
        try:
            return float(raw)
        except ValueError:
            print('Invalid number.')


def _ask_int(prompt: str, default: int | None = None) -> int:
    while True:
        raw = input(prompt).strip()
        if not raw and default is not None:
            return int(default)
        try:
            return int(raw)
        except ValueError:
            print('Invalid integer.')


def _find_item_by_id(items: list[dict[str, Any]], field_name: str, field_value: str) -> dict[str, Any] | None:
    for item in items:
        if item.get(field_name) == field_value:
            return item
    return None


def _short_id(value: str, max_len: int = 20) -> str:
    text = str(value or '').strip()
    if len(text) <= max_len:
        return text
    return f"{text[:10]}...{text[-6:]}"


def _status_banner() -> None:
    print('\n' + '=' * 58)
    print('  ONESEAM MENU')
    print('=' * 58)
    print('  0. Node Status')
    print('  1. Post Order')
    print('  2. My Orders')
    print('  3. Exit')
    print('=' * 58)
    print('Tip: confirm matches in "My Orders".')


def _select_expiry_ms() -> int:
    print('\nOrder validity (how long this order stays open):')
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

    print('\nOrder side:')
    print('  1. Sell')
    print('  2. Buy')
    side = input('Select [1]: ').strip() or '1'

    if side == '1':
        sell_asset = _ask_non_empty('Sell asset (coin you have, e.g. BTC): ').upper()
        buy_asset = _ask_non_empty('Buy asset (coin you want, e.g. USDT): ').upper()
        amount = _ask_float(f'Amount to sell ({sell_asset}): ')
        print(f'Price range ({buy_asset} per {sell_asset}):')
    else:
        buy_asset = _ask_non_empty('Asset to buy (coin you want, e.g. BTC): ').upper()
        sell_asset = _ask_non_empty('Asset to pay (coin you have, e.g. USDT): ').upper()
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

    print('\nOrder posted.')
    print(f"Order ID: {_short_id(intent.get('intent_id', ''))}")
    matches = intent.get('matches_detected') or []
    if matches:
        pretty = ', '.join(_short_id(x) for x in matches[:MAX_LIST_ITEMS])
        print(f"Matches found: {pretty}")
        print("Next step: open '2. My Orders' and confirm the match.")
    else:
        print("No match yet. Keep monitoring in '2. My Orders'.")


def _swap_state_hint(state: str) -> str:
    hints = {
        'WAIT_LOCK_A': 'Waiting for first lock transaction proof.',
        'WAIT_LOCK_B': 'Waiting for second lock transaction proof.',
        'READY_CLAIM': 'Both locks confirmed. Claim can proceed.',
        'CLAIMED_A': 'Side A claimed. Waiting side B claim.',
        'CLAIMED_B': 'Side B claimed. Waiting side A claim.',
        'COMPLETED': 'Swap completed.',
        'REFUNDED': 'Swap refunded.',
        'FAILED': 'Swap failed.',
    }
    return hints.get(state, 'Swap in progress.')


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
        state = str(swap.get('state', ''))
        print(f"Swap status: {state}")
        print(_swap_state_hint(state))
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
        print(f"Recommended now: {recommended.get('label','')}")
        if recommended.get('auto') and not recommended.get('risky'):
            auto_run = input('Run recommended action now? (y/n): ').strip().lower()
            if auto_run == 'y':
                adapter.execute_next_action(recommended, actor_ctx, source='simple_cli')
                continue

        print('Available actions (confirm-required = irreversible):')
        for idx, act in enumerate(actions, start=1):
            risk = 'confirm-required' if act.get('risky') else 'safe'
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
    print('\nOpen orders:')
    if not active_intents:
        print('  none')
    for item in active_intents[:MAX_LIST_ITEMS]:
        print(f"  - {_short_id(item.get('intent_id',''))} | {item.get('sell_asset','')}->{item.get('buy_asset','')} | {item.get('status','')}")

    print('\nMatches found:')
    if not matches:
        print('  none')
    for idx, item in enumerate(matches[:MAX_LIST_ITEMS], start=1):
        print(f"  [{idx}] {_short_id(item.get('match_id',''))} | {item.get('you_sell_asset','')}->{item.get('you_buy_asset','')} | {item.get('readiness','')}")

    print('\nCurrent swaps:')
    if not swaps:
        print('  none')
    for item in swaps[:MAX_LIST_ITEMS]:
        invoice = fee_invoices.get(item.get('swap_id', ''), None)
        invoice_status = (invoice or {}).get('payment_status', 'none')
        print(f"  - {_short_id(item.get('swap_id',''))} | {item.get('state','')} | fee={invoice_status}")

    if matches:
        print('\nSmall explanation: confirming match starts private swap coordination.')
        confirm_match = input('Confirm a match now? (y/n): ').strip().lower()
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
                print(f"[OK] Match confirmed: {_short_id(selected_match_id)}")
                print(f"Swap ID: {_short_id(swap_id)}")
                if swap_id:
                    _guided_swap_loop(adapter, actor_ctx, selected_match_id, swap_id, session=session)
                return
            print('[!] Invalid match selection.')

    open_swap = input('Open a swap by ID (optional): ').strip()
    if not open_swap:
        return
    match_id = ''
    for swap in swaps:
        if swap.get('swap_id') == open_swap:
            match_id = swap.get('match_id', '')
            break
    _guided_swap_loop(adapter, actor_ctx, match_id, open_swap, session=None)


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
