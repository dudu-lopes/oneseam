<!-- Copyright (c) 2026 Eduardo de Figueiredo. SPDX-License-Identifier: BUSL-1.1 -->

# Architecture

## Goal
ONESEAM provides a non-custodial dark-pool style coordination layer for private P2P OTC trading.

## Core Principles
- No custody of end-user funds.
- No backend transaction signing.
- Privacy-preserving order discovery.
- Deterministic state transitions and auditable events.

## Main Components
- `oneseam.py`: node runtime, API, state machine, persistence, security controls.
- `oneseam_blind_matching.py`: blind matching utilities (commitment/bucket overlap support).
- `oneseam_simple_cli.py`: trader-first guided CLI.

## High-Level Flow
1. Trader posts an intent (wallet-attested when required).
2. Node stores intent metadata and distributes private payload fragments.
3. Matching engine identifies compatible counterparties.
4. Traders open a secure session and start HTLC coordination.
5. Proof events advance swap state to terminal outcome.
6. Fee invoice can be issued post-settlement.

## Security Layers
- JWT + RBAC for API actors.
- Optional TLS/mTLS for REST and P2P.
- Ed25519 shard signatures.
- Immutable-style audit chain events.

## Data Layer
- SQLite by default; PostgreSQL optional.
- Core operational tables include intents, matches, swaps, shards, manifests, and audit records.
