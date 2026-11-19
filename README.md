# meru — Kshana Core (hosted verdict-only service)

मेरु — the axis at the centre of everything. **Private. Trade secret. Never public, never
shipped to a customer.**

This repository is the **Core** home in the Open → Pro → **Core** model. The crown-jewel PNT
methods run here, on Ashforde's servers, and never leave as code. A caller sends inputs with a
valid Kshana licence; the method runs server-side; only a **signed verdict** (the outcome plus
an Ed25519 signature) comes back. Because the method never reaches a customer binary, it
cannot be extracted or reverse-engineered — this is stronger and more permanent than any
on-device hardening, and it is what lets us say Arksa cannot be copied.

## Hosted methods

| Endpoint | Method | Returns (verdict only) |
|---|---|---|
| `POST /verdict/selfcal` | F1 — self-calibrating simulator loop | convergence, fidelity, calibrated parameters + uncertainty, signed lineage head |
| `POST /verdict/survey`  | F2 — integrity-driven ASF survey planner | coverage & mean PL before/after, chosen survey points |
| `GET  /health` | liveness | `{"ok":true}` |

Internals — per-iteration records, parameter state, the regenerated scenario, the full PL
grid — stay in the service and are never returned.

## Authorisation

A call is authorised by the caller's Kshana licence: `Authorization: Bearer <licence-token>`,
which must be valid, unexpired and `pro-eloran`-entitled, verified against the vendor public
key (`MERU_LICENCE_PUBKEY`). This is how a Pro customer "buys a licence and calls the server"
without ever holding the method. (v1 checks signature + entitlement + expiry; revocation-list
checking is the next step.)

## Run

```
MERU_KEY=<64-hex ed25519 seed> \
MERU_KEY_ID=meru-2026 \
MERU_LICENCE_PUBKEY=<64-hex vendor public key> \
MERU_ADDR=127.0.0.1:8099 \
cargo run --release
```

For development without licences: `MERU_ALLOW_UNAUTHENTICATED=1` (the server refuses to start
otherwise). Put the service behind a reverse proxy for TLS and rate limiting.

## Dependencies and the X3 rule

- The method code lives in the private `kshana-eloran` engine behind the `unfiled-methods`
  feature; licence verification reuses the `kshana-pro` library.
- **Local development** uses path dependencies on a sibling `kshana-pro` checkout
  (`../kshana-pro`). **Standalone build / CI** has no sibling: switch the two `path = ...`
  lines in `Cargo.toml` to the `git = ...` form noted there (needs a token for the private
  repo).
- **X3 (hard rule):** `kshana-pro` must never name or contain Core code. A Pro client reaches
  these methods only over the network, against a configurable endpoint — never by linking this
  crate. The direction is one-way: meru may depend on kshana-pro/kshana-eloran; they may not
  depend on meru.

## Status (v1)

Scaffold of the verdict-only service for F1 and F2, with signed verdicts, licence auth and the
two method wrappers. Not yet done: revocation-list checking, per-call metering/billing, request
rate limiting, TLS termination config, deployment manifests, and migrating the most sensitive
refinements to be Core-only (today F1/F2 also exist in `kshana-eloran` for the airgapped
on-prem fallback build). See the VCprep placement note for the per-method plan.
