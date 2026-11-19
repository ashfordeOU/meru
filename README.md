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

A call is authorised by the caller's Kshana licence: `Authorization: Bearer <licence-token>`.
It must be signed by a current vendor key (`MERU_LICENCE_PUBKEY`, several allowed for
rotation), unexpired, not on the signed revocation list (`MERU_REVOCATIONS`, re-read within
30 s of a change, older lists refused), and at the Pro tier or above (or explicitly grant
`pro-eloran`). Evaluation licences are refused. The on-device `pro-eloran` gate in Pro builds
stays Enterprise-only.

## Protection against copying

| Threat | What meru does |
|---|---|
| Reading the method | It never leaves the server. Callers get a signed verdict only |
| Rebuilding it from many answers | Outputs rounded (3 significant figures, angles to 1e-4 deg); per-licence rate (10/min) and daily quota (200); a probe detector pauses a licence that sends more than 60 distinct requests in an hour and raises an alert; the full survey grid only for Enterprise |
| Stolen or cancelled licence | Signed revocation list, hot-reloaded |
| Forged verdicts | Ed25519 signature; the verdict key can live in AWS KMS (`MERU_SIGNER=kms`) so a stolen disk holds no key; every signature self-checked |
| Flooding | Connection cap, running-job cap, read/write timeouts, bounded headers and body, chunked bodies refused, request-size limits checked before any work; nginx limits in front |
| Audit | Meter log: one line per call with hashes only, rebuilt into quotas on restart |

Customer terms must also forbid reverse engineering and systematic querying (legal).

## Client

Customers call it with the Pro command line, which verifies every verdict against the pinned
service public key before accepting it:

```
kshana-pro verdict survey request.json --url https://<host> --out verdict.json
kshana-pro verdict verify verdict.json
```

The key is built into Pro releases (`KSHANA_VERDICT_KEY` at build time, several keys allowed
during a rotation), or passed with `--trust`.

## Run

Development:

```
MERU_KEY=<64-hex seed> MERU_ALLOW_UNAUTHENTICATED=1 cargo run --release
```

Production: see `deploy/README.md` (KMS signer, revocation list, systemd + nginx or the
container image, alerting, go-live checklist).

| Variable | Default | Meaning |
|---|---|---|
| `MERU_ADDR` | `127.0.0.1:8099` | Listen address |
| `MERU_SIGNER` | `seed` | `seed` (`MERU_KEY`) or `kms` (`MERU_KMS_KEY_ID`, `MERU_KMS_REGION`, `MERU_KMS_ENDPOINT`) |
| `MERU_LINEAGE_KEY` | `MERU_KEY` | Seed for the F1 lineage record (required with KMS) |
| `MERU_KEY_ID` | signer key ID | Key ID placed in verdicts |
| `MERU_LICENCE_PUBKEY` | — | Vendor licence public key(s) |
| `MERU_LICENCE_ROOT_KID` | — | Root key ID(s) allowed to retire keys |
| `MERU_REVOCATIONS` | required | Signed revocation list path, or `none` (development) |
| `MERU_ALLOW_UNAUTHENTICATED` | — | `1`: no licence check (development) |
| `MERU_METER_LOG` | `meru-meter.jsonl` | Meter log path |
| `MERU_RATE_PER_MIN` / `MERU_DAILY_QUOTA` | 10 / 200 | Per-licence limits |
| `MERU_PROBE_DISTINCT_PER_HOUR` / `MERU_PROBE_BLOCK_S` | 60 / 3600 | Probe detector |
| `MERU_OUTPUT_SIGFIGS` | 3 | Significant figures kept |
| `MERU_MAX_CONN` / `MERU_MAX_JOBS` | 64 / CPUs | Capacity caps |
| `MERU_MAX_BODY` / `MERU_MAX_CELLS` | 2 MiB / 40000 | Request limits |
| `MERU_READ_TIMEOUT_S` / `MERU_WRITE_TIMEOUT_S` | 15 / 30 | Connection timeouts |

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

## Status (v2, 19 November 2026)

Hardened for the open internet: revocation, KMS signing, per-licence limits, probe detection,
output rounding, metering, request and connection limits, CI, deployment files. Tested: 12 unit
tests and an end-to-end test over a real socket (licences issued and revoked with the vendor
tools; every protection above exercised).

Still open (owner): the production host and keys (deploy/README.md checklist); patent filing;
customer terms. CI needs the `KSHANA_PRO_READ_TOKEN` repository secret.
