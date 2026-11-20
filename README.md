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
| `POST /verdict/cause`   | `cause` — what caused a vessel or aircraft position episode | classification (jamming / spoofing / self-reported track falsification / equipment fault / insufficient evidence), confidence in steps of 0.05, the episode window, the findings at outcome level, three answers (is the reported track false, was there RF interference, origin) |
| `POST /verdict/calibrate` | `calibrate` — general parametric calibration of a simulator against telemetry (F1's verdict for any model) | convergence, fidelity before/after, calibrated parameters + uncertainty and correlation, parameters at a bound or not constrained, signed lineage head |
| `POST /verdict/lunar-assist` | `lunar-assist` — long-validity lunar GNSS assistance packages | a signed `ks-lunar-gnss-assist/1` package (GNSS ephemeris and clock prediction for the satellites asked for, with a per-satellite integrity bound and an optional lunar time reference) and a statement on what the bound rests on |
| `GET  /health` | liveness | `{"ok":true}` |

Internals — per-iteration records, parameter state, the regenerated scenario, the full PL
grid, and for `cause` the per-class scores, weights and thresholds — stay in the service and
are never returned.

### `cause`: the cause of a position episode

For marine insurers (a claim cannot rest on the AIS track of a spoofed period), coastal states
(enforcement without an evidence standard), sanctions screening (a ship that falsified its own
AIS versus one that was the victim of interference) and LRIT/ECDIS disputes.

Request (JSON; times ISO-8601 UTC or Unix seconds):

| Field | Meaning |
|---|---|
| `platform` | `vessel` or `aircraft` |
| `subject_id` | MMSI, IMO, ICAO address (echoed, not used) |
| `window` | optional `{start_utc, end_utc}`; default the reported track's extent; at most 7 days |
| `reported` | the AIS/ADS-B track: `[{t, lat_deg, lon_deg, sog_kn?}]`; a report with no position (AIS 91/181) has the coordinates omitted |
| `independent` | optional tracks: `{source, id, positions, sigma_m?}` with `source` one of `radar`, `coastal_radar`, `sar`, `optical`, `mlat`, `other` (independent of the platform's GNSS), `lrit`, `secondary_gnss` (separate GNSS receivers on board), `sat_ais`, `coastal_ais` (relays of the platform's own reports; give `receiver_lat_deg`, `receiver_lon_deg`, `range_km` to test reception geometry) |
| `receiver` | optional onboard GNSS log: `epochs: [{t, fix?, cn0_dbhz[]? or cn0_mean_dbhz?, n_sats?, agc_db?, lat_deg?, lon_deg?, clock_bias_ns?}]`, optional `baseline_cn0_dbhz`, `baseline_agc_db`; epochs before the window serve as the baseline |
| `regional` | optional `kshana-pnt-interference-event/1` reports; supplying the list (even empty) states that regional monitoring covered the window |

The method is physics and consistency, not a learned model: kinematic plausibility (jumps,
frozen or circling tracks, silences, reported speed against positions), cross-source
disagreement patterns (which sources are independent of the platform's GNSS, which receivers
agree with which, relay reception geometry), signal-level signatures (broad C/N0 loss with the
AGC pulled down, C/N0 loss with normal AGC, uniform C/N0 rise, clock steps, loss of fix under
normal signals) and regional correlation. Findings combine into a confidence that is capped by
the number of independent lines of evidence; below 0.6 the answer is `insufficient_evidence`
(with the leading hypothesis). Request limits (before any work): 20,000 reported and 20,000
independent positions (`MERU_MAX_TRACK_POINTS`), 32 independent tracks, 50,000 receiver epochs
(`MERU_MAX_EPOCHS`), 64 satellites an epoch, 500 regional reports, a 7-day window.

Evidence class **MODELLED**: checked on synthetic episodes with known cause (one per class,
an aircraft case, and a randomised 120-episode ensemble on which stated confidence was not
above accuracy). Not validated on a labelled set of real incidents. It is an engineering
reconstruction, not a legal finding, and does not assess intent.

### `calibrate`: general parametric calibration against telemetry

F1 (`selfcal`) calibrates one model family (radio timing reference simulators in the Kshana Pro
scenario format). `calibrate` returns the same verdict for any simulator whose behaviour depends
on named parameters: power, thermal, clock, attitude, propulsion or a whole mission performance
simulator. Its client is Arksa's simulator recalibration (`arksa-kpro simcal`, AK8), whose answer
checks read `converged`, `stop_reason`, `passes`, `fidelity_first`, `fidelity_last`,
`posterior` (`{name, value, std_err}`) and `lineage.head`; this method returns exactly those.

Request (JSON; unknown fields refused):

| Field | Meaning |
|---|---|
| `subject` | optional label, echoed |
| `parameters` | `[{name, prior?, prior_sigma?, lower?, upper?, initial?}]`, at most 32; no `prior_sigma` is a flat prior |
| `model` | `{"kind": "expression", "observables": {"<observable>": "<expression in t and the parameters>"}}`, or `{"kind": "design", "runs": [{"params": {...}, "predictions": {"<observable>": [[t_s, value], ...]}}]}` |
| `observations` | `[{observable, t_s, value, sigma}]`, at most 20,000, and observations × parameters at most 200,000 |
| `tolerances` | optional per-observable fidelity tolerance (default 2 sigma) |
| `options` | `{max_iter}` (default 50, at most 100) |

* **expression**: arithmetic in `t` (s), `pi` and the parameters: `+ - * / ^`, parentheses and
  `exp ln log10 sqrt abs sin cos tan asin acos atan tanh sinh cosh min max pow atan2`; nothing
  else (at most 2,000 characters and 1,000 nodes).
* **design**: runs of the caller's own simulator at chosen parameter sets (at most 256 runs and
  500,000 prediction points). The service fits a quadratic response surface per observation
  (linear or without cross terms when the runs are few), adds its leave-one-out error to each
  observation's uncertainty and keeps the parameters inside the design's range. Any black-box
  simulator can be calibrated this way without the service running it.

Method (server-side): Levenberg–Marquardt on the whitened residuals plus the priors, in
coordinates that respect the bounds; uncertainty from the information matrix in physical
coordinates, inflated by the reduced chi^½ when above 1 (the F1 convention). The verdict adds
`chi2_reduced_first/last`, `n_obs`, `correlation`, `at_bound`, `not_constrained` (posterior not
narrower than 90 % of the prior), for a design `surface` (kind, runs, leave-one-out error), and a
lineage (initial and calibrated state hash-chained over the telemetry and model digests, with an
HMAC tag under the lineage key). Residuals, Jacobians, the surface and the iteration trace stay in
the service.

Evidence class **MODELLED**: checked by recovering known parameters of synthetic thermal, power
and black-box simulators (estimates within 4 standard errors; 2-standard-error coverage checked
over 20 noise draws), bounds and unconstrained parameters flagged. Calibrated parameters are what
best explains the telemetry supplied under the model supplied, not a validation.
### `lunar-assist`: long-validity lunar GNSS assistance packages

Lunar receivers mostly cannot decode GNSS navigation data at lunar C/N0, so they need a
ground-made ephemeris and clock prediction uploaded to them, valid for a day or more, with an
integrity bound (JAXA LNSS wants "at least 24H as effective age" for more than 60 GPS and
Galileo satellites; vcprep research 2026-11-20 report 13, findings 4–6, gap N7). The client is
Arksa's `arksa-kpro lunar-time assist request` (AK6), which posts this request and checks the
answer (signed verdict, method `lunar-assist`, package answers the request).

Request (JSON, as the Arksa client sends it; unknown fields refused):

| Field | Meaning |
|---|---|
| `satellites` | GNSS ids (`G01`, `E11`; G, E, R, C or J), at most 128 (`MERU_ASSIST_MAX_SATS`) |
| `validity_start` | start of validity, ISO, GPST, whole second |
| `validity_hours` | length of validity, at most 72 h |
| `step_s` | node spacing, 30–900 s |
| `integrity_risk` | largest integrity risk per independent sample, in (0, 0.5) |
| `lunar_time` | optional `{registry_id, registry_version, definition_id}`: the lunar time definition the user maps GNSS time with |

Answer: the verdict body carries `package` (format `ks-lunar-gnss-assist/1`, the client's
field order: GPST epoch grid with five extra nodes on each side of validity, ECEF positions in
mm and clocks in ps per satellite, the interpolation rule, the validity window, per satellite
`bound {sigma0_m, growth_m_per_h, growth2_m_per_h2, integrity_risk}` with `sigma(age)` in hours
from the start of validity, the lunar time reference, and the package's own Ed25519 signature by
the service key, because a package travels on to a receiver without the verdict envelope),
`source` (number and digest of the products used, data end, age of the data at the start of
validity), `integrity` (samples, the age the bound was tested to, whether the package asks for
more and the bound is then extrapolated, the lowest integrity risk the samples support at 95 %
confidence, and whether the requested risk is within that support) and `notice`. Bounds are
rounded up and the risk down to the service's significant figures, so output rounding leaves the
signed package unchanged.

The method stays in the service: per satellite, a batch least-squares fit of the open engine's
precise force model to the last `fit_hours` of observed positions (GCRS by the CIO chain),
propagated across the grid; a quadratic clock fit; and an integrity bound from re-running the
same pipeline from earlier cutoffs in the source history and comparing with what followed
(the conservative range error `|dr| + c|dt|` against age), overbounded per constellation and
age bin with confidence, enveloped over age, inflated per satellite where its own errors need
it, and shifted to the package's age origin. The fits, backtest errors, bins and coefficients are
not returned.

Configuration: `MERU_ASSIST_SOURCE` (directory of observed SP3 products in GPST, for example the
observed half of IGS ultra-rapid or rapid products; the 16 newest by name are read on each call;
without it the method answers "not offered"), `MERU_ASSIST_EOP` (finals2000A; without it UT1 =
UTC and no polar motion, applied identically both ways), `MERU_LUNAR_REGISTRIES` (further lunar
time registry files; version 1 is built in, a verbatim copy of Arksa's), `MERU_ASSIST_FIT_HOURS`
(24), `MERU_ASSIST_BACKTESTS` (4, spaced 6 h). The source must hold about `fit_hours` + 24 h of
history before the start of validity for the bound, and end no more than 24 h before it.

Evidence class **MODELLED**: checked on synthetic constellations (truth propagated with a richer
force model than the service fits, clocks with random-walk noise): 24 h-ahead errors of a few
metres, every error inside `K·sigma` for `K` = 5.33. Not yet scored against later precise
products over a campaign; the package format is a proposal, not a standard; no international
lunar time definition is adopted (the registry is PROVISIONAL). Below `lowest_risk_supported`
the bound rests on the Gaussian tail assumption, which the verdict states. Civil GNSS orbit and
clock prediction only.

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
| Rebuilding it from many answers | Outputs rounded (3 significant figures, angles to 1e-4 deg); per-licence rate (10/min) and daily quota (200); a probe detector pauses a licence that sends more than 60 distinct requests in an hour and raises an alert; the full survey grid only for Enterprise; `cause` returns no scores, weights or thresholds and a confidence in steps of 0.05 |
| A patient or split sweep | Query-pattern audit over 7 days: Sobol/Halton, Latin hypercube, grid and uniform-fill signatures per licence and across licences; alerts, delayed verdicts, optional pause and per-region cap; per-address rate; honeypot paths (see "Anti-extraction" below) |
| Reselling or copying verdicts | Each verdict names the licence it was issued to inside the signed body; numbers carry a keyed per-licence fingerprint inside one unit of their last figure, with canary cells; an ownership test names the licence from about 50 verdicts |
| Stolen or cancelled licence | Signed revocation list, hot-reloaded |
| Forged verdicts | Ed25519 signature; the verdict key can live in AWS KMS (`MERU_SIGNER=kms`) so a stolen disk holds no key; every signature self-checked |
| Flooding | Connection cap, running-job cap, read/write timeouts, bounded headers and body, chunked bodies refused, request-size limits checked before any work; nginx limits in front |
| Audit | Meter log: one line per call with hashes only, rebuilt into quotas on restart |

Customer terms must also forbid reverse engineering and systematic querying (legal). The fingerprint and the
audit must be disclosed in the customer terms before they are switched on in production (owner
decision).

## Anti-extraction (E27)

Literature: model extraction from answers alone is slowed, not stopped, by rounding; what works
is watching the query distribution (PRADA) and marking outputs so a copy can be traced. The
red-team harness below measures this on F2.

### Query-pattern audit (`src/audit.rs`)

Each admitted call is reduced to a *shape* (method + the sorted numeric field paths; arrays
longer than 16 become length, mean and spread; strings ignored) and a vector of numbers. Per
shape, every 8 calls, the service judges the licence's distinct points (normalised per varying
input) and, separately, every licence's points together:

| Signature | Rule (defaults) | Typical source |
|---|---|---|
| `low_discrepancy` | centred L2 discrepancy ≤ 0.35 × its expectation for independent uniform points | Sobol, Halton |
| `stratified` | every varying input ≥ 90 % distinct values, no gap wider than 2.5 × even spacing | Latin hypercube |
| `grid` | ≥ 3 evenly spaced values per input, ≥ 70 % of combinations used | full-factorial grid |
| `uniform_fill` | ≥ 96 points, discrepancy ratio ≤ 1.6, ≥ 60 % of coarse cells filled | independent uniform sampling |

Nothing is judged below 32 distinct points of one shape. **Cross-licence**: the union of all
licences' points of a shape (the latest 512 points of the 12 most active licences); licences that make it less uniform (ordinary clustered users) are
dropped one at a time; if two or more remain and the rest is space-filling, the licences the
pattern needs are named (`cross_licence`). On an alert: a meter-log line (`outcome`
`extraction_alert`, the shape hash, statistics and token IDs, never field names or values), an
`[meru][ALERT]` stderr line, and the licence is *suspect* for 24 h: its verdicts are delayed by
3 s, and refused with `MERU_AUDIT_PAUSE=1`. `MERU_REGION_CELLS_PER_DAY` caps new coarse input
cells (about 3 % steps per number) per licence per UTC day (off by default). Checked on
synthetic traffic: Sobol, Latin hypercube, grid and 128 uniform points flagged; ten runs of 200
clustered "real use" requests not flagged; a Sobol sweep split over three licences (30 calls
each, under the single-licence minimum) flagged and the three named, a bystander of the same
shape not named. False positives are possible (an evenly spaced 40-value trade study), hence
alert-and-delay by default.

**Privacy and retention**: in memory only — token ID, time, shape hash and the numbers rounded
to 4 significant figures — for 7 days (`MERU_AUDIT_WINDOW_S`), at most 4,096 points per shape
and 20,000 shapes; a restart starts afresh. Client addresses for the per-address limit are held
for one minute and never logged. Alerts stay in the meter log under its retention.

**Honeypots**: `POST /verdict/survey/grid`, `/verdict/selfcal/trace`, `/verdict/cause/scores`,
`/verdict/calibrate/residuals`, `/verdict/internal/params`, `/verdict/debug/model` answer exactly
like an unknown path (404); a licensed caller is marked suspect and a `honeypot` line is logged.

### Licence-bound verdicts

Every verdict outcome carries `"licence": {"token_id": "<the caller's token ID>"}` inside the
signed body, so a verdict passed on still names its licence, and changing it breaks the
signature. Existing clients verify unchanged (the field is inside `verdict`). The
`lunar-assist` package keeps its own format; its envelope is bound.

### Keyed fingerprints and canaries (`src/fingerprint.rs`)

For the numbers in a method's plan, the service rounds up or down instead of to nearest; the
direction is HMAC(licence key, method, coarse input cell, quantity family), the licence key
derived from the epoch key and the token ID. Plans: `survey-plan` (coverage before/after and per
pick; mean PL before/after and per pick), `selfcal` (posterior values), `calibrate` (posterior
values, reduced chi² first/last). Not fingerprinted: `cause`, `lunar-assist`, angles, integers,
counts, fidelity, classifications, confidences, uncertainties.

**Bound** (each method's stated output tolerance):
* every fingerprinted number is within **one unit in its last significant figure** of the
  unrounded value (nearest rounding: half a unit);
* a number with a stated standard uncertainty (`std_err`) is fingerprinted only when one unit
  in its last figure is **at most 0.2 of that uncertainty**;
* a number is never moved onto or off a value with fewer significant figures (0, 1, 0.9, 300),
  so comparisons with such thresholds answer as without the fingerprint;
* one direction per quantity family per verdict, and a family whose order would change stays at
  nearest rounding (coverage after ≥ before, picks in order);
* **no verdict class changes** (classifications, `converged`, `stop_reason`, chosen points).

Removing the fingerprint without the key means moving every listed number by up to one unit in
its last figure at random. Requests in the same coarse cell get the same directions, so
re-asking near-identical questions does not average it away. About one cell in 64 is a
**canary** cell (secret, keyed by the epoch) where every licence gets the same pattern; a copy's
match there shows it derives from meru answers whatever licence was used. The meter log marks
calls in canary cells (`"canary": true`).

**Keys**: `MERU_FINGERPRINT_KEYS` = a JSON file of epochs (`meru-fingerprint-keys/1`); the
latest whose `from_unix` has passed is in force. `meru fingerprint-keys rotate <file> [--from
<unix>]` adds a random epoch (file mode 0600). Never delete epochs: the file is the escrowed
history the ownership test needs; keep it in the secrets manager with a backup. Unset: no
fingerprint (warning at start).

**Ownership test**: `meru ownership --keys <file> --suspects <jsonl> (--licences <ids> | --meter
<meter log>)`; each line `{"method", "request", "verdict"}`. The service recomputes the
unrounded outcome, reads which way each family was rounded (one bit per input cell and
family), and scores every (licence, epoch). A licence is named when it explains ≥ 90 % of ≥ 16
bits at a chance below 1e-6 after multiplying by the candidates tried, clearly ahead of the
runner-up. Checked: 50 survey verdicts among 10 licences name the right one (every bit
matching) under an epoch since rotated; plainly rounded numbers, or numbers re-rounded to two
figures, name nobody.

### Red-team harness (`src/redteam.rs`, `meru redteam`)

A copier with one Pro licence sweeps three F2 inputs (station C latitude and longitude, noise
scale) with a Sobol sequence, one call every 10 minutes, and fits a Gaussian-kernel ridge
surrogate (length scale and ridge by leave-one-out). Result (`meru redteam`, default budgets,
64 held-out inputs; normalised RMS error against the unrounded answer):

| Queries | 16 | 32 | 64 | 128 | 256 |
|---|---|---|---|---|---|
| `mean_pl_before_m` (the error model, smooth) | 0.166 | 0.058 | **0.024** | 0.013 | 0.007 |
| `mean_pl_after_m` (the planner's choice) | 0.294 | 0.261 | 0.219 | 0.185 | 0.156 |

The smooth part is copied to within 5 % in about **64 queries**; the planner's outcome was not
within 5 % at 256. The old limits refused none of the copier's calls; the audit alerted at call
**32** (`low_discrepancy`, `stratified`); split over three licences, the cross-licence alert
named all three; 200 calls of ordinary use by three customers raised no alert; the ownership
test named the copier from 50 passed-on verdicts (95 of 95 bits). The surrogate's own
predictions do **not** carry the fingerprint (9 of 13 bits, most numbers foreign): the
fingerprint traces verdicts and copied tables, not a model refitted from them. Evidence class
**MODELLED**: one copier strategy on one configuration family; a better copier may need fewer
queries. Detection, delay and terms are what stop a sweep; rounding alone does not.

## Client

Customers call it with the Pro command line, which verifies every verdict against the pinned
service public key before accepting it:

```
kshana-pro verdict survey request.json --url https://<host> --out verdict.json
kshana-pro verdict cause episode.json --url https://<host> --out verdict.json
kshana-pro verdict calibrate request.json --url https://<host> --out verdict.json
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
| `MERU_MAX_TRACK_POINTS` / `MERU_MAX_EPOCHS` | 20000 / 50000 | `cause` request limits |
| `MERU_READ_TIMEOUT_S` / `MERU_WRITE_TIMEOUT_S` | 15 / 30 | Connection timeouts |
| `MERU_ASSIST_SOURCE` | — | `lunar-assist` source products (directory of SP3); unset: method not offered |
| `MERU_ASSIST_EOP` | — | finals2000A Earth orientation for `lunar-assist` |
| `MERU_LUNAR_REGISTRIES` | — | Extra lunar time registry files (comma separated) |
| `MERU_ASSIST_FIT_HOURS` / `MERU_ASSIST_BACKTESTS` / `MERU_ASSIST_MAX_SATS` | 24 / 4 / 128 | `lunar-assist` settings |
| `MERU_FINGERPRINT_KEYS` | — | Fingerprint key epochs file; unset: no fingerprint |
| `MERU_RATE_PER_IP_PER_MIN` | 60 | Calls a minute per client address (0 = off) |
| `MERU_TRUST_PROXY` | — | `1`: client address from `X-Real-IP` on loopback connections (nginx) |
| `MERU_AUDIT_WINDOW_S` / `MERU_AUDIT_MIN_POINTS` | 604800 / 32 | Audit memory and smallest judged set |
| `MERU_AUDIT_SUSPECT_S` / `MERU_AUDIT_DELAY_MS` / `MERU_AUDIT_PAUSE` | 86400 / 3000 / — | How long a flagged licence stays suspect, its verdict delay, `1` to refuse instead |
| `MERU_REGION_CELLS_PER_DAY` | 0 (off) | New coarse input cells per licence per day |
| `MERU_HONEYPOTS` | built-in list | Comma-separated honeypot paths, or `none` |

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

## Status (v2, 19 November 2026; `cause` and `calibrate` added 20 November 2026)

Hardened for the open internet: revocation, KMS signing, per-licence limits, probe detection,
output rounding, metering, request and connection limits, CI, deployment files. Tested: 33 unit
tests (15 for `cause`, 6 for `calibrate`) and two end-to-end tests over a real socket (licences
issued and revoked with the vendor tools; every protection above exercised, `cause` included;
`calibrate` accepted by the Pro verdict client).
## Status (v2, 19 November 2026; `cause` and `lunar-assist` added 20 November 2026)

Hardened for the open internet: revocation, KMS signing, per-licence limits, probe detection,
output rounding, metering, request and connection limits, CI, deployment files. Tested: 34 unit
tests (15 for `cause`, 7 for `lunar-assist` and its registry) and two end-to-end tests over a real
socket (licences issued and revoked with the vendor tools; every protection above exercised,
`cause` included; `lunar-assist` from a synthetic SP3 product, accepted by the Pro verdict
client).

Anti-extraction (E27, 20 November 2026): query-pattern audit, cross-licence correlation,
per-address limit, honeypots, delayed verdicts, licence-bound verdicts, keyed fingerprints with
canaries and key rotation, ownership test, red-team harness. Tested: 56 unit tests and four
end-to-end tests (the fourth: bound and fingerprinted verdicts accepted by the Pro client,
ownership test naming the licence, honeypot, audit alert and delay, per-address limit).

Still open (owner): disclose fingerprinting and auditing in the customer terms before turning
`MERU_FINGERPRINT_KEYS` on; the production host and keys (deploy/README.md checklist); patent filing;
customer terms. CI needs the `KSHANA_PRO_READ_TOKEN` repository secret.
