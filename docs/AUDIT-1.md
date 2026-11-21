# audit-1: conventions, units and API hardening of the hosted methods

Scope: the hosted verdict methods. Each was checked for three things:

1. **Conventions** where two inputs are combined: time scale (UTC, GPS, TAI, TT), frame
   (ECEF, ECI, GCRS, ITRS, RTN, ENU) and sign ("A − B").
2. **Units** implied by field names: dB against linear, ns against s against ps, deg against
   rad, m against km.
3. **API hardening** of the public endpoints: body size, rate limits, numeric ranges, no panics
   on malformed input, and bounded work per call.

The methods covered are calibrate, timing-correlation, gnss-leo-arbitration, delay-calibration,
ntrip-qos, flight-integrity, parametric-trigger (the insurance oracle), spaceweather,
perception-eval, feeder-trust, lunar-assist, rtk-quality, vision-claims and survey-plan.

Method: each module was read against its own documented conventions. Every reported finding was
then re-checked in the code. A fuzz-style test (`server::fuzz_tests`) mutates a valid request
for every endpoint field by field and runs it through the server's own dispatch.

**Fixed?** values in the table below:

* **fix** — a real bug, fixed on branch `meru/audit-1-fixes`, with a test and a CHANGELOG line.
* **audit-1** — a documentation or assertion gap, fixed on branch `meru/audit-1`.
* **open** — not changed; a decision or a larger change is proposed.

| # | Location | Issue | Risk | Fixed? |
|---|---|---|---|---|
| 1 | `ntrip_qos.rs` `analyse` | A summary whose window ended more than 30 days ago was stored, left out of the population, then looked up in it by index: **panic** (that call's thread fails). A future-dated window stayed in the population and shadowed later windows. | high (any licensed caller) | fix |
| 2 | `lunar_assist.rs` fit-arc guard | Compared `fit_s` (seconds) with a bound in hours, so it never fired. With `fit_hours` < 2.5 h, padding nodes before the arc took the epoch position. | medium (misconfiguration only; shipped 24 h) | fix |
| 3 | `gnss_leo.rs` `combine` | Single-family cap 0.75 > decision threshold 0.7: one family decided, against the documented rule. | high (changes `suspect`) | fix |
| 4 | `timing_correlation.rs` window grid | Window ends were on a per-site grid. Sites starting at times not 5 s apart never formed a group, and detection came later from wider groups or single sites. | high (detection timing) | fix |
| 5 | `timing_correlation.rs` `dt_s` | `dt_s` above about 13 s left fewer than 10 samples per 120 s window, so it returned no episodes silently. | medium | fix (refused above 12 s) |
| 6 | `parametric_oracle.rs` evaluation | Samples were assumed ascending and never sorted. Out-of-order samples gave negative intervals, and the trigger state could flip. | high (trigger state) | fix |
| 7 | `flight_integrity.rs` `compare` | A missing or unknown attestation `statement` ranked as most severe and never mismatched, so the attestation was reported as agreeing. | high | fix |
| 8 | `spaceweather.rs` validity | `valid_until` was `newest.max(at)` + hold, always `at` + hold, so an advisory outlived its inputs. | medium | fix |
| 9 | `spaceweather.rs` Kp loader | Files were taken in reverse name order and the first with any value at or before `at` won, so an archive file sorting last hid newer Kp. | medium (depends on file naming) | fix |
| 10 | `feeder_trust.rs` `tier_of` | The attestation was checked at the window start only, so a window running past expiry stayed attested at full weight. | medium-high | fix |
| 11 | `feeder_trust.rs` score | `floor(score·20)/20` floored 0.39999999999999997 to 0.35, losing a 0.05 step. | low (no class threshold crossed) | fix |
| 12 | `methods.rs` survey | Work is budget × candidates × cells (every cell is a candidate when none are given). Within 40,000 cells and budget 50, one call could run for hours: a **denial of service**. | high (public endpoint) | fix (`MERU_MAX_SURVEY_WORK`, default 5e6) |
| 13 | `cause.rs` `parse_iso`, `lunar_assist.rs` `parse_iso_s` | A day not in its month (2027-02-31) rolled over silently. | low | audit-1 (refused) |
| 14 | all methods, `Time` | Every time input is UTC; a GPS-time stamp is read 18 s late. This was undocumented. | medium (caller error) | audit-1 (documented at `parse_iso`) |
| 15 | `delay_cal.rs` | Negative standard uncertainties (antenna, reference) passed and vanished into the RSS. Assumed delays were not checked for being finite. | low | audit-1 (refused) |
| 16 | `parametric_oracle.rs` series | Site latitude and longitude were not range-checked. | low | audit-1 (refused) |
| 17 | `spaceweather.rs` regions | A longitude in 0..360 missed region boxes given in −180..180. | medium | audit-1 (normalised) |
| 18 | `parametric_oracle.rs` doc | C/N0 dB-Hz statistic (mean of dB against dB of mean) undocumented; `period_index` (a share) against `index_db_h` (dB·h). | doc | audit-1 |
| 19 | `gnss_leo.rs` doc | "Lost satellites" was listed as an indicator, but `n_sats` is unused. Tie handling and the offset sign were unstated. | doc | audit-1 |
| 20 | HTTP layer (`server.rs` `parse`) | Body ≤ 2 MB, header line and count limits, one `Content-Length`, chunked refused, 15 s read timeout, 64 connections, 60 per minute per address, plus per-licence rate and quota. | — | checked, no change |
| 21 | all endpoints | Malformed and extreme JSON: no panic on any mutation (fuzz test), and no non-finite number in an accepted answer. JSON cannot carry NaN or inf; `1e400` is refused by the parser. | — | audit-1 (test) |
| 22 | `perception_eval.rs`, `vision_claims.rs` | Epochs with protection level > alert limit count as "available", while a comment calls them unavailable. Availability and HMI-rate denominators depend on this. | medium (definition) | open: which definition? |
| 23 | `flight_integrity.rs` | A regional report with no location matches anywhere. `longest_gap_s` ignores telemetry gaps (no epochs). `near_total` and `shared_total` may come from different intervals. | medium | open (design) |
| 24 | `lunar_assist.rs` overbound | Each age bin's sigma is placed at the bin's upper edge, so it may under-cover the young end of a bin when error grows with age. | medium-low (integrity margin) | open (needs a study) |
| 25 | `lunar_assist.rs` SP3 | The time system in the SP3 header is not checked (taken as GPST). | low (IGS products are GPST) | open |
| 26 | `calibrate.rs` work | Work is bounded only by the product of the limits (parameters × observations × nodes × iterations), about 1e11 at the limits. | medium (licensed endpoint) | open: propose a product bound like #12 |
| 27 | `parametric_oracle.rs`, `rtk_quality.rs`, `feeder_trust.rs` work | Neighbour and episode scans are quadratic in the request: episodes × neighbours × samples; outages × epochs; bins × neighbours, streams². | medium | see below |
| 28 | `timing_correlation.rs` | With fewer than 10 baseline points the site's own drift baseline is 0. | low | open (doc) |
| 29 | `ntrip_qos.rs` | The store is re-read on every call, so cost grows with the store. | low now | open |

Each method's own conventions that were checked and found consistent (frames, signs, units)
are listed in the audit report to the coordinator. Nothing here changes a frame or a sign
convention: none of the reported errors was in a frame or a sign.
