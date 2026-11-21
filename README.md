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
| `POST /verdict/victim-actor` | `victim-actor` — was a vessel's AIS position the victim of external interference, or does the evidence fit manipulation of its own reports | `victim` / `actor` / `indeterminate`, confidence in steps of 0.05 with a leave-one-family-out interval, the episode window, findings at outcome level, three answers (is the reported track false, was the anomaly shared with nearby vessels, did regional monitoring report interference) |
| `POST /verdict/rtk-quality` | `rtk-quality` — RTK correction-service quality across many monitoring receivers | per mountpoint: fix availability and wrong-fix rate with 95 % intervals, error percentiles and growth with baseline, time to fix, correction age, the caller's targets met / not met / not shown; outage episodes read by scope (monitor, mountpoint, wide area) and correction freshness |
| `POST /verdict/flight-integrity` | `flight-integrity` — a signed per-flight positioning-integrity verdict for a drone flight | `NOMINAL` / `DEGRADED` / `INTEGRITY-SUSPECT` from the telemetry, recomputed; attribution `area` / `aircraft` / `indeterminate` from other flights nearby and regional reports, confidence in steps of 0.05; the client attestation's SHA-256 and whether it agrees |
| `POST /verdict/parametric-trigger` | `parametric-trigger` — a neutral oracle for a parametric GNSS-outage trigger on the service's station archive | `fired` / `not_fired` / `insufficient_data`, events with the outage index (dB·h), coverage, digests of the definition and the data used; never a payout |
| `POST /verdict/policy-wording` | `policy-wording` — which facts of a **synthetic** wording the signed PNT evidence answers | per fact `supported` / `not_supported` / `not_determinable` with the verdict it rests on; per clause counts and a reading; never a coverage position |
| `POST /verdict/spaceweather` | `spaceweather` — space-weather advisory per location and positioning service from live ionosphere inputs and per-region thresholds | per location: region, indicator levels (Kp, ROTI, S4), overall level and driver, `go` / `caution` / `no_go` for RTK, PPP and single-frequency, validity; the G scale and digests of the inputs |
| `POST /verdict/perception-eval` | `perception-eval` — an **evaluation** of a perception-aided positioning system's outputs, landmark identifications and integrity claims against tester truth | overall and per condition: availability, nominal / misleading / hazardously misleading counts and rates with 95 % intervals, error percentiles, protection-level tightness; landmark recall, precision, misidentification; claims met / not met / not shown |
| `POST /verdict/feeder-trust` | `feeder-trust` — how far each feeder of a crowd-sourced GNSS monitoring network can be trusted | per feeder: `trusted` / `probation` / `untrusted` / `insufficient_overlap`, a score in steps of 0.05, reasons and counts (provenance, corroboration by nearby feeders, duplicate streams, continuity) |
| `POST /verdict/archive-seal` | `archive-seal` — a signed, chained Merkle seal over a period of an evidence archive | the Merkle root over the entries' names and digests, count, bytes, period, sequence number and the previous seal it chains to |
| `POST /verdict/archive-query` | `archive-query` — aggregates of the observation archives by domain (incidents, ASF, LF noise, OSNMA failures, AIS vs RF, holdover, station KPIs) | per group: count, sources, mean, median, 95th percentile, maximum; small groups suppressed; never a row |
| `POST /verdict/vision-claims/register`, `POST /verdict/vision-claims` | the neutral vision-navigation claims test: register claims, then score a later campaign | a signed protocol; then per claim `shown` / `contradicted` / `not_shown` with the measured value, the 95 % interval and the campaign size needed |
| `POST /verdict/timing-correlation` | `timing-correlation` — cross-grandmaster and cross-operator correlation of timing offsets | correlated drift episodes (detection time by the group test and by the earliest single site, rate, sites and operators, scope: regional, constellation-wide, operator-wide, single site) and a NOC alert feed |
| `POST /verdict/gnss-leo-arbitration` | `gnss-leo-arbitration` — after the fact, which of a GNSS and a LEO timing solution the evidence supports when they disagree (evaluation evidence only) | per disagreement episode: the suspect source, the source the evidence supports, a confidence in steps of 0.05 and the findings; an integrity statement over the window |
| `POST /verdict/delay-calibration` | `delay-calibration` — a GNSS timing receiver's delay calibrated against a reference receiver, with a GUM uncertainty budget | per code: the delay (ns, and integer ps), standard and expanded (k = 2) uncertainty, the budget by component, tracks used and rejected |
| `POST /verdict/scorecard` | the insurer portal: a scorecard over the signed verdicts a policyholder shared (insurer licences in `MERU_INSURER_PORTAL`) | per method: verdicts, period, outcomes; never an underwriting decision |
| `POST /verdict/benchmark` | contributor-only population benchmark of an archive domain (contributors in `MERU_CONTRIBUTORS`) | the population's percentiles over sources and the contributor's own source's rank |
| `GET  /portal` | the insurer portal page (static, strict CSP) | a page that calls `POST /v2/verdict/scorecard` and shows the signed scorecard |
| `GET  /versions` | the API version policy | versions, paths, status, earliest sunset |
| `POST /verdict/ntrip-qos` | `ntrip-qos` — NTRIP caster and mountpoint quality-of-service scorecard from contributed monitor summaries (contributors only, give to get) | per mountpoint and per caster: score and components, population percentiles and rank (suppressed below five sources) |
| `GET  /health` | liveness | `{"ok":true}` |
| `GET  /crl` | the product register's revocation list (no licence needed) | the signed `kshana.register-crl/1` document |
| `POST /verdict/crl/revoke` | revoke a register entry (operator licences in `MERU_CRL_ADMINS`) | the revocation and the newly signed list |
| `POST /verdict/tlog/append` | log a signed evidence pack's SHA-256 in the transparency log (licensed) | index, inclusion proof and the signed tree head |
| `GET  /tlog/sth`, `/tlog/proof`, `/tlog/consistency`, `/tlog/entry`, `/tlog/find` | the transparency log's public read side | signed tree head; inclusion and consistency proofs; an entry (hashes only) |

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

### `victim-actor`: was the vessel spoofed, or did it manipulate its own AIS?

For sanctions screening and due diligence (a ship whose AIS went wrong: interference victim or
dark-fleet behaviour), insurers and coastal states. `cause` names the cause of one platform's
episode from its own sources and receiver; `victim-actor` adds what `cause` cannot see: the
other vessels in the same area at the same time. Interference rarely singles out one ship; a
falsified track does.

Request (JSON; times ISO-8601 UTC or Unix seconds; unknown fields refused):

| Field | Meaning |
|---|---|
| `subject_id` | MMSI or IMO (echoed, not used) |
| `window` | optional `{start_utc, end_utc}`; default the subject track's extent; at most 7 days |
| `reported` | the subject's AIS track `[{t, lat_deg, lon_deg, sog_kn?}]` (at least 3 positions; `sog_kn` accepted, not used by version 1) |
| `neighbours` | optional AIS tracks of other vessels in the area: `[{id, reported}]`; identifiers count distinct vessels and are never returned |
| `observations` | optional independent confirmations of the subject's position: `[{source, id?, t, lat_deg, lon_deg, sigma_m?}]`, `source` one of `sar`, `optical`, `radar`, `coastal_radar`, `rf` (the location of the subject's own transmissions as the caller's RF system determined it), `other` |
| `regional` | optional `kshana-pnt-interference-event/1` reports; supplying the list (even empty) states that regional monitoring covered the window |

The method is physics and consistency, not a learned model, in four families of evidence: the
subject's track (capture-like jumps and circles; a track too regular to come from a GNSS
receiver at sea; silences while nearby vessels kept being received), the nearby vessels (the
same kind of anomaly at the same time, the same false position, or an unaffected
neighbourhood), the independent observations (the reported track false while it was smooth and
plausible, which fits a composed track; false while it showed capture-like anomalies, which
both causes produce and so favours neither) and the regional reports. Findings combine into a
probability for the leading side, capped by how many families support it (one family never
decides); below 0.7 the answer is `indeterminate` with the leading hypothesis. The interval is
the range of that confidence when each family of evidence is left out in turn. Request limits
(before any work): 20,000 subject positions (`MERU_MAX_TRACK_POINTS`), 200 neighbour tracks
and 200,000 neighbour positions (`MERU_MAX_NEIGHBOUR_POINTS`), 1,000 observations, 500 regional
reports, a 7-day window. The method never estimates where an interference source is.

Evidence class **MODELLED**: checked on synthetic episodes with known truth in a busy sea area
(mass spoofing of the subject and its neighbours to one circling position; a composed track
drifting smoothly off the true course; an isolated 40 km jump and back; a silence; a clean
track) and a randomised 80-episode ensemble with neighbours, SAR and regional reports present
or absent at random: 47 of 60 anomalous episodes decided, all 47 correctly (mean stated
confidence 0.885), no clean track and no isolated jump called a victim. Not validated on a
labelled set of real incidents. `actor` means the evidence fits manipulation of the vessel's own
AIS reports; it is an engineering reconstruction, not a legal finding, and does not assess
intent. The open engine's `kshana ais-integrity` gives the per-track flags; this method gives
the attribution.

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

### `rtk-quality`: RTK correction-service quality at scale

Research backlog E15, the hosted part (caster and fix verification across a network; the item
text in the backlog is to confirm against this method). For a correction-service operator, a
reseller or a large user that runs monitoring receivers on surveyed marks, each taking
corrections from one caster mountpoint. One monitor shows whether that receiver got good fixes;
many monitors over many mountpoints show whether the service did, and why not when it did not.

Request (JSON; times ISO-8601 UTC or Unix seconds; unknown fields refused):

| Field | Meaning |
|---|---|
| `subject` | optional label, echoed |
| `window` | optional `{start_utc, end_utc}`, at most 31 days |
| `tolerance` | optional `{h_m (0.10), v_m (0.20), stale_age_s (10)}`: a fixed solution outside `h_m`/`v_m` is a wrong fix; corrections older than `stale_age_s` are stale |
| `targets` | optional `{min_fix_availability, max_wrong_fix_rate, max_h95_m, max_ttf95_s}` |
| `mountpoints` | `[{id, lat_deg, lon_deg, kind?}]` (base or nominal network base position) |
| `monitors` | `[{id, mountpoint, lat_deg, lon_deg, surveyed?}]`; `surveyed: false` judges a monitor against the median of its own fixed solutions (self-consistency: jumps seen, a constant offset not) |
| `series` | one per monitor, by column: `{monitor, t0, t_s[], fix, e_mm[], n_mm[], u_mm[]?, age_s[]?}`; `fix` one character an epoch (`F` fixed, `f` float, `D` code differential, `S` standalone, `N` none); errors about the mark in mm, `null` where there is no solution |

Answer, per mountpoint: fix availability and its 95 % Wilson interval, wrong fixes and the
wrong-fix rate with its interval, 95th percentile horizontal and vertical error of correct
fixes, horizontal error growth in mm per km of baseline (three monitors or more), time to fix
after a loss (median, 95th percentile), correction age (95th percentile) and stale share, and
each target `met`, `not_met` or `not_shown` (the interval straddles the target). Across the
network: totals, the five mountpoints with the highest bound on the wrong-fix rate, and the
outage episodes (no fixed solution for a while), each with its window, the mountpoints and the
number of monitors affected and reporting, its **scope** (`monitor`, `several_monitors`,
`mountpoint`, `wide_area`), whether corrections stayed `fresh`, went `stale` or were
`not_reported`, and a reading (for example a mountpoint's monitors with stale corrections fits a
caster, base or feed problem; monitors on several mountpoints with fresh corrections fits a
wide-area signal cause or a network processing fault). Per-monitor records, the scope rules and
the episode thresholds stay in the service. Request limits (before any work): 1,000 mountpoints,
5,000 monitors, 2,000,000 epochs (the body cap bounds this first), a 31-day window.

**Base audit (B1502).** A base whose declared position is wrong moves every rover that uses it
by the same amount: the fixes stay tight and look excellent, and are wrong. Per mountpoint,
`base_audit` gives the common offset (the median over surveyed monitors of each monitor's median
fixed offset from its mark), how far the monitors scatter about it, and a finding: `consistent`,
`base_coordinate_offset` (a shared offset of 2 cm horizontally or 4 cm vertically that the monitors
agree on), `frame_epoch_mismatch` (the shared offset matches, in either direction, the
ETRS89–ITRF drift at the base for the data's epoch: the Eurasian rotation of the ITRF2014 plate
motion model, Altamimi et al. 2017, applied from 1989.0, about 2.5 cm a year and 0.9 m by late
2026; the frames' small translation and scale terms are not modelled, to confirm against the
EUREF memo; Europe only) or `not_assessable`. Monitors may name the `mark` they stand on, so
mountpoints observed at the same marks (a network VRS and a single base, say) are compared in
`mountpoint_consistency`: the median difference of their offsets, `consistent` within 2 cm
horizontally and 4 cm vertically. Checked on fixtures: a base shifted 5 cm is flagged (its fixes
still count as correct, which is the point); an ETRS89/ITRF epoch mismatch (about 0.9 m) is
flagged in both directions, while an offset of the same size in another direction is a wrong base;
a single base shifted 5 cm disagrees with a VRS at the same marks and the audit names the single
base. The frame fixture is built with the same drift function it tests; the drift itself is
checked against the published rate (2 to 3 cm a year north-east in Europe).

Nothing here locates a transmitter or an interference source; episodes are read from the
monitors' own solutions only. Not fingerprinted (statistics of the caller's own monitors and
classifications). Evidence class **MODELLED**: checked on synthetic networks with a feed stall
on one mountpoint, a wide-area loss of fix with fresh corrections, a single-monitor outage and
injected wrong fixes (scopes, freshness, counts and target checks recovered). Not validated
against an operator's incident records.

### `flight-integrity`: a signed per-flight verdict for a drone flight

Research backlog E18, the hosted part of the per-flight attestation (the item text in the backlog
is to confirm against this method). The Kshana Pro client builds a local attestation
(`kshana-pro-utm-attestation/1`) from the flight's own telemetry; this method adds what one
flight's log cannot show and signs it.

Request (JSON; times ISO-8601 UTC or Unix seconds; unknown fields refused):

| Field | Meaning |
|---|---|
| `operation` | `{id, speed_m_s, contingency_m, dr_growth_m_per_s? (2)}` |
| `telemetry` | `[{t, lat_deg, lon_deg, fix_type, eph_m?, jamming_state?, spoofing_state?}]` (the Pro telemetry CSV's columns), 2 to 100,000 epochs, at most 24 h |
| `attestation` | optional: the client's attestation JSON; its canonical SHA-256 is bound into the signed verdict and its telemetry figures are compared with the recomputation |
| `others` | optional other flights in the area and time: `[{id, telemetry}]`, at most 100 flights and 500,000 epochs; identifiers count flights and are never returned |
| `regional` | optional `kshana-pnt-interference-event/1` reports (at most 500); supplying the list (even empty) states that regional monitoring covered the flight |

Answer: the statement (`NOMINAL`, `DEGRADED`, `INTEGRITY-SUSPECT`) and its reasons from the
telemetry checks, recomputed (share without a 3-D fix, longest gap and the dead-reckoning error
over it against the contingency buffer, receiver jamming and spoofing flags, position steps
faster than twice the planned speed plus 10 m/s, largest reported accuracy); for a flight that
was not nominal, the **attribution** `area` (other flights nearby degraded at the same time, or a
regional report), `aircraft` (other flights nearby unaffected; degradation without any receiver
flag) or `indeterminate` with the leading side, a confidence in steps of 0.05 capped by the
number of independent families of evidence (one family never decides), the findings at outcome
level, counts of other flights near and degraded with it, the client attestation's SHA-256,
whether it agrees and which fields do not (a client statement milder than the recomputed one is
a mismatch; a stricter one, from checks not repeated here, is not), the limits and the
decision-support statement. Comparisons, weights and thresholds stay in the service.

Decision support only: never a flight or operational authorisation, a SORA approval or a means
of compliance. Nothing here locates an interference source. Not fingerprinted (a statement, an
attribution and a confidence in steps of 0.05). Evidence class **MODELLED**: checked on
synthetic flights (a degradation shared with four nearby flights and a regional report read as
`area`; jumps with nearby traffic unaffected read as `aircraft`; no context read as
`indeterminate`; attestation agreement and mismatches). Not validated on recorded flights.
The Pro client side (a `remote_verdict` method entry and a call from `utm attest`) is a separate
kshana-pro change.

### `parametric-trigger`: a neutral oracle for a parametric outage trigger

Research backlog E28, B2801 hosted part (the item text in the backlog is to confirm against this
method). A parametric cover pays on an index, so the index must come from someone neither party
controls. The Kshana Pro client evaluates a trigger on the user's own station series
(`kshana-pro insurance trigger`); this method evaluates the same definition on the service's
**station archive** (`MERU_ORACLE_STATIONS`: a directory with `stations.toml`, `[[station]]`
`{id, lat_deg, lon_deg, operator, file, baseline_dbhz?}`, and per station a CSV `utc,cn0_dbhz`;
read on each call; the archive layout and how it is fed are to confirm) and signs the result.
Without an archive only `source: "caller"` is offered, and the verdict then says the data was the
caller's.

Request (JSON; unknown fields refused): `definition_id?`, `period_start_utc`, `period_end_utc`
(at most 92 days), `area {lat_deg, lon_deg, radius_km}` (at most 2,000 km), `trigger
{cn0_drop_db, min_sites (1), min_duration_min, max_gap_s (120), merge_gap_min (10)}` (the Pro
trigger's fields), `source` (`service`, default, or `caller`) and for `caller` `series [{site,
lat_deg, lon_deg, baseline_dbhz?, operator?, t_unix[], cn0_dbhz[]}]`. There is no cover, tier
or amount field.

Method: the Pro trigger's rules (baseline per site stated or the period median; degraded below
baseline minus `cn0_drop_db`; missing data never degraded, a gap longer than `max_gap_s` ends an
episode; episodes merged; times when `min_sites` sites are in an episode at once, merged; an
event lasting `min_duration_min` fires; index per event the sum of (baseline − C/N0) × time in
dB·h) plus one oracle rule: an episode at one station that no nearby station shares, while
nearby stations kept normal data, is excluded as uncorroborated (a station fault must not fire a
cover); the distances and counts stay in the service. Answer: `state` (`fired`, `not_fired`, or
`insufficient_data` when coverage is under half the period's site-hours), the events (window,
duration, sites, index, fires), the period index (degraded over observed site-hours), coverage
(stations, stations with data, independent operators, observed site-hours, share of the period,
episodes excluded), `definition_sha256` (the definition as evaluated, with the method version and
source) and `data_sha256` (the station data used), the limits and the statement: an index and a
trigger state, not insurance or financial advice, not a claim decision, not a payout and not an
interpretation of any wording. Ashforde has no insurer partners. Not fingerprinted (an oracle's
record reads the same for every party). Evidence class **MODELLED**: checked on synthetic station
archives (an area outage fires with the expected index; a lone station fault is excluded; a
longer minimum duration does not fire; no data is `insufficient_data`; archive and caller data
agree).

**Backtest (B2801).** A request may list archived events, `backtest: [{id, start_utc, end_utc,
basis}]` (at most 200; a documented basis is required and echoed): each is `matched` when a fired
event overlaps it within the merge gap, else `missed`, events outside the period are listed as
such, and fired events no archived event explains are counted. Checked on the synthetic archive
(the area outage matched, a lone station fault reported as an outage missed because the oracle
excludes it, an event outside the period listed). **No archived event with real station data and
a documented basis is carried here**: the service has no station archive yet, and none can be
cited; the real backtest is to confirm once an archive and documented events exist.

### `policy-wording`: what the PNT evidence answers in a synthetic wording

Research backlog E28, B2804 (to confirm against the backlog). Clauses such as a
malicious-electronic-means exclusion, a war exclusion against cyber cover, or a cyber buy-back
rest on facts; some the PNT evidence can answer and some it never can. **Synthetic wordings
only**: the wording is structured (identifiers, a kind, facts from a fixed vocabulary), never
policy text, and `synthetic` must be `true` or the request is refused.

Request: `wording {id, synthetic: true, clauses: [{id, kind: cover | exclusion | buyback |
condition, facts: [...]}]}` (identifiers 1 to 64 characters of `A-Z a-z 0-9 . _ -`, at most 64
clauses) and `evidence`: up to 16 verdicts this service issued (`cause`, `victim-actor`,
`parametric-trigger`), each checked against the service's own verdict key (a tampered or foreign
verdict is refused). Facts, version 1: `gnss_interference_occurred`, `gnss_jamming_indicated`,
`gnss_spoofing_indicated`, `own_track_falsified`, `equipment_fault_indicated`,
`regional_interference_reported`, `parametric_trigger_fired`, `intent_or_actor_identity` and
`cyber_intrusion` (the last two are always `not_determinable`: PNT evidence does not establish
who acted, why, or whether a computer system was accessed).

Answer: per fact `supported`, `not_supported` or `not_determinable` (no verdict answers it,
verdicts disagree, or a decision below the confidence the method requires), its basis and the
SHA-256 of the verdict it rests on; per clause the counts and a reading ("every fact the clause
names is supported", "at least one is not supported", "at least one cannot be determined from
the PNT evidence supplied"); the evidence used; and the statement: not insurance or legal advice,
not an interpretation of any wording and not a coverage position. Not fingerprinted. Evidence
class **MODELLED**: checked on labelled synthetic fixtures (a malicious-electronic-means
exclusion, a war exclusion, a cyber buy-back, a spoofing cover, a falsification condition, a
parametric cover) against signed `cause`, `victim-actor` and `parametric-trigger` verdicts,
including disagreeing and undecided evidence.

**Model clauses (B2804's four named questions).** A synthetic clause may stand for a public
model clause (`"model": "<id>"`) and then takes that clause's facts unless it lists its own. The
registry names each clause by name, number and publisher only; no clause text is reproduced, and
which facts each turns on is our reading, to confirm against the clause text (every answer says
so):

| `model` | Reference | Named question | Facts |
|---|---|---|---|
| `LMA5403` | Marine Cyber Endorsement, LMA5403, Lloyd's Market Association (2019, to confirm) | malicious electronic means | interference occurred, spoofing indicated, cyber intrusion, intent or actor |
| `CL380` | Institute Cyber Attack Exclusion Clause, CL380 (10/11/2003, publisher to confirm) | Clause 380 | spoofing indicated, cyber intrusion, intent or actor |
| `cyber-buy-back` | write-back of cover for non-malicious cyber events (a market practice; which endorsement to confirm) | cyber buy-back trigger | cyber intrusion, equipment fault, intent or actor |
| `LMA5564-LMA5567` | war, cyber war and cyber operation exclusion clauses, LMA5564 to LMA5567, Lloyd's Market Association (2021, to confirm) | war versus cyber boundary | interference occurred, regional interference reported, intent or actor |

Because who acted and why is never determinable from PNT evidence, the malicious element and the
war-versus-cyber boundary always stay open: the method says which of the other facts the
evidence supports. Labelled fixtures cover all four against a spoofing `cause` verdict and a
`victim-actor` verdict with regional interference reported. Still never a coverage position.

### `spaceweather`: a hosted space-weather advisory

Research backlog E35, the hosted part of B3502 (the item text in the backlog is to confirm
against this method). The Kshana Pro advisor (`kshana-pro agri advise`) runs on public indices
with a Kp proxy and climatology; this method adds **live ionosphere inputs** and **per-region
thresholds**.

Inputs (`MERU_SPACEWX_SOURCE`, a directory a separate fetcher keeps current; the 16 newest files
of each kind are read on each call; without it the method answers "not offered"):
`kp/*.json`, the NOAA SWPC planetary K-index product (the object form, `time_tag`/`Kp`, or the
older row form with a header row); `roti/*.json`, `meru-roti-map/1` maps of the rate of TEC
index (`{format, epoch_utc, cells: [{lat_deg, lon_deg, roti_tecu_per_min}]}`); `s4/*.json`,
`meru-s4-obs/1` amplitude scintillation (`{format, epoch_utc, stations: [{id, lat_deg, lon_deg,
s4}]}`). Which networks feed ROTI and S4, and the fetcher itself, are to confirm; nothing here
fetches. `MERU_SPACEWX_REGIONS` (TOML, `[[region]]` `{name, lat_min, lat_max, lon_min, lon_max,
roti_moderate, roti_high, s4_moderate, s4_high, kp_moderate, kp_high, basis}`) holds calibrated
thresholds for named regions; none are shipped.

Request: `locations [{id, lat_deg, lon_deg}]` (at most 200), optional `at_utc` (default now; at
most 30 days back and never in the future: this is not a forecast), optional `services` (`rtk`,
`ppp`, `single_frequency`; default all). Inputs after `at_utc` are not used; Kp is used for
6 hours after its interval starts, ROTI and S4 for 30 minutes after their epoch.

Answer, per location: the region (a named calibration, or the default band: `equatorial` by
modified dip latitude from the open engine's IGRF-14, `auroral` by a Kp-dependent oval boundary
in dipole latitude, `polar_cap`, `mid_latitude`), each indicator's value, distance, age and level,
the overall level (`quiet`, `moderate`, `high`) and the indicator that drove it, whether live
data was used, the status per service (`go`, `caution`, `no_go`) and how long the advisory holds
(15 minutes past the newest live input, or 3 hours on Kp alone). Overall: the NOAA G scale, the
input epochs, the number and SHA-256 of the input files, the limits (for example "Kp alone, a
proxy that does not see equatorial scintillation") and the statement. The default band
thresholds stay in the service.

Advisory only: not a forecast of any receiver's behaviour and not an operational instruction.
Not fingerprinted (levels, statuses, and input values that are the same for every caller).
Evidence class **MODELLED**: default thresholds follow published climatology, simplified, and
are not calibrated against observed receiver outcomes in any region; checked on synthetic
inputs (a storm evening with auroral, equatorial and mid-latitude locations; a quiet morning on
Kp alone; a regional calibration replacing the band).

**May 2024 storm backtest (B3502).** The Kp input also reads the GFZ Niemegk text file
(`Kp_ap_Ap_SN_F107_since_1932.txt` layout). A unit test runs the advisor hour by hour from 8 to 14
May 2024 on the published GFZ Kp series (Matzka et al. 2021, https://doi.org/10.5880/Kp.0001,
CC BY 4.0; the excerpt in `src/data/` keeps the file's header and attribution, sunspot numbers
removed) for fields in Manitoba, Iowa and Saskatchewan and one in Mato Grosso: the three North
American fields are never `high` on 8, 9 or 14 May, are `high` on the evening of 10 May, and RTK is
`no_go` at every hour of 11 May (Kp 7.7 to 9, G5 at 01:30 UT); the equatorial field is never
`high` from the Kp rule. Farmers in the Canadian Prairies and the US Midwest reported autosteer
and RTK trouble on 10 and 11 May 2024 (trade press, as cited by the Pro advisor's
documentation); this matches dates, not any receiver's measured behaviour. Kp only: no archived
ROTI or S4 maps for May 2024 are carried (to confirm, for example from IGS ROTI products).

### `perception-eval`: evaluation of perception and landmark integrity

Research backlog E40, B4002 (the item text in the backlog is to confirm against this method).
**Evaluation only**: the method scores outputs a system already produced against truth the
tester supplies. It computes no position, associates no detection with a map, fuses no sensors
and matches no map; the pairing of each detection with the landmark it really was is the
tester's.

Request (JSON; unknown fields refused): `system?`; `declaration {end_use, classification,
release, signals[], environment}`; `alert_limit_m`; `claims {min_availability?, max_hmi_rate?,
max_misidentification_rate?, max_h95_m?}`; `runs [{id, condition?, epochs: [{t, truth {e_m, n_m,
u_m?}, output {available, position?, hpl_m?, integrity_ok?}, in_view[], detections [{claimed,
truth?}]}]}]` (at most 500 runs, 500,000 epochs, 2,000,000 detections and landmarks in view).

A **civil-releasability screen** runs first, as in the Pro test-campaign evidence: an end use
naming a weapon, munition, missile, targeting, fire control or warhead, data that is not
`unclassified`, a release other than `public` or `civil-restricted`, a military or restricted
signal (PRS, M-code, P(Y), P-code, SAASM), or an environment outside `twin`, `simulator`,
`hil`, `lab-rf`, `field`, `flight` is refused. The declarations are the tester's.

Answer, overall and per condition: availability; the Stanford-diagram classes against the alert
limit (nominal; misleading: error above the protection level, protection level within the
limit; hazardously misleading: error above the limit while the protection level was within it;
epochs whose protection level exceeded the limit) and the HMI rate with its 95 % Wilson
interval; error percentiles and protection-level tightness (error over protection level, 95th
percentile); landmark recall of those truly in view, precision, misidentification rate, false
detections, misidentifications while the system reported its integrity as good. Each claim
`met`, `not_met` or `not_shown`, with a note when the campaign is too small to show a claimed
rate. Epochs are counted as independent (stated). Not fingerprinted. Not a certification or an
approval of the system. Evidence class **MODELLED**: checked on synthetic campaigns with known
counts (day and night conditions, injected hazardously misleading epochs, missed and
misidentified landmarks, false detections) and on the screen's refusals.

### Vision-navigation claims test (B4002)

A neutral test of a vendor's claims about a perception-aided positioning system, scoring outputs
only like `perception-eval` (no position computed, no map association, no fusion, the same
civil-releasability screen). Two steps:

1. `POST /verdict/vision-claims/register`: `{system, declaration, alert_limit_m, conditions[],
   claims[]}` where a claim is `horizontal_error {condition?, percentile, max_m}`, `availability
   {condition?, min}`, `hmi_rate {condition?, max}` or `misidentification_rate {condition?,
   max}`. Answers a signed protocol (`meru-vision-claims-protocol/1`, method `claims-protocol`)
   with its SHA-256 and registration time.
2. `POST /verdict/vision-claims`: `{protocol: <the signed protocol>, runs: [...]}` (runs as in
   `perception-eval`). The protocol must verify against this service's key (a claim changed after
   registration does not), and every epoch must follow the registration, so the claims cannot
   have been fitted to the results. Per claim: `shown` (the 95 % interval is on the claimed side:
   Wilson for rates, a distribution-free order-statistic interval for error percentiles),
   `contradicted` (on the other side) or `not_shown`, with the measured value, the interval and,
   for rates not shown, about how many epochs or detections would show the claim if the observed
   rate held (with no event, the rule of three). Each registered condition is `tested` with at
   least 100 epochs.

The same rules for every system, no ranking, no comparison between vendors; not a certification
or an approval. Checked on a synthetic campaign (error claims contradicted, availability and
misidentification shown, an HMI claim of 1e-5 not shown with about 300,000 epochs needed, an
untested condition) and on refusals (a campaign before registration, an altered protocol, a
claim on an unregistered condition, a weapon end use).

### `feeder-trust` and `archive-seal`: feeder trust and archives

Research backlog E26 (feeder trust and archives; the item text in the backlog is to confirm
against these two methods). They sit on top of the Pro observation provenance
(`kshana-obs-provenance/1`, `kshana-pro obs-provenance verify`): a signature shows who sent a
batch, not that its observations are true.

**`feeder-trust`.** Request: `network?`, `t0`, `bin_s` (60 to 3,600), `feeders [{id, lat_deg,
lon_deg, provenance? {batches, signed, unsigned, rejected, sequence_breaks}}]` (the provenance
summary from `obs-provenance verify`), `streams [{feeder, alarm, cn0_mean?}]` (one character a
bin: `1` interference alarm, `0` none, `-` no data; optional mean C/N0 per bin); at most 2,000
feeders, 20,000 bins a stream, 4,000,000 bins in all. Per feeder: provenance (signed share,
rejected batches, sequence breaks), corroboration (how many of its alarms a nearby feeder with
data shared; how often it joined when most nearby feeders alarmed), duplicate streams (the same
alarms over many bins, and the same C/N0 where given: a copied or replayed feed, or one station
posing as two; both streams are flagged, since the original cannot be told), continuity. Answer:
the class (`trusted`, `probation`, `untrusted`, `insufficient_overlap` for a feeder with no
nearby feeder to judge it by), a score in steps of 0.05, the reasons and the counts, and a
network summary. Weights and thresholds stay in the service. Nothing here estimates where an
interference source is.

**Two tiers and data weighting (B2602).** A feeder carrying a station attestation this service
issued (`meru-feeder-attestation/1`: for this feeder, current for the window, station within 1 km
of the declared one; anything else is ignored with the reason given) is in the **attested**
tier; every other feeder is **community** data. Corroboration and joining are judged against
attested neighbours wherever there are any (`judged_against`), so colluding community feeders
cannot vouch for each other. Each feeder gets a data **weight**: trusted 1, probation half its
score, insufficient overlap 0.3, untrusted 0, community data at half the weight of attested
data. `consensus` gives, bin by bin over the whole network as one area (per-area consensus to
confirm), the alarm by weighted and by plain majority vote, and how many bins the weighting
changed. Simulation (unit test): three attested feeders and one honest community feeder see a
real event; five colluding community feeders, each stream slightly different so they are not
duplicates, report a fake event and stay silent through the real one. By plain majority the
network reports the 35 fake bins and misses the 30 real ones; weighted, all five colluders are
untrusted (weight 0) and the network reports exactly the 30 real bins. Without attested
neighbours the method cannot single out a Sybil majority, and says whom it judged against.

**Station attestation endpoint.** `POST /verdict/feeder-attest` (operator licences listed in
`MERU_FEEDER_ATTESTERS`; others 403; not served when the list is empty): `{feeder_id, lat_deg,
lon_deg, provenance_key_id?, host_ref_sha256?, valid_days (1 to 400)}` answers a signed
attestation. Who hosts a station stays in the operator's separate host-identity store; the
attestation carries only a hash reference to it (the store itself is not part of meru). An
attestation says who may feed as attested data; it does not show that the observations are
true. Give-to-get (data access in return for feeding) is not built here (to confirm).

**`archive-seal`.** Request: `archive_id`, `period_start_utc`, `period_end_utc`, `entries
[{name, sha256, bytes?}]` (at most 100,000; the files stay with the holder) and `previous` (the
archive's previous seal as the service returned it; absent for the first). The service checks
the previous seal against its own key, that it is the same archive and that the new period does
not start before it ended, and signs: the Merkle root (`meru-archive-merkle/1`: entries sorted
by name, names unique; leaf = SHA-256(0x00 ‖ name ‖ 0x00 ‖ digest); node = SHA-256(0x01 ‖ left ‖
right); an odd node is carried up; `meru::archive_seal::{leaf, merkle_root, audit_path,
root_from_path}` implement it), the count, total bytes, period, first and last names, the
sequence number and the previous seal's hash and root. Anyone can show a file was sealed, offline,
with its audit path and the seal. A seal shows the service saw these digests under these names
at that time, after the previous seal; it does not show the files are correct and is not a
qualified time-stamp. The transparency log anchored by two authorities (E25 B2502) is not built
here.

Neither is fingerprinted (classes and scores in steps of 0.05; digests and counts). Evidence
class **MODELLED**: checked on a synthetic network (a shared event, a feeder with lone alarms, a
copied stream, a silent feeder, mostly unsigned batches, a rejected batch, an isolated feeder)
and on seal chains (audit paths for 1 to 17 entries; tampered, foreign, overlapping and
other-archive previous seals refused).

### Product register revocation list (`/crl`)

Research backlog E25, B2505, the hosted part (the register itself and the yearly revalidation are
to confirm). A product's register entry says it was **scored under method X** (a method of this
service at a stated version, with the verdict that holds the score); nothing here describes a
product as validated, approved or certified. An entry stops standing when the score is withdrawn,
the method version is superseded, the product changed after it was scored, the evidence was found
wrong, a key may be compromised, or the holder asks.

The list is issued **in the open engine's own format, `kshana.register-crl/1`**, so the open
register tools (`kshana register crl-check`, `kshana register view --crl`) read it unchanged;
format, issuing rules and the open vector are in [docs/CRL-FORMAT.md](docs/CRL-FORMAT.md).

* `POST /verdict/crl/revoke` (operator licences whose token IDs are in `MERU_CRL_ADMINS`; any other
  licence gets 403): `{id, revoked?, reason, note?}`: `id` the register entry id, `revoked` the
  date it applies from (default today), `reason` one of `score_withdrawn`, `method_superseded`,
  `product_changed`, `evidence_error`, `key_compromise`, `holder_request` (published as text).
  Appended to `MERU_CRL_LOG` (JSON Lines, append-only, read back at start, never edited); an id
  already revoked answers 409. The private `note` and the revoking token stay in the log and are
  never published. Metered like any call. The answer carries the new document, its SHA-256, the
  number of revocations and the transparency-log record.
* `GET /crl` (no licence; rate limited per address): the signed document itself (issuer
  `MERU_CRL_ISSUER`, `issued` today, `next_update` seven days later, the revocations, `signer` the
  service key published at `GET /keys`, Ed25519 `signature`). Re-issued after every revocation
  and each new UTC day. `meru::crl::check` is the same check the open reader makes.
* Each revocation is also appended to the transparency log when one is kept (kind
  `crl-revocation/1`, the SHA-256 of the revocation's compact JSON), so a later list cannot drop
  a revocation without the log showing it.

Without `MERU_CRL_LOG` both paths answer 404.

### Transparency log for signed evidence packs (`/tlog/`)

Research backlog E25, B2502 (the item text is to confirm). An append-only log of the SHA-256 of
signed evidence packs (Kshana dossiers, attestation directories, verdicts), so a holder can show
later that a pack existed at a time and that the log has only grown. Only hashes are kept; no
pack contents are ever received or returned.

* `POST /verdict/tlog/append` (any licence this instance serves; per-licence rate and quota;
  metered): `{pack_sha256, kind, signer_key_id?}`. Answers `{index, new, entry, inclusion,
  sth}`; a pack already logged answers its existing index with `new: false`. The submitting
  licence is kept in the log file pseudonymised (`h:` and 16 hex of SHA-256 of its token ID)
  and never returned.
* Public, read-only, rate limited per address: `GET /tlog/sth` (the signed tree head),
  `GET /tlog/proof?index=N[&size=M]` (inclusion proof), `GET /tlog/consistency?from=A&to=B`,
  `GET /tlog/entry?index=N`, `GET /tlog/find?pack_sha256=H`.
* Merkle tree as RFC 6962 / RFC 9162 define it (leaf = SHA-256(0x00 ‖ the entry's canonical
  JSON), node = SHA-256(0x01 ‖ left ‖ right), split at the largest power of two); the verifiers
  `meru::tlog::{verify_inclusion, verify_consistency}` follow RFC 9162 §2.1.3.2 and §2.1.4.2.
  A hash chain on top (chain(i) = SHA-256(0x02 ‖ chain(i−1) ‖ leaf(i))); every line of the log file
  (`MERU_TLOG_PATH`, JSON Lines, append-only, fsynced) is recomputed at start and a mismatch
  refuses the log.
* The signed tree head, `meru-tlog-sth/1` (size, root, chain head, time), is a signed verdict
  (method `tlog-sth`, evidence class `RECORD`) the Pro verdict client verifies.
* **Anchoring by two authorities**: each tree head carries two anchor receipts. Which authorities
  (for example an RFC 3161 time-stamp authority and a public ledger) and their protocols are to
  confirm; this build has the interface (`meru::tlog::Anchor`) and two placeholders named by
  `MERU_TLOG_ANCHORS` that send nothing and report `not_anchored`. Nothing here claims an anchor.

An entry shows that a hash was submitted at that time and has been in the log since; it says
nothing about whether the pack is correct. Without `MERU_TLOG_PATH` the paths answer 404. The
archive seals of `archive-seal` (feeder branch) use their own Merkle rule; this log follows the
RFC rule so standard verifiers apply. Checked: inclusion proofs for every leaf of trees of 1 to 33
leaves, consistency proofs for every pair of sizes up to 33, rewritten histories refused, a
tampered log file refused at start.

### `archive-query`: observation archives, aggregates only

Research backlog E26, B2603 (item text to confirm). The network's long-running archives, one per
domain: `incidents` (`duration_s`, `severity`), `asf` (`asf_ns`), `lf_noise` (`noise_dbuv_m`),
`osnma_failures` (`failed`, `auth_failures`), `ais_rf` (`mismatch_m`), `holdover` (`holdover_s`,
`drift_ns`), `station_kpi` (`availability`, `latency_s`); each record has a time, a position, a
source and an optional tag. Receiver fingerprints are not an archive domain here (to confirm).

* `POST /verdict/archive/ingest` (operator licences in `MERU_ARCHIVE_WRITERS`, others 403):
  `{records: [{domain, t, lat_deg, lon_deg, source, values, tag?}]}`, at most 10,000, checked
  all or nothing (unknown domains and value names refused), appended to
  `MERU_ARCHIVE_DIR/<domain>.jsonl`. Answers the count only.
* `POST /verdict/archive-query` (any licence; rate, quota, audit and meter as every method):
  `{domain, value, area {lat_deg, lon_deg, radius_km ≥ 10}, from_utc, to_utc (1 hour to 366 days),
  group (none, day, week, month), tag?}` answers a signed verdict with per group the count, the
  number of sources, mean, median, 95th percentile and maximum. **A group with fewer than 5
  records or 2 sources is suppressed**, so no query singles out one station or one event.

**No API returns a raw archive row**: no answer carries a record, a source, a position or a time
finer than the group; there is no export route, and `/verdict/archive/export` and
`/verdict/archive/rows` are honeypots. Residual risk: differencing overlapping queries can narrow
down groups; the minimum area, window and counts, output rounding and the query-pattern audit
slow it. Not fingerprinted. Checked: aggregates without any identifying field, suppression of a
lone station and a single incident, refusals, all-or-nothing ingest, and over a socket (ingest
refused to a customer, signed aggregates, honeypots logged).

### `timing-correlation`: cross-site timing correlation (B1903)

Research backlog E19, B1903 (item text to confirm). Each site (a GNSS-disciplined grandmaster, a
PRTC, a base station's timing receiver) reports the offset of its GNSS time against its own
independent reference. A slow-drift attack moves GNSS time slowly enough that one site stays
inside its alarm limit for a while; many sites drifting together at the same rate are seen much
sooner, because the noise of the combined drift estimate falls with the number of sites.

Request: `{subject?, sites: [{id, operator, lat_deg, lon_deg}], series: [{site, t0, dt_s,
offset_ns[]}]}` (at most 500 sites and 2,000,000 samples). The method estimates each site's drift
in a sliding window, less its own baseline slope, and tests groups (each region cluster, each
operator, all sites) for a common drift. Each episode gives the detection time by the group test,
the earliest single-site detection with the same test and the lead between them, the drift rate,
the sites, operators and regions affected and the scope: `regional_drift` (several operators in
one region: fits regional spoofing or interference; nothing is located), `constellation_wide`
(fits an upstream constellation time anomaly), `operator_wide` (one operator's sites, others
nearby unaffected: its own distribution or configuration), `single_site`, or `several_sites`. A
NOC alert feed gives one alert per episode with a severity (`critical` from 0.5 ns/s, about 1 µs
in half an hour, or constellation-wide). The window, thresholds and grouping stay in the service.
Not fingerprinted. Evidence class **MODELLED**. Acceptance, in simulation: a synthetic 1 ns/s
drift across the six sites of one region (three operators, 20 ns noise, each reference drifting up
to ±0.05 ns/s) is detected by the group test before any single site's own detector fires, on
five noise draws; constellation-wide and operator-wide drifts are read as such; a quiet network
raises no episode. Not checked against operators' incident logs.

### `gnss-leo-arbitration`: GNSS versus LEO trust arbitration (B2106)

Research backlog E21, B2106 (item text to confirm). **Evaluation and arbitration evidence only**:
the method reads solutions a receiver already produced and says, after the fact, which source the
evidence supports when they disagree. It computes no fused solution, steers no receiver and
switches no source; nothing it returns is a navigation or timing output.

Request: `{subject?, tolerance_ns (50), position_tolerance_m (100), clock_stability_ns_per_s
(0.05), epochs: [{t, gnss {valid, time_offset_ns?, cn0_mean_dbhz?, n_sats?, auth_ok?,
position?}, leo {valid, time_offset_ns?, quality?, n_sats?, auth_ok?, position?}}]}` (offsets
against the site's own clock; positions used only to detect disagreement). Episodes are runs of
at least three disagreeing epochs. Evidence in three families: **reference** (the site clock
modelled as a line through the epochs where both sources agreed before the episode, leaving out
the agreed epochs just before it, since a slow pull starts before the tolerance is crossed, with
an allowance growing at the clock's stability: the source that departs from the prediction is
suspect), **indicators** (a uniform GNSS C/N0 rise of 3 dB or a drop of 6 dB, failed
authentication of either source, a LEO quality figure below 0.5) and **dynamics** (a step in one
source at the start). Combined into a confidence in steps of 0.05, capped by the number of
families; below 0.7 the episode is `undetermined`. The integrity statement gives the agreement
share, the 95th percentile difference when agreeing, the epochs in disagreement and how many of
them have a supported source. If both sources were wrong together the method cannot see it
(stated). Not fingerprinted. Evidence class **MODELLED**. Fixtures: a GNSS fault (a 2 ns/s pull,
C/N0 rise, failed authentication) is arbitrated against GNSS with confidence 0.9 or more; a LEO
fault (a 400 ns step with a low quality figure) against LEO; agreement raises no episode; a
disagreement with no baseline and no indicators stays undetermined.

### `delay-calibration`: timing-receiver delay calibration (B1908)

Research backlog E19, B1908 (item text to confirm). A device under test (DUT) and a calibrated
reference receiver observe the same satellites, side by side on one clock (`co_located`) or in
`common_view`. Request: `{dut, setup {mode, baseline_km, dut_cable {value_ns, u_ns},
dut_reference_cable {value_ns, u_ns}, assumed_dut_cable_ns, assumed_dut_reference_cable_ns,
antenna_u_ns?}, codes: {"<code>": {assumed_delay_ns, reference_delay {value_ns, u_ns},
differences_ns[]}}}`, the differences being DUT minus reference per common track, computed with
the assumed DUT delay. The DUT's delay is the assumed value plus the mean difference, corrected
for the cables as measured against as assumed. Uncertainty after the GUM: Type A from a robust
mean with outliers rejected and the uncertainty from batch means (so correlated noise such as
repeating multipath is not counted as independent; the rule and the batching stay in the
service); Type B from the reference receiver's calibration, the cable and connection
measurements, the antenna (default 1 ns) and, in common view, a baseline term (0.5 ns per 1,000
km, to confirm against the laboratory's own budget); combined and expanded with k = 2. The delay
and expanded uncertainty are also given as integer picoseconds, which the verdict's rounding to
significant figures leaves untouched. Not a statement that the receiver meets any requirement.
Not fingerprinted. Evidence class **MODELLED** until compared with a calibration laboratory's
result for the same receiver. Acceptance: known delays (25.2 to 41.0 ns) recovered within the
expanded uncertainty with 2 ns noise, a repeating 1 ns multipath term and outliers (rejected), and
over a socket, the signed verdict verified by the Pro client.

### API versions, insurer portal and contributor benchmarks (B2506)

Research backlog E25, B2506 (item text to confirm).

**Versions.** Version 1 is `/verdict/<method>` (also `/v1/verdict/<method>`): the signed verdict
exactly as before, so existing clients are unchanged. Version 2 is `/v2/verdict/<method>`: the same
signed verdict inside an envelope `{api_version: 2, method, method_version, deprecation,
verdict}`. Both are served together (checked end to end on the same request: the verdicts verify
with the Pro client, and v2 carries the identical signed verdict). `GET /versions` publishes the
policy: a version is served for at least **five years** after its successor is released (version 1
not before 2026-11-20 + 5 years = 2031-11-20), and a sunset date is announced there before a
version ends. Signed verdicts are the same in every version; only the envelope differs. nginx
passes `/v1/verdict/`, `/v2/verdict/` (POST) and `/versions` (GET).

**Insurer portal.** `POST /verdict/scorecard` (insurer licences listed in `MERU_INSURER_PORTAL`;
others 403): `{subject, verdicts: [<signed verdicts the policyholder shared>]}`; each must be this
service's (checked against its key). Answers a signed scorecard: per method the number of
verdicts, the first and last, and their outcomes (classification, statement, state, attribution
or finding), and the verdict hashes. A summary of the evidence shared; never an underwriting,
pricing or claims decision, and not insurance advice. Ashforde has no insurer partners; this is
the API the portal uses. **The portal page** is served by meru at `GET /portal` (with `/portal.js`
and `/portal.css`, built into the binary): the underwriter pastes or loads the shared verdicts and
their insurer licence token; the page calls `POST /v2/verdict/scorecard` and shows the signed
scorecard, with a note on checking it offline (`kshana-pro verdict verify scorecard.json --trust
<service key>`) and a button to save it. Self-contained under a strict content-security policy
(`default-src 'none'`, scripts, styles and requests from this origin only, nothing inline, no
framing, no external script, style or font); the token stays in the page's memory and goes only
into that request's Authorization header. It says, at the top, that a scorecard is never an
underwriting, pricing or claims decision, and names no insurer partners. nginx passes `/portal`,
`/portal.js` and `/portal.css` (GET).

**Contributor benchmarks.** `POST /verdict/benchmark` (contributor licences listed in
`MERU_CONTRIBUTORS`, a JSON object of token ID to the archive sources each feeds; others 403):
`{domain, value, area, from_utc, to_utc (1 to 366 days), source}` for one of the contributor's own
sources: the population's percentiles over sources (10th to 90th), the source's own mean and its
percentile rank. Give to get: only contributors, only their own sources, suppressed below five
sources, and no other source's figure is returned.

### `ntrip-qos`: hosted NTRIP caster quality scorecard (B1501, hosted part)

Research backlog E15, the hosted part of B1501 (item text to confirm; the open engine's caster
monitor produces the summaries). **Give to get**: only contributor licences (`MERU_CONTRIBUTORS`,
token ID to the sources each feeds; others 403) may call it, each call contributes the caller's
summaries to the append-only store (`MERU_NTRIP_QOS_STORE`; without it the method is not
offered), and a summary must come from one of the caller's own sources.

Request: `{summaries: [{source, caster, mountpoint, window_start_utc, window_end_utc (10 minutes
to 31 days), latency_ms_p50, latency_ms_p95, completeness (0–1), staleness_events, stale_s?,
uptime (0–1)}]}` (at most 2,000). Answer, signed: per mountpoint the caller's score (0–100) and
its components (latency p95, completeness, staleness events per hour, uptime), its window, and the
**population** of the latest contribution of every source that observed the same mountpoint in
the last 30 days: percentiles 10 to 90 and the caller's rank, or `suppressed` below five
sources; per caster the same over its mountpoints. No other source is named or returned. The
score's weights and breakpoints stay in the service. Not fingerprinted. Evidence class
**MODELLED**: a score of what the contributing monitors saw, not of the caster's internals.
Checked: a stale-prone feed ranks in the bottom third of seven sources; a mountpoint nobody else
watches is suppressed; summaries for another contributor's source are refused; and over a socket
(non-contributor 403, a signed verdict the Pro client verifies).

## Authorisation

A call is authorised by the caller's Kshana licence: `Authorization: Bearer <licence-token>`.
It must be signed by a current vendor key (`MERU_LICENCE_PUBKEY`, several allowed for
rotation), unexpired, not on the signed revocation list (`MERU_REVOCATIONS`, re-read within
30 s of a change, older lists refused), and at the Pro tier or above (or explicitly grant
`pro-eloran`). Evaluation licences are refused. The on-device `pro-eloran` gate in Pro builds
stays Enterprise-only.

## Deployment profiles and the service credential (20 November 2026)

Owner decision (roadmap 0.42 §1i, option B): in Arksa's cloud the **same meru binary** runs as an
internal service next to Arksa, on the private network only. Arksa authenticates with **one service
credential**, not per-customer licences. A Sovereign install gets a **contracted meru instance**
alongside it. meru is never compiled into Arksa. The public meru keeps serving Kshana Pro customers
unchanged. `MERU_PROFILE` picks the profile; unset is `public`; any other value is refused at start.

| | `public` (default) | `arksa-internal` | `sovereign-contracted` |
|---|---|---|---|
| Who it serves | Kshana Pro customer licences | Arksa's service credential only | the Sovereign install's service credential only |
| Service credential | refused (403) | accepted | accepted |
| Customer licence | accepted (unchanged) | refused (403) | refused (403) |
| Listen address | any (nginx in front, deploy/) | loopback or private address; a public address is refused at start; `0.0.0.0` warns | same as `arksa-internal` |
| Public endpoint | yes, TLS via nginx | none | none (the contract decides the network) |
| Per-address limit default | 60/min | off (`MERU_RATE_PER_IP_PER_MIN` to set one) | off |
| Tenant tag in the meter log (`MERU_TENANT_TAG`) | not read | `plain` | `hashed` (set by the contract: `plain`, `hashed` or `off`) |
| `POST /verdict/batch` | not served (404) | served | served |
| Unauthenticated mode | development only | refused at start | refused at start |

### Service credential

An ordinary vendor-signed v2 licence token, issued with the existing vendor tools and the existing
vendor key, verified by the same code (signature, key rotation, expiry, revocation list). What makes
it a service credential is in its signed claims:

* `features` holds exactly one `meru-service:<client>` entry; the client must be in
  `MERU_SERVICE_CLIENTS` (default `arksa`);
* `products` includes `service`;
* it is a v2 token with a token ID (so the revocation list can name it) and an expiry (so it is
  rotated).

A token that carries the marker but breaks a rule is refused on every profile. Issue one (per
deployment: Arksa cloud, and one per contracted Sovereign instance):

```
kshana-pro license issue --tier enterprise --licensee "Arksa cloud (meru service)" --days 365 \
  --product service --feature meru-service:arksa --register register.jsonl --note "arksa-internal"
```

Rotate it before expiry: issue the next one, deploy it to Arksa, then revoke the old token ID and
rebuild the revocation list. The token goes to Arksa through its secret store, never in a repository.

For a call with the service credential:

| Protection | Customer licence (public) | Service credential (internal profiles) |
|---|---|---|
| Daily quota, probe detector | on | off: Arksa's own design sweeps are many distinct requests by design |
| Rate | per licence (`MERU_RATE_PER_MIN`) | `MERU_SERVICE_RATE_PER_MIN` (600) per credential |
| Running-job and connection caps, body and request limits | on | on (shared) |
| Query-pattern audit | alerts, delay, optional pause, region cap | **record-only**: alert lines are written to the meter log (with `"service"`), stderr says `audit (record only, service credential)`; nothing is delayed, paused or refused |
| Fingerprint | when keys are configured | off (our own product) |
| Licence binding and signature | on | on: `licence.token_id` is the service credential's token ID |
| Metering | on | on, with `"service": "<client>"` and the tenant tag |

### Tenant/mission tag and metering

The caller may send `X-Meru-Tenant: <tag>` (1 to 64 characters of `A-Z a-z 0-9 . _ -`; anything
else is refused with 400 on an internal profile). The meter line gains `"tenant"`: as given
(`plain`, Arksa's own cost data in Arksa's cloud), or `h:` and the first 16 hex characters of its
SHA-256 (`hashed`, the `sovereign-contracted` default: pseudonymous, since a guessable tag can be
recovered by trying candidates), or nothing (`off`). The public profile does not read the header.

`meru meter summary [--log <meter log>] [--from <unix>] [--to <unix>] [--json]` prints per tenant
and method: calls answered, calls not answered, compute time of the answered calls and of all
calls (milliseconds). Alert lines are not calls and are left out.

### Batch route (recalibration)

`POST /verdict/batch` (internal profiles, service credential only):
`{"requests": [{"method": "calibrate" | "selfcal", "request": {...}}, ...]}`, 1 to `MERU_BATCH_MAX`
(16) requests. Each item is rate limited, audited (record-only), metered (under its own method path)
and signed exactly as its own call would be; the items run one after another in one running-job
slot. The answer is `{"results": [...]}` in request order, each `{"verdict": <signed verdict>}` or
`{"status": <code>, "error": "..."}`. The envelope is not signed; every verdict in it is. The whole
batch is one body, so `MERU_MAX_BODY` bounds it.

## Protection against copying

| Threat | What meru does |
|---|---|
| Reading the method | It never leaves the server. Callers get a signed verdict only |
| Rebuilding it from many answers | Outputs rounded (3 significant figures, angles to 1e-4 deg); per-licence rate (10/min) and daily quota (200); a probe detector pauses a licence that sends more than 60 distinct requests in an hour and raises an alert; the full survey grid only for Enterprise; `cause` and `victim-actor` return no scores, weights or thresholds and a confidence in steps of 0.05 |
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
`/verdict/victim-actor/scores`, `/verdict/calibrate/residuals`, `/verdict/ntrip-qos/sources`, `/verdict/timing-correlation/sites`, `/verdict/gnss-leo-arbitration/weights`, `/verdict/delay-calibration/batches`, `/verdict/rtk-quality/monitors`, `/verdict/flight-integrity/scores`, `/verdict/parametric-trigger/stations`, `/verdict/policy-wording/rules`, `/verdict/spaceweather/thresholds`, `/verdict/perception-eval/raw`, `/verdict/feeder-trust/weights`, `/verdict/archive/export`, `/verdict/archive/rows`, `/verdict/internal/params`, `/verdict/debug/model` answer exactly
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
values, reduced chi² first/last). Not fingerprinted: `cause`, `lunar-assist`, `victim-actor`, `rtk-quality`, `flight-integrity`, `parametric-trigger`, `policy-wording`, `spaceweather`, `perception-eval`, `feeder-trust`, `archive-seal`, `archive-query`
(a classification, confidences in steps of 0.05 and outcome-level counts: no number with a
last figure to carry a bit without moving a stated confidence), angles, integers, counts,
fidelity, classifications, confidences, uncertainties.

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
| `MERU_MAX_TRACK_POINTS` / `MERU_MAX_EPOCHS` | 20000 / 50000 | `cause` request limits (track points also `victim-actor`) |
| `MERU_MAX_NEIGHBOUR_POINTS` | 200000 | `victim-actor` neighbour positions in total |
| `MERU_READ_TIMEOUT_S` / `MERU_WRITE_TIMEOUT_S` | 15 / 30 | Connection timeouts |
| `MERU_ASSIST_SOURCE` | — | `lunar-assist` source products (directory of SP3); unset: method not offered |
| `MERU_ASSIST_EOP` | — | finals2000A Earth orientation for `lunar-assist` |
| `MERU_LUNAR_REGISTRIES` | — | Extra lunar time registry files (comma separated) |
| `MERU_ASSIST_FIT_HOURS` / `MERU_ASSIST_BACKTESTS` / `MERU_ASSIST_MAX_SATS` | 24 / 4 / 128 | `lunar-assist` settings |
| `MERU_FINGERPRINT_KEYS` | — | Fingerprint key epochs file; unset: no fingerprint |
| `MERU_RATE_PER_IP_PER_MIN` | 60 (`public`), 0 (internal profiles) | Calls a minute per client address (0 = off) |
| `MERU_TRUST_PROXY` | — | `1`: client address from `X-Real-IP` on loopback connections (nginx) |
| `MERU_AUDIT_WINDOW_S` / `MERU_AUDIT_MIN_POINTS` | 604800 / 32 | Audit memory and smallest judged set |
| `MERU_AUDIT_SUSPECT_S` / `MERU_AUDIT_DELAY_MS` / `MERU_AUDIT_PAUSE` | 86400 / 3000 / — | How long a flagged licence stays suspect, its verdict delay, `1` to refuse instead |
| `MERU_REGION_CELLS_PER_DAY` | 0 (off) | New coarse input cells per licence per day |
| `MERU_HONEYPOTS` | built-in list | Comma-separated honeypot paths, or `none` |
| `MERU_PROFILE` | `public` | `public`, `arksa-internal` or `sovereign-contracted` (unknown values refused) |
| `MERU_SERVICE_CLIENTS` | `arksa` | Service clients a service credential may name (comma separated) |
| `MERU_SERVICE_RATE_PER_MIN` | 600 | Calls a minute per service credential (0 = no limit) |
| `MERU_TENANT_TAG` | per profile | `plain`, `hashed` or `off` (internal profiles only) |
| `MERU_BATCH_MAX` | 16 | Requests in one `POST /verdict/batch` (1..256) |

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

`victim-actor` (E07 B0702, 20 November 2026): 67 unit tests (11 for `victim-actor`, the
randomised ensemble included) and the four end-to-end tests (the first now also posts a
`victim-actor` episode: signed, bound, outcome only, unknown fields refused). The Pro client
does not list the method yet (`kshana-pro` `src/remote_verdict.rs` METHODS needs
`("victim-actor", "victim-actor")` and a `kshana-pro verdict victim-actor` line); until then it
is reachable over HTTP only.

Deployment profiles and the service credential (roadmap 0.42 §1i, 20 November 2026): profiles
`public`, `arksa-internal`, `sovereign-contracted`; the service credential on the vendor licence
token; tenant-tagged metering and `meru meter summary`; the batch route for recalibration. Tested
with unit tests (profile parsing, bind addresses, tenant tags, credential rules, service rate,
meter summary) and two end-to-end tests over a real socket (credential refused on public and
accepted on internal, customer licences the other way round, revoked and foreign credentials
refused, no fingerprint, record-only audit through a Sobol sweep with pause on, tenant metering
plain and hashed, batch).

Still open (owner): disclose fingerprinting and auditing in the customer terms before turning
`MERU_FINGERPRINT_KEYS` on; the production host and keys (deploy/README.md checklist); patent filing;
customer terms. CI runs on a GitHub-hosted runner and needs no secret (kshana-pro is public).
