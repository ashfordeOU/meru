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
`/verdict/victim-actor/scores`, `/verdict/calibrate/residuals`, `/verdict/rtk-quality/monitors`, `/verdict/flight-integrity/scores`, `/verdict/parametric-trigger/stations`, `/verdict/policy-wording/rules`, `/verdict/spaceweather/thresholds`, `/verdict/internal/params`, `/verdict/debug/model` answer exactly
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
values, reduced chi² first/last). Not fingerprinted: `cause`, `lunar-assist`, `victim-actor`, `rtk-quality`, `flight-integrity`, `parametric-trigger`, `policy-wording`, `spaceweather`
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
