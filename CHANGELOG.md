# Changelog

Changes that alter what a hosted method returns, newest first. Each entry names the outputs
affected.

## audit-1 (2026-11-21)

- **flight-integrity**: an attestation with no `statement`, or one this method does not know
  (for example `"nominal"` in lower case), ranked as the most severe statement and so never
  counted as a mismatch: the attestation was reported as agreeing. It is now a mismatch.
  Affected outputs: `attestation.agrees` (now `false`) and `attestation.mismatched` (now lists
  `statement`) for such attestations.
- **parametric-trigger**: samples were evaluated in the order given (caller series and archive
  files), assuming ascending times; out-of-order samples gave negative intervals, so observed and
  degraded hours, the event index and the trigger state could be wrong (a reversed series turned a
  `fired` trigger into not fired). Samples are now sorted by time first. Affected outputs: `state`,
  `events`, `period_index`, coverage and the per-site figures, for requests or archive files with
  out-of-order samples.
- **timing-correlation**: drift windows ended on a per-site grid (first sample + 420 s + k·5 s),
  so sites whose series started at times differing by other than a multiple of 5 s never shared a
  window and were never tested together: a region's common drift was then caught later, by a
  wider group or by single sites. Window ends now lie on an absolute 5 s grid. A sample interval
  too coarse for the 120 s window (above 12 s) gave "no episodes" silently and is now refused
  (422). Affected outputs: `episodes[].detected_utc`, `detected_by_group`, `lead_s`, `scope` and
  the `noc_alerts` timing, for series with staggered starts.
- **gnss-leo-arbitration**: "one family never decides" did not hold: the confidence cap for a
  single evidence family was 0.75, above the 0.7 decision threshold, so one reference finding or
  one strong indicator named a suspect source on its own. The single-family cap is now 0.65.
  Affected outputs: `episodes[].suspect` (now `undetermined` where only one family pointed at a
  source), `episodes[].confidence` (at most 0.65 for one family), and the integrity statement's
  share of time the evidence identifies a source.
- **lunar-assist**: the configuration guard "the fit arc must be longer than the padded grid"
  compared seconds with hours and never fired. With `fit_hours` below 2.5 h, padding nodes before
  the arc start would take the epoch position, and the package's `pos_mm` near the start of
  validity would be wrong. It now refuses such a configuration ("service misconfigured: fit_hours
  too short"). Affected outputs: none with the shipped configuration (`fit_hours` 24); only
  misconfigured services, which now refuse instead of answering.
- **ntrip-qos**: a summary whose window ended more than 30 days ago made the call fail (the
  service thread panicked looking up a population it had left out), and a future-dated window was
  stored and kept in the population, shadowing the source's later windows. Both are now refused
  with 422 ("the window must end within the last 30 days and not in the future"). Affected
  outputs: none for valid calls; such calls now answer 422 instead of failing or skewing later
  `population` percentiles.
