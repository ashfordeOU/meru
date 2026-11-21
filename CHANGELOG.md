# Changelog

Changes that alter what a hosted method returns, newest first. Each entry names the outputs
affected.

## audit-1 (2026-11-21)

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
