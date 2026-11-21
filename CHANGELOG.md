# Changelog

Changes that alter what a hosted method returns, newest first. Each entry names the outputs
affected.

## audit-1 (2026-11-21)

- **ntrip-qos**: a summary whose window ended more than 30 days ago made the call fail (the
  service thread panicked looking up a population it had left out), and a future-dated window was
  stored and kept in the population, shadowing the source's later windows. Both are now refused
  with 422 ("the window must end within the last 30 days and not in the future"). Affected
  outputs: none for valid calls; such calls now answer 422 instead of failing or skewing later
  `population` percentiles.
