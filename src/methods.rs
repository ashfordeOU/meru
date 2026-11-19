// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The two hosted methods. Each runs the engine method server-side and returns a signed
//! verdict carrying the outcome only, coarsened ([`crate::outputs`]); the per-iteration
//! records, internal parameter state, regenerated scenario and full grids stay in the service.
//!
//! * F1 — the self-calibrating simulator loop ([`selfcal_verdict`]).
//! * F2 — the integrity-driven ASF survey planner ([`survey_verdict`]).
//!
//! Every request is checked against [`Limits`] before any work starts, so one caller cannot
//! tie up the service with an enormous grid or scenario.

use crate::outputs::coarsen;
use crate::verdict::{sign, SignedVerdict};
use kshana_eloran::calreg::Register;
use kshana_eloran::plan::survey::{plan, SurveyConfig};
use kshana_eloran::valid::selfcal::{run_selfcal, RefObservation, RefSite, SelfCalConfig};
use kshana_eloran::Scenario;
use kshana_pro::license::signer::LicenceSigner;
use serde::Deserialize;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};

/// How verdicts are signed and rounded.
pub struct Signing<'a> {
    /// Signs the verdict (seed or key vault).
    pub signer: &'a dyn LicenceSigner,
    /// Key identifier placed in the verdict.
    pub key_id: &'a str,
    /// Seed for the F1 lineage register (an internal record kept by the method).
    pub lineage_seed: &'a [u8; 32],
    /// Key identifier of the lineage seed.
    pub lineage_key_id: &'a str,
    /// Significant figures kept on outcome numbers.
    pub sigfigs: u32,
}

/// Size limits on a request, checked before any work starts.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Most grid cells (or candidate points) a survey may evaluate.
    pub max_cells: usize,
    /// Most survey points a plan may choose.
    pub max_budget: usize,
    /// Most self-calibration iterations.
    pub max_iter: usize,
    /// Most observations or reference sites.
    pub max_obs: usize,
    /// Most signal samples a scenario may simulate (duration × sample rate).
    pub max_samples: f64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_cells: 40_000,
            max_budget: 50,
            max_iter: 50,
            max_obs: 5_000,
            max_samples: 5.0e7,
        }
    }
}

/// Request for F1 (self-calibrating simulator loop).
#[derive(Clone, Debug, Deserialize)]
pub struct SelfCalRequest {
    /// The base scenario (TOML).
    pub scenario_toml: String,
    pub config: SelfCalConfig,
    pub sites: Vec<RefSite>,
    pub observations: Vec<RefObservation>,
}

static WORK_SEQ: AtomicU64 = AtomicU64::new(0);

/// Run F1 and return a signed verdict: convergence, fidelity, the calibrated parameters with
/// their uncertainty, and the signed lineage head. The per-iteration records, internal
/// parameter state and the regenerated scenario stay in the service.
pub fn selfcal_verdict(
    req: &SelfCalRequest,
    s: &Signing,
    limits: &Limits,
    utc: &str,
) -> Result<SignedVerdict, String> {
    if req.config.max_iter > limits.max_iter {
        return Err(format!(
            "config.max_iter above the limit of {}",
            limits.max_iter
        ));
    }
    if req.observations.len() > limits.max_obs || req.sites.len() > limits.max_obs {
        return Err(format!(
            "more than {} observations or sites",
            limits.max_obs
        ));
    }
    let base = Scenario::from_toml(&req.scenario_toml).map_err(|e| format!("scenario: {e}"))?;
    let p = &base.scene.params;
    let samples = p.duration_s * p.fs_hz;
    if !samples.is_finite() || samples > limits.max_samples {
        return Err(format!(
            "scenario too large: duration_s x fs_hz above {:.0} samples",
            limits.max_samples
        ));
    }
    base.build().map_err(|e| format!("scenario: {e}"))?;
    // A per-request lineage register, kept inside the service, in its own directory.
    let dir = std::env::temp_dir().join(format!(
        "meru-{}-{}",
        std::process::id(),
        WORK_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let register = Register::open(&dir.join("lineage.jsonl"));
    let r = run_selfcal(
        &base,
        &req.config,
        &req.sites,
        &req.observations,
        None,
        &register,
        s.lineage_seed,
        s.lineage_key_id,
    );
    let _ = std::fs::remove_dir_all(&dir);
    let r = r?;
    let scores = r.scores();
    let mut verdict = json!({
        "converged": r.converged,
        "stop_reason": r.stop_reason,
        "passes": r.records.len(),
        "regenerations": r.regenerations,
        "fidelity_first": scores.first().copied(),
        "fidelity_last": scores.last().copied(),
        "posterior": r.posterior.iter().map(|p| json!({"name": p.name, "value": p.value, "std_err": p.std_err})).collect::<Vec<_>>(),
        "lineage": {
            "head": r.signature.head,
            "entries": r.signature.n_entries,
            "scenario_hash": r.signature.scenario_hash,
            "recording_digest": r.recording_digest,
            "key_id": r.signature.key_id,
        },
    });
    coarsen(&mut verdict, s.sigfigs);
    sign("selfcal", "MODELLED", verdict, s.signer, s.key_id, utc)
}

/// Request for F2 (integrity-driven ASF survey planner).
#[derive(Clone, Debug, Deserialize)]
pub struct SurveyRequest {
    pub config: SurveyConfig,
    /// Include the per-cell protection-level grid. An internal detail: refused unless the
    /// caller's licence allows it (`allow_grid`).
    #[serde(default)]
    pub include_grid: bool,
}

/// Number of cells the survey grid covers.
fn survey_cells(c: &SurveyConfig) -> f64 {
    if c.step_deg.is_nan() || c.step_deg <= 0.0 || !c.step_deg.is_finite() {
        return f64::INFINITY;
    }
    let lat = ((c.area[1] - c.area[0]).abs() / c.step_deg).floor() + 1.0;
    let lon = ((c.area[3] - c.area[2]).abs() / c.step_deg).floor() + 1.0;
    lat * lon
}

/// Run F2 and return a signed verdict: coverage and mean protection level before and after,
/// and the chosen survey points. The protection-level grid is returned only when asked for
/// and `allow_grid` is true (Enterprise licences).
pub fn survey_verdict(
    req: &SurveyRequest,
    s: &Signing,
    limits: &Limits,
    allow_grid: bool,
    utc: &str,
) -> Result<SignedVerdict, String> {
    let c = &req.config;
    let cells = survey_cells(c);
    if !cells.is_finite()
        || cells > limits.max_cells as f64
        || c.candidates.len() > limits.max_cells
    {
        return Err(format!(
            "survey too large: more than {} grid cells or candidates (raise step_deg or shrink the area)",
            limits.max_cells
        ));
    }
    if c.budget > limits.max_budget {
        return Err(format!("budget above the limit of {}", limits.max_budget));
    }
    if req.include_grid && !allow_grid {
        return Err("the full protection-level grid is not available on this licence".into());
    }
    let p = plan(c)?;
    let mut verdict = json!({
        "coverage_before": p.coverage_before,
        "coverage_after": p.coverage_after,
        "mean_pl_before_m": p.mean_pl_before_m,
        "mean_pl_after_m": p.mean_pl_after_m,
        "picks": p.picks.iter().map(|k| json!({"order": k.order, "lat_deg": k.lat_deg, "lon_deg": k.lon_deg, "coverage": k.coverage, "mean_pl_m": k.mean_pl_m})).collect::<Vec<_>>(),
        "evidence": p.evidence,
    });
    if req.include_grid {
        verdict["grid"] = json!(p
            .grid
            .iter()
            .map(|(a, o, b, c)| json!({"lat_deg": a, "lon_deg": o, "pl_before_m": b, "pl_after_m": c}))
            .collect::<Vec<_>>());
    }
    coarsen(&mut verdict, s.sigfigs);
    sign("survey-plan", "MODELLED", verdict, s.signer, s.key_id, utc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::verify;
    use ed25519_dalek::SigningKey;

    const SEED: [u8; 32] = *b"meru-service-test-key-32-bytes!!";

    fn key() -> ([u8; 32], String) {
        let pk = SigningKey::from_bytes(&SEED).verifying_key().to_bytes();
        (SEED, hex::encode(pk))
    }

    fn signing(seed: &[u8; 32]) -> Signing<'_> {
        Signing {
            signer: seed,
            key_id: "k1",
            lineage_seed: seed,
            lineage_key_id: "k1",
            sigfigs: 3,
        }
    }

    #[test]
    fn survey_verdict_is_signed_and_hides_the_grid() {
        let (seed, pk) = key();
        let cfg: SurveyConfig = toml::from_str(
            r#"
            area = [54.0, 56.0, 10.0, 13.0]
            step_deg = 0.5
            budget = 3
            stations = [["A", 57.5, 10.0], ["B", 52.5, 8.5], ["C", 54.5, 16.0]]
            "#,
        )
        .unwrap();
        let v = survey_verdict(
            &SurveyRequest {
                config: cfg.clone(),
                include_grid: false,
            },
            &signing(&seed),
            &Limits::default(),
            false,
            "2026-11-19T06:00:00Z",
        )
        .unwrap();
        assert_eq!(v.method, "survey-plan");
        assert!(verify(&v, &pk).is_empty(), "{:?}", verify(&v, &pk));
        // A tampered verdict does not verify.
        let mut t = v.clone();
        t.verdict["coverage_after"] = json!(1.0);
        assert!(!verify(&t, &pk).is_empty());
        // Internal grid withheld by default, refused without the licence right, present with it.
        assert!(v.verdict.get("grid").is_none());
        let want_grid = SurveyRequest {
            config: cfg.clone(),
            include_grid: true,
        };
        let e = survey_verdict(&want_grid, &signing(&seed), &Limits::default(), false, "t")
            .unwrap_err();
        assert!(e.contains("not available on this licence"), "{e}");
        let g = survey_verdict(
            &want_grid,
            &signing(&seed),
            &Limits::default(),
            true,
            "2026-11-19T06:00:00Z",
        )
        .unwrap();
        assert!(g.verdict.get("grid").is_some());
        assert!(verify(&g, &pk).is_empty());
    }

    #[test]
    fn selfcal_verdict_returns_outcome_only() {
        let (seed, pk) = key();
        let scenario = r#"
[scene]
start_utc = "2026-11-19T00:00:00Z"
duration_s = 0.05
fs_hz = 1000000
[receiver]
type = "static"
lat_deg = 55.0
lon_deg = 3.0
[[outputs]]
type = "e_field"
[[chains]]
name = "c"
gri_us = 99300
[[chains.stations]]
id = "M"
role = "master"
position = { lat_deg = 56.0, lon_deg = 1.0 }
[[chains.stations]]
id = "X"
role = "secondary"
position = { lat_deg = 54.0, lon_deg = 5.0 }
emission_delay_us = 13000.0
"#;
        use kshana_eloran::valid::selfcal::SectionSpec;
        let mut config = SelfCalConfig::new(
            "svc",
            "core",
            "2026-11-19",
            vec![SectionSpec {
                name: "all".into(),
                vertices: vec![[53.0, 0.0], [57.0, 0.0], [57.0, 7.0], [53.0, 7.0]],
                eps_r: None,
                prior_sigma_s_m: 0.002,
                prior_log10_std: 0.3,
            }],
        );
        config.max_iter = 3;
        let sites = vec![RefSite {
            id: "s1".into(),
            position: kshana_eloran::geo::Geo::new(55.0, 3.0),
        }];
        let obs = vec![RefObservation {
            site: "s1".into(),
            chain: "c".into(),
            station: "M".into(),
            kind: kshana_eloran::valid::selfcal::ObsKind::GroundToa,
            value_ns: 0.0,
            sigma_ns: 20.0,
        }];
        match selfcal_verdict(
            &SelfCalRequest {
                scenario_toml: scenario.into(),
                config,
                sites,
                observations: obs,
            },
            &signing(&seed),
            &Limits::default(),
            "2026-11-19T06:00:00Z",
        ) {
            Ok(v) => {
                assert_eq!(v.method, "selfcal");
                assert!(verify(&v, &pk).is_empty());
                assert!(v.verdict.get("converged").is_some() && v.verdict.get("lineage").is_some());
                assert!(
                    v.verdict.get("records").is_none()
                        && v.verdict.get("scenario").is_none()
                        && v.verdict.get("params").is_none()
                );
            }
            Err(e) => assert!(
                e.contains("selfcal") || e.contains("observation") || e.contains("parameter"),
                "{e}"
            ),
        }
    }

    #[test]
    fn oversized_requests_are_refused_before_any_work() {
        let (seed, _) = key();
        let mut cfg = SurveyConfig {
            area: [0.0, 10.0, 0.0, 10.0],
            step_deg: 0.001,
            budget: 3,
            ..SurveyConfig::default()
        };
        let req = |c: &SurveyConfig| SurveyRequest {
            config: c.clone(),
            include_grid: false,
        };
        let e = survey_verdict(&req(&cfg), &signing(&seed), &Limits::default(), false, "t")
            .unwrap_err();
        assert!(e.contains("survey too large"), "{e}");
        cfg.step_deg = 0.0;
        assert!(
            survey_verdict(&req(&cfg), &signing(&seed), &Limits::default(), false, "t")
                .unwrap_err()
                .contains("survey too large")
        );
        cfg.step_deg = 1.0;
        cfg.budget = 1000;
        assert!(
            survey_verdict(&req(&cfg), &signing(&seed), &Limits::default(), false, "t")
                .unwrap_err()
                .contains("budget")
        );
    }

    #[test]
    fn survey_numbers_are_coarsened() {
        let (seed, _) = key();
        let cfg: SurveyConfig = toml::from_str(
            r#"
            area = [54.0, 56.0, 10.0, 13.0]
            step_deg = 0.5
            budget = 2
            stations = [["A", 57.5, 10.0], ["B", 52.5, 8.5], ["C", 54.5, 16.0]]
            "#,
        )
        .unwrap();
        let v = survey_verdict(
            &SurveyRequest {
                config: cfg,
                include_grid: false,
            },
            &signing(&seed),
            &Limits::default(),
            false,
            "t",
        )
        .unwrap();
        let x = v.verdict["mean_pl_after_m"].as_f64().unwrap();
        assert_eq!(x, crate::outputs::round_sig(x, 3));
    }
}
