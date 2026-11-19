// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The two hosted methods. Each runs the engine method server-side and returns a signed
//! verdict carrying the outcome only; the per-iteration records, internal parameter state,
//! regenerated scenario and full grids stay in the service.
//!
//! * F1 — the self-calibrating simulator loop ([`selfcal_verdict`]).
//! * F2 — the integrity-driven ASF survey planner ([`survey_verdict`]).

use crate::verdict::{sign, SignedVerdict};
use kshana_eloran::calreg::Register;
use kshana_eloran::plan::survey::{plan, SurveyConfig};
use kshana_eloran::valid::selfcal::{run_selfcal, RefObservation, RefSite, SelfCalConfig};
use kshana_eloran::Scenario;
use serde::Deserialize;
use serde_json::json;

/// Request for F1 (self-calibrating simulator loop).
#[derive(Clone, Debug, Deserialize)]
pub struct SelfCalRequest {
    /// The base scenario (TOML).
    pub scenario_toml: String,
    pub config: SelfCalConfig,
    pub sites: Vec<RefSite>,
    pub observations: Vec<RefObservation>,
}

/// Run F1 and return a signed verdict: convergence, fidelity, the calibrated parameters with
/// their uncertainty, and the signed lineage head. The per-iteration records, internal
/// parameter state and the regenerated scenario stay in the service.
pub fn selfcal_verdict(
    req: &SelfCalRequest,
    seed: &[u8; 32],
    key_id: &str,
    utc: &str,
) -> Result<SignedVerdict, String> {
    let base = Scenario::from_toml(&req.scenario_toml).map_err(|e| format!("scenario: {e}"))?;
    base.build().map_err(|e| format!("scenario: {e}"))?;
    // A per-request lineage register, kept inside the service.
    let dir = std::env::temp_dir().join(format!(
        "meru-{}-{}",
        std::process::id(),
        utc.replace([':', '-'], "")
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let reg_path = dir.join("lineage.jsonl");
    let register = Register::open(&reg_path);
    let r = run_selfcal(
        &base,
        &req.config,
        &req.sites,
        &req.observations,
        None,
        &register,
        seed,
        key_id,
    );
    let _ = std::fs::remove_dir_all(&dir);
    let r = r?;
    let scores = r.scores();
    let verdict = json!({
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
    Ok(sign("selfcal", "MODELLED", verdict, seed, key_id, utc))
}

/// Request for F2 (integrity-driven ASF survey planner).
#[derive(Clone, Debug, Deserialize)]
pub struct SurveyRequest {
    pub config: SurveyConfig,
    /// Include the full per-cell protection-level grid (an internal detail; off by default).
    #[serde(default)]
    pub include_grid: bool,
}

/// Run F2 and return a signed verdict: coverage and mean protection level before and after,
/// and the chosen survey points. The full protection-level grid is internal unless asked for.
pub fn survey_verdict(
    req: &SurveyRequest,
    seed: &[u8; 32],
    key_id: &str,
    utc: &str,
) -> Result<SignedVerdict, String> {
    let p = plan(&req.config)?;
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
            .map(|(a, o, b, c)| json!([a, o, b, c]))
            .collect::<Vec<_>>());
    }
    Ok(sign("survey-plan", "MODELLED", verdict, seed, key_id, utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::verify;
    use ed25519_dalek::SigningKey;

    fn key() -> ([u8; 32], String) {
        let seed = *b"meru-service-test-key-32-bytes!!";
        let pk = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        (seed, hex::encode(pk))
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
            &seed,
            "k1",
            "2026-11-19T06:00:00Z",
        )
        .unwrap();
        assert_eq!(v.method, "survey-plan");
        assert!(verify(&v, &pk).is_empty(), "{:?}", verify(&v, &pk));
        // A tampered verdict does not verify.
        let mut t = v.clone();
        t.verdict["coverage_after"] = json!(1.0);
        assert!(!verify(&t, &pk).is_empty());
        // Internal grid withheld by default, present on request.
        assert!(v.verdict.get("grid").is_none());
        let g = survey_verdict(
            &SurveyRequest {
                config: cfg,
                include_grid: true,
            },
            &seed,
            "k1",
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
            &seed,
            "k1",
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
}
