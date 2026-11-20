// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;
use crate::audit::tests::Lcg;
use crate::methods::{raw_outcome, Limits};
use serde_json::json;

fn keys(n: usize) -> FpKeys {
    FpKeys {
        format: KEYS_FORMAT.into(),
        epochs: (0..n)
            .map(|i| Epoch {
                id: format!("e{i}"),
                from_unix: i as i64 * 1000,
                key_hex: hex::encode([i as u8 + 1; 32]),
            })
            .collect(),
    }
}

/// A survey request with station C moved and a budget.
pub(crate) fn survey(lat: f64, lon: f64, budget: usize) -> Value {
    json!({"config": {"area": [54.0, 56.0, 10.0, 13.0], "step_deg": 0.5, "budget": budget,
        "stations": [["A", 57.5, 10.0], ["B", 52.5, 8.5], ["C", lat, lon]], "candidates": [],
        "sigma_floor_m": 15.0, "sigma_scale_m": 60.0, "corr_km": 80.0, "survey_noise_m": 5.0,
        "toa_noise_m": 10.0, "k_pl": 5.33, "target_pl_m": 300.0}, "include_grid": false})
}

fn raw(m: &str, r: &Value) -> Result<Value, String> {
    raw_outcome(m, r, &Limits::default())
}

#[test]
fn directed_rounding_basics() {
    assert_eq!(round_dir(0.81243, 3, true), 0.813);
    assert_eq!(round_dir(0.81243, 3, false), 0.812);
    assert_eq!(round_dir(-0.81243, 3, true), -0.812);
    assert_eq!(
        round_dir(0.125, 3, true),
        0.125,
        "exact numbers carry no bit"
    );
    assert_eq!(round_dir(123.456, 3, true), 124.0);
    assert_eq!(round_dir(0.99961, 3, true), 1.0);
    assert_eq!(quantum(123.4, 3), 1.0);
    assert!(is_round(0.9, 3) && is_round(1.0, 3) && is_round(300.0, 3) && !is_round(0.913, 3));
}

/// The bound, on random verdict-shaped numbers and directions: within one unit in the last
/// figure, never onto or off a round value, family order kept, per-item uncertainty rule.
#[test]
fn fingerprint_stays_inside_the_stated_bound() {
    let mut r = Lcg(42);
    for trial in 0..2000 {
        let x = |r: &mut Lcg| (r.next() * 2.0 - 0.5) * 10f64.powi((r.next() * 6.0) as i32 - 3);
        let c0 = r.next();
        let c1 = (c0 + r.next() * 0.01).min(0.99999);
        let se = r.next() * 0.01;
        let raw = json!({
            "coverage_before": c0, "coverage_after": c1,
            "mean_pl_before_m": x(&mut r).abs() + 1.0, "mean_pl_after_m": x(&mut r).abs() + 1.0,
            "picks": [{"order": 1, "lat_deg": 55.123456, "lon_deg": 12.5, "coverage": c0 + (c1 - c0) * 0.3, "mean_pl_m": 400.123},
                      {"order": 2, "lat_deg": 55.5, "lon_deg": 12.987654, "coverage": c0 + (c1 - c0) * 0.7, "mean_pl_m": 399.9}],
            "posterior": [{"name": "a", "value": 1.0 + x(&mut r), "std_err": se}],
            "evidence": "MODELLED",
        });
        let bits = [r.next() < 0.5, r.next() < 0.5];
        for method in ["survey-plan", "calibrate"] {
            let mut v = raw.clone();
            apply(&mut v, method, 3, &|f| {
                Some(if f == "coverage" { bits[0] } else { bits[1] })
            });
            let mut n = raw.clone();
            coarsen(&mut n, 3);
            for l in leaves(&raw, method, 3) {
                let y = v.pointer(&l.pointer).unwrap().as_f64().unwrap();
                let nn = n.pointer(&l.pointer).unwrap().as_f64().unwrap();
                let q = quantum(l.x, 3);
                assert!(
                    (y - l.x).abs() < q * (1.0 + 1e-9),
                    "{trial} {} {} {y}",
                    l.pointer,
                    l.x
                );
                if y != nn {
                    assert!(!is_round(y, 3) && !is_round(nn, 3), "{y} {nn}");
                    assert!(l.tolerable);
                }
            }
            // Everything outside the plan is exactly the plain rounding.
            for k in [
                "evidence",
                "picks/0/lat_deg",
                "picks/1/lon_deg",
                "picks/0/order",
                "posterior/0/std_err",
            ] {
                assert_eq!(
                    v.pointer(&format!("/{k}")),
                    n.pointer(&format!("/{k}")),
                    "{k}"
                );
            }
            // Order of the coverage family kept.
            let g = |p: &str| v.pointer(p).unwrap().as_f64().unwrap();
            assert!(g("/coverage_before") <= g("/picks/0/coverage"));
            assert!(g("/picks/0/coverage") <= g("/picks/1/coverage"));
            assert!(g("/picks/1/coverage") <= g("/coverage_after"));
            // Posterior value: only when one unit is within 0.2 standard uncertainties.
            let pv = raw["posterior"][0]["value"].as_f64().unwrap();
            if method == "calibrate" && quantum(pv, 3) > 0.2 * se {
                assert_eq!(v["posterior"][0]["value"], n["posterior"][0]["value"]);
            }
        }
    }
}

#[test]
fn survey_verdicts_differ_by_licence_inside_the_bound_and_keep_their_class() {
    let k = keys(1);
    let req = survey(54.5, 16.0, 3);
    let r = raw("survey-plan", &req).unwrap();
    let mut seen = std::collections::HashSet::new();
    for t in 0..12 {
        let m = Mark::new(&k.epochs[0], &format!("tok{t}"), "survey-plan", &req).unwrap();
        let mut v = r.clone();
        m.apply(&mut v, 3);
        // Same as plain rounding except fingerprinted numbers, each within one unit.
        let mut n = r.clone();
        coarsen(&mut n, 3);
        for l in leaves(&r, "survey-plan", 3) {
            let y = v.pointer(&l.pointer).unwrap().as_f64().unwrap();
            assert!((y - l.x).abs() < quantum(l.x, 3));
        }
        assert_eq!(
            v["picks"].as_array().unwrap().len(),
            n["picks"].as_array().unwrap().len()
        );
        for (a, b) in v["picks"]
            .as_array()
            .unwrap()
            .iter()
            .zip(n["picks"].as_array().unwrap())
        {
            assert_eq!(a["lat_deg"], b["lat_deg"]);
            assert_eq!(a["lon_deg"], b["lon_deg"]);
            assert_eq!(a["order"], b["order"]);
        }
        assert_eq!(v["evidence"], n["evidence"]);
        seen.insert(v.to_string());
    }
    assert!(seen.len() > 1, "licences get different fingerprints");
}

#[test]
fn key_file_rotation_keeps_history() {
    let dir = std::env::temp_dir().join(format!("meru-fp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("keys.json");
    let _ = std::fs::remove_file(&p);
    let a = FpKeys::rotate(&p, 100).unwrap();
    let b = FpKeys::rotate(&p, 200).unwrap();
    let k = FpKeys::load(&p).unwrap();
    assert_eq!(k.epochs.len(), 2);
    assert_ne!(k.epochs[0].key_hex, k.epochs[1].key_hex);
    assert_eq!(k.active(150).unwrap().id, a);
    assert_eq!(k.active(250).unwrap().id, b);
    assert!(k.active(50).is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(FpKeys::parse(r#"{"format":"x","epochs":[]}"#).is_err());
    let dup = json!({"format": KEYS_FORMAT, "epochs": [
        {"id": "a", "from_unix": 0, "key_hex": "00".repeat(32)},
        {"id": "a", "from_unix": 1, "key_hex": "11".repeat(32)}]});
    assert!(FpKeys::parse(&dup.to_string()).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

fn requests(n: usize, seed: u64) -> Vec<Value> {
    let mut r = Lcg(seed);
    (0..n)
        .map(|_| {
            survey(
                52.0 + r.next() * 6.0,
                14.0 + r.next() * 5.0,
                2 + (r.next() * 3.0) as usize,
            )
        })
        .collect()
}

/// Acceptance (B2702): the ownership test recovers the licence from 50 verdicts, under an
/// epoch that has since been rotated out, and names nobody for unfingerprinted numbers.
#[test]
fn ownership_test_recovers_the_licence_from_50_verdicts() {
    let k = keys(2);
    let cands: Vec<String> = (0..10).map(|i| format!("licence-{i}")).collect();
    let reqs = requests(50, 9);
    let mk = |tok: &str, epoch: &Epoch| -> Vec<Suspect> {
        reqs.iter()
            .map(|q| {
                let mut v = raw("survey-plan", q).unwrap();
                Mark::new(epoch, tok, "survey-plan", q)
                    .unwrap()
                    .apply(&mut v, 3);
                Suspect {
                    method: "survey-plan".into(),
                    request: q.clone(),
                    verdict: v,
                }
            })
            .collect()
    };
    let rep = ownership(&mk("licence-3", &k.epochs[0]), &k, &cands, 3, &raw);
    assert_eq!(rep.attributed.as_deref(), Some("licence-3"), "{rep:#?}");
    assert_eq!(rep.foreign, 0);
    let best = &rep.scores[0];
    assert_eq!((best.epoch.as_str(), best.matches), ("e0", best.bits));
    assert!(best.bits >= 30, "{best:?}");
    let other = rep
        .scores
        .iter()
        .find(|s| s.token_id != "licence-3")
        .unwrap();
    assert!(other.log10_p > -4.0, "{other:?}");

    // Plain rounding (no fingerprint): nobody is named.
    let plain: Vec<Suspect> = reqs
        .iter()
        .map(|q| {
            let mut v = raw("survey-plan", q).unwrap();
            coarsen(&mut v, 3);
            Suspect {
                method: "survey-plan".into(),
                request: q.clone(),
                verdict: v,
            }
        })
        .collect();
    assert!(ownership(&plain, &k, &cands, 3, &raw).attributed.is_none());

    // Numbers rounded again to two figures are not meru's: counted as foreign, nobody named.
    let mut rer = mk("licence-3", &k.epochs[1]);
    for s in &mut rer {
        crate::outputs::coarsen(&mut s.verdict, 2);
    }
    let rep = ownership(&rer, &k, &cands, 3, &raw);
    assert!(rep.attributed.is_none() && rep.foreign > 0, "{rep:#?}");
}

#[test]
fn canary_cells_give_every_licence_the_same_pattern() {
    let k = keys(1);
    let e = &k.epochs[0];
    // Find canary requests by search (about one cell in 64).
    let mut canaries = vec![];
    let mut rng = Lcg(77);
    let wide = (0..4000).map(|_| {
        let mut q = survey(
            45.0 + rng.next() * 20.0,
            5.0 + rng.next() * 20.0,
            1 + (rng.next() * 5.0) as usize,
        );
        q["config"]["sigma_scale_m"] = json!(30.0 + rng.next() * 60.0);
        q
    });
    for q in wide {
        if Mark::new(e, "x", "survey-plan", &q).unwrap().is_canary() {
            canaries.push(q);
        }
        if canaries.len() == 8 {
            break;
        }
    }
    assert!(canaries.len() >= 4, "{}", canaries.len());
    for q in &canaries {
        let a = Mark::new(e, "licence-a", "survey-plan", q).unwrap();
        let b = Mark::new(e, "licence-b", "survey-plan", q).unwrap();
        assert!(a.is_canary() && b.is_canary());
        assert_eq!(a.up("coverage"), b.up("coverage"));
        assert_eq!(a.up("pl"), b.up("pl"));
    }
    // Numbers from canary cells count towards the canary score, not any licence.
    let sus: Vec<Suspect> = canaries
        .iter()
        .map(|q| {
            let mut v = raw("survey-plan", q).unwrap();
            Mark::new(e, "licence-a", "survey-plan", q)
                .unwrap()
                .apply(&mut v, 3);
            Suspect {
                method: "survey-plan".into(),
                request: q.clone(),
                verdict: v,
            }
        })
        .collect();
    let rep = ownership(&sus, &k, &["licence-a".into()], 3, &raw);
    assert!(
        rep.canary_bits > 0 && rep.canary_matches == rep.canary_bits,
        "{rep:#?}"
    );
    assert_eq!(rep.scores[0].bits, 0);
}

#[test]
fn unfingerprinted_methods_are_left_alone() {
    assert!(plan("cause").is_empty() && plan("lunar-assist").is_empty());
    let mut v = json!({"classification": "jamming", "confidence": 0.8123});
    let mut n = v.clone();
    apply(&mut v, "cause", 3, &|_| Some(true));
    coarsen(&mut n, 3);
    assert_eq!(v, n);
    assert!(log10_tail(50, 50) < -15.0 && log10_tail(50, 25) > -0.5);
}
