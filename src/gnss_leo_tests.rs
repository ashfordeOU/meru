// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;

const T0: f64 = 1_795_000_000.0;

/// 30 minutes at 1 Hz. The site clock drifts 0.02 ns/s; both sources read it with 5 ns noise
/// (deterministic). `fault` adjusts an epoch's GNSS and LEO values from second `t`.
fn epochs(fault: &dyn Fn(f64, &mut Value, &mut Value)) -> Vec<Value> {
    (0..1800)
        .map(|i| {
            let t = i as f64;
            let clock = 0.02 * t;
            let mut g = json!({"valid": true, "time_offset_ns": clock + 5.0 * (t * 0.7).sin(),
                "cn0_mean_dbhz": 42.0 + 0.3 * (t * 0.11).sin(), "n_sats": 10, "auth_ok": true});
            let mut l = json!({"valid": true, "time_offset_ns": clock + 5.0 * (t * 0.37).cos(),
                "quality": 0.9, "n_sats": 4});
            fault(t, &mut g, &mut l);
            json!({"t": T0 + t, "gnss": g, "leo": l})
        })
        .collect()
}

fn req(e: Vec<Value>) -> ArbitrationRequest {
    serde_json::from_value(json!({"subject": "synthetic site", "epochs": e})).unwrap()
}

/// B2106 acceptance: a fault injected on GNSS (a slow time pull with a C/N0 rise and failed
/// authentication) is arbitrated against GNSS.
#[test]
fn a_gnss_fault_is_arbitrated_against_gnss() {
    let v = analyse(
        &req(epochs(&|t, g, _l| {
            if t >= 1000.0 {
                g["time_offset_ns"] =
                    json!(g["time_offset_ns"].as_f64().unwrap() + 2.0 * (t - 1000.0));
                g["cn0_mean_dbhz"] = json!(47.0);
                g["auth_ok"] = json!(false);
            }
        })),
        &ArbitrationLimits::default(),
    )
    .unwrap();
    let e = &v["episodes"][0];
    assert_eq!(e["suspect"], "gnss", "{v:#}");
    assert_eq!(e["evidence_supports"], "leo");
    assert!(e["confidence"].as_f64().unwrap() >= 0.9, "{e:#}");
    assert_eq!(v["episodes"].as_array().unwrap().len(), 1);
}

/// B2106 acceptance: a fault injected on LEO (a 400 ns time step with a low quality figure) is
/// arbitrated against LEO.
#[test]
fn a_leo_fault_is_arbitrated_against_leo() {
    let v = analyse(
        &req(epochs(&|t, _g, l| {
            if (1200.0..1500.0).contains(&t) {
                l["time_offset_ns"] = json!(l["time_offset_ns"].as_f64().unwrap() + 400.0);
                l["quality"] = json!(0.3);
            }
        })),
        &ArbitrationLimits::default(),
    )
    .unwrap();
    let e = &v["episodes"][0];
    assert_eq!(e["suspect"], "leo", "{v:#}");
    assert_eq!(e["evidence_supports"], "gnss");
    assert_eq!(
        v["integrity"]["disagreement_epochs_with_a_supported_source"],
        300
    );
}

#[test]
fn agreement_needs_no_arbitration_and_thin_evidence_stays_undetermined() {
    let v = analyse(&req(epochs(&|_, _, _| {})), &ArbitrationLimits::default()).unwrap();
    assert_eq!(v["episodes"].as_array().unwrap().len(), 0);
    assert_eq!(v["integrity"]["agreement_share"], 1.0);
    // A disagreement from the very start: no agreed baseline, no indicators: undetermined.
    let e: Vec<Value> = epochs(&|t, g, _l| {
        g["time_offset_ns"] = json!(g["time_offset_ns"].as_f64().unwrap() + 300.0 + 0.0 * t);
        g.as_object_mut().unwrap().remove("cn0_mean_dbhz");
        g.as_object_mut().unwrap().remove("auth_ok");
    });
    let v = analyse(&req(e), &ArbitrationLimits::default()).unwrap();
    assert_eq!(v["episodes"][0]["suspect"], "undetermined", "{v:#}");
    // Nothing here is a fused or navigation output.
    let s = v.to_string();
    assert!(!s.contains("fused_") && !s.contains("solution_ns"));
    assert!(v["statement"]
        .as_str()
        .unwrap()
        .contains("no fused solution"));
}

#[test]
fn refusals() {
    let mut r = req(epochs(&|_, _, _| {}));
    r.tolerance_ns = 0.0;
    assert!(analyse(&r, &ArbitrationLimits::default()).is_err());
    let l = ArbitrationLimits { max_epochs: 100 };
    assert!(analyse(&req(epochs(&|_, _, _| {})), &l).is_err());
}

/// audit-1: one family never decides. The single-family cap was 0.75, above the 0.7 decision
/// threshold, so one reference finding (or one strong indicator) named a suspect on its own.
#[test]
fn one_family_alone_never_decides() {
    for (family, weight) in [("reference", 2.2), ("indicators", 1.3), ("dynamics", 5.0)] {
        let f = vec![Finding {
            family,
            suspect: Src::Gnss,
            weight,
            text: String::new(),
        }];
        let (side, p) = combine(&f);
        assert_eq!(side, Some(Src::Gnss));
        assert!(p < DECIDE_AT, "{family}: {p}");
    }
    // Two families can still decide.
    let f = vec![
        Finding {
            family: "reference",
            suspect: Src::Gnss,
            weight: 2.2,
            text: String::new(),
        },
        Finding {
            family: "indicators",
            suspect: Src::Gnss,
            weight: 1.3,
            text: String::new(),
        },
    ];
    assert!(combine(&f).1 >= DECIDE_AT);
}
