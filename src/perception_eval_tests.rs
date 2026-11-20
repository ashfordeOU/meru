// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;

fn declaration() -> Value {
    json!({"end_use": "road vehicle lane-level positioning", "classification": "unclassified",
        "release": "public", "signals": ["GPS L1 C/A", "Galileo E1"], "environment": "field"})
}

/// A synthetic campaign: `day` (1,000 epochs, 0.3 m error, HPL 1.5 m, three landmarks in view,
/// all identified) and `night` (1,000 epochs; 10 epochs with a 6 m error under an HPL of 2 m,
/// alert limit 5 m: hazardously misleading; one landmark in view missed in half the epochs;
/// one detection a epoch in 50 claimed as the wrong landmark while the system said its integrity
/// was good; 20 false detections; 50 epochs unavailable).
fn campaign() -> PerceptionRequest {
    let mut runs = vec![];
    for cond in ["day", "night"] {
        let mut eps = vec![];
        for i in 0..1000usize {
            let t = 1_795_000_000.0 + i as f64;
            let night = cond == "night";
            let big = night && i % 100 == 7;
            let err = if big { 6.0 } else { 0.3 };
            let unavailable = night && i % 20 == 3;
            let mut det = vec![
                json!({"claimed": "LM-A", "truth": "LM-A"}),
                json!({"claimed": "LM-B", "truth": "LM-B"}),
            ];
            if !(night && i % 2 == 0) {
                det.push(json!({"claimed": "LM-C", "truth": "LM-C"}));
            }
            if night && i % 50 == 11 {
                det.push(json!({"claimed": "LM-D", "truth": "LM-E"}));
            }
            if night && i % 50 == 13 {
                det.push(json!({"claimed": "LM-F", "truth": null}));
            }
            eps.push(json!({
                "t": t,
                "truth": {"e_m": i as f64, "n_m": 0.0},
                "output": {"available": !unavailable, "position": {"e_m": i as f64 + err, "n_m": 0.0},
                    "hpl_m": if night { 2.0 } else { 1.5 }, "integrity_ok": true},
                "in_view": ["LM-A", "LM-B", "LM-C"],
                "detections": det,
            }));
        }
        runs.push(json!({"id": format!("RUN-{cond}"), "condition": cond, "epochs": eps}));
    }
    serde_json::from_value(json!({
        "system": "SYNTH-PERCEPTION-1",
        "declaration": declaration(),
        "alert_limit_m": 5.0,
        "claims": {"min_availability": 0.9, "max_hmi_rate": 1e-4, "max_misidentification_rate": 0.01, "max_h95_m": 1.0},
        "runs": runs,
    }))
    .unwrap()
}

fn cond<'a>(v: &'a Value, c: &str) -> &'a Value {
    v["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["condition"] == c)
        .unwrap()
}

#[test]
fn integrity_classes_and_landmark_scores() {
    let v = analyse(&campaign(), &PerceptionLimits::default()).unwrap();
    let day = cond(&v, "day");
    assert_eq!(day["integrity"]["hazardously_misleading"], 0);
    assert_eq!(day["integrity"]["nominal"], 1000);
    assert_eq!(day["landmarks"]["recall"]["value"], 1.0);
    let night = cond(&v, "night");
    // 50 unavailable; of the 10 large errors, i % 100 == 7 never coincides with i % 20 == 3.
    assert_eq!(night["integrity"]["availability"]["count"], 950);
    assert_eq!(night["integrity"]["hazardously_misleading"], 10);
    assert_eq!(night["landmarks"]["misidentified_while_integrity_ok"], 20);
    assert_eq!(night["landmarks"]["false_detections"], 20);
    let recall = night["landmarks"]["recall"]["value"].as_f64().unwrap();
    assert!((recall - (2500.0 / 3000.0)).abs() < 1e-9, "{recall}");
    // Overall claims.
    assert_eq!(v["claims"]["min_availability"], "met");
    assert_eq!(v["claims"]["max_hmi_rate"], "not_met");
    // 20 misidentified of 5,540 detections: upper bound about 0.0056, under 0.01.
    assert_eq!(v["claims"]["max_misidentification_rate"], "met");
    assert_eq!(v["claims"]["max_h95_m"], "met");
    // The day run alone cannot show a 1e-4 HMI rate with 1,000 epochs: the note says so.
    let mut r = campaign();
    r.runs.truncate(1);
    let v = analyse(&r, &PerceptionLimits::default()).unwrap();
    assert_eq!(v["claims"]["max_hmi_rate"], "not_shown");
    assert!(v["notes"][0].as_str().unwrap().contains("cannot be shown"));
}

#[test]
fn the_civil_releasability_screen_runs_first() {
    for (k, val, want) in [
        (
            "end_use",
            json!("missile seeker terminal guidance"),
            "missile",
        ),
        (
            "end_use",
            json!("Fire control for an artillery battery"),
            "fire control",
        ),
        ("classification", json!("restricted"), "unclassified"),
        ("release", json!("export-controlled"), "release"),
        ("signals", json!(["GPS M-code"]), "m-code"),
        ("signals", json!(["Galileo PRS"]), "prs"),
        ("signals", json!(["GPS P(Y)"]), "p(y)"),
        ("environment", json!("battlefield"), "environment"),
    ] {
        let mut r = serde_json::to_value(declaration()).unwrap();
        r[k] = val;
        let mut req = campaign();
        req.declaration = serde_json::from_value(r).unwrap();
        let e = analyse(&req, &PerceptionLimits::default()).unwrap_err();
        assert!(e.contains(want), "{k}: {e}");
    }
    // A civil signal that merely contains the letters is not refused.
    let mut req = campaign();
    req.declaration.signals = vec!["Galileo E5 AltBOC express".into(), "BeiDou B1C".into()];
    assert!(analyse(&req, &PerceptionLimits::default()).is_ok());
}

#[test]
fn refusals_and_no_navigation_inputs() {
    let mut r = campaign();
    r.alert_limit_m = 0.0;
    assert!(analyse(&r, &PerceptionLimits::default()).is_err());
    let mut r = campaign();
    r.runs[0].epochs.swap(3, 4);
    assert!(analyse(&r, &PerceptionLimits::default())
        .unwrap_err()
        .contains("time order"));
    let l = PerceptionLimits {
        max_epochs: 100,
        ..PerceptionLimits::default()
    };
    assert!(analyse(&campaign(), &l).is_err());
    // No map, no raw sensor data: the request has no such field.
    let mut v = serde_json::to_value(declaration()).unwrap();
    v["map"] = json!("tiles.mbtiles");
    assert!(serde_json::from_value::<Declaration>(v).is_err());
    assert!(
        serde_json::from_value::<Epoch>(json!({"t": 0, "truth": {"e_m": 0, "n_m": 0},
        "output": {"available": true}, "point_cloud": []}))
        .is_err()
    );
}

#[test]
fn verdict_is_signed() {
    let seed = *b"meru-service-test-key-32-bytes!!";
    let pk = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    );
    let s = crate::methods::Signing {
        signer: &seed,
        key_id: "k1",
        lineage_seed: &seed,
        lineage_key_id: "k1",
        sigfigs: 3,
        bind: None,
    };
    let v = perception_verdict(&campaign(), &s, &PerceptionLimits::default(), "t").unwrap();
    assert_eq!(v.method, "perception-eval");
    assert!(crate::verdict::verify(&v, &pk).is_empty());
    assert!(!v.verdict.to_string().contains("RUN-day"));
}
