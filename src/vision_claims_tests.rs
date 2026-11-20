// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;

const SEED: [u8; 32] = *b"meru-service-test-key-32-bytes!!";
const REG: i64 = 1_795_000_000;

fn signing() -> crate::methods::Signing<'static> {
    crate::methods::Signing {
        signer: &SEED,
        key_id: "k1",
        lineage_seed: &SEED,
        lineage_key_id: "k1",
        sigfigs: 3,
        bind: None,
    }
}

fn key() -> String {
    hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&SEED)
            .verifying_key()
            .to_bytes(),
    )
}

/// A vendor's claims for a synthetic system.
fn protocol() -> Protocol {
    serde_json::from_value(json!({
        "system": "SYNTH-VISION-NAV-1",
        "declaration": {"end_use": "road vehicle lane-level positioning", "classification": "unclassified",
            "release": "public", "signals": ["GPS L1 C/A"], "environment": "field"},
        "alert_limit_m": 2.0,
        "conditions": ["day", "night", "rain"],
        "claims": [
            {"kind": "horizontal_error", "percentile": 95.0, "max_m": 0.5},
            {"kind": "horizontal_error", "condition": "night", "percentile": 95.0, "max_m": 0.3},
            {"kind": "availability", "min": 0.98},
            {"kind": "hmi_rate", "max": 1e-5},
            {"kind": "misidentification_rate", "condition": "day", "max": 0.01},
        ]
    }))
    .unwrap()
}

/// A campaign after registration: day and night, 3,000 epochs each, errors spread from 0 to
/// 0.4 m by day and 0 to 0.6 m by night, all available, no hazardously misleading epoch, one
/// misidentification in 2,000 detections by day. No rain run.
fn campaign(start: f64) -> Vec<Value> {
    ["day", "night"]
        .iter()
        .map(|c| {
            let scale = if *c == "day" { 0.4 } else { 0.6 };
            let eps: Vec<Value> = (0..3000)
                .map(|i| {
                    let err = scale * ((i * 7919) % 3000) as f64 / 3000.0;
                    let det = if *c == "day" && i % 3 == 0 {
                        vec![json!({"claimed": if i == 999 { "LM-B" } else { "LM-A" }, "truth": "LM-A"})]
                    } else {
                        vec![]
                    };
                    json!({"t": start + i as f64, "truth": {"e_m": 0.0, "n_m": 0.0},
                        "output": {"available": true, "position": {"e_m": err, "n_m": 0.0}, "hpl_m": 1.5},
                        "detections": det})
                })
                .collect();
            json!({"id": c, "condition": c, "epochs": eps})
        })
        .collect()
}

fn claim(v: &Value, i: usize) -> &Value {
    &v["claims"][i]
}

#[test]
fn registered_claims_are_scored_neutrally() {
    let p = register_verdict(&protocol(), &signing(), REG).unwrap();
    assert_eq!(p.method, "claims-protocol");
    let r: ScoreRequest =
        serde_json::from_value(json!({"protocol": p, "runs": campaign(REG as f64 + 60.0)}))
            .unwrap();
    let v = score(&r, &key()).unwrap();
    // Overall 95th percentile about 0.57 m (half the epochs reach 0.6 m): above 0.5 m, clearly.
    assert_eq!(claim(&v, 0)["status"], "contradicted", "{:#}", claim(&v, 0));
    // Night 95th percentile about 0.57 m against a 0.3 m claim: contradicted.
    assert_eq!(claim(&v, 1)["status"], "contradicted");
    // Availability 1.0 over 6,000 epochs against 0.98: shown.
    assert_eq!(claim(&v, 2)["status"], "shown");
    // HMI 1e-5 with no event in 6,000 epochs: not shown; about 300,000 epochs needed.
    assert_eq!(claim(&v, 3)["status"], "not_shown");
    assert_eq!(claim(&v, 3)["epochs_needed_to_show"], 300_000);
    // Day misidentification: 1 in 1,000 detections, interval under 0.01: shown.
    assert_eq!(claim(&v, 4)["status"], "shown", "{:#}", claim(&v, 4));
    // Rain was registered but not tested.
    let rain = v["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["condition"] == "rain")
        .unwrap();
    assert_eq!(rain["tested"], false);
    assert_eq!(v["summary"]["shown"], 2);
    assert!(v["statement"].as_str().unwrap().contains("ranks no one"));
}

#[test]
fn a_campaign_before_registration_or_a_foreign_protocol_is_refused() {
    let p = register_verdict(&protocol(), &signing(), REG).unwrap();
    let r: ScoreRequest =
        serde_json::from_value(json!({"protocol": p, "runs": campaign(REG as f64 - 100.0)}))
            .unwrap();
    assert!(score(&r, &key()).unwrap_err().contains("predates"));
    // A protocol changed after registration does not verify.
    let mut t = register_verdict(&protocol(), &signing(), REG).unwrap();
    t.verdict["protocol"]["claims"][0]["max_m"] = json!(5.0);
    let r: ScoreRequest =
        serde_json::from_value(json!({"protocol": t, "runs": campaign(REG as f64 + 60.0)}))
            .unwrap();
    assert!(score(&r, &key())
        .unwrap_err()
        .contains("not one this service registered"));
}

#[test]
fn registration_is_checked() {
    let mut p = protocol();
    p.claims.push(Claim::HmiRate {
        condition: Some("fog".into()),
        max: 1e-4,
    });
    assert!(register_verdict(&p, &signing(), REG)
        .unwrap_err()
        .contains("not registered"));
    let mut p = protocol();
    p.declaration.end_use = "missile guidance".into();
    assert!(register_verdict(&p, &signing(), REG)
        .unwrap_err()
        .contains("civil-releasability"));
}
