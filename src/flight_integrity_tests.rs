// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;

const T0: f64 = 1_795_000_000.0;

/// A flight of 20 minutes at 1 Hz, 10 m/s east from `start`; `degrade` marks the epochs (s
/// after T0) without a 3-D fix and with the receiver's jamming flag; `jump_at` moves one epoch
/// by 2 km.
fn flight(start: (f64, f64), degrade: Option<(f64, f64)>, jump_at: Option<f64>) -> Vec<Value> {
    (0..1200)
        .map(|i| {
            let t = i as f64;
            let mut lon = start.1 + 10.0 * t / (111_320.0 * start.0.to_radians().cos());
            if jump_at == Some(t) {
                lon += 0.03;
            }
            let bad = degrade.is_some_and(|(a, b)| t >= a && t < b);
            json!({
                "t": T0 + t,
                "lat_deg": start.0,
                "lon_deg": lon,
                "fix_type": if bad { 0 } else { 3 },
                "eph_m": if bad { 50.0 } else { 1.5 },
                "jamming_state": if bad { 2 } else { 0 },
                "spoofing_state": 0,
            })
        })
        .collect()
}

fn request(
    subject: Vec<Value>,
    others: Vec<Vec<Value>>,
    regional: Option<Vec<Value>>,
) -> FlightRequest {
    let others: Vec<Value> = others
        .into_iter()
        .enumerate()
        .map(|(i, t)| json!({"id": format!("UAS-{i}"), "telemetry": t}))
        .collect();
    let mut v = json!({
        "operation": {"id": "OP-SYNTH-1", "speed_m_s": 10.0, "contingency_m": 500.0},
        "telemetry": subject,
        "others": others,
    });
    if let Some(r) = regional {
        v["regional"] = json!(r);
    }
    serde_json::from_value(v).unwrap()
}

fn region_event() -> Value {
    json!({
        "format": "kshana-pnt-interference-event/1",
        "id": "reg-jam",
        "start_utc": iso(T0 as i64),
        "end_utc": iso(T0 as i64 + 1200),
        "systems": [{"system": "gnss", "band": "L1"}],
        "kind": "jamming",
        "location": {"lat_deg": 52.0, "lon_deg": 5.05, "radius_m": 20000.0},
        "observers": ["monitor-1", "monitor-2"],
        "confidence": 0.8,
        "basis": "monitoring network",
        "corroborated": true,
    })
}

const NEAR: [(f64, f64); 4] = [(52.01, 5.0), (52.02, 5.01), (51.99, 5.02), (52.03, 4.99)];

#[test]
fn area_cause_when_nearby_flights_degrade_together() {
    let deg = Some((300.0, 360.0));
    let others = NEAR.iter().map(|p| flight(*p, deg, None)).collect();
    let v = analyse(
        &request(
            flight((52.0, 5.0), deg, None),
            others,
            Some(vec![region_event()]),
        ),
        &FlightLimits::default(),
    )
    .unwrap();
    assert_eq!(v["statement"], "DEGRADED", "{v:#}");
    assert_eq!(v["attribution"], "area", "{v:#}");
    assert!(v["confidence"].as_f64().unwrap() >= 0.7);
    assert_eq!(v["context"]["other_flights_near"], 4);
    assert_eq!(v["context"]["other_flights_degraded_with_it"], 4);
    assert_eq!(v["context"]["regional_interference"], true);
    // Nothing internal: no other flight ids, no scores.
    let s = v.to_string();
    assert!(!s.contains("UAS-0") && !s.contains("score"));
}

#[test]
fn aircraft_cause_when_nearby_flights_are_unaffected() {
    let others = NEAR.iter().map(|p| flight(*p, None, None)).collect();
    let v = analyse(
        &request(flight((52.0, 5.0), None, Some(400.0)), others, Some(vec![])),
        &FlightLimits::default(),
    )
    .unwrap();
    assert_eq!(v["statement"], "INTEGRITY-SUSPECT", "{v:#}");
    assert_eq!(v["telemetry"]["position_jumps"], 2);
    assert_eq!(v["attribution"], "aircraft", "{v:#}");
}

#[test]
fn indeterminate_without_context_and_nominal_needs_none() {
    let v = analyse(
        &request(
            flight((52.0, 5.0), Some((300.0, 360.0)), None),
            vec![],
            None,
        ),
        &FlightLimits::default(),
    )
    .unwrap();
    assert_eq!(v["attribution"], "indeterminate", "{v:#}");
    assert_eq!(v["leading"], "area");
    assert!(v["limits"].to_string().contains("No other flights"));
    let v = analyse(
        &request(flight((52.0, 5.0), None, None), vec![], None),
        &FlightLimits::default(),
    )
    .unwrap();
    assert_eq!(v["statement"], "NOMINAL");
    assert_eq!(v["attribution"], "not_applicable");
    assert!(v["confidence"].is_null());
}

#[test]
fn far_flights_are_not_context() {
    let deg = Some((300.0, 360.0));
    let others = vec![flight((53.0, 6.0), None, None)];
    let v = analyse(
        &request(flight((52.0, 5.0), deg, None), others, None),
        &FlightLimits::default(),
    )
    .unwrap();
    assert_eq!(v["context"]["other_flights_near"], 0);
    assert!(v["limits"].to_string().contains("No other flight was near"));
}

/// An attestation as the Pro client writes it for this flight.
fn attestation(statement: &str) -> Value {
    json!({
        "format": "kshana-pro-utm-attestation/1",
        "evidence": "MODELLED",
        "operation": "OP-SYNTH-1",
        "epochs": 1200,
        "skipped_rows": 0,
        "share_no_3d_fix": 0.05,
        "longest_gap_s": 60.0,
        "gap_dr_error_m": 120.0,
        "jamming_epochs": 60,
        "spoofing_epochs": 0,
        "position_jumps": 0,
        "statement": statement,
        "reasons": [],
    })
}

#[test]
fn attestation_is_bound_and_compared() {
    let deg = Some((300.0, 360.0));
    let mut r = request(flight((52.0, 5.0), deg, None), vec![], None);
    r.attestation = Some(attestation("DEGRADED"));
    let v = analyse(&r, &FlightLimits::default()).unwrap();
    assert_eq!(v["attestation"]["agrees"], true, "{v:#}");
    assert_eq!(
        v["attestation"]["sha256"],
        canonical_sha256(&attestation("DEGRADED"))
    );
    // A client that claims less than the telemetry shows is caught; a stricter one is not.
    r.attestation = Some(attestation("NOMINAL"));
    let v = analyse(&r, &FlightLimits::default()).unwrap();
    assert_eq!(v["attestation"]["agrees"], false);
    assert_eq!(v["attestation"]["mismatched"], json!(["statement"]));
    r.attestation = Some(attestation("INTEGRITY-SUSPECT"));
    assert_eq!(
        analyse(&r, &FlightLimits::default()).unwrap()["attestation"]["agrees"],
        true
    );
    let mut a = attestation("DEGRADED");
    a["jamming_epochs"] = json!(3);
    r.attestation = Some(a);
    let v = analyse(&r, &FlightLimits::default()).unwrap();
    assert_eq!(v["attestation"]["mismatched"], json!(["jamming_epochs"]));
    // audit-1: a missing or unknown statement is a mismatch (it used to agree with anything).
    for st in [json!(null), json!("nominal"), json!("OK"), json!(3)] {
        let mut a = attestation("DEGRADED");
        a["statement"] = st.clone();
        if st.is_null() {
            a.as_object_mut().unwrap().remove("statement");
        }
        r.attestation = Some(a);
        let v = analyse(&r, &FlightLimits::default()).unwrap();
        assert_eq!(v["attestation"]["agrees"], false, "{st}: {v:#}");
        assert_eq!(v["attestation"]["mismatched"], json!(["statement"]), "{st}");
    }
    r.attestation = Some(json!({"format": "something-else"}));
    assert!(analyse(&r, &FlightLimits::default()).is_err());
}

#[test]
fn refusals() {
    let l = FlightLimits {
        max_epochs: 100,
        ..FlightLimits::default()
    };
    let r = request(flight((52.0, 5.0), None, None), vec![], None);
    assert!(analyse(&r, &l).unwrap_err().contains("telemetry"));
    let mut r = request(flight((52.0, 5.0), None, None), vec![], None);
    r.operation.speed_m_s = 0.0;
    assert!(analyse(&r, &FlightLimits::default()).is_err());
    let mut bad = region_event();
    bad["format"] = json!("nope");
    let r = request(
        flight((52.0, 5.0), Some((10.0, 20.0)), None),
        vec![],
        Some(vec![bad]),
    );
    assert!(analyse(&r, &FlightLimits::default())
        .unwrap_err()
        .contains("regional[0]"));
    assert!(serde_json::from_value::<FlightRequest>(
        json!({"operation": {}, "telemetry": [], "extra": 1})
    )
    .is_err());
}

#[test]
fn verdict_is_signed_with_the_decision_support_statement() {
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
    let v = flight_verdict(
        &request(flight((52.0, 5.0), None, None), vec![], None),
        &s,
        &FlightLimits::default(),
        "2026-11-20T00:00:00Z",
    )
    .unwrap();
    assert_eq!(v.method, "flight-integrity");
    assert!(crate::verdict::verify(&v, &pk).is_empty());
    assert_eq!(v.verdict["decision_support"], DECISION_SUPPORT);
}
