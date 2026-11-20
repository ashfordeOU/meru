// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;

/// 500 five-minute bins. Feeders F1–F8 within about 60 km of 59.4 N 24.7 E, F9 900 km away. A
/// shared interference event in bins 100–129 seen by F1–F5 and F7; F5 also raises 30 lone
/// alarms; F6 sends a copy of F2's stream; F7 is silent through most of the event (it alarms in
/// 3 of its 30 bins); F8 alarms with the crowd but has few signed batches; F4 had a batch
/// rejected; F9 is alone.
fn network() -> FeederRequest {
    let pos = [
        ("F1", 59.40, 24.70),
        ("F2", 59.45, 24.80),
        ("F3", 59.35, 24.60),
        ("F4", 59.50, 24.95),
        ("F5", 59.30, 24.90),
        ("F6", 59.42, 24.75),
        ("F7", 59.60, 24.50),
        ("F8", 59.25, 24.55),
        ("F9", 65.00, 30.00),
    ];
    let mut feeders = vec![];
    let mut streams = vec![];
    for (k, (id, la, lo)) in pos.iter().enumerate() {
        let prov = match *id {
            "F4" => json!({"batches": 100, "signed": 99, "rejected": 1}),
            "F8" => json!({"batches": 100, "signed": 30, "unsigned": 70}),
            _ => json!({"batches": 100, "signed": 100}),
        };
        feeders.push(json!({"id": id, "lat_deg": la, "lon_deg": lo, "provenance": prov}));
        let src = if *id == "F6" { 1 } else { k };
        let mut alarm = String::new();
        let mut cn0 = vec![];
        for b in 0..500usize {
            let event = (100..130).contains(&b);
            let a = match pos[src].0 {
                "F5" => event || (b % 13 == 5 && b > 200 && b < 600),
                "F7" => event && b % 10 == 0,
                "F9" => b % 97 == 3,
                _ => event,
            };
            alarm.push(if a { '1' } else { '0' });
            cn0.push(json!(
                44.0 + (b as f64 * 0.37 + src as f64).sin() - if a { 8.0 } else { 0.0 }
            ));
        }
        streams.push(json!({"feeder": id, "alarm": alarm, "cn0_mean": cn0}));
    }
    serde_json::from_value(json!({
        "network": "SYNTH-NET",
        "t0": "2026-11-20T00:00:00Z",
        "bin_s": 300,
        "feeders": feeders,
        "streams": streams,
    }))
    .unwrap()
}

fn row<'a>(v: &'a Value, id: &str) -> &'a Value {
    v["feeders"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .unwrap()
}

#[test]
fn classes_follow_the_evidence() {
    let v = analyse(&network(), &FeederLimits::default()).unwrap();
    assert_eq!(row(&v, "F1")["class"], "trusted", "{v:#}");
    assert_eq!(row(&v, "F3")["class"], "trusted");
    // A copy and its source are both untrusted: which is the original cannot be told.
    assert_eq!(row(&v, "F2")["class"], "untrusted");
    assert_eq!(row(&v, "F6")["class"], "untrusted");
    assert!(row(&v, "F6")["reasons"].to_string().contains("duplicates"));
    assert_eq!(v["summary"]["duplicate_stream_pairs"], 1);
    // A rejected batch.
    assert_eq!(row(&v, "F4")["class"], "untrusted");
    // Lone alarms.
    let f5 = row(&v, "F5");
    assert_ne!(f5["class"], "trusted", "{f5:#}");
    assert!(f5["reasons"]
        .to_string()
        .contains("shared by a nearby feeder"));
    // Silent while the crowd alarmed.
    let f7 = row(&v, "F7");
    assert_eq!(f7["class"], "probation", "{f7:#}");
    assert!(f7["reasons"].to_string().contains("silent"));
    // Mostly unsigned.
    assert_eq!(row(&v, "F8")["class"], "probation");
    // Alone in its area.
    assert_eq!(row(&v, "F9")["class"], "insufficient_overlap");
    // Scores in steps of 0.05.
    for r in v["feeders"].as_array().unwrap() {
        let s = r["trust_score"].as_f64().unwrap();
        assert!(((s * 20.0).round() - s * 20.0).abs() < 1e-9, "{s}");
    }
}

#[test]
fn refusals() {
    let mut r = network();
    r.bin_s = 5.0;
    assert!(analyse(&r, &FeederLimits::default()).is_err());
    let mut r = network();
    r.streams[0].alarm.replace_range(0..1, "x");
    assert!(analyse(&r, &FeederLimits::default())
        .unwrap_err()
        .contains("expected 1, 0 or -"));
    let mut r = network();
    r.streams[0].feeder = "nobody".into();
    assert!(analyse(&r, &FeederLimits::default())
        .unwrap_err()
        .contains("unknown feeder"));
    let mut r = network();
    r.feeders[0].provenance = Some(Provenance {
        batches: 1,
        signed: 5,
        ..Provenance::default()
    });
    assert!(analyse(&r, &FeederLimits::default()).is_err());
    let l = FeederLimits {
        max_bins: 100,
        ..FeederLimits::default()
    };
    assert!(analyse(&network(), &l).is_err());
}

const SEED: [u8; 32] = *b"meru-service-test-key-32-bytes!!";

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

fn service_key() -> String {
    hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&SEED)
            .verifying_key()
            .to_bytes(),
    )
}

const T0: i64 = 1_795_132_800; // 2026-11-20T00:00:00Z

fn attestation(id: &str, la: f64, lo: f64) -> Value {
    let r = AttestRequest {
        feeder_id: id.into(),
        lat_deg: la,
        lon_deg: lo,
        provenance_key_id: Some(format!("kid-{id}")),
        host_ref_sha256: Some("ab".repeat(32)),
        valid_days: 365,
    };
    serde_json::to_value(attest_verdict(&r, &signing(), T0 - 86_400).unwrap()).unwrap()
}

/// B2602 acceptance, in simulation: a poisoned feed is down-weighted. Three attested feeders and
/// one honest community feeder see a real event in bins 100–129. Five colluding community
/// feeders (a Sybil majority, each stream slightly different so they are not duplicates) report
/// a fake event in bins 300–339 and stay silent through the real one. By plain majority the
/// network would report the fake event and miss the real one; weighted, it does the opposite.
fn poisoned() -> FeederRequest {
    let mut feeders = vec![];
    let mut streams = vec![];
    let mut add = |id: &str, la: f64, lo: f64, att: bool, alarm: &dyn Fn(usize) -> bool| {
        let mut f = json!({"id": id, "lat_deg": la, "lon_deg": lo});
        if att {
            f["attestation"] = attestation(id, la, lo);
            f["provenance"] = json!({"batches": 50, "signed": 50});
        }
        feeders.push(f);
        let s: String = (0..500).map(|b| if alarm(b) { '1' } else { '0' }).collect();
        streams.push(json!({"feeder": id, "alarm": s}));
    };
    // Each honest station misses a different bin of the real event (they are separate receivers).
    let real = |miss: usize| move |b: usize| (100..130).contains(&b) && b != miss;
    for (k, id) in ["A1", "A2", "A3"].iter().enumerate() {
        add(id, 59.40 + 0.03 * k as f64, 24.70, true, &real(101 + 5 * k));
    }
    add("C1", 59.45, 24.80, false, &real(125));
    for k in 0..5usize {
        let skip = 300 + 7 * k;
        add(
            &format!("P{k}"),
            59.42,
            24.75 + 0.01 * k as f64,
            false,
            &move |b| (300..340).contains(&b) && b != skip,
        );
    }
    serde_json::from_value(
        json!({"network": "SIM", "t0": "2026-11-20T00:00:00Z", "bin_s": 300,
        "feeders": feeders, "streams": streams}),
    )
    .unwrap()
}

#[test]
fn a_poisoned_feed_is_down_weighted() {
    let v = analyse_with(&poisoned(), &FeederLimits::default(), Some(&service_key())).unwrap();
    for id in ["A1", "A2", "A3"] {
        assert_eq!(row(&v, id)["tier"], "attested", "{v:#}");
        assert_eq!(row(&v, id)["class"], "trusted");
        assert_eq!(row(&v, id)["weight"], 1.0);
    }
    let c1 = row(&v, "C1");
    assert_eq!(c1["tier"], "community");
    assert_eq!(c1["judged_against"], "attested_neighbours");
    assert_eq!(c1["class"], "trusted", "{c1:#}");
    for k in 0..5 {
        let p = row(&v, &format!("P{k}"));
        assert_eq!(p["class"], "untrusted", "{p:#}");
        assert_eq!(p["weight"], 0.0);
    }
    assert_eq!(v["summary"]["duplicate_stream_pairs"], 0);
    // Plain majority: the 35 fake bins where all five poisoners alarm, and none of the real ones.
    assert_eq!(v["consensus"]["alarm_bins_unweighted"], 35);
    // Weighted: exactly the 30 real bins.
    assert_eq!(v["consensus"]["alarm_bins_weighted"], 30);
    assert_eq!(
        v["consensus"]["bins_where_weighting_changed_the_answer"],
        65
    );
}

#[test]
fn without_attested_neighbours_a_sybil_majority_is_judged_by_everyone() {
    // The same network with no attestations: the colluders corroborate each other, so the
    // method cannot single them out; it says whom it judged against.
    let v = analyse(&poisoned(), &FeederLimits::default()).unwrap();
    assert_eq!(row(&v, "P0")["judged_against"], "all_neighbours");
    assert_eq!(v["summary"]["attested"], 0);
}

#[test]
fn attestations_are_checked() {
    let key = service_key();
    let f = |att: Value, la: f64| -> Feeder {
        serde_json::from_value(
            json!({"id": "A1", "lat_deg": la, "lon_deg": 24.7, "attestation": att}),
        )
        .unwrap()
    };
    let t = T0 as f64;
    assert!(tier_of(&f(attestation("A1", 59.4, 24.7), 59.4), Some(&key), t).0);
    // Another feeder's attestation, a moved station, an expired one, a forged one.
    assert!(!tier_of(&f(attestation("A2", 59.4, 24.7), 59.4), Some(&key), t).0);
    assert!(!tier_of(&f(attestation("A1", 59.4, 24.7), 59.5), Some(&key), t).0);
    assert!(
        !tier_of(
            &f(attestation("A1", 59.4, 24.7), 59.4),
            Some(&key),
            t + 400.0 * 86_400.0
        )
        .0
    );
    let mut forged = attestation("A1", 59.4, 24.7);
    forged["verdict"]["valid_until"] = json!("2099-01-01T00:00:00Z");
    assert!(!tier_of(&f(forged, 59.4), Some(&key), t).0);
    // Issuance refusals.
    let bad = AttestRequest {
        feeder_id: "bad id".into(),
        lat_deg: 0.0,
        lon_deg: 0.0,
        provenance_key_id: None,
        host_ref_sha256: None,
        valid_days: 30,
    };
    assert!(attest_verdict(&bad, &signing(), T0).is_err());
    let long = AttestRequest {
        feeder_id: "ok".into(),
        valid_days: 1000,
        ..bad
    };
    assert!(attest_verdict(&long, &signing(), T0).is_err());
}
