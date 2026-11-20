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
