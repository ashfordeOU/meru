// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;

const SEED: [u8; 32] = *b"meru-service-test-key-32-bytes!!";

fn key() -> String {
    hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&SEED)
            .verifying_key()
            .to_bytes(),
    )
}

fn v(method: &str, utc: &str, o: Value) -> SignedVerdict {
    crate::verdict::sign(method, "MODELLED", o, &SEED, "k1", utc).unwrap()
}

#[test]
fn the_version_policy_keeps_v1_five_years() {
    let p = versions();
    assert_eq!(p["versions"][0]["sunset_not_before"], "2031-11-20");
    assert_eq!(p["versions"][1]["status"], "current");
    let sv = v(
        "cause",
        "t",
        json!({"method": "cause/1", "classification": "external_spoofing"}),
    );
    let e = v2_envelope(&sv);
    assert_eq!(e["api_version"], 2);
    assert_eq!(e["method_version"], "cause/1");
    // The signed verdict inside is the same, and still verifies.
    let inner: SignedVerdict = serde_json::from_value(e["verdict"].clone()).unwrap();
    assert!(verify(&inner, &key()).is_empty());
    assert_eq!(inner, sv);
}

#[test]
fn a_scorecard_summarises_shared_verdicts() {
    let r = ScorecardRequest {
        subject: "SYNTH-VESSEL-1".into(),
        verdicts: vec![
            v(
                "cause",
                "2026-10-01T00:00:00Z",
                json!({"classification": "external_spoofing"}),
            ),
            v(
                "cause",
                "2026-11-01T00:00:00Z",
                json!({"classification": "insufficient_evidence"}),
            ),
            v(
                "victim-actor",
                "2026-11-02T00:00:00Z",
                json!({"classification": "victim"}),
            ),
        ],
    };
    let s = scorecard(&r, &key()).unwrap();
    assert_eq!(s["verdicts"], 3);
    let c = s["methods"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["method"] == "cause")
        .unwrap();
    assert_eq!(c["verdicts"], 2);
    assert_eq!(c["first_utc"], "2026-10-01T00:00:00Z");
    assert_eq!(c["outcomes"]["classification:external_spoofing"], 1);
    for w in ["premium", "price", "underwrite\"", "accept", "decline"] {
        let mut t = s.clone();
        t.as_object_mut().unwrap().remove("statement");
        assert!(!t.to_string().contains(w), "{w}");
    }
    // A forged verdict is refused.
    let mut bad = r.clone();
    bad.verdicts[0].verdict["classification"] = json!("self_reported_track_falsification");
    assert!(scorecard(&bad, &key()).unwrap_err().contains("verdicts[0]"));
}

#[test]
fn benchmarks_place_only_the_contributors_own_source() {
    let d = std::env::temp_dir().join(format!("meru-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let lock = crate::archives::ArchiveLock::default();
    let recs: Vec<Value> = (0..7)
        .flat_map(|k| {
            (0..4).map(move |i| {
                json!({"domain": "station_kpi", "t": 1_793_491_200.0 + i as f64 * 86_400.0,
                    "lat_deg": 59.4 + 0.01 * k as f64, "lon_deg": 24.7, "source": format!("ST-{k}"),
                    "values": {"availability": 0.90 + 0.01 * k as f64}})
            })
        })
        .collect();
    crate::archives::ingest(
        &d,
        &lock,
        &serde_json::from_value(json!({"records": recs})).unwrap(),
    )
    .unwrap();
    let cfg = ArchiveConfig {
        dir: Some(d.clone()),
        writers: vec![],
    };
    let req = |src: &str| -> BenchmarkRequest {
        serde_json::from_value(json!({"domain": "station_kpi", "value": "availability",
            "area": {"lat_deg": 59.4, "lon_deg": 24.7, "radius_km": 50},
            "from_utc": "2026-11-01T00:00:00Z", "to_utc": "2026-11-08T00:00:00Z", "source": src}))
        .unwrap()
    };
    let b = benchmark(&req("ST-1"), &cfg, &["ST-1".into()]).unwrap();
    assert_eq!(b["population_sources"], 7);
    assert!((b["own_mean"].as_f64().unwrap() - 0.91).abs() < 1e-9);
    assert!((b["own_percentile_rank"].as_f64().unwrap() - 1.0 / 7.0).abs() < 1e-9);
    // No other source is named.
    let s = b.to_string();
    for k in [0, 2, 3, 4, 5, 6] {
        assert!(!s.contains(&format!("ST-{k}")), "{s}");
    }
    // Someone else's source: refused.
    assert!(benchmark(&req("ST-2"), &cfg, &["ST-1".into()]).is_err());
    let _ = std::fs::remove_dir_all(d);
}
