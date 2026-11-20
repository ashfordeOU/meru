// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;

const D0: f64 = 1_793_491_200.0; // 2026-11-01T00:00:00Z

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("meru-arch-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Seven days of holdover reports from four stations around 59.4 N 24.7 E, two a station a day,
/// and a lone station 500 km away; one domain per test.
fn seed(d: &Path) {
    let lock = ArchiveLock::default();
    let mut recs = vec![];
    for day in 0..7 {
        for (k, (la, lo)) in [
            (59.40, 24.70),
            (59.45, 24.80),
            (59.35, 24.60),
            (59.50, 24.90),
        ]
        .iter()
        .enumerate()
        {
            for half in [0.0, 12.0] {
                let t = D0 + day as f64 * 86_400.0 + 3600.0 * (k as f64 + half);
                recs.push(json!({"domain": "holdover", "t": t, "lat_deg": la, "lon_deg": lo,
                    "source": format!("STN-{k}"),
                    "values": {"holdover_s": 600.0 + 100.0 * k as f64, "drift_ns": 50.0 + day as f64}}));
            }
        }
        recs.push(
            json!({"domain": "holdover", "t": D0 + day as f64 * 86_400.0, "lat_deg": 63.0,
            "lon_deg": 27.0, "source": "LONE-1", "values": {"holdover_s": 9999.0}}),
        );
    }
    recs.push(
        json!({"domain": "incidents", "t": D0, "lat_deg": 59.4, "lon_deg": 24.7,
        "source": "STN-0", "tag": "jamming", "values": {"duration_s": 1800.0, "severity": 2.0}}),
    );
    let r: IngestRequest = serde_json::from_value(json!({"records": recs})).unwrap();
    assert_eq!(ingest(d, &lock, &r).unwrap(), 64);
}

fn cfg(d: &Path) -> ArchiveConfig {
    ArchiveConfig {
        dir: Some(d.to_path_buf()),
        writers: vec![],
    }
}

fn q(v: Value) -> QueryRequest {
    serde_json::from_value(v).unwrap()
}

/// B2603 acceptance: no answer returns a raw archive row.
#[test]
fn aggregates_only_never_rows() {
    let d = dir("agg");
    seed(&d);
    let v = query(
        &q(json!({"domain": "holdover", "value": "holdover_s",
            "area": {"lat_deg": 59.4, "lon_deg": 24.7, "radius_km": 100},
            "from_utc": D0, "to_utc": D0 + 7.0 * 86_400.0, "group": "day"})),
        &cfg(&d),
    )
    .unwrap();
    let g = v["groups"].as_array().unwrap();
    assert_eq!(g.len(), 7);
    assert_eq!(g[0]["group"], "2026-11-01");
    assert_eq!(g[0]["count"], 8);
    assert_eq!(g[0]["sources"], 4);
    assert_eq!(g[0]["mean"], 750.0);
    // Nothing that identifies a row: no source, no position, no exact time, no lone value.
    let s = v.to_string();
    for w in ["STN-", "LONE", "59.45", "24.8", "T01:00:00", "9999"] {
        assert!(!s.contains(w), "{w} in {s}");
    }
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn small_groups_are_suppressed() {
    let d = dir("supp");
    seed(&d);
    // The lone station: 7 records but one source.
    let v = query(
        &q(json!({"domain": "holdover", "value": "holdover_s",
            "area": {"lat_deg": 63.0, "lon_deg": 27.0, "radius_km": 50},
            "from_utc": D0, "to_utc": D0 + 7.0 * 86_400.0})),
        &cfg(&d),
    )
    .unwrap();
    assert_eq!(v["groups"][0]["suppressed"], true);
    assert!(v["groups"][0].get("mean").is_none());
    // One incident: suppressed too.
    let v = query(
        &q(
            json!({"domain": "incidents", "value": "duration_s", "tag": "jamming",
            "area": {"lat_deg": 59.4, "lon_deg": 24.7, "radius_km": 100},
            "from_utc": D0, "to_utc": D0 + 86_400.0}),
        ),
        &cfg(&d),
    )
    .unwrap();
    assert_eq!(v["groups_suppressed"], 1);
    assert!(!v.to_string().contains("1800"));
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn queries_and_ingests_are_checked() {
    let d = dir("check");
    seed(&d);
    let base = json!({"domain": "holdover", "value": "holdover_s",
        "area": {"lat_deg": 59.4, "lon_deg": 24.7, "radius_km": 100},
        "from_utc": D0, "to_utc": D0 + 86_400.0});
    let bad = |k: &str, v: Value| {
        let mut x = base.clone();
        x[k] = v;
        query(&q(x), &cfg(&d)).unwrap_err()
    };
    assert!(bad(
        "area",
        json!({"lat_deg": 59.4, "lon_deg": 24.7, "radius_km": 1})
    )
    .contains("radius"));
    assert!(bad("to_utc", json!(D0 + 60.0)).contains("at least an hour"));
    assert!(bad("domain", json!("raw_rows")).contains("unknown domain"));
    assert!(bad("value", json!("source")).contains("no value"));
    assert!(query(&q(base.clone()), &ArchiveConfig::default())
        .unwrap_err()
        .contains("not offered"));
    // A query has no field that could ask for rows.
    let mut x = base.clone();
    x["include_rows"] = json!(true);
    assert!(serde_json::from_value::<QueryRequest>(x).is_err());
    // Ingest: unknown value names and domains are refused, all or nothing.
    let lock = ArchiveLock::default();
    let r: IngestRequest = serde_json::from_value(json!({"records": [
        {"domain": "asf", "t": D0, "lat_deg": 59.4, "lon_deg": 24.7, "source": "S", "values": {"asf_ns": 300.0}},
        {"domain": "asf", "t": D0, "lat_deg": 59.4, "lon_deg": 24.7, "source": "S", "values": {"secret": 1.0}},
    ]}))
    .unwrap();
    assert!(ingest(&d, &lock, &r).unwrap_err().contains("records[1]"));
    assert!(!d.join("asf.jsonl").exists());
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn weeks_start_on_monday() {
    // 2026-11-04 is a Wednesday; its week starts Monday 2026-11-02.
    let t = crate::cause::parse_iso("2026-11-04T12:00:00Z").unwrap();
    assert_eq!(group_key(t, Group::Week), "2026-11-02");
    assert_eq!(group_key(t, Group::Month), "2026-11");
}
