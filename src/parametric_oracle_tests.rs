// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;

const P0: f64 = 1_793_491_200.0; // 2026-11-01T00:00:00Z

/// Five synthetic stations (A–D within 40 km of 59.4 N 24.7 E, E 600 km away), one sample a
/// minute for two days at 45 dB-Hz with a little wander. Faults: A–D 10 dB down from 10 h to
/// 12 h (an area outage); D alone 10 dB down from 20 h to 22 h (a station fault, neighbours
/// normal); B without data from 30 h to 31 h.
type Station = (&'static str, f64, f64, &'static str, Vec<(f64, f64)>);

pub(crate) fn stations() -> Vec<Station> {
    let sites = [
        ("A", 59.40, 24.70, "op-1"),
        ("B", 59.55, 24.90, "op-2"),
        ("C", 59.30, 25.00, "op-3"),
        ("D", 59.45, 24.40, "op-1"),
        ("E", 64.80, 25.50, "op-4"),
    ];
    sites
        .iter()
        .enumerate()
        .map(|(k, &(id, la, lo, op))| {
            let mut s = vec![];
            for m in 0..(48 * 60) {
                let h = m as f64 / 60.0;
                if id == "B" && (30.0..31.0).contains(&h) {
                    continue;
                }
                let mut c = 45.0 + 0.4 * (m as f64 * 0.05 + k as f64).sin();
                if id != "E" && (10.0..12.0).contains(&h) {
                    c -= 10.0;
                }
                if id == "D" && (20.0..22.0).contains(&h) {
                    c -= 10.0;
                }
                s.push((P0 + m as f64 * 60.0, c));
            }
            (id, la, lo, op, s)
        })
        .collect()
}

fn archive() -> (std::path::PathBuf, OracleConfig) {
    let dir = std::env::temp_dir().join(format!(
        "meru-oracle-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut reg = String::new();
    for (id, la, lo, op, s) in stations() {
        reg += &format!(
            "[[station]]\nid = \"{id}\"\nlat_deg = {la}\nlon_deg = {lo}\noperator = \"{op}\"\nfile = \"{id}.csv\"\n\n"
        );
        let mut csv = String::from("utc,cn0_dbhz\n");
        for (t, c) in s {
            csv += &format!("{t},{c}\n");
        }
        std::fs::write(dir.join(format!("{id}.csv")), csv).unwrap();
    }
    std::fs::write(dir.join("stations.toml"), reg).unwrap();
    let cfg = OracleConfig {
        stations_dir: Some(dir.clone()),
        ..OracleConfig::default()
    };
    (dir, cfg)
}

fn request(source: &str) -> TriggerRequest {
    let mut v = json!({
        "definition_id": "SYNTH-COVER-1",
        "period_start_utc": "2026-11-01T00:00:00Z",
        "period_end_utc": "2026-11-03T00:00:00Z",
        "area": {"lat_deg": 59.4, "lon_deg": 24.7, "radius_km": 100.0},
        "trigger": {"cn0_drop_db": 6.0, "min_sites": 2, "min_duration_min": 30.0},
        "source": source,
    });
    if source == "caller" {
        v["series"] = json!(stations()
            .into_iter()
            .map(|(id, la, lo, op, s)| json!({
                "site": id, "lat_deg": la, "lon_deg": lo, "operator": op,
                "t_unix": s.iter().map(|x| x.0).collect::<Vec<_>>(),
                "cn0_dbhz": s.iter().map(|x| x.1).collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>());
    }
    serde_json::from_value(v).unwrap()
}

#[test]
fn the_archive_fires_on_an_area_outage_and_excludes_a_station_fault() {
    let (dir, cfg) = archive();
    let v = analyse(&request("service"), &TriggerLimits::default(), &cfg).unwrap();
    assert_eq!(v["state"], "fired", "{v:#}");
    assert_eq!(v["source"], "service_archive");
    let ev = v["events"].as_array().unwrap();
    assert_eq!(ev.len(), 1, "{ev:#?}");
    assert_eq!(ev[0]["sites"], 4);
    assert_eq!(ev[0]["fires"], true);
    let d = ev[0]["duration_min"].as_f64().unwrap();
    assert!((d - 120.0).abs() <= 2.0, "{d}");
    // About 4 sites × 10 dB × 2 h.
    let idx = ev[0]["index_db_h"].as_f64().unwrap();
    assert!((idx - 80.0).abs() < 3.0, "{idx}");
    // E is outside the area; D's lone fault is excluded.
    assert_eq!(v["coverage"]["stations"], 4);
    assert_eq!(v["coverage"]["independent_operators"], 3);
    assert_eq!(v["coverage"]["episodes_excluded_uncorroborated"], 1);
    let cov = v["coverage"]["share_of_period"].as_f64().unwrap();
    assert!(cov > 0.97, "{cov} {v:#}");
    assert_eq!(v["definition_sha256"].as_str().unwrap().len(), 64);
    // No payout, no amount.
    let s = v.to_string();
    assert!(!s.contains("payout\"") && !s.contains("amount"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn caller_data_gives_the_same_state_and_says_so() {
    let (dir, cfg) = archive();
    let a = analyse(&request("service"), &TriggerLimits::default(), &cfg).unwrap();
    let b = analyse(
        &request("caller"),
        &TriggerLimits::default(),
        &OracleConfig::default(),
    )
    .unwrap();
    assert_eq!(b["source"], "caller_supplied");
    assert_eq!(a["state"], b["state"]);
    assert_eq!(a["events"], b["events"]);
    assert_eq!(a["data_sha256"], b["data_sha256"]);
    assert_ne!(a["definition_sha256"], b["definition_sha256"]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn not_fired_and_insufficient_data() {
    let (dir, cfg) = archive();
    // A longer minimum duration: the 2 h outage does not fire.
    let mut r = request("service");
    r.trigger.min_duration_min = 180.0;
    let v = analyse(&r, &TriggerLimits::default(), &cfg).unwrap();
    assert_eq!(v["state"], "not_fired");
    assert_eq!(v["events"][0]["fires"], false);
    // A period after the archive ends: no data.
    let mut r = request("service");
    r.period_start_utc = Time::Iso("2026-11-10T00:00:00Z".into());
    r.period_end_utc = Time::Iso("2026-11-11T00:00:00Z".into());
    let v = analyse(&r, &TriggerLimits::default(), &cfg).unwrap();
    assert_eq!(v["state"], "insufficient_data");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn refusals() {
    let e = analyse(
        &request("service"),
        &TriggerLimits::default(),
        &OracleConfig::default(),
    )
    .unwrap_err();
    assert!(e.contains("not offered"), "{e}");
    let mut r = request("caller");
    r.series[0].cn0_dbhz.pop();
    assert!(
        analyse(&r, &TriggerLimits::default(), &OracleConfig::default())
            .unwrap_err()
            .contains("same length")
    );
    let mut r = request("service");
    r.period_end_utc = Time::Iso("2027-06-01T00:00:00Z".into());
    assert!(
        analyse(&r, &TriggerLimits::default(), &OracleConfig::default())
            .unwrap_err()
            .contains("period")
    );
    let mut r = request("caller");
    r.source = Source::Service;
    assert!(
        analyse(&r, &TriggerLimits::default(), &OracleConfig::default())
            .unwrap_err()
            .contains("only read with source")
    );
    let mut r = request("service");
    r.trigger.min_sites = 0;
    assert!(analyse(&r, &TriggerLimits::default(), &OracleConfig::default()).is_err());
    // Payout terms are not a field of this method.
    assert!(serde_json::from_value::<TriggerRequest>(json!({
        "period_start_utc": 0, "period_end_utc": 1,
        "area": {"lat_deg": 0, "lon_deg": 0, "radius_km": 1},
        "trigger": {"cn0_drop_db": 6, "min_duration_min": 30},
        "cover": {"tiers": []},
    }))
    .is_err());
}
