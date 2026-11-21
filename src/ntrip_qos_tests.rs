// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;

const NOW: f64 = 1_795_132_800.0; // 2026-11-20T00:00:00Z

fn summary(src: &str, mp: &str, lat95: f64, comp: f64, stale: u32, up: f64) -> Summary {
    serde_json::from_value(json!({
        "source": src, "caster": "caster.example", "mountpoint": mp,
        "window_start_utc": NOW - 86_400.0, "window_end_utc": NOW - 60.0,
        "latency_ms_p50": lat95 / 2.0, "latency_ms_p95": lat95, "completeness": comp,
        "staleness_events": stale, "stale_s": stale as f64 * 10.0, "uptime": up
    }))
    .unwrap()
}

fn store(tag: &str) -> NtripQosConfig {
    let p = std::env::temp_dir().join(format!("meru-ntrip-{tag}-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&p);
    NtripQosConfig { store: Some(p) }
}

#[test]
fn give_to_get_with_population_percentiles() {
    let cfg = store("pop");
    let lock = StoreLock::default();
    // Six other contributors on MP1, from good to poor.
    for k in 0..6 {
        let src = format!("FEED-{k}");
        let r = NtripQosRequest {
            summaries: vec![summary(
                &src,
                "MP1",
                800.0 + 500.0 * k as f64,
                0.99 - 0.01 * k as f64,
                k,
                0.999 - 0.005 * k as f64,
            )],
        };
        analyse(&r, &cfg, &lock, &[src], NOW).unwrap();
    }
    // The caller: a stale-prone feed on MP1, and MP2 that nobody else watches.
    let r = NtripQosRequest {
        summaries: vec![
            summary("MINE", "MP1", 3000.0, 0.93, 12, 0.96),
            summary("MINE", "MP2", 600.0, 1.0, 0, 1.0),
        ],
    };
    let v = analyse(&r, &cfg, &lock, &["MINE".into()], NOW).unwrap();
    let mp1 = v["mountpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["mountpoint"] == "MP1")
        .unwrap();
    assert_eq!(mp1["population"]["sources"], 7);
    let rank = mp1["population"]["rank"].as_f64().unwrap();
    assert!(rank < 0.3, "the stale-prone feed ranks low: {rank}");
    let mp2 = v["mountpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["mountpoint"] == "MP2")
        .unwrap();
    assert_eq!(mp2["population"]["suppressed"], true);
    assert!(mp2["score"].as_f64().unwrap() > 95.0);
    assert_eq!(v["casters"][0]["mountpoints"], 2);
    // No other source is named.
    let s = v.to_string();
    assert!(!s.contains("FEED-"), "{s}");
    let _ = std::fs::remove_file(cfg.store.unwrap());
}

#[test]
fn only_your_own_sources_and_checked_summaries() {
    let cfg = store("own");
    let lock = StoreLock::default();
    let r = NtripQosRequest {
        summaries: vec![summary("SOMEONE-ELSE", "MP1", 900.0, 0.99, 0, 1.0)],
    };
    assert!(analyse(&r, &cfg, &lock, &["MINE".into()], NOW)
        .unwrap_err()
        .contains("not one of your sources"));
    let mut bad = summary("MINE", "MP1", 900.0, 1.5, 0, 1.0);
    assert!(analyse(
        &NtripQosRequest {
            summaries: vec![bad.clone()]
        },
        &cfg,
        &lock,
        &["MINE".into()],
        NOW
    )
    .is_err());
    bad.completeness = 0.99;
    bad.window_end_utc = Time::Unix(NOW - 86_400.0 + 60.0);
    assert!(analyse(
        &NtripQosRequest {
            summaries: vec![bad]
        },
        &cfg,
        &lock,
        &["MINE".into()],
        NOW
    )
    .unwrap_err()
    .contains("10 minutes"));
    assert!(analyse(
        &r,
        &NtripQosConfig::default(),
        &lock,
        &["SOMEONE-ELSE".into()],
        NOW
    )
    .unwrap_err()
    .contains("not offered"));
}

#[test]
fn the_score_orders_good_and_bad_streams() {
    let good = check(&summary("A", "M", 700.0, 1.0, 0, 1.0)).unwrap();
    let stale = check(&summary("A", "M", 700.0, 1.0, 48, 1.0)).unwrap();
    let slow = check(&summary("A", "M", 4500.0, 1.0, 0, 1.0)).unwrap();
    let gappy = check(&summary("A", "M", 700.0, 0.85, 0, 0.9)).unwrap();
    assert!((score(&good) - 100.0).abs() < 1e-9);
    assert!(
        score(&stale) < score(&good) && score(&slow) < score(&good) && score(&gappy) < score(&slow)
    );
}
