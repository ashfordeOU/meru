// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;

/// 2026-11-20T00:00:00Z.
const DAY: f64 = 1_795_132_800.0;

/// A synthetic live-input directory: Kp for 20 November (1.0 until 15 UT, then 7.33 from 18 UT,
/// in the SWPC object form) and a day-before file in the older row form; a ROTI map at 18:00
/// (Nordic 1.8, central Brazil 2.5, central Europe 0.1 TECU/min) and S4 at 18:00 (central Brazil
/// 0.7).
fn inputs(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("meru-swx-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for k in ["kp", "roti", "s4"] {
        std::fs::create_dir_all(d.join(k)).unwrap();
    }
    let kp: Vec<Value> = (0..8)
        .map(|i| {
            json!({"time_tag": format!("2026-11-20T{:02}:00:00", i * 3), "Kp": if i >= 6 { 7.33 } else { 1.0 },
                "a_running": 5, "station_count": 8})
        })
        .collect();
    std::fs::write(d.join("kp/swpc-2026-11-20.json"), json!(kp).to_string()).unwrap();
    std::fs::write(
        d.join("kp/swpc-2026-11-19.json"),
        r#"[["time_tag","Kp","a_running","station_count"],["2026-11-19 21:00:00.000","2.00","7","8"]]"#,
    )
    .unwrap();
    std::fs::write(
        d.join("roti/2026-11-20T1800.json"),
        json!({"format": "meru-roti-map/1", "epoch_utc": "2026-11-20T18:00:00Z", "cells": [
            {"lat_deg": 60.0, "lon_deg": 10.0, "roti_tecu_per_min": 1.8},
            {"lat_deg": -12.0, "lon_deg": -55.0, "roti_tecu_per_min": 2.5},
            {"lat_deg": 48.0, "lon_deg": 10.0, "roti_tecu_per_min": 0.1},
        ]})
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        d.join("s4/2026-11-20T1800.json"),
        json!({"format": "meru-s4-obs/1", "epoch_utc": "2026-11-20T18:00:00Z", "stations": [
            {"id": "BR-1", "lat_deg": -13.0, "lon_deg": -56.0, "s4": 0.7},
        ]})
        .to_string(),
    )
    .unwrap();
    d
}

fn cfg(dir: &Path) -> SpaceWxConfig {
    SpaceWxConfig {
        source_dir: Some(dir.to_path_buf()),
        regions: vec![],
    }
}

fn req(at: f64) -> SpaceWxRequest {
    serde_json::from_value(json!({
        "at_utc": at,
        "locations": [
            {"id": "farm-no", "lat_deg": 60.0, "lon_deg": 10.5},
            {"id": "farm-br", "lat_deg": -12.0, "lon_deg": -55.5},
            {"id": "site-es", "lat_deg": 40.4, "lon_deg": -3.7},
        ]
    }))
    .unwrap()
}

fn loc<'a>(v: &'a Value, id: &str) -> &'a Value {
    v["locations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["id"] == id)
        .unwrap()
}

#[test]
fn storm_evening_live_inputs_per_region() {
    let d = inputs("storm");
    let at = DAY + 18.0 * 3600.0 + 600.0;
    let v = analyse(&req(at), &SpaceWxLimits::default(), &cfg(&d), at + 60.0).unwrap();
    assert_eq!(v["g_scale"], "G3");
    // Norway: auroral, ROTI and Kp high: RTK and PPP no-go.
    let no = loc(&v, "farm-no");
    assert_eq!(no["region"], "auroral", "{no:#}");
    assert_eq!(no["level"], "high");
    assert_eq!(no["services"]["rtk"], "no_go");
    assert_eq!(no["live_data"], true);
    // Brazil: equatorial; Kp 7.33 is not an equatorial effect; ROTI and S4 drive it; single
    // frequency no-go there.
    let br = loc(&v, "farm-br");
    assert_eq!(br["region"], "equatorial", "{br:#}");
    assert_eq!(br["indicators"]["kp"]["level"], "quiet");
    assert_eq!(br["level"], "high");
    assert_eq!(br["services"]["single_frequency"], "no_go");
    // Spain: no live cell within reach; Kp 7.33 at mid latitude is high on its own.
    let es = loc(&v, "site-es");
    assert_eq!(es["region"], "mid_latitude", "{es:#}");
    assert!(es["indicators"].get("roti").is_none());
    assert_eq!(es["driver"], "kp");
    assert_eq!(es["services"]["single_frequency"], "caution");
    assert_eq!(v["inputs"]["sha256"].as_str().unwrap().len(), 64);
    // No threshold leaves.
    assert!(!v.to_string().contains("roti_high"));
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn quiet_morning_rests_on_kp_alone_and_says_so() {
    let d = inputs("quiet");
    let at = DAY + 6.0 * 3600.0 + 600.0;
    let v = analyse(&req(at), &SpaceWxLimits::default(), &cfg(&d), at).unwrap();
    assert_eq!(v["g_scale"], "G0");
    assert!(v["inputs"]["roti_map_utc"].is_null());
    for id in ["farm-no", "site-es"] {
        let l = loc(&v, id);
        assert_eq!(l["level"], "quiet", "{l:#}");
        assert_eq!(l["services"]["rtk"], "go");
        assert_eq!(l["live_data"], false);
    }
    assert!(v["limits"][0].as_str().unwrap().contains("Kp alone"));
    // The older row-form file serves a time on the day before.
    let at = DAY - 1800.0;
    let v = analyse(&req(at), &SpaceWxLimits::default(), &cfg(&d), DAY).unwrap();
    assert_eq!(v["inputs"]["kp_utc"], "2026-11-19T21:00:00Z");
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn a_regional_calibration_replaces_the_band() {
    let d = inputs("region");
    let mut c = cfg(&d);
    c.regions = parse_regions(
        r#"
[[region]]
name = "iberia-calibrated"
lat_min = 36.0
lat_max = 44.0
lon_min = -10.0
lon_max = 4.0
roti_moderate = 0.3
roti_high = 1.0
s4_moderate = 0.3
s4_high = 0.6
kp_moderate = 8.0
kp_high = 9.0
basis = "synthetic calibration for the test"
"#,
    )
    .unwrap();
    let at = DAY + 18.0 * 3600.0 + 600.0;
    let v = analyse(&req(at), &SpaceWxLimits::default(), &c, at).unwrap();
    let es = loc(&v, "site-es");
    assert_eq!(es["region"], "iberia-calibrated");
    assert_eq!(es["thresholds"], "regional_calibration");
    assert_eq!(es["level"], "quiet");
    // audit-1: a location given in 0..360 longitude (-3.7 as 356.3) falls in the same region.
    let mut r = req(at);
    r.locations[2].lon_deg = 356.3;
    let v = analyse(&r, &SpaceWxLimits::default(), &c, at).unwrap();
    assert_eq!(loc(&v, "site-es")["region"], "iberia-calibrated");
    assert!(parse_regions("[[region]]\nname='x'\nlat_min=1\nlat_max=0\nlon_min=0\nlon_max=1\nroti_moderate=1\nroti_high=2\ns4_moderate=0.1\ns4_high=0.2\nkp_moderate=1\nkp_high=2\nbasis='b'\n").is_err());
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn refusals() {
    let d = inputs("refuse");
    let at = DAY + 18.0 * 3600.0;
    assert!(analyse(
        &req(at),
        &SpaceWxLimits::default(),
        &SpaceWxConfig::default(),
        at
    )
    .unwrap_err()
    .contains("not offered"));
    // Not a forecast.
    assert!(
        analyse(&req(at + 7200.0), &SpaceWxLimits::default(), &cfg(&d), at)
            .unwrap_err()
            .contains("future")
    );
    // Long after the inputs: nothing current.
    let late = DAY + 5.0 * 86_400.0;
    assert!(
        analyse(&req(late), &SpaceWxLimits::default(), &cfg(&d), late)
            .unwrap_err()
            .contains("no current")
    );
    let mut r = req(at);
    r.locations[0].lat_deg = 95.0;
    assert!(analyse(&r, &SpaceWxLimits::default(), &cfg(&d), at).is_err());
    std::fs::write(
        d.join("roti/zz.json"),
        r#"{"format":"other","epoch_utc":"2026-11-20T00:00:00Z","cells":[]}"#,
    )
    .unwrap();
    assert!(analyse(&req(at), &SpaceWxLimits::default(), &cfg(&d), at)
        .unwrap_err()
        .contains("unknown format"));
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn verdict_is_signed() {
    let d = inputs("signed");
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
    let at = DAY + 18.0 * 3600.0 + 600.0;
    let v =
        spaceweather_verdict(&req(at), &s, &SpaceWxLimits::default(), &cfg(&d), at, "t").unwrap();
    assert_eq!(v.method, "spaceweather");
    assert!(crate::verdict::verify(&v, &pk).is_empty());
    let _ = std::fs::remove_dir_all(d);
}

/// B3502 acceptance: the May 2024 storm backtest on the published GFZ Kp series (Matzka et al.
/// 2021, https://doi.org/10.5880/Kp.0001, CC BY 4.0; excerpt 7–14 May 2024 in
/// `src/data/`). Kp alone: no archived ROTI or S4 for May 2024 is carried here (to confirm).
/// Fields in Manitoba, Iowa and Saskatchewan, and one in Mato Grosso near the magnetic equator.
#[test]
fn may_2024_storm_backtest() {
    let d = std::env::temp_dir().join(format!("meru-swx-may24-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("kp")).unwrap();
    std::fs::write(
        d.join("kp/gfz-2024-05.txt"),
        include_str!("data/gfz-kp-2024-05-07-to-14.txt"),
    )
    .unwrap();
    let c = cfg(&d);
    let req = |at: f64| -> SpaceWxRequest {
        serde_json::from_value(json!({"at_utc": at, "locations": [
            {"id": "manitoba", "lat_deg": 49.95, "lon_deg": -97.2},
            {"id": "iowa", "lat_deg": 42.0, "lon_deg": -93.5},
            {"id": "saskatchewan", "lat_deg": 52.1, "lon_deg": -106.6},
            {"id": "mato-grosso", "lat_deg": -12.6, "lon_deg": -55.7},
        ]}))
        .unwrap()
    };
    let may =
        |d: u32, h: u32| crate::cause::parse_iso(&format!("2024-05-{d:02}T{h:02}:30:00Z")).unwrap();
    // Hours at which each field is high or allows RTK.
    let mut high: std::collections::BTreeMap<&str, Vec<(u32, u32)>> = Default::default();
    let mut rtk_ok_storm = vec![];
    for day in 8..=14u32 {
        for h in 0..24u32 {
            let at = may(day, h);
            let v = analyse(&req(at), &SpaceWxLimits::default(), &c, at).unwrap();
            for l in v["locations"].as_array().unwrap() {
                let id = l["id"].as_str().unwrap();
                if l["level"] == "high" {
                    high.entry(match id {
                        "manitoba" => "manitoba",
                        "iowa" => "iowa",
                        "saskatchewan" => "saskatchewan",
                        _ => "mato-grosso",
                    })
                    .or_default()
                    .push((day, h));
                }
                if (day == 11) && id != "mato-grosso" && l["services"]["rtk"] != "no_go" {
                    rtk_ok_storm.push((id.to_string(), h));
                }
            }
        }
    }
    for f in ["manitoba", "iowa", "saskatchewan"] {
        let hs = &high[f];
        // Never high on 8 and 9 May (Kp at most 2.3), high on 10 May from the evening (Kp 7.7 from
        // 15 UT), clear again on 14 May (Kp at most 2.3).
        assert!(
            !hs.iter().any(|(d, _)| *d == 8 || *d == 9 || *d == 14),
            "{f}: {hs:?}"
        );
        assert!(
            hs.contains(&(10, 18)) && hs.contains(&(10, 21)),
            "{f}: {hs:?}"
        );
    }
    // 11 May, Kp 7.7 to 9 all day (G4 to G5): RTK no-go at every hour in all three.
    assert!(rtk_ok_storm.is_empty(), "{rtk_ok_storm:?}");
    // Mato Grosso is untouched by the Kp storm rule at high level.
    assert!(
        !high.contains_key("mato-grosso"),
        "{:?}",
        high.get("mato-grosso")
    );
    // The G scale on 11 May at 01:30 UT (Kp 9.0) is G5.
    let at = may(11, 1);
    assert_eq!(
        analyse(&req(at), &SpaceWxLimits::default(), &c, at).unwrap()["g_scale"],
        "G5"
    );
    let _ = std::fs::remove_dir_all(d);
}

/// audit-1: `valid_until` ignored the inputs' age: inputs are at most 30 min (live) or 6 h (Kp)
/// old, so `newest.max(at)` was always `at`, and an advisory from a 25-minute-old ROTI map was
/// declared valid for 40 minutes past its map. It now ends no later than the inputs do.
#[test]
fn validity_never_outlasts_the_inputs() {
    let d = inputs("validity");
    // Live: ROTI and S4 at 18:00, asked at 18:25 → until 18:30 (not 18:40).
    let at = DAY + 18.0 * 3600.0 + 1500.0;
    let v = analyse(&req(at), &SpaceWxLimits::default(), &cfg(&d), at).unwrap();
    assert_eq!(
        loc(&v, "farm-no")["valid_until_utc"],
        "2026-11-20T18:30:00Z"
    );
    // Kp alone: the 21:00 value of the day before, asked at 01:30 with no newer Kp file → until
    // 03:00 (21:00 + 6 h), not 04:30.
    std::fs::remove_file(d.join("kp/swpc-2026-11-20.json")).unwrap();
    let at = DAY + 5400.0;
    let v = analyse(&req(at), &SpaceWxLimits::default(), &cfg(&d), at).unwrap();
    assert_eq!(
        loc(&v, "site-es")["valid_until_utc"],
        "2026-11-20T03:00:00Z"
    );
    let _ = std::fs::remove_dir_all(d);
}

/// audit-1: Kp files were tried newest name first and the first file with any value at or before
/// `at` was taken, so an older archive whose name sorts last hid the newer daily file.
#[test]
fn the_newest_kp_wins_whatever_the_file_names() {
    let d = inputs("kpnames");
    std::fs::write(
        d.join("kp/zz-archive.json"),
        r#"[["time_tag","Kp","a_running","station_count"],["2026-11-19 21:00:00.000","2.00","7","8"]]"#,
    )
    .unwrap();
    let at = DAY + 22.0 * 3600.0;
    let v = analyse(&req(at), &SpaceWxLimits::default(), &cfg(&d), at).unwrap();
    assert_eq!(v["inputs"]["kp_utc"], "2026-11-20T21:00:00Z");
    assert_eq!(v["g_scale"], "G3");
    let _ = std::fs::remove_dir_all(d);
}
