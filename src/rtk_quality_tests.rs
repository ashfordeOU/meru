// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;
use crate::cause::Time;

/// A synthetic network: mountpoints A, B, C with three monitors each at 5, 15 and 30 km from
/// the base, 1 Hz for two hours. Faults: mountpoint B's feed stalls (all its monitors lose fix,
/// corrections stale) from 1000 to 1600 s; every monitor loses fix with fresh corrections from
/// 3000 to 3300 s (a wide-area cause); monitor A1 alone has no solution from 5000 to 5200 s;
/// monitor C3 holds 20 wrong fixes (190 mm east) from 6000 s.
pub(crate) fn network() -> RtkQualityRequest {
    let bases = [("A", 52.0, 5.0), ("B", 52.5, 6.0), ("C", 53.0, 7.0)];
    let mut mountpoints = vec![];
    let mut monitors = vec![];
    let mut series = vec![];
    for (bi, (b, la, lo)) in bases.iter().enumerate() {
        mountpoints.push(Mountpoint {
            id: b.to_string(),
            lat_deg: *la,
            lon_deg: *lo,
            kind: Some("single_base".into()),
        });
        for (k, km) in [5.0, 15.0, 30.0].iter().enumerate() {
            let id = format!("{b}{}", k + 1);
            monitors.push(Monitor {
                id: id.clone(),
                mountpoint: b.to_string(),
                lat_deg: la + km / 111.2,
                lon_deg: *lo,
                surveyed: true,
            });
            let (mut t_s, mut fix, mut e, mut n, mut u, mut age) =
                (vec![], String::new(), vec![], vec![], vec![], vec![]);
            for i in 0..7200usize {
                let t = i as f64;
                let ph = (bi * 3 + k) as f64;
                let sd = 5.0 + 1.0 * km;
                let mut c = 'F';
                let mut a = 1.0 + 0.5 * (t * 0.01 + ph).sin().abs();
                if *b == "B" && (1000.0..1600.0).contains(&t) {
                    c = 'f';
                    a = 30.0 + (t - 1000.0) * 0.1;
                }
                if (3000.0..3300.0).contains(&t) {
                    c = 'f';
                }
                if id == "A1" && (5000.0..5200.0).contains(&t) {
                    c = 'N';
                }
                let mut de = sd * (t * 0.37 + ph).sin();
                let dn = sd * (t * 0.29 + 2.0 * ph).cos();
                if id == "C3" && (6000.0..6020.0).contains(&t) {
                    de += 190.0;
                }
                let (de, dn) = if c == 'f' {
                    (de * 20.0, dn * 20.0)
                } else {
                    (de, dn)
                };
                t_s.push(t);
                fix.push(c);
                if c == 'N' {
                    e.push(None);
                    n.push(None);
                    u.push(None);
                } else {
                    e.push(Some(de));
                    n.push(Some(dn));
                    u.push(Some(2.0 * sd * (t * 0.23 + ph).sin()));
                }
                age.push(Some(a));
            }
            series.push(Series {
                monitor: id,
                t0: Time::Unix(1_795_000_000.0),
                t_s,
                fix,
                e_mm: e,
                n_mm: n,
                u_mm: Some(u),
                age_s: Some(age),
            });
        }
    }
    RtkQualityRequest {
        subject: Some("synthetic network".into()),
        window: None,
        tolerance: Tolerance::default(),
        targets: Targets {
            min_fix_availability: Some(0.95),
            max_wrong_fix_rate: Some(0.0002),
            max_h95_m: Some(0.05),
            max_ttf95_s: None,
        },
        mountpoints,
        monitors,
        series,
    }
}

fn row<'a>(v: &'a Value, id: &str) -> &'a Value {
    v["mountpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .unwrap()
}

#[test]
fn episodes_are_read_by_scope_and_correction_age() {
    let v = analyse(&network(), &RtkQualityLimits::default()).unwrap();
    let eps = v["episodes"].as_array().unwrap();
    assert_eq!(eps.len(), 3, "{eps:#?}");
    // B's feed stall: the mountpoint's monitors, corrections stale.
    assert_eq!(eps[0]["scope"], "mountpoint");
    assert_eq!(eps[0]["mountpoints"], json!(["B"]));
    assert_eq!(eps[0]["corrections"], "stale");
    assert_eq!(eps[0]["monitors_affected"], 3);
    // Every monitor: wide area, corrections fresh.
    assert_eq!(eps[1]["scope"], "wide_area");
    assert_eq!(eps[1]["corrections"], "fresh");
    assert_eq!(eps[1]["monitors_affected"], 9);
    assert!(eps[1]["reading"].as_str().unwrap().contains("wide-area"));
    // A1 alone.
    assert_eq!(eps[2]["scope"], "monitor");
    assert_eq!(v["network"]["episodes"]["wide_area"], 1);
    // Nothing internal leaves: no per-monitor records, no thresholds.
    let s = v.to_string();
    assert!(!s.contains("\"A1\"") && !s.contains("MOUNTPOINT_SHARE") && !s.contains("outages"));
}

#[test]
fn wrong_fixes_and_targets() {
    let v = analyse(&network(), &RtkQualityLimits::default()).unwrap();
    let c = row(&v, "C");
    assert_eq!(c["wrong_fixes"], 20);
    assert_eq!(row(&v, "A")["wrong_fixes"], 0);
    assert_eq!(v["network"]["highest_wrong_fix_bound"][0], "C");
    // C: 20 wrong in about 20,700 fixes; the interval sits above 0.0002 → not met.
    assert_eq!(c["targets"]["max_wrong_fix_rate"], "not_met");
    // A: no wrong fix in about 20,500: the upper bound (about 0.00019) is below 0.0002 → met.
    assert_eq!(row(&v, "A")["targets"]["max_wrong_fix_rate"], "met");
    // B lost 900 s of 7200 on all three monitors: availability 0.875 → not met.
    let b = row(&v, "B");
    assert!((b["fix_availability"].as_f64().unwrap() - 0.875).abs() < 1e-3);
    assert_eq!(b["targets"]["min_fix_availability"], "not_met");
    // Error grows about 1 mm per km in the synthetic network.
    let g = row(&v, "A")["h_growth_mm_per_km"].as_f64().unwrap();
    assert!(g > 0.5 && g < 2.0, "{g}");
    // h95 of 30 km monitors is ~ 35 mm·√2 at most: within 0.05 m.
    assert_eq!(row(&v, "A")["targets"]["max_h95_m"], "met");
    // Stale share on B: the 600 s stall over 21,600 epochs.
    let st = b["stale_share"].as_f64().unwrap();
    assert!((st - 600.0 / 7200.0).abs() < 0.01, "{st}");
    let ttf = b["ttf95_s"].as_f64().unwrap();
    assert!(ttf >= 300.0, "{ttf}");
}

#[test]
fn self_consistency_monitor_sees_jumps_not_offsets() {
    let mut r = network();
    // Give C3 a constant 0.5 m offset and no surveyed mark: the jumps still count, the offset
    // cannot be seen.
    for m in r.monitors.iter_mut().filter(|m| m.id == "C3") {
        m.surveyed = false;
    }
    for s in r.series.iter_mut().filter(|s| s.monitor == "C3") {
        for x in s.e_mm.iter_mut().flatten() {
            *x += 500.0;
        }
    }
    let v = analyse(&r, &RtkQualityLimits::default()).unwrap();
    assert_eq!(row(&v, "C")["wrong_fixes"], 20);
    assert_eq!(row(&v, "C")["self_consistency_monitors"], 1);
}

#[test]
fn window_and_refusals() {
    let mut r = network();
    r.window = Some(Window {
        start_utc: Time::Unix(1_795_000_000.0 + 2000.0),
        end_utc: Time::Unix(1_795_000_000.0 + 4000.0),
    });
    let v = analyse(&r, &RtkQualityLimits::default()).unwrap();
    assert_eq!(v["network"]["epochs"], 9 * 2001);
    assert_eq!(v["episodes"].as_array().unwrap().len(), 1);

    let l = RtkQualityLimits {
        max_epochs: 1000,
        ..RtkQualityLimits::default()
    };
    assert!(analyse(&network(), &l).unwrap_err().contains("epochs"));
    let mut r = network();
    r.series[0].fix.pop();
    assert!(analyse(&r, &RtkQualityLimits::default())
        .unwrap_err()
        .contains("same length"));
    let mut r = network();
    r.series[0].fix = r.series[0].fix.replacen('F', "X", 1);
    assert!(analyse(&r, &RtkQualityLimits::default())
        .unwrap_err()
        .contains("fix code"));
    let mut r = network();
    r.monitors[0].mountpoint = "Z".into();
    assert!(analyse(&r, &RtkQualityLimits::default())
        .unwrap_err()
        .contains("unknown mountpoint"));
    let mut r = network();
    r.targets.max_wrong_fix_rate = Some(2.0);
    assert!(analyse(&r, &RtkQualityLimits::default()).is_err());
    let mut r = network();
    r.series[1].t_s[5] = 3.0;
    assert!(analyse(&r, &RtkQualityLimits::default())
        .unwrap_err()
        .contains("increasing"));
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
    let v = rtk_quality_verdict(
        &network(),
        &s,
        &RtkQualityLimits::default(),
        "2026-11-20T00:00:00Z",
    )
    .unwrap();
    assert_eq!(v.method, "rtk-quality");
    assert_eq!(v.evidence_class, "MODELLED");
    assert!(crate::verdict::verify(&v, &pk).is_empty());
}

#[test]
fn wilson_interval() {
    let (a, b) = wilson95(0, 100);
    assert!(a == 0.0 && (b - 0.037).abs() < 0.001);
    let (a, b) = wilson95(50, 100);
    assert!((a - 0.404).abs() < 0.001 && (b - 0.596).abs() < 0.001);
}
