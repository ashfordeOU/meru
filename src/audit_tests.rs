// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;
use serde_json::json;

/// A deterministic uniform generator (tests only).
pub(crate) struct Lcg(pub(crate) u64);
impl Lcg {
    pub(crate) fn next(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// A survey request with station C at (lat, lon) and a noise scale: the copier's three inputs.
fn survey_req(lat: f64, lon: f64, scale: f64) -> Value {
    json!({"config": {"area": [54.0, 56.0, 10.0, 13.0], "step_deg": 0.5, "budget": 3,
        "stations": [["A", 57.5, 10.0], ["B", 52.5, 8.5], ["C", lat, lon]],
        "sigma_scale_m": scale}, "include_grid": false})
}

fn sweep_point(u: &[f64]) -> Value {
    survey_req(50.0 + 10.0 * u[0], 12.0 + 8.0 * u[1], 30.0 + 60.0 * u[2])
}

/// Benign use: a few real configurations, each asked several times with small changes.
fn benign(seed: u64, n: usize) -> Vec<Value> {
    let mut r = Lcg(seed);
    let sites = [
        (54.5, 16.0),
        (55.2, 14.1),
        (53.9, 17.3),
        (56.4, 15.2),
        (55.0, 13.0),
    ];
    (0..n)
        .map(|i| {
            let (la, lo) = sites[i % sites.len()];
            let scale = [60.0, 45.0, 60.0, 75.0][(r.next() * 4.0) as usize % 4];
            survey_req(
                la + (r.next() - 0.5) * 0.1,
                lo + (r.next() - 0.5) * 0.1,
                scale,
            )
        })
        .collect()
}

fn vecs(reqs: &[Value]) -> Vec<Vec<f64>> {
    reqs.iter()
        .map(|r| {
            features("survey", r)
                .values
                .iter()
                .map(|x| crate::outputs::round_sig(*x, AUDIT_SIGFIGS))
                .collect()
        })
        .collect()
}

fn lhs(n: usize, d: usize, seed: u64) -> Vec<Vec<f64>> {
    let mut r = Lcg(seed);
    let mut cols: Vec<Vec<f64>> = (0..d)
        .map(|_| {
            let mut c: Vec<f64> = (0..n).map(|i| (i as f64 + r.next()) / n as f64).collect();
            for i in (1..n).rev() {
                let j = (r.next() * (i + 1) as f64) as usize % (i + 1);
                c.swap(i, j);
            }
            c
        })
        .collect();
    (0..n)
        .map(|i| cols.iter_mut().map(|c| c[i]).collect())
        .collect()
}

#[test]
fn features_ignore_strings_and_summarise_long_arrays() {
    let a = features("survey", &survey_req(54.5, 16.0, 60.0));
    let b = features(
        "survey",
        &json!({"config": {"area": [54.0, 56.0, 10.0, 13.0], "step_deg": 0.5, "budget": 3,
        "stations": [["X", 57.5, 10.0], ["Y", 52.5, 8.5], ["Z", 1.0, 2.0]],
        "sigma_scale_m": 9.0}, "include_grid": true}),
    );
    assert_eq!(a.shape, b.shape, "names and values do not change the shape");
    assert_eq!(a.values.len(), a.paths.len());
    assert!(a.paths.iter().any(|p| p == ".config.stations[2][1]"));
    let long: Vec<Value> = (0..40)
        .map(|i| json!({"t": i, "lat_deg": 50.0 + i as f64}))
        .collect();
    let f = features("cause", &json!({"reported": long}));
    assert!(f.paths.contains(&".reported[]#len".to_string()));
    assert!(f.paths.contains(&".reported[].lat_deg#mean".to_string()));
    assert_eq!(f.values.len(), 5);
    // Coarse cells: near neighbours share one; a different budget does not.
    let c = |r: &Value| coarse_cell("survey", r);
    assert_eq!(
        c(&survey_req(54.5, 16.0, 60.0)),
        c(&survey_req(54.51, 16.01, 60.1))
    );
    assert_ne!(
        c(&survey_req(54.5, 16.0, 60.0)),
        c(&survey_req(54.5, 16.0, 90.0))
    );
}

#[test]
fn discrepancy_matches_its_random_expectation() {
    let mut r = Lcg(7);
    let mut ratios = vec![];
    for _ in 0..20 {
        let x: Vec<Vec<f64>> = (0..64)
            .map(|_| (0..3).map(|_| r.next()).collect())
            .collect();
        ratios.push(cd2(&x) / cd2_random(64, 3));
    }
    let mean = ratios.iter().sum::<f64>() / ratios.len() as f64;
    assert!((mean - 1.0).abs() < 0.2, "{mean}");
    let s = sobol(64, 3);
    assert!(cd2(&s) / cd2_random(64, 3) < 0.2);
    // The Sobol points are the standard ones: dimension 1 is van der Corput.
    assert_eq!(s[0], vec![0.5, 0.5, 0.5]);
    assert_eq!(s[1][0], 0.75);
    assert_eq!(s[2][0], 0.25);
}

#[test]
fn sweeps_are_flagged_and_benign_use_is_not() {
    let cfg = AuditConfig::default();
    let sob: Vec<Value> = sobol(64, 3).iter().map(|u| sweep_point(u)).collect();
    let s = stats(&vecs(&sob));
    let r = s.rules(&cfg);
    assert!(r.contains(&"low_discrepancy"), "{s:?} {r:?}");

    let l: Vec<Value> = lhs(48, 3, 3).iter().map(|u| sweep_point(u)).collect();
    let s = stats(&vecs(&l));
    assert!(s.rules(&cfg).contains(&"stratified"), "{s:?}");

    let mut g = vec![];
    for i in 0..6 {
        for j in 0..6 {
            g.push(survey_req(
                50.0 + 2.0 * i as f64,
                12.0 + 1.5 * j as f64,
                60.0,
            ));
        }
    }
    let s = stats(&vecs(&g));
    assert!(s.grid && s.rules(&cfg).contains(&"grid"), "{s:?}");

    let mut rng = Lcg(11);
    let uni: Vec<Value> = (0..128)
        .map(|_| sweep_point(&[rng.next(), rng.next(), rng.next()]))
        .collect();
    let s = stats(&vecs(&uni));
    assert!(s.rules(&cfg).contains(&"uniform_fill"), "{s:?}");
    // Below the minimum nothing is judged.
    let s = stats(&vecs(&uni[..20]));
    assert!(s.rules(&cfg).is_empty(), "{s:?}");

    for seed in 1..=10 {
        let b = benign(seed, 200);
        let s = stats(&vecs(&b));
        assert!(s.rules(&cfg).is_empty(), "benign {seed}: {s:?}");
    }
}

#[test]
fn auditor_alerts_once_marks_suspect_and_forgets_after_the_window() {
    let a = Auditor::new(AuditConfig {
        window_s: 10_000,
        suspect_s: 500,
        ..AuditConfig::default()
    });
    let mut alerts = vec![];
    for (i, u) in sobol(96, 3).iter().enumerate() {
        let v = a.observe("copier", "survey", &sweep_point(u), i as i64 * 60);
        alerts.extend(v.alerts);
    }
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].kind, "single_licence");
    assert_eq!(alerts[0].licences, vec!["copier".to_string()]);
    assert!(a.is_suspect("copier", 96 * 60));
    assert!(!a.is_suspect("copier", 96 * 60 + 600));
    // Benign licences in the same window are untouched.
    for (i, r) in benign(3, 150).iter().enumerate() {
        let v = a.observe("customer", "survey", r, 6000 + i as i64);
        assert!(v.alerts.is_empty() && !v.suspect, "{:?}", v.alerts);
    }
    // The alert text holds no field names or values.
    let text = serde_json::to_string(&alerts[0]).unwrap();
    assert!(
        !text.contains("stations") && !text.contains("54."),
        "{text}"
    );
}

#[test]
fn sobol_sweep_split_across_three_licences_is_detected() {
    // Each licence sends 30 points (below the single-licence minimum of 32); a bystander with
    // ordinary requests of the same shape is in the same window.
    let a = Auditor::new(AuditConfig::default());
    let pts = sobol(90, 3);
    let mut alerts = vec![];
    for (i, r) in benign(5, 40).iter().enumerate() {
        alerts.extend(a.observe("bystander", "survey", r, i as i64).alerts);
    }
    for (i, u) in pts.iter().enumerate() {
        let lic = ["s1", "s2", "s3"][i / 30];
        alerts.extend(
            a.observe(lic, "survey", &sweep_point(u), 100 + i as i64 * 600)
                .alerts,
        );
    }
    let cross: Vec<&Alert> = alerts
        .iter()
        .filter(|a| a.kind == "cross_licence")
        .collect();
    assert!(!cross.is_empty(), "{alerts:?}");
    let named = &cross.last().unwrap().licences;
    for s in ["s1", "s2", "s3"] {
        assert!(
            cross.iter().any(|a| a.licences.iter().any(|l| l == s)),
            "{s} not named: {cross:?}"
        );
    }
    assert!(
        !cross
            .iter()
            .any(|a| a.licences.iter().any(|l| l == "bystander")),
        "{named:?}"
    );
    assert!(alerts.iter().all(|a| a.kind != "single_licence"));
    for s in ["s1", "s2", "s3"] {
        assert!(a.is_suspect(s, 100 + 90 * 600));
    }
    assert!(!a.is_suspect("bystander", 100 + 90 * 600));

    // Interleaved (round robin) splits are caught too.
    let a = Auditor::new(AuditConfig::default());
    let mut kinds = vec![];
    for (i, u) in pts.iter().enumerate() {
        let lic = ["r1", "r2", "r3"][i % 3];
        kinds.extend(
            a.observe(lic, "survey", &sweep_point(u), i as i64 * 600)
                .alerts
                .into_iter()
                .map(|a| (a.kind, a.licences)),
        );
    }
    assert!(
        kinds
            .iter()
            .any(|(k, l)| k == "cross_licence" && l.len() == 3),
        "{kinds:?}"
    );
}

#[test]
fn pause_mode_and_the_daily_region_cap_refuse() {
    let a = Auditor::new(AuditConfig {
        pause: true,
        ..AuditConfig::default()
    });
    let mut refused = None;
    for (i, u) in sobol(64, 3).iter().enumerate() {
        let v = a.observe("p", "survey", &sweep_point(u), i as i64);
        if v.refuse.is_some() {
            refused = Some(i);
            break;
        }
    }
    assert!(refused.is_some_and(|i| i < 64), "{refused:?}");

    let a = Auditor::new(AuditConfig {
        max_new_cells_per_day: 3,
        ..AuditConfig::default()
    });
    for (i, s) in [30.0, 45.0, 70.0].iter().enumerate() {
        assert!(a
            .observe("c", "survey", &survey_req(54.5, 16.0, *s), i as i64)
            .refuse
            .is_none());
    }
    // A repeat of a known region is fine; a fourth region is refused, with one alert.
    assert!(a
        .observe("c", "survey", &survey_req(54.5, 16.0, 30.0), 5)
        .refuse
        .is_none());
    let v = a.observe("c", "survey", &survey_req(54.5, 16.0, 90.0), 6);
    assert!(v.refuse.unwrap().contains("distinct input regions"));
    assert_eq!(v.alerts[0].kind, "region_cap");
    assert!(a
        .observe("c", "survey", &survey_req(54.5, 16.0, 90.0), 7)
        .alerts
        .is_empty());
    // A new UTC day resets the cap.
    assert!(a
        .observe("c", "survey", &survey_req(54.5, 16.0, 90.0), 86_400)
        .refuse
        .is_none());
}

#[test]
fn honeypot_flag_marks_suspect() {
    let a = Auditor::new(AuditConfig::default());
    let al = a.flag("h", "honeypot", "/internal/residuals", 10);
    assert_eq!(al.kind, "honeypot");
    assert!(a.is_suspect("h", 11));
    assert!(!a.is_suspect("other", 11));
}
