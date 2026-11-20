// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;
use crate::cause::Time;

/// A deterministic pseudo-random normal generator (Box–Muller on an LCG).
struct Rng(u64);
impl Rng {
    fn u(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 11) as f64 + 0.5) / (1u64 << 53) as f64
    }
    fn n(&mut self) -> f64 {
        (-2.0 * self.u().ln()).sqrt() * (2.0 * std::f64::consts::PI * self.u()).cos()
    }
}

const T0: f64 = 1_795_000_000.0;

/// Twelve sites: region A (Tallinn area) with sites of operators X, Y, Z; region B (Lisbon area)
/// with sites of X, Y, Z. 1 Hz offsets for 30 minutes, 20 ns white noise, each site's own reference
/// drifting a little (up to ±0.05 ns/s). `drift` maps a site to (onset s, rate ns/s).
fn network(drift: &dyn Fn(&str) -> Option<(f64, f64)>, seed: u64) -> CorrelationRequest {
    let mut rng = Rng(seed);
    let mut sites = vec![];
    let mut series = vec![];
    let regions = [("A", 59.4, 24.7), ("B", 38.7, -9.1)];
    for (rg, la, lo) in regions {
        for (k, op) in ["X", "Y", "Z", "X", "Y", "Z"].iter().enumerate() {
            let id = format!("{rg}{k}-{op}");
            sites.push(Site {
                id: id.clone(),
                operator: op.to_string(),
                lat_deg: la + 0.1 * k as f64,
                lon_deg: lo,
            });
            let own = 0.05 * (rng.u() * 2.0 - 1.0);
            let d = drift(&id);
            let y: Vec<Option<f64>> = (0..1800)
                .map(|i| {
                    let t = i as f64;
                    let mut v = own * t + 20.0 * rng.n();
                    if let Some((on, rate)) = d {
                        if t > on {
                            v += rate * (t - on);
                        }
                    }
                    Some(v)
                })
                .collect();
            series.push(Series {
                site: id,
                t0: Time::Unix(T0),
                dt_s: 1.0,
                offset_ns: y,
            });
        }
    }
    CorrelationRequest {
        subject: Some("synthetic timing network".into()),
        sites,
        series,
    }
}

/// B1903 acceptance: a synthetic 1 ns/s drift across the sites of one region (three operators) is
/// detected by the cross-site test before any single site's own detector fires.
#[test]
fn a_regional_drift_is_detected_before_any_single_site() {
    for seed in [1, 2, 3, 4, 5] {
        let r = network(
            &|id: &str| id.starts_with('A').then_some((900.0, 1.0)),
            seed,
        );
        let v = analyse(&r, &CorrelationLimits::default()).unwrap();
        let eps = v["episodes"].as_array().unwrap();
        assert_eq!(eps.len(), 1, "seed {seed}: {eps:#?}");
        let e = &eps[0];
        assert_eq!(e["scope"], "regional_drift", "{e:#}");
        assert_eq!(e["operators_affected"], 3);
        assert_eq!(e["sites_affected"], 6);
        let lead = e["lead_s"].as_i64().unwrap();
        assert!(
            lead > 0,
            "seed {seed}: group detection must come first, lead {lead}: {e:#}"
        );
        let rate = e["drift_ns_per_s"].as_f64().unwrap();
        assert!((0.5..1.5).contains(&rate), "{rate}");
        assert_eq!(v["noc_alerts"][0]["severity"], "critical");
    }
}

#[test]
fn scopes_constellation_operator_and_quiet() {
    // Every site: constellation-wide.
    let v = analyse(
        &network(&|_| Some((900.0, 0.5)), 7),
        &CorrelationLimits::default(),
    )
    .unwrap();
    assert_eq!(v["episodes"][0]["scope"], "constellation_wide", "{v:#}");
    // Operator X everywhere, Y and Z unaffected: the operator's own distribution.
    let v = analyse(
        &network(&|id: &str| id.ends_with("-X").then_some((900.0, 0.5)), 8),
        &CorrelationLimits::default(),
    )
    .unwrap();
    assert_eq!(v["episodes"][0]["scope"], "operator_wide", "{v:#}");
    // No drift: no episode in a quiet network.
    let v = analyse(&network(&|_| None, 9), &CorrelationLimits::default()).unwrap();
    assert_eq!(v["episodes"].as_array().unwrap().len(), 0, "{v:#}");
}

#[test]
fn refusals() {
    let mut r = network(&|_| None, 1);
    r.series[0].site = "nobody".into();
    assert!(analyse(&r, &CorrelationLimits::default())
        .unwrap_err()
        .contains("unknown site"));
    let mut r = network(&|_| None, 1);
    r.series[0].dt_s = 0.0;
    assert!(analyse(&r, &CorrelationLimits::default()).is_err());
    let l = CorrelationLimits {
        max_samples: 100,
        ..CorrelationLimits::default()
    };
    assert!(analyse(&network(&|_| None, 1), &l).is_err());
}
