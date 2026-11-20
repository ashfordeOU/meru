// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
// Tests of `lunar-assist` on a synthetic constellation: a "truth" world propagated with a
// richer force model than the service fits (higher-degree gravity, a different radiation
// pressure, an unmodelled along-track acceleration) and clocks with random-walk noise, written
// as SP3 products; the package is scored against the truth that followed.

use super::*;
use crate::methods::Signing;
use crate::verdict::verify;
use ed25519_dalek::SigningKey;
use kshana_pro::kshana::precise_od::EmpiricalAccel;
use kshana_pro::kshana::sp3::{Sp3Epoch, Sp3File, Sp3Header, Sp3SatState};

const SEED: [u8; 32] = *b"meru-lunar-assist-test-seed-32b!";

/// GPST seconds of 2027-01-04T00:00:00 (the test's start of validity).
fn vstart() -> f64 {
    parse_iso_s("2027-01-04T00:00:00").unwrap()
}

fn epoch_of(t: f64) -> EpochUtc {
    let s = format_s(t.round() as i64);
    let (d, tm) = s.split_once('T').unwrap();
    let dp: Vec<&str> = d.split('-').collect();
    let tp: Vec<&str> = tm.split(':').collect();
    EpochUtc {
        year: dp[0].parse().unwrap(),
        month: dp[1].parse().unwrap(),
        day: dp[2].parse().unwrap(),
        hour: tp[0].parse().unwrap(),
        minute: tp[1].parse().unwrap(),
        second: tp[2].parse().unwrap(),
    }
}

/// A deterministic standard normal stream (LCG + Box–Muller).
struct Rng(u64);
impl Rng {
    fn uniform(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 11) as f64 + 0.5) / (1u64 << 53) as f64
    }
    fn normal(&mut self) -> f64 {
        let (u, v) = (self.uniform(), self.uniform());
        (-2.0 * u.ln()).sqrt() * (2.0 * std::f64::consts::PI * v).cos()
    }
}

/// The truth: `(sat, positions ECEF, clocks s)` on a 900 s grid from `t_first` for `n` epochs.
struct Truth {
    times: Vec<f64>,
    sats: Vec<(String, Vec<[f64; 3]>, Vec<f64>)>,
}

fn truth(sats: &[&str], t_first: f64, n: usize) -> Truth {
    let pl = Pipeline {
        eop: zero_eop(),
        fit_s: 0.0,
        clock_fit_s: 0.0,
        degree: 8,
    };
    let times: Vec<f64> = (0..n).map(|i| t_first + i as f64 * 900.0).collect();
    let mut out = vec![];
    let mut rng = Rng(7);
    for (k, sat) in sats.iter().enumerate() {
        let galileo = sat.starts_with('E');
        let a: f64 = if galileo { 29_600e3 } else { 26_560e3 };
        let inc: f64 = if galileo { 56f64 } else { 55f64 }.to_radians();
        let raan = (k as f64 * 97.0).to_radians();
        let u0 = (k as f64 * 53.0).to_radians();
        let v = (3.986_004_418e14 / a).sqrt();
        let (cu, su) = (u0.cos(), u0.sin());
        let (co, so) = (raan.cos(), raan.sin());
        let (ci, si) = (inc.cos(), inc.sin());
        let r0 = [
            a * (co * cu - so * su * ci),
            a * (so * cu + co * su * ci),
            a * su * si,
        ];
        let v0 = [
            v * (-co * su - so * cu * ci),
            v * (-so * su + co * cu * ci),
            v * cu * si,
        ];
        // Richer than what the service fits: degree 8 (service: 4 in the tests), a radiation
        // coefficient of 1.3, and an unmodelled along-track and radial acceleration.
        let mut fm = pl.model(t_first);
        fm.set_cr(1.3);
        fm.set_empirical(Some(EmpiricalAccel {
            transverse: [2e-10, 0.0, 0.0],
            radial: [0.0, 3e-10, 0.0],
            ..EmpiricalAccel::default()
        }));
        let p = Prediction {
            fm,
            t0: t_first,
            r0,
            v0,
            clk: None,
            cutoff: t_first,
        };
        let pos: Vec<[f64; 3]> = pl.predict(&p, &times).into_iter().map(|x| x.0).collect();
        // Clock: offset, drift, ageing, random walk in frequency, white phase noise.
        let (mut c, mut y) = (1e-4 * (k as f64 + 1.0), 2e-12);
        let mut clk = vec![];
        for _ in &times {
            clk.push(c + 1.5e-11 * rng.normal());
            y += 1e-15 * rng.normal() + 1e-17;
            c += y * 900.0;
        }
        out.push((sat.to_string(), pos, clk));
    }
    Truth { times, sats: out }
}

fn sp3_text(t: &Truth, from: usize, to: usize) -> String {
    let f = Sp3File {
        header: Sp3Header {
            version: 'd',
            has_velocity: false,
            start: epoch_of(t.times[from]),
            num_epochs: to - from,
            sat_ids: t.sats.iter().map(|s| s.0.clone()).collect(),
        },
        epochs: (from..to)
            .map(|i| Sp3Epoch {
                time: epoch_of(t.times[i]),
                sats: t
                    .sats
                    .iter()
                    .map(|s| Sp3SatState {
                        sat: s.0.clone(),
                        pos_m: s.1[i],
                        clock_us: s.2[i] * 1e6,
                        vel_m_s: None,
                    })
                    .collect(),
            })
            .collect(),
    };
    f.to_sp3_string()
}

fn test_config() -> AssistConfig {
    AssistConfig {
        fit_hours: 12.0,
        clock_fit_hours: 12.0,
        backtests: 4,
        backtest_spacing_hours: 6.0,
        geopotential_degree: 4,
        ..AssistConfig::default()
    }
}

fn request(sats: &[&str], hours: f64) -> AssistRequest {
    AssistRequest {
        satellites: sats.iter().map(|s| s.to_string()).collect(),
        validity_start: "2027-01-04T00:00:00".into(),
        validity_hours: hours,
        step_s: 300,
        integrity_risk: 1e-7,
        lunar_time: Some(LunarTimeWanted {
            registry_id: "ks-lunar-time-definitions".into(),
            registry_version: 1,
            definition_id: "tl-w0-turyshev-south-pole".into(),
        }),
    }
}

fn signing(seed: &[u8; 32]) -> Signing<'_> {
    Signing {
        signer: seed,
        key_id: "k1",
        lineage_seed: seed,
        lineage_key_id: "k1",
        sigfigs: 3,
    }
}

const SATS: [&str; 4] = ["G01", "G02", "G03", "E01"];

/// One shared run: 2 days of source products, then 1 day of truth to score against.
fn shared() -> &'static (Truth, std::path::PathBuf, SignedVerdict) {
    static RUN: std::sync::OnceLock<(Truth, std::path::PathBuf, SignedVerdict)> =
        std::sync::OnceLock::new();
    RUN.get_or_init(|| {
        // 42 h of observed data up to the start of validity, then 24 h of truth after it.
        let first = vstart() - 42.0 * 3600.0;
        let t = truth(&SATS, first, 42 * 4 + 1 + 24 * 4 + 8);
        let dir = std::env::temp_dir().join(format!("meru-la-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Two overlapping products (the later wins on shared epochs).
        std::fs::write(dir.join("a_day1.sp3"), sp3_text(&t, 0, 100)).unwrap();
        std::fs::write(dir.join("b_day2.sp3"), sp3_text(&t, 90, 42 * 4 + 1)).unwrap();
        let cfg = AssistConfig {
            source_dir: Some(dir.clone()),
            ..test_config()
        };
        let v = lunar_assist_verdict(
            &request(&SATS, 24.0),
            &signing(&SEED),
            &AssistLimits::default(),
            &cfg,
            "2027-01-04T00:05:00Z",
        )
        .unwrap();
        (t, dir, v)
    })
}

fn pubkey() -> String {
    hex::encode(SigningKey::from_bytes(&SEED).verifying_key().to_bytes())
}

#[test]
fn package_is_signed_and_answers_the_request() {
    let (_, _, v) = shared();
    assert_eq!(v.method, "lunar-assist");
    assert_eq!(v.evidence_class, "MODELLED");
    assert!(verify(v, &pubkey()).is_empty());
    let pkg: AssistPackage = serde_json::from_value(v.verdict["package"].clone()).unwrap();
    // The package signature verifies on the bytes the client recomputes after parsing.
    assert!(
        pkg.verify_signature(&pubkey()).is_empty(),
        "{:?}",
        pkg.verify_signature(&pubkey())
    );
    let mut t = pkg.clone();
    t.satellites[0].pos_mm[20][0] += 1;
    assert!(
        !t.verify_signature(&pubkey()).is_empty(),
        "tampering is caught"
    );
    // The checks the client makes (`service::answers`).
    assert_eq!(pkg.format, FORMAT);
    assert_eq!(pkg.time_system, "GPST");
    let names: Vec<&str> = pkg.satellites.iter().map(|s| s.sat.as_str()).collect();
    assert_eq!(names, SATS);
    let start = parse_iso_s(&pkg.start).unwrap();
    let want = vstart() - start;
    assert!(
        pkg.validity_start_s as f64 <= want && pkg.validity_end_s as f64 >= want + 24.0 * 3600.0
    );
    assert!(pkg.validity_end_s <= pkg.step_s as i64 * (pkg.n_epochs as i64 - 1));
    assert!(pkg.step_s <= 300);
    for s in &pkg.satellites {
        assert_eq!(s.pos_mm.len(), pkg.n_epochs as usize);
        assert!(s.bound.integrity_risk <= 1e-7 && s.bound.sigma0_m > 0.0);
        assert!(s.bound.growth_m_per_h >= 0.0 && s.bound.growth2_m_per_h2 >= 0.0);
    }
    let lt = pkg.lunar_time.as_ref().unwrap();
    assert_eq!(lt.registry.definition_id, "tl-w0-turyshev-south-pole");
    assert_eq!(lt.registry.registry_version, 1);
    assert!(lt.notice.contains("PROVISIONAL"));
    // Outcome only: no fits, errors, bins or coefficients of the method.
    let body = serde_json::to_string(&v.verdict).unwrap();
    for k in ["\"bins\"", "\"residual", "\"cr\"", "\"samples_by", "\"fit_"] {
        assert!(!body.contains(k), "{k} leaked");
    }
    assert_eq!(v.verdict["integrity"]["requested_risk"], json!(1e-7));
    assert_eq!(
        v.verdict["integrity"]["risk_within_sample_support"],
        json!(false)
    );
}

#[test]
fn prediction_tracks_the_truth_and_the_bound_holds() {
    let (t, _, v) = shared();
    let pkg: AssistPackage = serde_json::from_value(v.verdict["package"].clone()).unwrap();
    let start = parse_iso_s(&pkg.start).unwrap();
    let mut worst_ratio: f64 = 0.0;
    let mut worst_err: f64 = 0.0;
    let mut n = 0;
    for (k, s) in pkg.satellites.iter().enumerate() {
        let tr = &t.sats[k];
        assert_eq!(tr.0, s.sat);
        for (i, node) in s.pos_mm.iter().enumerate() {
            let ti = start + i as f64 * pkg.step_s as f64;
            let rel = ti - start;
            if rel < pkg.validity_start_s as f64 || rel > pkg.validity_end_s as f64 {
                continue;
            }
            // Truth nodes every 900 s.
            let Some(j) = t.times.iter().position(|x| (x - ti).abs() < 1e-6) else {
                continue;
            };
            let dr = ((node[0] as f64 * 1e-3 - tr.1[j][0]).powi(2)
                + (node[1] as f64 * 1e-3 - tr.1[j][1]).powi(2)
                + (node[2] as f64 * 1e-3 - tr.1[j][2]).powi(2))
            .sqrt();
            let dt = (s.clock_ps[i] as f64 * 1e-12 - tr.2[j]).abs();
            let e = dr + C_M_S * dt;
            let age_h = (rel - pkg.validity_start_s as f64) / 3600.0;
            worst_ratio = worst_ratio.max(e / s.bound.sigma_m(age_h));
            worst_err = worst_err.max(e);
            n += 1;
        }
    }
    assert!(n > 300, "{n}");
    // A prediction a day ahead within tens of metres (synthetic world, MODELLED), and every
    // error inside 5.33 sigma (K for 1e-7) of its bound; a sane bound is not wildly loose.
    eprintln!("worst error {worst_err:.2} m, worst error/sigma {worst_ratio:.2}, {n} nodes");
    assert!(worst_err < 60.0, "worst error {worst_err} m");
    assert!(
        worst_ratio < 5.33,
        "an error exceeded K·sigma: ratio {worst_ratio}"
    );
    assert!(
        worst_ratio > 0.2,
        "bound far too loose: ratio {worst_ratio}"
    );
}

#[test]
fn requests_are_checked_before_any_work() {
    let lim = AssistLimits::default();
    let ok = request(&SATS, 24.0);
    assert!(validate(&ok, &lim).is_ok());
    let mut r = ok.clone();
    r.satellites = vec![];
    assert!(validate(&r, &lim).unwrap_err().contains("at least one"));
    let mut r = ok.clone();
    r.satellites = vec!["G01".into(), "G01".into()];
    assert!(validate(&r, &lim).unwrap_err().contains("twice"));
    let mut r = ok.clone();
    r.satellites = vec!["LRO".into()];
    assert!(validate(&r, &lim).unwrap_err().contains("not a GNSS id"));
    let mut r = ok.clone();
    r.validity_hours = 500.0;
    assert!(validate(&r, &lim).unwrap_err().contains("validity_hours"));
    let mut r = ok.clone();
    r.step_s = 5;
    assert!(validate(&r, &lim).unwrap_err().contains("step_s"));
    let mut r = ok.clone();
    r.integrity_risk = 0.7;
    assert!(validate(&r, &lim).unwrap_err().contains("integrity_risk"));
    let mut r = ok.clone();
    r.validity_start = "2027-13-01T00:00:00".into();
    assert!(validate(&r, &lim).is_err());
    let mut r = ok.clone();
    r.satellites = (1..=99).map(|i| format!("G{i:02}")).collect();
    r.step_s = 30;
    r.validity_hours = 72.0;
    assert!(validate(&r, &lim)
        .unwrap_err()
        .contains("package too large"));
    // Unknown request fields are refused (a client typo is not silently ignored).
    assert!(serde_json::from_str::<AssistRequest>(
        r#"{"satellites":["G01"],"validity_start":"2027-01-04T00:00:00","validity_hours":24,"step_s":300,"integrity_risk":1e-7,"extra":1}"#
    )
    .is_err());
}

#[test]
fn source_problems_are_refused_with_a_reason() {
    let (_, dir, _) = shared();
    let cfg = AssistConfig {
        source_dir: Some(dir.clone()),
        ..test_config()
    };
    let lim = AssistLimits::default();
    let s = signing(&SEED);
    // A satellite the source does not hold.
    let e = lunar_assist_verdict(&request(&["G01", "G31"], 24.0), &s, &lim, &cfg, "t").unwrap_err();
    assert!(e.contains("no source data for G31"), "{e}");
    // Products too old for the start of validity.
    let mut r = request(&["G01"], 24.0);
    r.validity_start = "2027-01-07T00:00:00".into();
    let e = lunar_assist_verdict(&r, &s, &lim, &cfg, "t").unwrap_err();
    assert!(e.contains("too old"), "{e}");
    // An unknown lunar time definition or registry version.
    let mut r = request(&["G01"], 24.0);
    r.lunar_time.as_mut().unwrap().definition_id = "tl-default".into();
    let e = lunar_assist_verdict(&r, &s, &lim, &cfg, "t").unwrap_err();
    assert!(e.contains("no default"), "{e}");
    let mut r = request(&["G01"], 24.0);
    r.lunar_time.as_mut().unwrap().registry_version = 9;
    let e = lunar_assist_verdict(&r, &s, &lim, &cfg, "t").unwrap_err();
    assert!(e.contains("not available"), "{e}");
    // Too little history to derive a bound.
    let mut r = request(&["G01"], 24.0);
    r.validity_start = "2027-01-02T18:00:00".into();
    let e = lunar_assist_verdict(&r, &s, &lim, &cfg, "t").unwrap_err();
    assert!(e.contains("too little"), "{e}");
    // No source configured: the method is not offered.
    let e =
        lunar_assist_verdict(&request(&["G01"], 24.0), &s, &lim, &test_config(), "t").unwrap_err();
    assert!(e.contains("not offered"), "{e}");
}

#[test]
fn overbound_and_envelope_cover_their_inputs() {
    // A Gaussian sample of sigma 2 is overbounded by a sigma not far above 2.
    let mut rng = Rng(11);
    let e: Vec<f64> = (0..400).map(|_| 2.0 * rng.normal()).collect();
    let s = overbound_sigma(&e).unwrap();
    assert!((2.0..3.2).contains(&s), "{s}");
    // Heavier tails need a larger sigma.
    let mut heavy = e.clone();
    heavy.extend([25.0, -30.0]);
    assert!(overbound_sigma(&heavy).unwrap() > s);
    // The envelope lies on or above every point and has non-negative coefficients.
    let pts = [(3.0, 1.0), (6.0, 1.5), (12.0, 3.0), (24.0, 9.0)];
    let c = envelope(&pts, 24.0);
    assert!(c.iter().all(|x| *x >= 0.0));
    for (a, s) in pts {
        assert!(c[0] + c[1] * a + c[2] * a * a >= s - 1e-12);
    }
    // Bounds round up, risks down, and the service's rounding leaves them alone.
    assert_eq!(ceil_sig(1.2301, 3), 1.24);
    assert_eq!(ceil_sig(1.23, 3), 1.23);
    assert_eq!(floor_sig(1.2399e-7, 3), 1.23e-7);
    for x in [ceil_sig(0.0123456, 3), floor_sig(3.3333e-8, 3)] {
        assert_eq!(round_sig(x, 3), x);
    }
    // Clopper–Pearson: zero events in 59 trials bounds p by 5 % at 95 %.
    assert!((cp_upper(0, 59, 0.95) - 0.0495).abs() < 1e-3);
}
