// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;

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

/// A synthetic co-located comparison: the DUT's true delay `truth` for code C1 (assumed 30 ns),
/// its cable measured 2 ns longer than assumed, 1,440 tracks over 5 days with 2 ns white noise, a
/// slowly repeating 1 ns multipath term and a few outliers.
fn request(truth: f64, seed: u64) -> DelayRequest {
    let mut rng = Rng(seed);
    let assumed = 30.0;
    let cable_extra = 2.0;
    let d: Vec<Value> = (0..1440)
        .map(|i| {
            let mp = 1.0 * ((i % 288) as f64 / 288.0 * std::f64::consts::TAU).sin();
            let mut x = (truth - assumed) + cable_extra + mp + 2.0 * rng.n();
            if i % 300 == 17 {
                x += 80.0;
            }
            json!(x)
        })
        .collect();
    serde_json::from_value(json!({
        "dut": "SYNTH-RX-7",
        "setup": {"mode": "co_located", "baseline_km": 0.0,
            "dut_cable": {"value_ns": 102.0, "u_ns": 0.3}, "dut_reference_cable": {"value_ns": 15.0, "u_ns": 0.2},
            "assumed_dut_cable_ns": 100.0, "assumed_dut_reference_cable_ns": 15.0},
        "codes": {"C1": {"assumed_delay_ns": assumed, "reference_delay": {"value_ns": 28.0, "u_ns": 1.5},
            "differences_ns": d}}
    }))
    .unwrap()
}

/// B1908 acceptance: a known delay is recovered within the stated uncertainty.
#[test]
fn a_known_delay_is_recovered_within_its_uncertainty() {
    for (truth, seed) in [(34.7, 1u64), (25.2, 2), (41.0, 3), (30.0, 4)] {
        let v = analyse(&request(truth, seed), &DelayLimits::default()).unwrap();
        let c = &v["codes"]["C1"];
        let d = c["delay_ns"].as_f64().unwrap();
        let big_u = c["expanded_uncertainty_ns"].as_f64().unwrap();
        assert!((d - truth).abs() <= big_u, "truth {truth}: {d} ± {big_u}");
        // The outliers (one track in 300) are rejected.
        assert_eq!(c["tracks_rejected"], 5);
        // The budget names every term; the reference calibration dominates.
        assert_eq!(c["budget"].as_array().unwrap().len(), 5);
        assert!(
            (big_u - 2.0 * (1.5f64.powi(2) + 0.3f64.powi(2) + 0.2f64.powi(2) + 1.0).sqrt()).abs()
                < 0.2
        );
    }
}

#[test]
fn common_view_adds_a_baseline_term_and_refusals() {
    let mut r = request(30.0, 5);
    r.setup.mode = "common_view".into();
    r.setup.baseline_km = 800.0;
    let v = analyse(&r, &DelayLimits::default()).unwrap();
    assert_eq!(v["codes"]["C1"]["budget"].as_array().unwrap().len(), 6);
    r.setup.baseline_km = 0.0;
    assert!(analyse(&r, &DelayLimits::default()).is_err());
    let mut r = request(30.0, 5);
    r.setup.mode = "guess".into();
    assert!(analyse(&r, &DelayLimits::default()).is_err());
    let mut r = request(30.0, 5);
    r.codes.get_mut("C1").unwrap().differences_ns.truncate(10);
    assert!(analyse(&r, &DelayLimits::default())
        .unwrap_err()
        .contains("usable tracks"));
}

#[test]
fn verdict_verifies_with_the_service_key() {
    let seed = *b"meru-service-test-key-32-bytes!!";
    let s = crate::methods::Signing {
        signer: &seed,
        key_id: "k1",
        lineage_seed: &seed,
        lineage_key_id: "k1",
        sigfigs: 3,
        bind: None,
    };
    let v = delay_verdict(&request(34.7, 1), &s, &DelayLimits::default(), "t").unwrap();
    let pk = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    );
    assert!(crate::verdict::verify(&v, &pk).is_empty());
    // The integer picoseconds keep full resolution; the ns figure is rounded like every verdict.
    let ps = v.verdict["codes"]["C1"]["delay_ps"].as_i64().unwrap();
    let raw = analyse(&request(34.7, 1), &DelayLimits::default()).unwrap();
    assert_eq!(
        ps,
        (raw["codes"]["C1"]["delay_ns"].as_f64().unwrap() * 1000.0).round() as i64
    );
    // Rounded to 3 significant figures like every verdict, still within the uncertainty.
    let d = v.verdict["codes"]["C1"]["delay_ns"].as_f64().unwrap();
    assert!(
        (d - 34.7).abs()
            <= v.verdict["codes"]["C1"]["expanded_uncertainty_ns"]
                .as_f64()
                .unwrap()
    );
}
