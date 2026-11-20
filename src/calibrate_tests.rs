// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;
use crate::verdict::verify;
use ed25519_dalek::SigningKey;

const SEED: [u8; 32] = *b"meru-calibrate-test-seed-32byte!";

/// A deterministic standard normal stream.
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

fn param(
    name: &str,
    prior: f64,
    sigma: Option<f64>,
    lo: Option<f64>,
    hi: Option<f64>,
) -> ParamSpec {
    ParamSpec {
        name: name.into(),
        prior: Some(prior),
        prior_sigma: sigma,
        lower: lo,
        upper: hi,
        initial: None,
    }
}

/// A thermal node cooling towards ambient: `T = Ta + (T0 − Ta)·exp(−t/tau)`, and a battery
/// voltage with a linear sag, both sampled every 60 s with noise.
fn thermal_request(seed: u64) -> CalibrateRequest {
    let (ta, t0, tau, v0, k) = (-12.0, 35.0, 1800.0, 28.4, 2.0e-4);
    let mut rng = Rng(seed);
    let mut obs = vec![];
    for i in 0..120 {
        let t = i as f64 * 60.0;
        obs.push(Observation {
            observable: "thermal.panel_c".into(),
            t_s: t,
            value: ta + (t0 - ta) * (-t / tau).exp() + 0.3 * rng.normal(),
            sigma: 0.3,
        });
        obs.push(Observation {
            observable: "eps.bus_v".into(),
            t_s: t,
            value: v0 - k * t + 0.02 * rng.normal(),
            sigma: 0.02,
        });
    }
    CalibrateRequest {
        subject: Some("TOY-1".into()),
        parameters: vec![
            param("ambient", 0.0, Some(20.0), None, None),
            param("start", 30.0, Some(10.0), None, None),
            param("tau", 1000.0, Some(2000.0), Some(1.0), Some(20000.0)),
            param("v0", 28.0, Some(1.0), None, None),
            param("sag", 1e-4, None, Some(0.0), None),
        ],
        model: ModelSpec::Expression {
            observables: BTreeMap::from([
                (
                    "thermal.panel_c".into(),
                    "ambient + (start - ambient) * exp(-t / tau)".into(),
                ),
                ("eps.bus_v".into(), "v0 - sag * t".into()),
            ]),
        },
        observations: obs,
        tolerances: BTreeMap::from([("eps.bus_v".into(), 0.05)]),
        options: CalOptions::default(),
    }
}

fn post(v: &Value, name: &str) -> (f64, f64) {
    let p = v["posterior"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == name)
        .unwrap();
    (p["value"].as_f64().unwrap(), p["std_err"].as_f64().unwrap())
}

#[test]
fn expression_model_recovers_known_parameters_with_honest_uncertainty() {
    let v = calibrate(&thermal_request(3), &CalibrateLimits::default(), &SEED, "k").unwrap();
    assert_eq!(v["converged"], json!(true), "{v}");
    for (name, truth) in [
        ("ambient", -12.0),
        ("start", 35.0),
        ("tau", 1800.0),
        ("v0", 28.4),
        ("sag", 2.0e-4),
    ] {
        let (x, s) = post(&v, name);
        assert!(s > 0.0, "{name}");
        assert!((x - truth).abs() < 4.0 * s, "{name}: {x} ± {s} vs {truth}");
        assert!(
            s < 0.05 * truth.abs().max(1.0),
            "{name}: {s} is not informative"
        );
    }
    // The start values miss the voltage tolerance; the calibrated model meets it.
    let (f0, f1) = (
        v["fidelity_first"].as_f64().unwrap(),
        v["fidelity_last"].as_f64().unwrap(),
    );
    assert!(f1 > f0 && f1 > 80.0, "{f0} -> {f1}");
    let chi = v["chi2_reduced_last"].as_f64().unwrap();
    assert!((0.6..1.5).contains(&chi), "{chi}");
    assert_eq!(v["at_bound"], json!([]));
    assert_eq!(v["subject"], "TOY-1");
    // An uncertainty check over repetitions: the error is within 2 std_err most of the time.
    let mut inside = 0;
    for seed in 10..30 {
        let v = calibrate(
            &thermal_request(seed),
            &CalibrateLimits::default(),
            &SEED,
            "k",
        )
        .unwrap();
        let (x, s) = post(&v, "tau");
        if (x - 1800.0).abs() <= 2.0 * s {
            inside += 1;
        }
    }
    assert!(inside >= 16, "{inside}/20 within 2 std_err");
}

#[test]
fn bounds_hold_and_unconstrained_parameters_are_flagged() {
    let mut r = thermal_request(5);
    // The truth (tau 1800 s) lies above this upper bound: the estimate sits on the bound.
    r.parameters[2].upper = Some(900.0);
    r.parameters[2].prior = Some(600.0);
    // A parameter no observation depends on keeps its prior and is flagged.
    r.parameters
        .push(param("unused_gain", 1.0, Some(0.5), None, None));
    if let ModelSpec::Expression { observables } = &mut r.model {
        observables.insert("eps.bus_v".into(), "v0 - sag * t + 0 * unused_gain".into());
    }
    let v = calibrate(&r, &CalibrateLimits::default(), &SEED, "k").unwrap();
    let (tau, _) = post(&v, "tau");
    assert!(tau <= 900.0 && tau > 899.0, "{tau}");
    assert!(
        v["at_bound"].as_array().unwrap().contains(&json!("tau")),
        "{v}"
    );
    let (g, gs) = post(&v, "unused_gain");
    // It keeps its prior; its uncertainty is the prior's, inflated with every other one by
    // the misfit the bound forces (reduced chi^½ above 1).
    let infl = v["chi2_reduced_last"].as_f64().unwrap().sqrt();
    assert!(infl > 2.0, "{infl}");
    assert!(
        (g - 1.0).abs() < 1e-6 && (gs / (0.5 * infl) - 1.0).abs() < 0.1,
        "{g} {gs} {infl}"
    );
    assert!(v["not_constrained"]
        .as_array()
        .unwrap()
        .contains(&json!("unused_gain")));
}

/// A black-box simulator the service never sees: only its runs over a design.
fn simulator(drag: f64, bias: f64, t: f64) -> f64 {
    bias + 400.0 * (1.0 - (-drag * t / 600.0).exp()) + 2.0 * (t / 900.0).sin()
}

fn design_request(truth: (f64, f64), levels: &[f64], biases: &[f64]) -> CalibrateRequest {
    let times: Vec<f64> = (0..=60).map(|i| i as f64 * 60.0).collect();
    let mut runs = vec![];
    for &d in levels {
        for &b in biases {
            runs.push(DesignRun {
                params: BTreeMap::from([("drag".into(), d), ("bias".into(), b)]),
                predictions: BTreeMap::from([(
                    "prop.range_m".into(),
                    times.iter().map(|t| [*t, simulator(d, b, *t)]).collect(),
                )]),
            });
        }
    }
    let mut rng = Rng(9);
    let observations = times
        .iter()
        .skip(1)
        .step_by(2)
        .map(|t| Observation {
            observable: "prop.range_m".into(),
            t_s: *t + 7.0,
            value: simulator(truth.0, truth.1, *t + 7.0) + 0.5 * rng.normal(),
            sigma: 0.5,
        })
        .filter(|o| o.t_s <= 3600.0)
        .collect();
    CalibrateRequest {
        subject: None,
        parameters: vec![
            param("drag", 1.0, Some(0.5), Some(0.0), None),
            param("bias", 0.0, Some(10.0), None, None),
        ],
        model: ModelSpec::Design { runs },
        observations,
        tolerances: BTreeMap::new(),
        options: CalOptions::default(),
    }
}

#[test]
fn design_model_calibrates_a_black_box_simulator() {
    let r = design_request(
        (1.15, 3.0),
        &[0.8, 0.9, 1.0, 1.1, 1.2, 1.3, 1.4],
        &[-5.0, 0.0, 5.0, 10.0],
    );
    let v = calibrate(&r, &CalibrateLimits::default(), &SEED, "k").unwrap();
    assert_eq!(v["converged"], json!(true), "{v}");
    let (d, ds) = post(&v, "drag");
    let (b, bs) = post(&v, "bias");
    assert!((d - 1.15).abs() < 4.0 * ds && ds < 0.02, "{d} ± {ds}");
    assert!((b - 3.0).abs() < 4.0 * bs && bs < 1.0, "{b} ± {bs}");
    assert_eq!(v["surface"]["kind"], "quadratic");
    assert_eq!(v["surface"]["runs"], 28);
    // A truth outside the design: the estimate stays on the design's edge and says so.
    let r = design_request((1.8, 3.0), &[0.8, 1.0, 1.2, 1.4], &[-5.0, 0.0, 5.0, 10.0]);
    let v = calibrate(&r, &CalibrateLimits::default(), &SEED, "k").unwrap();
    let (d, _) = post(&v, "drag");
    assert!(d <= 1.4 + 1e-9, "{d}");
    assert!(
        v["at_bound"].as_array().unwrap().contains(&json!("drag")),
        "{v}"
    );
    // Too few runs for even a linear surface with an error estimate.
    let r = design_request((1.0, 0.0), &[0.9, 1.1], &[0.0]);
    let e = calibrate(&r, &CalibrateLimits::default(), &SEED, "k").unwrap_err();
    assert!(e.contains("needs at least 4 runs"), "{e}");
    // A design that does not vary one parameter.
    let r = design_request((1.0, 0.0), &[0.9, 1.0, 1.1, 1.2, 1.3], &[0.0]);
    let e = calibrate(&r, &CalibrateLimits::default(), &SEED, "k").unwrap_err();
    assert!(e.contains("does not vary parameter 'bias'"), "{e}");
}

#[test]
fn verdict_has_the_selfcal_shape_and_is_signed_with_a_stable_lineage() {
    let s = Signing {
        signer: &SEED,
        key_id: "k1",
        lineage_seed: &SEED,
        lineage_key_id: "lin",
        sigfigs: 3,
        bind: None,
    };
    let req = thermal_request(3);
    let v = calibrate_verdict(
        &req,
        &s,
        &CalibrateLimits::default(),
        "2026-11-20T00:00:00Z",
    )
    .unwrap();
    let pk = hex::encode(SigningKey::from_bytes(&SEED).verifying_key().to_bytes());
    assert!(verify(&v, &pk).is_empty());
    assert_eq!(v.method, "calibrate");
    assert_eq!(v.evidence_class, "MODELLED");
    // The fields the simulator-recalibration client reads.
    let o = &v.verdict;
    assert!(o["converged"].is_boolean());
    assert!(o["stop_reason"].is_string() && o["passes"].is_u64());
    assert!(o["fidelity_first"].is_number() && o["fidelity_last"].is_number());
    for p in o["posterior"].as_array().unwrap() {
        assert!(p["name"].is_string() && p["value"].is_number() && p["std_err"].is_number());
    }
    assert_eq!(o["lineage"]["head"].as_str().unwrap().len(), 64);
    // Outcome only, rounded.
    let body = serde_json::to_string(o).unwrap();
    for k in ["\"residual", "\"jacobian", "\"iterations\"", "\"coef"] {
        assert!(!body.contains(k), "{k} leaked");
    }
    let x = o["posterior"][2]["value"].as_f64().unwrap();
    assert_eq!(x, crate::outputs::round_sig(x, 3));
    // The same request gives the same lineage head; other telemetry another one; the tag
    // depends on the service's lineage key.
    let again = calibrate(&req, &CalibrateLimits::default(), &SEED, "lin").unwrap();
    assert_eq!(again["lineage"]["head"], o["lineage"]["head"]);
    let other = calibrate(
        &thermal_request(4),
        &CalibrateLimits::default(),
        &SEED,
        "lin",
    )
    .unwrap();
    assert_ne!(other["lineage"]["head"], o["lineage"]["head"]);
    let k2 = calibrate(&req, &CalibrateLimits::default(), &[7u8; 32], "lin").unwrap();
    assert_ne!(k2["lineage"]["tag"], o["lineage"]["tag"]);
}

#[test]
fn expressions_parse_with_the_usual_precedence_and_refuse_anything_else() {
    let vars = vec!["t".to_string(), "a".to_string()];
    let ev = |s: &str, t: f64, a: f64| Expr::parse(s, &vars).unwrap().eval(&[t, a]);
    assert_eq!(ev("1 + 2 * 3", 0.0, 0.0), 7.0);
    assert_eq!(ev("-2^2", 0.0, 0.0), -4.0);
    assert_eq!(ev("2^3^2", 0.0, 0.0), 512.0);
    assert_eq!(ev("(1 + 2) * 3", 0.0, 0.0), 9.0);
    assert_eq!(ev("a * t - 1.5e1", 2.0, 10.0), 5.0);
    assert_eq!(ev("max(a, t) + min(1, 2) + pow(2, 3)", 3.0, 4.0), 13.0);
    assert!((ev("sqrt(a) + exp(0) + ln(1) + sin(pi/2)", 0.0, 9.0) - 5.0).abs() < 1e-12);
    for bad in [
        "a +",
        "foo(1)",
        "b * t",
        "(1 + 2",
        "max(1)",
        "1 2",
        "a; drop",
        &"(".repeat(100),
    ] {
        assert!(Expr::parse(bad, &vars).is_err(), "{bad}");
    }
    let long = vec!["a"; 2000].join("+");
    assert!(Expr::parse(&long, &vars).unwrap_err().contains("nodes"));
}

#[test]
fn requests_are_checked_before_any_work() {
    let lim = CalibrateLimits::default();
    let ok = thermal_request(3);
    assert!(validate(&ok, &lim).is_ok());
    let mut r = ok.clone();
    r.parameters.push(r.parameters[0].clone());
    assert!(validate(&r, &lim).unwrap_err().contains("twice"));
    let mut r = ok.clone();
    r.parameters[0].name = "exp".into();
    assert!(validate(&r, &lim).unwrap_err().contains("plain identifier"));
    let mut r = ok.clone();
    r.parameters[0].prior_sigma = Some(0.0);
    assert!(validate(&r, &lim).unwrap_err().contains("positive"));
    let mut r = ok.clone();
    r.parameters[2].lower = Some(5e4);
    assert!(validate(&r, &lim)
        .unwrap_err()
        .contains("lower must be below"));
    let mut r = ok.clone();
    r.observations[0].sigma = -1.0;
    assert!(validate(&r, &lim).unwrap_err().contains("positive sigma"));
    let mut r = ok.clone();
    r.observations[0].observable = "aocs.rate".into();
    assert!(validate(&r, &lim)
        .unwrap_err()
        .contains("no model expression for observable 'aocs.rate'"));
    let mut r = ok.clone();
    r.options.max_iter = 10_000;
    assert!(validate(&r, &lim).unwrap_err().contains("max_iter"));
    let small = CalibrateLimits {
        max_jacobian: 100,
        ..CalibrateLimits::default()
    };
    assert!(validate(&ok, &small)
        .unwrap_err()
        .contains("observations x parameters"));
    // A model naming something that is not a parameter is refused at compile time.
    let mut r = ok.clone();
    if let ModelSpec::Expression { observables } = &mut r.model {
        observables.insert("eps.bus_v".into(), "v0 - leak * t".into());
    }
    let e = calibrate(&r, &lim, &SEED, "k").unwrap_err();
    assert!(e.contains("unknown name 'leak'"), "{e}");
    // Unknown fields are refused.
    assert!(serde_json::from_str::<CalibrateRequest>(
        r#"{"parameters":[{"name":"a","prior":1}],"model":{"kind":"expression","observables":{"x":"a"}},"observations":[{"observable":"x","t_s":0,"value":1,"sigma":1}],"extra":1}"#
    )
    .is_err());
    assert!(serde_json::from_str::<CalibrateRequest>(
        r#"{"parameters":[{"name":"a","prior":1}],"model":{"kind":"expression","observables":{"x":"a"}},"observations":[{"observable":"x","t_s":0,"value":1,"sigma":1}]}"#
    )
    .is_ok());
}
