// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
// Unit tests of the `cause` method on synthetic but realistic episodes with known cause:
// a 12-knot vessel in the Gulf of Finland observed for two hours (AIS every 30 s, VTS radar
// every 2 min, SAR detections, LRIT every 15 min, a 1 Hz-class receiver log every 10 s), and
// a 450-knot aircraft (ADS-B every 5 s, multilateration every 10 s). The anomaly, where there
// is one, runs from 40 to 80 minutes.

use super::*;
use serde_json::{json, Value};

const T0: f64 = 1_795_000_000.0;
const DUR: f64 = 7200.0;
const A0: f64 = 2400.0;
const A1: f64 = 4800.0;

struct Rng(u64);
impl Rng {
    fn u(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
    fn g(&mut self) -> f64 {
        let (a, b) = (self.u().max(1e-12), self.u());
        (-2.0 * a.ln()).sqrt() * (2.0 * std::f64::consts::PI * b).cos()
    }
    fn chance(&mut self, p: f64) -> bool {
        self.u() < p
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Truth {
    Jam,
    Spoof,
    Falsify,
    Fault,
}

impl Truth {
    fn class(self) -> &'static str {
        match self {
            Truth::Jam => "external_interference_jamming",
            Truth::Spoof => "external_spoofing",
            Truth::Falsify => "self_reported_track_falsification",
            Truth::Fault => "equipment_fault",
        }
    }
}

#[derive(Clone, Copy)]
struct Opt {
    radar: bool,
    sar: bool,
    lrit: bool,
    receiver: bool,
    regional: bool,
    sat_ais: bool,
    /// Scales the anomaly (offset size, C/N0 change).
    mag: f64,
    seed: u64,
}

impl Default for Opt {
    fn default() -> Self {
        Opt {
            radar: true,
            sar: true,
            lrit: false,
            receiver: true,
            regional: true,
            sat_ais: false,
            mag: 1.0,
            seed: 7,
        }
    }
}

fn iso_t(t: f64) -> String {
    crate::server::iso((T0 + t) as i64)
}

/// Move (lat, lon) by north/east kilometres.
fn shift(p: (f64, f64), n_km: f64, e_km: f64) -> (f64, f64) {
    (
        p.0 + n_km / 111.2,
        p.1 + e_km / (111.2 * p.0.to_radians().cos()),
    )
}

fn vessel_truth(t: f64) -> (f64, f64) {
    let d = 12.0 * 1.852 * t / 3600.0;
    let h = 80f64.to_radians();
    shift((59.50, 24.00), d * h.cos(), d * h.sin())
}

fn noisy(r: &mut Rng, p: (f64, f64), sigma_m: f64) -> (f64, f64) {
    shift(p, r.g() * sigma_m / 1000.0, r.g() * sigma_m / 1000.0)
}

fn fix(t: f64, p: Option<(f64, f64)>, sog: Option<f64>) -> Value {
    let mut v = json!({"t": iso_t(t)});
    if let Some((la, lo)) = p {
        v["lat_deg"] = json!(la);
        v["lon_deg"] = json!(lo);
    }
    if let Some(s) = sog {
        v["sog_kn"] = json!(s);
    }
    v
}

fn region_event(kind: &str, at: (f64, f64)) -> Value {
    json!({
        "format": "kshana-pnt-interference-event/1",
        "id": format!("reg-{kind}"),
        "start_utc": iso_t(A0 - 300.0),
        "end_utc": iso_t(A1 + 300.0),
        "systems": [{"system": "gnss", "band": "L1"}],
        "kind": kind,
        "location": {"lat_deg": at.0, "lon_deg": at.1, "radius_m": 30000.0},
        "observers": ["coastal-monitor-1", "coastal-monitor-2"],
        "confidence": 0.8,
        "basis": "monitoring network",
        "corroborated": true,
    })
}

/// A vessel episode of the given cause.
fn vessel(truth: Truth, o: Opt) -> Value {
    let mut r = Rng(o.seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let anom = |t: f64| (A0..=A1).contains(&t);
    let core = |t: f64| (A0 + 120.0..=A1 - 120.0).contains(&t);
    let spoof_off = |t: f64| {
        if anom(t) {
            30.0 * o.mag * (t - A0) / (A1 - A0)
        } else {
            0.0
        }
    };
    let fals_km = 40.0 * o.mag;
    // What the platform's own GNSS believed.
    let gnss_pos = |t: f64| {
        let p = vessel_truth(t);
        match truth {
            Truth::Spoof => shift(p, spoof_off(t) * 0.6, spoof_off(t) * 0.8),
            _ => p,
        }
    };
    let mut reported = vec![];
    let mut t = 0.0;
    while t <= DUR {
        let sog = Some(12.0 + 0.2 * r.g());
        let p = match truth {
            Truth::Jam if core(t) => None,
            Truth::Falsify if anom(t) => Some(shift(vessel_truth(t), 5.0, fals_km)),
            Truth::Fault if anom(t) => Some(vessel_truth(A0)),
            _ => Some(noisy(&mut r, gnss_pos(t), 5.0)),
        };
        reported.push(fix(t, p, sog));
        t += 30.0;
    }
    let mut independent = vec![];
    if o.radar {
        let mut pos = vec![];
        let mut t = 60.0;
        while t <= DUR {
            pos.push(fix(t, Some(noisy(&mut r, vessel_truth(t), 80.0)), None));
            t += 120.0;
        }
        independent.push(json!({"source": "coastal_radar", "id": "VTS", "positions": pos}));
    }
    if o.sar {
        let pos: Vec<Value> = [A0 + 600.0, A0 + 1500.0]
            .iter()
            .map(|&t| fix(t, Some(noisy(&mut r, vessel_truth(t), 100.0)), None))
            .collect();
        independent.push(json!({"source": "sar", "id": "pass-1", "positions": pos}));
    }
    if o.lrit {
        let mut pos = vec![];
        let mut t = 0.0;
        while t <= DUR {
            if !(truth == Truth::Jam && core(t)) {
                pos.push(fix(t, Some(noisy(&mut r, gnss_pos(t), 10.0)), None));
            }
            t += 900.0;
        }
        independent.push(json!({"source": "lrit", "positions": pos}));
    }
    if o.sat_ais {
        let pos: Vec<Value> = reported
            .iter()
            .step_by(10)
            .filter(|f| f.get("lat_deg").is_some())
            .cloned()
            .collect();
        independent.push(json!({"source": "sat_ais", "id": "provider", "positions": pos}));
    }
    let mut v = json!({
        "platform": "vessel",
        "subject_id": "IMO 9000001",
        "reported": reported,
        "independent": independent,
    });
    if o.receiver {
        let sats = [45.0, 43.0, 47.0, 38.0, 36.0, 41.0, 44.0, 39.0, 35.0, 42.0];
        let mut eps = vec![];
        let mut t = -600.0;
        while t <= DUR {
            let mut cn0: Vec<f64> = sats.iter().map(|c| c + 0.5 * r.g()).collect();
            let mut agc = 40.0 + 0.1 * r.g();
            let mut clock = 20.0 * (t + 600.0) + 2.0 * r.g();
            let mut fixed = true;
            match truth {
                Truth::Jam if anom(t) => {
                    let drop = 15.0 * o.mag + 5.0;
                    cn0 = cn0
                        .iter()
                        .map(|c| c - drop)
                        .filter(|c| *c >= 22.0)
                        .collect();
                    agc -= 8.0 * o.mag;
                    fixed = cn0.len() >= 4;
                }
                Truth::Spoof if anom(t) => {
                    cn0 = (0..10).map(|_| 49.0 + 0.5 * r.g()).collect();
                    agc -= 2.0;
                    clock += 8000.0;
                }
                Truth::Fault if anom(t) => fixed = false,
                _ => {}
            }
            let mut e = json!({"t": iso_t(t), "fix": fixed, "cn0_dbhz": cn0, "agc_db": agc, "clock_bias_ns": clock});
            if fixed {
                let p = noisy(&mut r, gnss_pos(t), 5.0);
                e["lat_deg"] = json!(p.0);
                e["lon_deg"] = json!(p.1);
            }
            eps.push(e);
            t += 10.0;
        }
        v["receiver"] = json!({"epochs": eps});
    }
    if o.regional {
        let at = vessel_truth(A0 + 1200.0);
        v["regional"] = match truth {
            Truth::Jam => json!([region_event("jamming", at)]),
            Truth::Spoof => json!([region_event("spoofing", at)]),
            _ => json!([]),
        };
    }
    v
}

fn req(v: &Value) -> CauseRequest {
    serde_json::from_value(v.clone()).expect("request deserialises")
}

fn run(v: &Value) -> Value {
    analyse(&req(v), &CauseLimits::default()).expect("analysis runs")
}

fn class(out: &Value) -> &str {
    out["classification"].as_str().unwrap()
}

#[test]
fn jamming_episode() {
    let out = run(&vessel(Truth::Jam, Opt::default()));
    assert_eq!(class(&out), Truth::Jam.class(), "{out:#}");
    assert!(out["confidence"].as_f64().unwrap() >= 0.85);
    assert_eq!(out["questions"]["rf_interference"], "indicated");
    assert_eq!(out["questions"]["origin"], "external");
    assert_eq!(
        out["questions"]["reported_track"],
        "consistent_with_independent_sources"
    );
    // The window brackets the injected anomaly.
    let w0 = parse_iso(out["window"]["start_utc"].as_str().unwrap()).unwrap() - T0;
    let w1 = parse_iso(out["window"]["end_utc"].as_str().unwrap()).unwrap() - T0;
    assert!((A0 - 60.0..=A0 + 300.0).contains(&w0), "{w0}");
    assert!((A1 - 300.0..=A1 + 60.0).contains(&w1), "{w1}");
}

#[test]
fn spoofing_episode() {
    let o = Opt {
        lrit: true,
        ..Opt::default()
    };
    let out = run(&vessel(Truth::Spoof, o));
    assert_eq!(class(&out), Truth::Spoof.class(), "{out:#}");
    assert!(out["confidence"].as_f64().unwrap() >= 0.85);
    assert_eq!(out["questions"]["reported_track"], "false");
    assert_eq!(out["questions"]["origin"], "external");
    let text = out["evidence"].to_string();
    assert!(text.contains("same false positions"), "{text}");
    assert!(text.contains("receiver itself produced"), "{text}");
}

#[test]
fn falsification_episode() {
    let out = run(&vessel(Truth::Falsify, Opt::default()));
    assert_eq!(class(&out), Truth::Falsify.class(), "{out:#}");
    assert!(out["confidence"].as_f64().unwrap() >= 0.85);
    assert_eq!(out["questions"]["origin"], "own_ship");
    assert_eq!(out["questions"]["rf_interference"], "not_indicated");
    assert_eq!(out["questions"]["reported_track"], "false");
}

#[test]
fn equipment_fault_episode() {
    let out = run(&vessel(Truth::Fault, Opt::default()));
    assert_eq!(class(&out), Truth::Fault.class(), "{out:#}");
    assert!(out["confidence"].as_f64().unwrap() >= 0.85);
    assert_eq!(out["questions"]["origin"], "equipment");
    assert!(out["evidence"].to_string().contains("frozen"));
}

#[test]
fn sanctions_screen_without_receiver_log_is_more_cautious() {
    // Typical screening: AIS and SAR/radar only. Falsification is still the leading cause,
    // with less confidence than when the receiver log is available.
    let o = Opt {
        receiver: false,
        ..Opt::default()
    };
    let full = run(&vessel(Truth::Falsify, Opt::default()));
    let out = run(&vessel(Truth::Falsify, o));
    let lead = out
        .get("confidence")
        .map(|_| class(&out))
        .or(out["leading_hypothesis"].as_str())
        .unwrap();
    assert_eq!(lead, Truth::Falsify.class(), "{out:#}");
    let c = out
        .get("confidence")
        .or(out.get("leading_confidence"))
        .and_then(Value::as_f64)
        .unwrap();
    assert!(c < full["confidence"].as_f64().unwrap(), "{c}");
    assert!(out["limits"].to_string().contains("receiver observables"));
}

#[test]
fn false_track_without_a_discriminator_names_no_cause() {
    // Radar shows the AIS track is false, but nothing tells an external spoofer from the
    // ship's own manipulation: the answer says so instead of guessing.
    let o = Opt {
        receiver: false,
        regional: false,
        sar: false,
        ..Opt::default()
    };
    let out = run(&vessel(Truth::Falsify, o));
    assert_eq!(class(&out), INSUFFICIENT, "{out:#}");
    assert_eq!(out["questions"]["reported_track"], "false");
    assert_eq!(out["questions"]["origin"], "undetermined");
    assert!(out["window"].is_object());
}

#[test]
fn reported_track_alone_is_insufficient() {
    // One jump in an AIS track and nothing else to weigh it against.
    let mut v = vessel(
        Truth::Falsify,
        Opt {
            radar: false,
            sar: false,
            receiver: false,
            regional: false,
            ..Opt::default()
        },
    );
    v["independent"] = json!([]);
    let out = run(&v);
    assert_eq!(class(&out), INSUFFICIENT, "{out:#}");
    assert!(out.get("confidence").is_none());
    assert!(out["leading_hypothesis"].is_string());
    assert_eq!(out["questions"]["origin"], "undetermined");
}

#[test]
fn clean_episode_finds_no_anomaly() {
    // Truth::Jam with the anomaly scaled to nothing is not a clean track (nulls remain), so
    // build a clean one by hand: reported = radar = receiver, nothing unusual.
    let mut v = vessel(Truth::Falsify, Opt::default());
    let clean = vessel(Truth::Jam, Opt::default());
    v["receiver"] = json!(null);
    let mut rep = vec![];
    let mut t = 0.0;
    while t <= DUR {
        rep.push(fix(t, Some(vessel_truth(t)), Some(12.0)));
        t += 30.0;
    }
    v["reported"] = json!(rep);
    v["independent"] = clean["independent"].clone();
    let out = run(&v);
    assert_eq!(class(&out), INSUFFICIENT, "{out:#}");
    assert!(out["limits"].to_string().contains("No anomaly"));
    assert_eq!(
        out["questions"]["reported_track"],
        "consistent_with_independent_sources"
    );
    assert!(out["window"].is_null());
}

#[test]
fn antenna_fault_is_not_called_jamming() {
    // C/N0 falls across the sky but the AGC does not move: less signal, not more noise.
    let mut v = vessel(Truth::Jam, Opt::default());
    for e in v["receiver"]["epochs"].as_array_mut().unwrap() {
        e["agc_db"] = json!(40.0);
    }
    v["regional"] = json!([]);
    let out = run(&v);
    assert_ne!(class(&out), Truth::Jam.class(), "{out:#}");
    assert!(out["evidence"].to_string().contains("antenna or cable"));
}

#[test]
fn aircraft_spoofed_to_a_fixed_point() {
    let mut r = Rng(99);
    let truth = |t: f64| {
        let d = 450.0 * 1.852 * t / 3600.0;
        shift((48.0, 30.0), 0.0, d)
    };
    let fixed = (48.45, 30.6);
    let mut rep = vec![];
    let mut t = 0.0;
    while t <= 1800.0 {
        let p = if t >= 900.0 {
            fixed
        } else {
            noisy(&mut r, truth(t), 10.0)
        };
        rep.push(fix(t, Some(p), Some(if t >= 900.0 { 0.0 } else { 450.0 })));
        t += 5.0;
    }
    let mut mlat = vec![];
    let mut t = 0.0;
    while t <= 1800.0 {
        mlat.push(fix(t, Some(noisy(&mut r, truth(t), 100.0)), None));
        t += 10.0;
    }
    let ev = json!({
        "format": "kshana-pnt-interference-event/1", "id": "a1",
        "start_utc": iso_t(600.0), "end_utc": iso_t(2400.0),
        "systems": [{"system": "gnss", "band": "L1"}], "kind": "spoofing",
        "location": {"lat_deg": 48.2, "lon_deg": 30.5, "radius_m": 80000.0},
        "observers": ["flight-a", "flight-b", "flight-c"], "confidence": 0.7,
        "basis": "ADS-B NIC/NACp", "corroborated": true
    });
    let v = json!({
        "platform": "aircraft", "subject_id": "4CA123",
        "reported": rep,
        "independent": [{"source": "mlat", "id": "network", "positions": mlat}],
        "regional": [ev],
    });
    let out = run(&v);
    assert_eq!(class(&out), Truth::Spoof.class(), "{out:#}");
    assert_eq!(out["platform"], "aircraft");
    assert!(out["evidence"].to_string().contains("fixed point"));
}

#[test]
fn relay_out_of_radio_range() {
    // A coastal AIS station heard the vessel, but the vessel reported a position 120 km away.
    let o = Opt {
        receiver: false,
        regional: false,
        sar: false,
        ..Opt::default()
    };
    let mut v = vessel(Truth::Falsify, o);
    let station = vessel_truth(A0 + 1200.0);
    let heard: Vec<Value> = v["reported"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| {
            let t = parse_iso(f["t"].as_str().unwrap()).unwrap() - T0;
            (A0..=A1).contains(&t)
        })
        .step_by(10)
        .cloned()
        .collect();
    v["independent"].as_array_mut().unwrap().push(json!({
        "source": "coastal_ais", "id": "station-1", "positions": heard,
        "receiver_lat_deg": station.0, "receiver_lon_deg": station.1, "range_km": 25.0,
    }));
    let out = run(&v);
    assert!(
        out["evidence"].to_string().contains("out of radio range"),
        "{out:#}"
    );
    assert_eq!(out["questions"]["reported_track"], "false");
}

#[test]
fn outputs_carry_no_internals() {
    for truth in [Truth::Jam, Truth::Spoof, Truth::Falsify, Truth::Fault] {
        let out = run(&vessel(truth, Opt::default()));
        let s = out.to_string();
        for k in [
            "score",
            "weight",
            "llr",
            "threshold",
            "posterior",
            "prior",
            "cap",
        ] {
            assert!(!s.contains(&format!("\"{k}")), "{k} in {s}");
        }
        for e in out["evidence"].as_array().unwrap() {
            let st = e["strength"].as_str().unwrap();
            assert!(["weak", "moderate", "strong"].contains(&st));
        }
        // Confidence is given in steps of 0.05.
        let c = out["confidence"].as_f64().unwrap();
        assert!(((c * 20.0) - (c * 20.0).round()).abs() < 1e-9, "{c}");
    }
}

#[test]
fn request_limits_and_validation() {
    let lim = CauseLimits {
        max_track_points: 100,
        ..CauseLimits::default()
    };
    let v = vessel(Truth::Jam, Opt::default());
    let e = analyse(&req(&v), &lim).unwrap_err();
    assert!(e.contains("too many reported positions"), "{e}");
    let lim = CauseLimits {
        max_epochs: 10,
        ..CauseLimits::default()
    };
    assert!(analyse(&req(&v), &lim)
        .unwrap_err()
        .contains("receiver epochs"));
    let lim = CauseLimits {
        max_window_s: 3600.0,
        ..CauseLimits::default()
    };
    assert!(analyse(&req(&v), &lim)
        .unwrap_err()
        .contains("window too long"));
    // Bad positions, times and regional reports are refused with a reason.
    let mut bad = v.clone();
    bad["reported"][3]["lat_deg"] = json!(95.0);
    assert!(analyse(&req(&bad), &CauseLimits::default())
        .unwrap_err()
        .contains("out of range"));
    let mut bad = v.clone();
    bad["reported"][3]["t"] = json!("yesterday");
    assert!(analyse(&req(&bad), &CauseLimits::default())
        .unwrap_err()
        .contains("expected YYYY"));
    let mut bad = v.clone();
    bad["regional"][0]["observers"] = json!([]);
    assert!(analyse(&req(&bad), &CauseLimits::default())
        .unwrap_err()
        .contains("regional[0]"));
    let mut bad = v.clone();
    bad["reported"] = json!([fix(0.0, Some((59.0, 24.0)), None)]);
    assert!(analyse(&req(&bad), &CauseLimits::default())
        .unwrap_err()
        .contains("at least two"));
    // Unix-second times and AIS "not available" (91/181) are accepted.
    let mut ok = v.clone();
    ok["reported"][0]["t"] = json!(T0);
    ok["reported"][1]["lat_deg"] = json!(91.0);
    ok["reported"][1]["lon_deg"] = json!(181.0);
    assert!(analyse(&req(&ok), &CauseLimits::default()).is_ok());
}

#[test]
fn iso_times_parse() {
    assert_eq!(parse_iso("1970-01-01T00:00:00Z").unwrap(), 0.0);
    assert_eq!(
        parse_iso("2026-11-20T00:00:00.5Z").unwrap(),
        1_795_132_800.5
    );
    assert!(parse_iso("2026-13-20T00:00:00Z").is_err());
    assert!(parse_iso("2026-11-20 00:00:00Z").is_err());
    assert_eq!(
        parse_iso(&crate::server::iso(1_795_000_123)).unwrap(),
        1_795_000_123.0
    );
}

/// Calibration on a randomised synthetic ensemble: data families present or absent at
/// random, anomaly size varied, noise varied. When the method names a cause it should be
/// right about as often as its confidence says, and it should rarely name the wrong one.
#[test]
fn confidence_is_calibrated_on_synthetic_ensemble() {
    let mut r = Rng(20_261_120);
    let mut decided = 0usize;
    let mut correct = 0usize;
    let mut undecided = 0usize;
    let mut sum_conf = 0.0;
    let mut by_band: std::collections::BTreeMap<&str, (usize, usize)> = Default::default();
    let n_per = 30;
    for truth in [Truth::Jam, Truth::Spoof, Truth::Falsify, Truth::Fault] {
        for i in 0..n_per {
            let o = Opt {
                radar: r.chance(0.7),
                sar: r.chance(0.4),
                lrit: r.chance(0.3),
                receiver: r.chance(0.6),
                regional: r.chance(0.6),
                sat_ais: r.chance(0.3),
                mag: 0.4 + 1.2 * r.u(),
                seed: 1000 + i as u64 * 7 + truth as u64 * 1000,
            };
            let out = run(&vessel(truth, o));
            let c = class(&out);
            if c == INSUFFICIENT {
                undecided += 1;
                continue;
            }
            decided += 1;
            let conf = out["confidence"].as_f64().unwrap();
            sum_conf += conf;
            let ok = c == truth.class();
            if !ok && std::env::var("CAUSE_DEBUG").is_ok() {
                eprintln!("MISS truth {truth:?} got {c} conf {conf} radar {} sar {} lrit {} rx {} reg {} sat {} mag {:.2}\n  {}", o.radar, o.sar, o.lrit, o.receiver, o.regional, o.sat_ais, o.mag,
                    out["evidence"].as_array().unwrap().iter().map(|e| format!("{} [{}]", e["finding"], e["strength"])).collect::<Vec<_>>().join("\n  "));
            }
            if ok {
                correct += 1;
            }
            let e = by_band
                .entry(match out["confidence_band"].as_str().unwrap() {
                    "high" => "high",
                    "medium" => "medium",
                    _ => "low",
                })
                .or_default();
            e.0 += 1;
            e.1 += ok as usize;
        }
    }
    let acc = correct as f64 / decided as f64;
    let mean_conf = sum_conf / decided as f64;
    eprintln!(
        "decided {decided}, correct {correct} (accuracy {acc:.3}), mean confidence {mean_conf:.3}, \
         insufficient {undecided}, by band {by_band:?}"
    );
    // Accuracy at least the mean stated confidence (no over-confidence), allowing for the
    // ensemble's sampling noise.
    assert!(
        acc + 0.05 >= mean_conf,
        "over-confident: {acc} < {mean_conf}"
    );
    assert!(acc >= 0.85, "accuracy {acc}");
    if let Some((n, k)) = by_band.get("high") {
        assert!(*k as f64 / *n as f64 >= 0.85, "high band {k}/{n}");
    }
    // Most episodes with some corroborating data are decided.
    assert!(
        undecided * 3 <= 4 * n_per,
        "too many undecided: {undecided}"
    );
}
