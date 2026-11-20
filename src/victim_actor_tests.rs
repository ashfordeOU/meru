// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
// Unit tests of the `victim-actor` method on synthetic episodes with known truth: a 12-knot
// subject vessel in the Gulf of Finland for two hours (AIS every 30 s, 3 m noise) among
// neighbouring vessels within 40 km. The episode, where there is one, runs from 40 to 80
// minutes. Victims: the subject and most neighbours are pulled by one spoofed position that
// circles at 1 km radius. Actors: the subject's own reports drift smoothly away from where it
// is (a composed track), or jump to a place 40 km away and back, while the neighbours are
// unaffected.

use super::*;
use serde_json::{json, Value};

const T0: f64 = 1_795_000_000.0;
const DUR: f64 = 7200.0;
const A0: f64 = 2400.0;
const A1: f64 = 4800.0;
const STEP: f64 = 30.0;

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
    /// The subject and most neighbours pulled to one circling false position.
    MassSpoof,
    /// The subject's own reports composed to drift away smoothly.
    SmoothFalsify,
    /// The subject's own reports jump 40 km away and back; neighbours unaffected.
    Teleport,
    /// Nothing happens.
    Clean,
}

#[derive(Clone, Copy)]
struct Opt {
    neighbours: usize,
    /// Share of nearby neighbours the spoofing reaches (MassSpoof).
    reach: f64,
    sar: bool,
    regional: bool,
    /// A composed track without receiver noise (SmoothFalsify).
    noiseless_fake: bool,
    seed: u64,
}

impl Default for Opt {
    fn default() -> Self {
        Opt {
            neighbours: 10,
            reach: 0.7,
            sar: true,
            regional: true,
            noiseless_fake: false,
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

fn mover(start: (f64, f64), kn: f64, hdg_deg: f64) -> impl Fn(f64) -> (f64, f64) {
    move |t: f64| {
        let d = kn * 1.852 * t / 3600.0;
        let h = hdg_deg.to_radians();
        shift(start, d * h.cos(), d * h.sin())
    }
}

const SUBJECT_START: (f64, f64) = (59.50, 24.00);

/// The spoofed position: a 1 km circle 25 km north-east of the subject's start, 30° a minute.
fn spoof_point(t: f64) -> (f64, f64) {
    let c = shift(SUBJECT_START, 18.0, 18.0);
    let th = ((t - A0) / 60.0 * 30.0).to_radians();
    shift(c, th.cos(), th.sin())
}

fn rep(r: &mut Rng, t: f64, p: (f64, f64), sigma_m: f64, sog: f64) -> Value {
    let q = shift(p, r.g() * sigma_m / 1000.0, r.g() * sigma_m / 1000.0);
    json!({"t": iso_t(t), "lat_deg": q.0, "lon_deg": q.1, "sog_kn": sog})
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

fn episode(truth: Truth, o: Opt) -> Value {
    let mut r = Rng(o.seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let anom = |t: f64| (A0..A1).contains(&t);
    let subject_truth = mover(SUBJECT_START, 12.0, 80.0);
    // The subject's reports.
    let mut reported = Vec::new();
    let mut t = 0.0;
    while t <= DUR {
        let tr = subject_truth(t);
        let v = match truth {
            Truth::MassSpoof if anom(t) => rep(&mut r, t, spoof_point(t), 3.0, 15.0),
            Truth::SmoothFalsify if anom(t) => {
                // A composed track: 30 minutes on a straight line 20 degrees off the true
                // course, then 10 minutes back to the true position, all at plausible speed.
                let off = mover(subject_truth(A0), 12.0, 100.0);
                let bend = A0 + 1800.0;
                let p = if t <= bend {
                    off(t - A0)
                } else {
                    let (a, b) = (off(bend - A0), subject_truth(A1));
                    let f = (t - bend) / (A1 - bend);
                    (a.0 + f * (b.0 - a.0), a.1 + f * (b.1 - a.1))
                };
                let sigma = if o.noiseless_fake { 0.0 } else { 3.0 };
                rep(&mut r, t, p, sigma, 12.0)
            }
            Truth::Teleport if anom(t) => rep(&mut r, t, shift(tr, 40.0, 0.0), 3.0, 12.0),
            _ => rep(&mut r, t, tr, 3.0, 12.0),
        };
        reported.push(v);
        t += STEP;
    }
    // Neighbours within about 40 km.
    let mut neighbours = Vec::new();
    for i in 0..o.neighbours {
        let start = shift(SUBJECT_START, (r.u() - 0.5) * 60.0, (r.u() - 0.3) * 60.0);
        let kn = 8.0 + 8.0 * r.u();
        let path = mover(start, kn, 360.0 * r.u());
        let reached = truth == Truth::MassSpoof && r.chance(o.reach);
        let mut tr = Vec::new();
        let mut t = 7.0 * i as f64 % STEP;
        while t <= DUR {
            let p = if reached && anom(t) {
                spoof_point(t)
            } else {
                path(t)
            };
            tr.push(rep(&mut r, t, p, 3.0, kn));
            t += STEP;
        }
        neighbours.push(json!({"id": format!("23000{i:04}"), "reported": tr}));
    }
    let mut v = json!({
        "subject_id": "230999999",
        "reported": reported,
        "neighbours": neighbours,
    });
    if o.sar {
        // Two SAR detections inside the episode, at the subject's true positions.
        let obs: Vec<Value> = [A0 + 900.0, A0 + 1500.0]
            .iter()
            .map(|&t| {
                let p = subject_truth(t);
                json!({"source": "sar", "id": "pass-1", "t": iso_t(t), "lat_deg": p.0, "lon_deg": p.1})
            })
            .collect();
        v["observations"] = json!(obs);
    }
    if o.regional {
        v["regional"] = match truth {
            Truth::MassSpoof => json!([region_event("spoofing", shift(SUBJECT_START, 10.0, 15.0))]),
            _ => json!([]),
        };
    }
    v
}

fn req(v: &Value) -> VictimActorRequest {
    serde_json::from_value(v.clone()).unwrap()
}

fn run(v: &Value) -> Value {
    analyse(&req(v), &VictimActorLimits::default()).unwrap()
}

fn class(out: &Value) -> &str {
    out["classification"].as_str().unwrap()
}

fn findings(out: &Value) -> String {
    out["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| format!("{} [{} {}]", e["finding"], e["supports"], e["strength"]))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn mass_spoofing_is_a_victim() {
    let out = run(&episode(Truth::MassSpoof, Opt::default()));
    assert_eq!(class(&out), "victim", "{}", findings(&out));
    assert!(out["confidence"].as_f64().unwrap() >= 0.85);
    assert_eq!(out["questions"]["shared_with_nearby_vessels"], "yes");
    assert_eq!(out["questions"]["regional_interference"], "reported");
    assert_eq!(out["questions"]["reported_track"], "false");
    let ci = &out["confidence_interval"];
    let c = out["confidence"].as_f64().unwrap();
    assert!(ci["low"].as_f64().unwrap() <= c && c <= ci["high"].as_f64().unwrap());
    assert_eq!(ci["basis"], "leave_one_evidence_family_out");
    // The episode window covers the spoofing.
    let w0 = parse(&out["window"]["start_utc"]);
    assert!((w0 - (T0 + A0)).abs() <= 1200.0, "{}", out["window"]);
}

fn parse(v: &Value) -> f64 {
    crate::cause::parse_iso(v.as_str().unwrap()).unwrap()
}

#[test]
fn mass_spoofing_without_regional_reports_still_rests_on_the_neighbours() {
    let o = Opt {
        regional: false,
        sar: false,
        ..Opt::default()
    };
    let out = run(&episode(Truth::MassSpoof, o));
    assert_eq!(class(&out), "victim", "{}", findings(&out));
    assert!(findings(&out).contains("same position as other vessels"));
}

#[test]
fn smooth_composed_track_is_an_actor() {
    let out = run(&episode(Truth::SmoothFalsify, Opt::default()));
    assert_eq!(class(&out), "actor", "{}", findings(&out));
    assert!(out["confidence"].as_f64().unwrap() >= 0.85);
    assert_eq!(out["questions"]["shared_with_nearby_vessels"], "no");
    assert_eq!(out["questions"]["regional_interference"], "not_reported");
    assert_eq!(out["questions"]["reported_track"], "false");
}

#[test]
fn a_noiseless_composed_track_is_too_regular() {
    let o = Opt {
        noiseless_fake: true,
        sar: false,
        regional: false,
        neighbours: 0,
        ..Opt::default()
    };
    let out = run(&episode(Truth::SmoothFalsify, o));
    let f = findings(&out);
    assert!(f.contains("too regular"), "{f}");
    // One family alone never decides.
    assert_eq!(class(&out), "indeterminate", "{f}");
    assert_eq!(out["leading_hypothesis"], "actor");
    // The same track with its receiver noise is not too regular.
    let o = Opt {
        noiseless_fake: false,
        ..o
    };
    let out = run(&episode(Truth::SmoothFalsify, o));
    assert!(!findings(&out).contains("too regular"));
    assert_eq!(out["anomaly_found"], false);
}

#[test]
fn an_isolated_jump_is_not_called_a_victim() {
    for regional in [false, true] {
        let o = Opt {
            regional,
            ..Opt::default()
        };
        let out = run(&episode(Truth::Teleport, o));
        assert_ne!(class(&out), "victim", "{}", findings(&out));
        assert_eq!(out["questions"]["shared_with_nearby_vessels"], "no");
    }
    // Without neighbours or regional reports, a jump and a false track name nobody.
    let o = Opt {
        neighbours: 0,
        regional: false,
        ..Opt::default()
    };
    let out = run(&episode(Truth::Teleport, o));
    assert_eq!(class(&out), "indeterminate", "{}", findings(&out));
}

#[test]
fn a_clean_track_finds_no_anomaly() {
    let out = run(&episode(Truth::Clean, Opt::default()));
    assert_eq!(class(&out), "indeterminate");
    assert_eq!(out["anomaly_found"], false);
    assert!(out.get("confidence").is_none());
    assert!(out["window"].is_null());
    assert_eq!(
        out["questions"]["reported_track"],
        "consistent_with_observations"
    );
}

#[test]
fn a_silence_while_neighbours_are_heard_is_weak_actor_evidence() {
    let mut v = episode(Truth::Clean, Opt::default());
    let rep = v["reported"].as_array().unwrap().clone();
    // Drop 50 minutes of the subject's reports.
    let kept: Vec<Value> = rep
        .into_iter()
        .filter(|x| {
            let t = parse(&x["t"]) - T0;
            !(3000.0..6000.0).contains(&t)
        })
        .collect();
    v["reported"] = json!(kept);
    v.as_object_mut().unwrap().remove("observations");
    let out = run(&v);
    let f = findings(&out);
    assert!(
        f.contains("reports stopped while nearby vessels kept being received"),
        "{f}"
    );
    assert_eq!(class(&out), "indeterminate", "{f}");
}

#[test]
fn outputs_carry_no_internals() {
    for truth in [Truth::MassSpoof, Truth::SmoothFalsify, Truth::Teleport] {
        let out = run(&episode(truth, Opt::default()));
        let s = out.to_string();
        for k in ["score", "weight", "threshold", "posterior", "prior", "cap"] {
            assert!(!s.contains(&format!("\"{k}")), "{k} in {s}");
        }
        // Neighbour identifiers are used to count, never returned.
        assert!(!s.contains("230000001"), "{s}");
        for e in out["evidence"].as_array().unwrap() {
            assert!(["weak", "moderate", "strong"].contains(&e["strength"].as_str().unwrap()));
            assert!(["victim", "actor", "neither"].contains(&e["supports"].as_str().unwrap()));
        }
        for key in ["confidence", "leading_confidence"] {
            if let Some(c) = out[key].as_f64() {
                assert!(((c * 20.0) - (c * 20.0).round()).abs() < 1e-9, "{c}");
            }
        }
    }
}

#[test]
fn request_validation_and_limits() {
    let v = episode(Truth::MassSpoof, Opt::default());
    // Unknown fields are refused, at the top level and inside.
    let mut bad = v.clone();
    bad["subject_name"] = json!("x");
    assert!(serde_json::from_value::<VictimActorRequest>(bad).is_err());
    let mut bad = v.clone();
    bad["reported"][0]["heading_deg"] = json!(10);
    assert!(serde_json::from_value::<VictimActorRequest>(bad).is_err());
    let mut bad = v.clone();
    bad["observations"][0]["source"] = json!("rumour");
    assert!(serde_json::from_value::<VictimActorRequest>(bad).is_err());
    // Limits before any work.
    let r = req(&v);
    let lim = |f: &dyn Fn(&mut VictimActorLimits)| {
        let mut l = VictimActorLimits::default();
        f(&mut l);
        analyse(&r, &l).unwrap_err()
    };
    assert!(lim(&|l| l.max_track_points = 10).contains("too many reported positions"));
    assert!(lim(&|l| l.max_neighbours = 2).contains("too many neighbour tracks"));
    assert!(lim(&|l| l.max_neighbour_points = 100).contains("too many neighbour positions"));
    assert!(lim(&|l| l.max_observations = 1).contains("too many observations"));
    assert!(lim(&|l| l.max_window_s = 3600.0).contains("window too long"));
    // Bad values are refused with a reason.
    let mut bad = v.clone();
    bad["reported"][3]["lat_deg"] = json!(95.0);
    assert!(analyse(&req(&bad), &VictimActorLimits::default())
        .unwrap_err()
        .contains("reported[3]"));
    let mut bad = v.clone();
    bad["neighbours"][1]["reported"][0]["t"] = json!("yesterday");
    assert!(analyse(&req(&bad), &VictimActorLimits::default())
        .unwrap_err()
        .contains("neighbours[1].reported[0]"));
    let mut bad = v.clone();
    bad["observations"][0]["sigma_m"] = json!(-1.0);
    assert!(analyse(&req(&bad), &VictimActorLimits::default())
        .unwrap_err()
        .contains("sigma_m"));
    let mut bad = v.clone();
    bad["regional"][0]["observers"] = json!([]);
    assert!(analyse(&req(&bad), &VictimActorLimits::default())
        .unwrap_err()
        .contains("regional[0]"));
    let mut bad = v.clone();
    bad["reported"] = json!([v["reported"][0], v["reported"][1]]);
    assert!(analyse(&req(&bad), &VictimActorLimits::default())
        .unwrap_err()
        .contains("at least three"));
}

#[test]
fn the_verdict_is_not_fingerprinted() {
    assert!(crate::fingerprint::plan("victim-actor").is_empty());
    assert_eq!(
        crate::server::method_of("/verdict/victim-actor"),
        Some("victim-actor")
    );
}

/// Calibration on a randomised synthetic ensemble: neighbours, their reach, SAR and regional
/// reports present or absent at random. When the method names a side it should be right at
/// least as often as its confidence says, it should never name a side on a clean track, and
/// it should never call an isolated jump a victim.
#[test]
fn confidence_is_calibrated_on_synthetic_ensemble() {
    let mut r = Rng(20_261_120);
    let (mut decided, mut correct, mut undecided) = (0usize, 0usize, 0usize);
    let mut sum_conf = 0.0;
    let n_per = 20;
    for truth in [
        Truth::MassSpoof,
        Truth::SmoothFalsify,
        Truth::Teleport,
        Truth::Clean,
    ] {
        for i in 0..n_per {
            let o = Opt {
                neighbours: (r.u() * 14.0) as usize,
                reach: 0.3 + 0.6 * r.u(),
                sar: r.chance(0.6),
                regional: r.chance(0.6),
                noiseless_fake: r.chance(0.3),
                seed: 1000 + i as u64 * 7 + truth as u64 * 1000,
            };
            let out = run(&episode(truth, o));
            let c = class(&out);
            match truth {
                Truth::Clean => {
                    assert_eq!(c, "indeterminate", "{}", findings(&out));
                    continue;
                }
                Truth::Teleport => {
                    assert_ne!(c, "victim", "{}", findings(&out));
                }
                _ => {}
            }
            if c == "indeterminate" {
                undecided += 1;
                continue;
            }
            decided += 1;
            let conf = out["confidence"].as_f64().unwrap();
            sum_conf += conf;
            let want = match truth {
                Truth::MassSpoof => "victim",
                _ => "actor",
            };
            if c == want {
                correct += 1;
            } else if std::env::var("VA_DEBUG").is_ok() {
                eprintln!("MISS {truth:?} got {c} {conf}\n{}", findings(&out));
            }
        }
    }
    let acc = correct as f64 / decided.max(1) as f64;
    let mean_conf = sum_conf / decided.max(1) as f64;
    eprintln!(
        "decided {decided}, correct {correct} (accuracy {acc:.3}), mean confidence {mean_conf:.3}, \
         indeterminate {undecided}"
    );
    assert!(decided >= 25, "decided {decided}");
    assert!(
        acc + 0.05 >= mean_conf,
        "over-confident: {acc} < {mean_conf}"
    );
    assert!(acc >= 0.9, "accuracy {acc}");
}
