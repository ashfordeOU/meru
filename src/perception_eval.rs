// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The `perception-eval` method: an independent, signed **evaluation** of a perception-aided
//! positioning system's outputs, its landmark identifications and its integrity claims, against
//! truth the tester supplies (research backlog E40, B4002).
//!
//! A perception-aided system (camera, lidar or radar landmarks feeding a position) states a
//! position, a protection level and the landmarks it believes it saw. A tester knows where the
//! platform really was and which landmarks were really there. This method compares the two and
//! scores them; it never computes a position, never associates a detection with a map, never
//! fuses sensors and never matches a map. The pairing of each detection with the landmark it
//! really was (or with none) is the tester's, in the request.
//!
//! Scores, overall and per test condition, with 95 % (Wilson) intervals where they are rates:
//!
//! * **positioning integrity** (the Stanford-diagram classes against the caller's alert limit):
//!   available epochs, nominal, misleading (error above the protection level, protection level
//!   within the alert limit), hazardously misleading (error above the alert limit while the
//!   system said the protection level was within it), and unavailable; error percentiles and
//!   how tight the protection level was (error over protection level, 95th percentile);
//! * **landmark identification**: recall of the landmarks truly in view, precision of the
//!   detections, the **misidentification** rate (a detection claimed as the wrong landmark),
//!   false detections (no landmark there), and misidentifications while the system reported
//!   its integrity as good;
//! * the system's own **claims** checked: `met`, `not_met` or `not_shown`.
//!
//! A civil-releasability screen runs first, as in the Pro test-campaign evidence: the request
//! declares its end use, data classification and release, and a campaign that names a weapon end
//! use, is not unclassified, or names a military or restricted signal is refused. Evaluation
//! only. Evidence class MODELLED.

use crate::cause::Time;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Method identifier written into every outcome. A change to any rule is a new version.
pub const METHOD_VERSION: &str = "perception-eval/1";

/// What every verdict says about itself.
pub const STATEMENT: &str = "An evaluation of the outputs supplied against the truth supplied. \
It computes no position, associates nothing with a map and fuses no sensors; it is not a \
certification or an approval of the system.";

// ------------------------------------------------------------------------------------------
// Request
// ------------------------------------------------------------------------------------------

/// The civil-releasability declaration (the tester's).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    /// What the system is for, in a few words (for example "road vehicle lane-level positioning").
    pub end_use: String,
    /// Must be `unclassified`.
    pub classification: String,
    /// `public` or `civil-restricted`.
    pub release: String,
    /// Signals the system uses (for example `GPS L1 C/A`, `Galileo E1`), checked against the
    /// restricted list.
    #[serde(default)]
    pub signals: Vec<String>,
    /// Where the outputs were obtained: `twin`, `simulator`, `hil`, `lab-rf`, `field` or `flight`.
    pub environment: String,
}

/// A position in the tester's local frame, metres.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Local {
    pub e_m: f64,
    pub n_m: f64,
    #[serde(default)]
    pub u_m: Option<f64>,
}

/// What the system output at one epoch.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Output {
    /// False when the system declared its output unavailable.
    pub available: bool,
    #[serde(default)]
    pub position: Option<Local>,
    /// Horizontal protection level the system stated, metres.
    #[serde(default)]
    pub hpl_m: Option<f64>,
    /// The system's own integrity flag (true: it reported its integrity as good).
    #[serde(default)]
    pub integrity_ok: Option<bool>,
}

/// One detection the system reported, with the tester's pairing.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detection {
    /// The landmark the system claimed it saw.
    pub claimed: String,
    /// The landmark it really was, as the tester paired it; `None`: nothing was there.
    #[serde(default)]
    pub truth: Option<String>,
}

/// One epoch.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    pub t: Time,
    /// Where the platform really was (the tester's reference).
    pub truth: Local,
    pub output: Output,
    /// Landmarks truly in view (tester's).
    #[serde(default)]
    pub in_view: Vec<String>,
    #[serde(default)]
    pub detections: Vec<Detection>,
}

/// A run under one test condition.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub id: String,
    /// The test condition (for example `night`, `rain`, `urban-canyon`, `gnss-denied`).
    #[serde(default)]
    pub condition: Option<String>,
    pub epochs: Vec<Epoch>,
}

/// The system's own claims, checked against the scores.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    #[serde(default)]
    pub min_availability: Option<f64>,
    #[serde(default)]
    pub max_hmi_rate: Option<f64>,
    #[serde(default)]
    pub max_misidentification_rate: Option<f64>,
    #[serde(default)]
    pub max_h95_m: Option<f64>,
}

/// Request for the `perception-eval` method.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerceptionRequest {
    /// The system's name, echoed.
    #[serde(default)]
    pub system: Option<String>,
    pub declaration: Declaration,
    /// Horizontal alert limit, metres.
    pub alert_limit_m: f64,
    #[serde(default)]
    pub claims: Claims,
    pub runs: Vec<Run>,
}

/// Request limits.
#[derive(Clone, Debug)]
pub struct PerceptionLimits {
    pub max_runs: usize,
    pub max_epochs: usize,
    pub max_detections: usize,
}

impl Default for PerceptionLimits {
    fn default() -> Self {
        PerceptionLimits {
            max_runs: 500,
            max_epochs: 500_000,
            max_detections: 2_000_000,
        }
    }
}

// ------------------------------------------------------------------------------------------
// Civil-releasability screen
// ------------------------------------------------------------------------------------------

const WEAPON_TERMS: &[&str] = &[
    "weapon",
    "munition",
    "missile",
    "targeting",
    "target acquisition",
    "fire control",
    "warhead",
    "loitering",
    "guided bomb",
];
const RESTRICTED_SIGNALS: &[&str] = &["prs", "m-code", "mcode", "p(y)", "p-code", "pcode", "saasm"];
const ENVIRONMENTS: &[&str] = &["twin", "simulator", "hil", "lab-rf", "field", "flight"];

fn screen(d: &Declaration) -> Result<(), String> {
    let end = d.end_use.to_ascii_lowercase();
    if d.end_use.trim().is_empty() {
        return Err("declaration.end_use is required".into());
    }
    if let Some(w) = WEAPON_TERMS.iter().find(|w| end.contains(*w)) {
        return Err(format!(
            "refused by the civil-releasability screen: the end use names '{w}'"
        ));
    }
    if !d.classification.trim().eq_ignore_ascii_case("unclassified") {
        return Err(
            "refused by the civil-releasability screen: the data must be unclassified".into(),
        );
    }
    if !matches!(d.release.trim(), "public" | "civil-restricted") {
        return Err(
            "refused by the civil-releasability screen: release must be public or civil-restricted"
                .into(),
        );
    }
    for s in &d.signals {
        let l = s.to_ascii_lowercase();
        if let Some(r) = RESTRICTED_SIGNALS.iter().find(|r| {
            l.split(|c: char| c.is_whitespace() || c == ',' || c == '/' || c == ';')
                .any(|tok| tok == **r)
        }) {
            return Err(format!(
                "refused by the civil-releasability screen: a military or restricted signal is named ({r})"
            ));
        }
    }
    if !ENVIRONMENTS.contains(&d.environment.as_str()) {
        return Err(format!(
            "declaration.environment must be one of {}",
            ENVIRONMENTS.join(", ")
        ));
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------
// Scoring
// ------------------------------------------------------------------------------------------

fn wilson95(k: usize, n: usize) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    let (z, nf) = (1.959_964, n as f64);
    let p = k as f64 / nf;
    let d = 1.0 + z * z / nf;
    let c = (p + z * z / (2.0 * nf)) / d;
    let h = z * (p * (1.0 - p) / nf + z * z / (4.0 * nf * nf)).sqrt() / d;
    ((c - h).max(0.0), (c + h).min(1.0))
}

fn pct(v: &[f64], p: f64) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    let mut s = v.to_vec();
    s.sort_by(f64::total_cmp);
    let k = ((p / 100.0) * s.len() as f64).ceil().max(1.0) as usize - 1;
    Some(s[k.min(s.len() - 1)])
}

/// The tallies of one condition (or all).
#[derive(Clone, Debug, Default)]
struct Tally {
    epochs: usize,
    available: usize,
    nominal: usize,
    mi: usize,
    hmi: usize,
    /// Available epochs whose protection level exceeded the alert limit (system unavailable for
    /// the operation by its own statement).
    pl_above_al: usize,
    h_err: Vec<f64>,
    tightness: Vec<f64>,
    in_view: usize,
    in_view_found: usize,
    detections: usize,
    correct: usize,
    misid: usize,
    false_det: usize,
    misid_while_ok: usize,
}

impl Tally {
    fn add(&mut self, e: &Epoch, al: f64) {
        self.epochs += 1;
        let o = &e.output;
        if o.available {
            if let Some(p) = o.position {
                self.available += 1;
                let h = ((p.e_m - e.truth.e_m).powi(2) + (p.n_m - e.truth.n_m).powi(2)).sqrt();
                self.h_err.push(h);
                match o.hpl_m.filter(|x| x.is_finite() && *x > 0.0) {
                    Some(pl) if pl > al => self.pl_above_al += 1,
                    Some(pl) => {
                        self.tightness.push(h / pl);
                        if h > al {
                            self.hmi += 1;
                        } else if h > pl {
                            self.mi += 1;
                        } else {
                            self.nominal += 1;
                        }
                    }
                    // No protection level: an error above the alert limit is hazardous.
                    None => {
                        if h > al {
                            self.hmi += 1;
                        } else {
                            self.nominal += 1;
                        }
                    }
                }
            }
        }
        self.in_view += e.in_view.len();
        let mut found: Vec<&str> = vec![];
        for d in &e.detections {
            self.detections += 1;
            match &d.truth {
                None => self.false_det += 1,
                Some(t) if *t == d.claimed => {
                    self.correct += 1;
                    if e.in_view.contains(t) && !found.contains(&t.as_str()) {
                        found.push(t);
                    }
                }
                Some(_) => {
                    self.misid += 1;
                    if o.integrity_ok == Some(true) {
                        self.misid_while_ok += 1;
                    }
                }
            }
        }
        self.in_view_found += found.len();
    }

    fn rate(&self, k: usize, n: usize) -> Value {
        if n == 0 {
            return Value::Null;
        }
        let (a, b) = wilson95(k, n);
        json!({"value": k as f64 / n as f64, "interval_95": [a, b], "count": k, "of": n})
    }

    fn report(&self) -> Value {
        json!({
            "epochs": self.epochs,
            "integrity": {
                "availability": self.rate(self.available, self.epochs),
                "nominal": self.nominal,
                "misleading": self.mi,
                "hazardously_misleading": self.hmi,
                "hmi_rate": self.rate(self.hmi, self.available),
                "pl_above_alert_limit": self.pl_above_al,
                "h50_m": pct(&self.h_err, 50.0),
                "h95_m": pct(&self.h_err, 95.0),
                "h_max_m": self.h_err.iter().copied().reduce(f64::max),
                "error_over_pl_95": pct(&self.tightness, 95.0),
            },
            "landmarks": {
                "in_view": self.in_view,
                "recall": self.rate(self.in_view_found, self.in_view),
                "detections": self.detections,
                "precision": self.rate(self.correct, self.detections),
                "misidentification_rate": self.rate(self.misid, self.detections),
                "false_detections": self.false_det,
                "misidentified_while_integrity_ok": self.misid_while_ok,
            },
        })
    }
}

fn check_rate(k: usize, n: usize, target: f64, at_most: bool) -> &'static str {
    if n == 0 {
        return "not_shown";
    }
    let (a, b) = wilson95(k, n);
    match at_most {
        true if b <= target => "met",
        true if a > target => "not_met",
        false if a >= target => "met",
        false if b < target => "not_met",
        _ => "not_shown",
    }
}

/// Run the method; the raw (unrounded, unsigned) outcome.
pub fn analyse(r: &PerceptionRequest, l: &PerceptionLimits) -> Result<Value, String> {
    screen(&r.declaration)?;
    if !(r.alert_limit_m.is_finite() && r.alert_limit_m > 0.0) {
        return Err("alert_limit_m must be a positive number".into());
    }
    if r.runs.is_empty() || r.runs.len() > l.max_runs {
        return Err(format!("1 to {} runs", l.max_runs));
    }
    let n_ep: usize = r.runs.iter().map(|x| x.epochs.len()).sum();
    let n_det: usize = r
        .runs
        .iter()
        .flat_map(|x| x.epochs.iter())
        .map(|e| e.detections.len() + e.in_view.len())
        .sum();
    if n_ep == 0 || n_ep > l.max_epochs || n_det > l.max_detections {
        return Err(format!(
            "1 to {} epochs and at most {} detections and landmarks in view",
            l.max_epochs, l.max_detections
        ));
    }
    let c = &r.claims;
    for (k, x) in [
        ("claims.min_availability", c.min_availability),
        ("claims.max_hmi_rate", c.max_hmi_rate),
        (
            "claims.max_misidentification_rate",
            c.max_misidentification_rate,
        ),
    ] {
        if x.is_some_and(|x| !(0.0..=1.0).contains(&x)) {
            return Err(format!("{k} must be within 0 to 1"));
        }
    }
    let mut all = Tally::default();
    let mut per: BTreeMap<String, Tally> = BTreeMap::new();
    for run in &r.runs {
        let cond = run
            .condition
            .clone()
            .unwrap_or_else(|| "unspecified".into());
        let mut prev = f64::NEG_INFINITY;
        for (i, e) in run.epochs.iter().enumerate() {
            let t =
                e.t.secs()
                    .map_err(|x| format!("run '{}' epoch {i}: {x}", run.id))?;
            if t < prev {
                return Err(format!("run '{}': epochs out of time order at {i}", run.id));
            }
            prev = t;
            let fin = |p: &Local| p.e_m.is_finite() && p.n_m.is_finite();
            if !fin(&e.truth) || e.output.position.as_ref().is_some_and(|p| !fin(p)) {
                return Err(format!(
                    "run '{}' epoch {i}: positions must be finite",
                    run.id
                ));
            }
            all.add(e, r.alert_limit_m);
            per.entry(cond.clone()).or_default().add(e, r.alert_limit_m);
        }
    }
    let mut claims = serde_json::Map::new();
    if let Some(x) = c.min_availability {
        claims.insert(
            "min_availability".into(),
            json!(check_rate(all.available, all.epochs, x, false)),
        );
    }
    if let Some(x) = c.max_hmi_rate {
        claims.insert(
            "max_hmi_rate".into(),
            json!(check_rate(all.hmi, all.available, x, true)),
        );
    }
    if let Some(x) = c.max_misidentification_rate {
        claims.insert(
            "max_misidentification_rate".into(),
            json!(check_rate(all.misid, all.detections, x, true)),
        );
    }
    if let Some(x) = c.max_h95_m {
        claims.insert(
            "max_h95_m".into(),
            json!(match pct(&all.h_err, 95.0) {
                None => "not_shown",
                Some(h) if h <= x => "met",
                Some(_) => "not_met",
            }),
        );
    }
    let mut notes = vec![];
    if all.hmi == 0 && all.available > 0 {
        let (_, b) = wilson95(0, all.available);
        notes.push(format!(
            "No hazardously misleading epoch was seen; with {} available epochs the 95 % upper bound on the rate is {:.3e}, so smaller claimed rates cannot be shown by this campaign.",
            all.available, b
        ));
    }
    notes.push("Epochs are counted as independent; correlated epochs make the intervals narrower than the evidence supports.".into());
    Ok(json!({
        "method_version": METHOD_VERSION,
        "system": r.system,
        "environment": r.declaration.environment,
        "alert_limit_m": r.alert_limit_m,
        "runs": r.runs.len(),
        "overall": all.report(),
        "conditions": per.iter().map(|(k, t)| { let mut v = t.report(); v["condition"] = json!(k); v }).collect::<Vec<_>>(),
        "claims": claims,
        "notes": notes,
        "statement": STATEMENT,
    }))
}

/// Run the `perception-eval` method and return a signed verdict. Not fingerprinted: scores of
/// the caller's own outputs.
pub fn perception_verdict(
    req: &PerceptionRequest,
    s: &crate::methods::Signing,
    limits: &PerceptionLimits,
    utc: &str,
) -> Result<crate::SignedVerdict, String> {
    let v = analyse(req, limits)?;
    crate::methods::finish("perception-eval", v, s, utc)
}

#[cfg(test)]
#[path = "perception_eval_tests.rs"]
mod tests;
