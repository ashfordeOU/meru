// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The neutral vision-navigation claims test (research backlog E40, B4002): a vendor's claims
//! about a perception-aided positioning system, registered before the test, then scored against a
//! campaign that follows the registration.
//!
//! 1. `POST /verdict/vision-claims/register`: the system, the civil-releasability declaration,
//!    the alert limit, the test conditions and the claims are registered; the answer is a signed
//!    protocol (`meru-vision-claims-protocol/1`) with its SHA-256 and registration time. Claims
//!    cannot be changed afterwards without a new registration, which the record shows.
//! 2. `POST /verdict/vision-claims`: the signed protocol and the campaign (runs of outputs, truth
//!    and landmark pairings as in `perception-eval`). The protocol must verify against this
//!    service's key, and every epoch must be **after** the registration, so the claims cannot have
//!    been fitted to the results. Each claim is `shown` (the 95 % interval is on the claimed side),
//!    `contradicted` (on the other side) or `not_shown`, with the measured value, the interval and,
//!    where the campaign was too small, about how many epochs would be needed.
//!
//! Neutral: the same rules for every system, no ranking, no comparison between vendors. It scores
//! outputs only: no position is computed, nothing is associated with a map, no sensor is fused.
//! Not a certification or an approval. Evidence class MODELLED.

use crate::perception_eval::{screen, wilson95, Declaration, Run};
use crate::verdict::{verify, SignedVerdict};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Format of the registered protocol.
pub const PROTOCOL_FORMAT: &str = "meru-vision-claims-protocol/1";
/// Fewest epochs under a condition for the system to be said to have been tested in it.
pub const MIN_CONDITION_EPOCHS: usize = 100;

/// One claim.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Claim {
    /// The `percentile` (for example 95) of horizontal error is at most `max_m`.
    HorizontalError {
        #[serde(default)]
        condition: Option<String>,
        percentile: f64,
        max_m: f64,
    },
    /// Availability is at least `min` (0–1).
    Availability {
        #[serde(default)]
        condition: Option<String>,
        min: f64,
    },
    /// The hazardously-misleading rate per available epoch is at most `max`.
    HmiRate {
        #[serde(default)]
        condition: Option<String>,
        max: f64,
    },
    /// The landmark misidentification rate per detection is at most `max`.
    MisidentificationRate {
        #[serde(default)]
        condition: Option<String>,
        max: f64,
    },
}

/// What is registered.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocol {
    pub system: String,
    pub declaration: Declaration,
    pub alert_limit_m: f64,
    /// The conditions the system claims to operate in; each must be tested.
    pub conditions: Vec<String>,
    pub claims: Vec<Claim>,
}

/// Scoring request: the signed protocol and the campaign.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreRequest {
    pub protocol: SignedVerdict,
    pub runs: Vec<Run>,
}

fn check_protocol(p: &Protocol) -> Result<(), String> {
    screen(&p.declaration)?;
    if p.system.trim().is_empty() || p.system.len() > 128 {
        return Err("system: 1 to 128 characters".into());
    }
    if !(p.alert_limit_m.is_finite() && p.alert_limit_m > 0.0) {
        return Err("alert_limit_m must be a positive number".into());
    }
    if p.claims.is_empty() || p.claims.len() > 64 || p.conditions.len() > 32 {
        return Err("1 to 64 claims and at most 32 conditions".into());
    }
    for c in &p.claims {
        let (cond, ok) = match c {
            Claim::HorizontalError {
                condition,
                percentile,
                max_m,
            } => (
                condition,
                (50.0..100.0).contains(percentile) && max_m.is_finite() && *max_m > 0.0,
            ),
            Claim::Availability { condition, min } => (condition, (0.0..=1.0).contains(min)),
            Claim::HmiRate { condition, max } | Claim::MisidentificationRate { condition, max } => {
                (condition, *max > 0.0 && *max < 1.0)
            }
        };
        if !ok {
            return Err(format!("claim {c:?}: value out of range"));
        }
        if let Some(k) = cond {
            if !p.conditions.contains(k) {
                return Err(format!(
                    "claim names condition '{k}', which is not registered"
                ));
            }
        }
    }
    Ok(())
}

/// Register a protocol: the signed record.
pub fn register_verdict(
    p: &Protocol,
    s: &crate::methods::Signing,
    now: i64,
) -> Result<SignedVerdict, String> {
    check_protocol(p)?;
    let body = serde_json::to_value(p).map_err(|e| e.to_string())?;
    let sha = hex::encode(Sha256::digest(
        serde_json::to_vec(&body).unwrap_or_default(),
    ));
    let v = json!({
        "format": PROTOCOL_FORMAT,
        "protocol": body,
        "protocol_sha256": sha,
        "registered_utc": crate::server::iso(now),
        "statement": "Claims registered before the test. A campaign scored against this protocol must follow this time.",
    });
    crate::methods::finish("claims-protocol", v, s, &crate::server::iso(now))
}

/// The figures of one condition (or all).
#[derive(Default)]
struct Fig {
    epochs: usize,
    available: usize,
    hmi: usize,
    h: Vec<f64>,
    detections: usize,
    misid: usize,
}

fn status_max(k: usize, n: usize, max: f64) -> (&'static str, Value) {
    if n == 0 {
        return ("not_shown", Value::Null);
    }
    let (a, b) = wilson95(k, n);
    let s = if b <= max {
        "shown"
    } else if a > max {
        "contradicted"
    } else {
        "not_shown"
    };
    (s, json!([a, b]))
}

/// About how many trials would show a rate of at most `max` if the observed rate held (zero
/// events: the rule of three).
fn needed(k: usize, n: usize, max: f64) -> Option<usize> {
    let p = if n == 0 { 0.0 } else { k as f64 / n as f64 };
    if p >= max {
        return None;
    }
    if k == 0 {
        return Some((3.0 / max).ceil() as usize);
    }
    // Wilson upper bound ≈ p + 1.96 sqrt(p(1-p)/n) ≤ max.
    Some(((1.96f64.powi(2) * p * (1.0 - p)) / (max - p).powi(2)).ceil() as usize)
}

/// Distribution-free 95 % interval of the q-quantile from n sorted samples (normal approximation
/// to the binomial order statistics); `None` when n is too small for the bound.
fn quantile_interval(s: &[f64], q: f64) -> Option<(f64, f64)> {
    let n = s.len() as f64;
    let sd = (n * q * (1.0 - q)).sqrt();
    let lo = (n * q - 1.96 * sd).floor();
    let hi = (n * q + 1.96 * sd).ceil();
    if lo < 1.0 || hi > n {
        return None;
    }
    Some((s[lo as usize - 1], s[hi as usize - 1]))
}

/// Score a campaign against a signed protocol; the raw outcome.
pub fn score(r: &ScoreRequest, service_key: &str) -> Result<Value, String> {
    let pv = &r.protocol;
    let p = verify(pv, service_key);
    if !p.is_empty() || pv.method != "claims-protocol" {
        return Err(format!(
            "protocol: not one this service registered: {}",
            p.join("; ")
        ));
    }
    let proto: Protocol = serde_json::from_value(pv.verdict["protocol"].clone())
        .map_err(|e| format!("protocol: {e}"))?;
    check_protocol(&proto)?;
    let reg = pv.verdict["registered_utc"]
        .as_str()
        .ok_or("protocol: no registration time")
        .and_then(|t| crate::cause::parse_iso(t).map_err(|_| "protocol: bad registration time"))?;
    if r.runs.is_empty() || r.runs.iter().map(|x| x.epochs.len()).sum::<usize>() > 500_000 {
        return Err("1 run or more and at most 500,000 epochs".into());
    }
    let al = proto.alert_limit_m;
    let mut all = Fig::default();
    let mut by: std::collections::BTreeMap<String, Fig> = Default::default();
    for run in &r.runs {
        let cond = run
            .condition
            .clone()
            .unwrap_or_else(|| "unspecified".into());
        for (i, e) in run.epochs.iter().enumerate() {
            let t = e.t.secs()?;
            if t < reg {
                return Err(format!(
                    "run '{}' epoch {i} predates the protocol's registration: claims must be registered before the test",
                    run.id
                ));
            }
            for f in [&mut all, by.entry(cond.clone()).or_default()] {
                f.epochs += 1;
                if e.output.available {
                    if let Some(p) = e.output.position {
                        f.available += 1;
                        let h = (p.e_m - e.truth.e_m).hypot(p.n_m - e.truth.n_m);
                        f.h.push(h);
                        let pl_ok = e.output.hpl_m.is_none_or(|pl| pl <= al);
                        if h > al && pl_ok {
                            f.hmi += 1;
                        }
                    }
                }
                for d in &e.detections {
                    f.detections += 1;
                    if d.truth.as_ref().is_some_and(|t| *t != d.claimed) {
                        f.misid += 1;
                    }
                }
            }
        }
    }
    let empty = Fig::default();
    let fig = |c: &Option<String>| -> &Fig {
        match c {
            None => &all,
            Some(k) => by.get(k).unwrap_or(&empty),
        }
    };
    let mut rows = vec![];
    for c in &proto.claims {
        let row = match c {
            Claim::HorizontalError {
                condition,
                percentile,
                max_m,
            } => {
                let f = fig(condition);
                let mut s = f.h.clone();
                s.sort_by(f64::total_cmp);
                let q = percentile / 100.0;
                let measured = if s.is_empty() {
                    None
                } else {
                    Some(s[((q * s.len() as f64).ceil() as usize).clamp(1, s.len()) - 1])
                };
                let (st, iv) = match quantile_interval(&s, q) {
                    Some((a, b)) if b <= *max_m => ("shown", json!([a, b])),
                    Some((a, b)) if a > *max_m => ("contradicted", json!([a, b])),
                    Some((a, b)) => ("not_shown", json!([a, b])),
                    None => ("not_shown", Value::Null),
                };
                json!({"claim": c, "status": st, "measured_m": measured, "interval_95": iv, "samples": s.len()})
            }
            Claim::Availability { condition, min } => {
                let f = fig(condition);
                let (a, b) = wilson95(f.available, f.epochs);
                let st = if f.epochs == 0 {
                    "not_shown"
                } else if a >= *min {
                    "shown"
                } else if b < *min {
                    "contradicted"
                } else {
                    "not_shown"
                };
                json!({"claim": c, "status": st, "measured": if f.epochs > 0 { json!(f.available as f64 / f.epochs as f64) } else { Value::Null },
                    "interval_95": [a, b], "samples": f.epochs})
            }
            Claim::HmiRate { condition, max } => {
                let f = fig(condition);
                let (st, iv) = status_max(f.hmi, f.available, *max);
                json!({"claim": c, "status": st, "events": f.hmi, "samples": f.available, "interval_95": iv,
                    "epochs_needed_to_show": if st == "not_shown" { json!(needed(f.hmi, f.available, *max)) } else { Value::Null }})
            }
            Claim::MisidentificationRate { condition, max } => {
                let f = fig(condition);
                let (st, iv) = status_max(f.misid, f.detections, *max);
                json!({"claim": c, "status": st, "events": f.misid, "samples": f.detections, "interval_95": iv,
                    "detections_needed_to_show": if st == "not_shown" { json!(needed(f.misid, f.detections, *max)) } else { Value::Null }})
            }
        };
        rows.push(row);
    }
    let conditions: Vec<Value> = proto
        .conditions
        .iter()
        .map(|k| {
            let n = by.get(k).map_or(0, |f| f.epochs);
            json!({"condition": k, "epochs": n, "tested": n >= MIN_CONDITION_EPOCHS})
        })
        .collect();
    let count = |s: &str| rows.iter().filter(|r| r["status"] == s).count();
    Ok(json!({
        "method_version": "vision-claims/1",
        "system": proto.system,
        "protocol_sha256": pv.verdict["protocol_sha256"],
        "protocol_verdict_sha256": pv.verdict_sha256,
        "registered_utc": pv.verdict["registered_utc"],
        "environment": proto.declaration.environment,
        "claims": rows,
        "summary": {"shown": count("shown"), "contradicted": count("contradicted"), "not_shown": count("not_shown")},
        "conditions": conditions,
        "notes": [
            "Epochs are counted as independent; correlated epochs make the intervals narrower than the evidence supports.",
            format!("A registered condition counts as tested with at least {MIN_CONDITION_EPOCHS} epochs."),
        ],
        "statement": "A neutral score of registered claims against a later campaign. It computes no position, associates nothing with a map and fuses no sensors; it is not a certification or an approval of the system, and it ranks no one.",
    }))
}

/// Score and sign.
pub fn score_verdict(
    r: &ScoreRequest,
    s: &crate::methods::Signing,
    utc: &str,
) -> Result<SignedVerdict, String> {
    let pk = s
        .signer
        .public_key()
        .map_err(|e| format!("service key unavailable: {e}"))?;
    let v = score(r, &hex::encode(pk))?;
    crate::methods::finish("vision-claims", v, s, utc)
}

#[cfg(test)]
#[path = "vision_claims_tests.rs"]
mod tests;
