// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The `flight-integrity` method: a signed per-flight positioning-integrity verdict for a drone
//! flight (research backlog E18, the hosted part of the per-flight attestation).
//!
//! The Kshana Pro client builds a local attestation from the flight's own telemetry
//! (`kshana-pro-utm-attestation/1`: fix gaps, receiver flags, jumps, dead-reckoning error over
//! the longest gap, map exposure, Remote ID). This method gives what a flight's own log cannot:
//!
//! * an **independent recomputation** of the attestation's telemetry checks from the same
//!   telemetry, and whether the attestation the client sent agrees with it;
//! * **area context**: other flights in the same area and time (the operator's own fleet, or
//!   a U-space service provider's traffic) and regional interference reports
//!   (`kshana-pnt-interference-event/1`), so a degraded flight is read as sharing an
//!   **area** cause (others degraded at the same time, or a report) or as specific to the
//!   **aircraft** (others nearby unaffected), or `indeterminate`;
//! * a statement (`NOMINAL`, `DEGRADED`, `INTEGRITY-SUSPECT`), the attribution with a
//!   confidence in steps of 0.05, and the SHA-256 of the client's attestation inside the signed
//!   body, so the verdict countersigns that attestation.
//!
//! The attribution rules, thresholds and per-flight comparisons stay in the service. Decision
//! support only: never a flight or operational authorisation, a SORA approval or a means of
//! compliance. Nothing here locates an interference source. Evidence class MODELLED.

use crate::cause::{parse_iso, Time};
use crate::server::iso;
use kshana_pro::ievents;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Method identifier written into every outcome. A change to any rule is a new version.
pub const METHOD_VERSION: &str = "flight-integrity/1";

/// The decision-support statement every verdict carries.
pub const DECISION_SUPPORT: &str = "Decision support only. Not a flight authorisation, not an \
operational authorisation or a SORA approval, not a means of compliance and not a substitute for \
the operator's assessment, the USSP's procedures or the authority's review. Nothing here locates \
an interference source.";

/// Lowest confidence at which an attribution is named.
const DECIDE_AT: f64 = 0.7;
/// Another flight is near when within this distance of the subject at about the same time, km.
const NEAR_KM: f64 = 15.0;
/// "About the same time", seconds.
const NEAR_DT_S: f64 = 30.0;
/// Slack around a degraded interval when matching others and reports, seconds.
const OVERLAP_S: f64 = 60.0;
/// Reach of a located regional report beyond its stated radius, km.
const REG_REACH_KM: f64 = 25.0;
/// Shortest stretch without a 3-D fix that counts as degraded, seconds.
const MIN_GAP_S: f64 = 2.0;

// ------------------------------------------------------------------------------------------
// Request
// ------------------------------------------------------------------------------------------

/// One telemetry epoch, as in the Pro telemetry CSV (`t_utc, lat, lon, fix_type, eph_m,
/// jamming_state, spoofing_state`).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    pub t: Time,
    pub lat_deg: f64,
    pub lon_deg: f64,
    /// 0 no fix, 2 2-D, 3 3-D and above.
    pub fix_type: u8,
    #[serde(default)]
    pub eph_m: Option<f64>,
    /// Receiver jamming indicator (2 or more: jamming indicated).
    #[serde(default)]
    pub jamming_state: Option<u8>,
    /// Receiver spoofing indicator (2 or more: spoofing indicated).
    #[serde(default)]
    pub spoofing_state: Option<u8>,
}

/// The operation's parameters the checks need.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    /// Operation id, echoed.
    pub id: String,
    /// Planned ground speed, m/s.
    pub speed_m_s: f64,
    /// Contingency buffer, metres.
    pub contingency_m: f64,
    /// Growth of the dead-reckoning error, metres per second without a fix (the client's
    /// dead-reckoning model for the UAS class, linearised; default 2 m/s).
    #[serde(default = "d_dr")]
    pub dr_growth_m_per_s: f64,
}

fn d_dr() -> f64 {
    2.0
}

/// Another flight in the same area and time.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtherFlight {
    /// Its identifier (counts distinct flights; never returned).
    #[serde(default)]
    pub id: String,
    pub telemetry: Vec<Epoch>,
}

/// Request for the `flight-integrity` method.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlightRequest {
    pub operation: Operation,
    pub telemetry: Vec<Epoch>,
    /// The client's local attestation (`kshana-pro-utm-attestation/1`), as JSON. Its SHA-256
    /// (canonical form) is bound into the verdict and its telemetry checks are compared.
    #[serde(default)]
    pub attestation: Option<Value>,
    /// Other flights in the same area and time.
    #[serde(default)]
    pub others: Vec<OtherFlight>,
    /// Regional interference reports; supplying the list (even empty) states that regional
    /// monitoring covered the flight.
    #[serde(default)]
    pub regional: Option<Vec<ievents::Event>>,
}

/// Request limits, checked before any work.
#[derive(Clone, Debug)]
pub struct FlightLimits {
    pub max_epochs: usize,
    pub max_others: usize,
    pub max_other_epochs: usize,
    pub max_regional: usize,
    /// Longest flight, hours.
    pub max_hours: f64,
}

impl Default for FlightLimits {
    fn default() -> Self {
        FlightLimits {
            max_epochs: 100_000,
            max_others: 100,
            max_other_epochs: 500_000,
            max_regional: 500,
            max_hours: 24.0,
        }
    }
}

// ------------------------------------------------------------------------------------------
// Telemetry checks (the attestation's, recomputed)
// ------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Tel {
    t: f64,
    lat: f64,
    lon: f64,
    fix: u8,
    eph: Option<f64>,
    jam: bool,
    spoof: bool,
}

fn parse(eps: &[Epoch], who: &str) -> Result<Vec<Tel>, String> {
    let mut v = Vec::with_capacity(eps.len());
    for (i, e) in eps.iter().enumerate() {
        let t = e.t.secs().map_err(|x| format!("{who}[{i}]: {x}"))?;
        if !(e.lat_deg.is_finite()
            && e.lon_deg.is_finite()
            && e.lat_deg.abs() <= 90.0
            && e.lon_deg.abs() <= 360.0)
        {
            return Err(format!("{who}[{i}]: position out of range"));
        }
        v.push(Tel {
            t,
            lat: e.lat_deg,
            lon: e.lon_deg,
            fix: e.fix_type,
            eph: e.eph_m.filter(|x| x.is_finite()),
            jam: e.jamming_state.is_some_and(|j| j >= 2),
            spoof: e.spoofing_state.is_some_and(|s| s >= 2),
        });
    }
    v.sort_by(|a, b| a.t.total_cmp(&b.t));
    Ok(v)
}

fn dist_km(a_lat: f64, a_lon: f64, b_lat: f64, b_lon: f64) -> f64 {
    let (la1, lo1, la2, lo2) = (
        a_lat.to_radians(),
        a_lon.to_radians(),
        b_lat.to_radians(),
        b_lon.to_radians(),
    );
    let h = ((la2 - la1) / 2.0).sin().powi(2)
        + la1.cos() * la2.cos() * ((lo2 - lo1) / 2.0).sin().powi(2);
    2.0 * 6371.0088 * h.sqrt().min(1.0).asin()
}

/// The telemetry checks and the degraded intervals of one flight.
#[derive(Clone, Debug, Default)]
struct Checks {
    epochs: usize,
    no3d: usize,
    longest_gap_s: f64,
    jam: usize,
    spoof: usize,
    jumps: usize,
    max_eph: Option<f64>,
    /// Intervals in which the flight was degraded (no 3-D fix, receiver flags, jumps).
    degraded: Vec<(f64, f64)>,
}

fn checks(tel: &[Tel], speed: f64) -> Checks {
    let mut c = Checks {
        epochs: tel.len(),
        ..Checks::default()
    };
    let vlim = 2.0 * speed + 10.0;
    let mut start: Option<f64> = None;
    let mut bad: Vec<(f64, f64)> = vec![];
    for (i, e) in tel.iter().enumerate() {
        if e.fix < 3 {
            c.no3d += 1;
            let s = *start.get_or_insert(e.t);
            c.longest_gap_s = c.longest_gap_s.max(e.t - s);
        } else if let Some(s) = start.take() {
            c.longest_gap_s = c.longest_gap_s.max(e.t - s);
            if e.t - s >= MIN_GAP_S {
                bad.push((s, e.t));
            }
        }
        if e.jam {
            c.jam += 1;
            bad.push((e.t, e.t));
        }
        if e.spoof {
            c.spoof += 1;
            bad.push((e.t, e.t));
        }
        if i > 0 {
            let p = &tel[i - 1];
            if p.fix >= 3 && e.fix >= 3 {
                let dt = (e.t - p.t).max(1e-3);
                if dist_km(p.lat, p.lon, e.lat, e.lon) * 1000.0 / dt > vlim {
                    c.jumps += 1;
                    bad.push((p.t, e.t));
                }
            }
        }
        if let Some(x) = e.eph {
            c.max_eph = Some(c.max_eph.map_or(x, |m: f64| m.max(x)));
        }
    }
    if let (Some(s), Some(l)) = (start, tel.last()) {
        if l.t - s >= MIN_GAP_S {
            bad.push((s, l.t));
        }
    }
    // Merge degraded intervals that touch within the overlap slack.
    bad.sort_by(|a, b| a.0.total_cmp(&b.0));
    for (s, e) in bad {
        match c.degraded.last_mut() {
            Some(last) if s <= last.1 + OVERLAP_S => last.1 = last.1.max(e),
            _ => c.degraded.push((s, e)),
        }
    }
    c
}

/// The subject's position near time `t` (the epoch closest in time, within [`NEAR_DT_S`]).
fn at(tel: &[Tel], t: f64) -> Option<(f64, f64)> {
    let i = tel.partition_point(|e| e.t < t);
    [i.checked_sub(1), Some(i)]
        .into_iter()
        .flatten()
        .filter_map(|k| tel.get(k))
        .filter(|e| (e.t - t).abs() <= NEAR_DT_S)
        .min_by(|a, b| (a.t - t).abs().total_cmp(&(b.t - t).abs()))
        .map(|e| (e.lat, e.lon))
}

// ------------------------------------------------------------------------------------------
// Attribution
// ------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Side {
    Area,
    Aircraft,
}

struct Finding {
    family: &'static str,
    side: Side,
    /// 1 weak, 2 moderate, 3 strong.
    strength: u8,
    text: String,
}

/// Compare the subject's degraded intervals with the other flights near it at the time.
fn neighbours(
    subj: &[Tel],
    deg: &[(f64, f64)],
    others: &[(Vec<Tel>, Checks)],
    f: &mut Vec<Finding>,
) -> (usize, usize) {
    let (mut near_total, mut shared_total) = (0usize, 0usize);
    for &(s, e) in deg {
        let (q0, q1) = (s - OVERLAP_S, e + OVERLAP_S);
        let (mut near, mut shared) = (0usize, 0usize);
        for (tel, ch) in others {
            let is_near = tel.iter().filter(|o| o.t >= q0 && o.t <= q1).any(|o| {
                at(subj, o.t).is_some_and(|(la, lo)| dist_km(la, lo, o.lat, o.lon) <= NEAR_KM)
            });
            if !is_near {
                continue;
            }
            near += 1;
            if ch.degraded.iter().any(|&(a, b)| a <= q1 && b >= q0) {
                shared += 1;
            }
        }
        near_total = near_total.max(near);
        shared_total = shared_total.max(shared);
    }
    if near_total == 0 {
        return (0, 0);
    }
    let frac = shared_total as f64 / near_total as f64;
    if shared_total >= 2 || (shared_total == 1 && near_total == 1) {
        f.push(Finding {
            family: "other_flights",
            side: Side::Area,
            strength: if shared_total >= 2 && frac >= 0.5 {
                3
            } else {
                2
            },
            text: format!(
                "{shared_total} of {near_total} other flights nearby were degraded at the same time"
            ),
        });
    } else if shared_total == 0 {
        f.push(Finding {
            family: "other_flights",
            side: Side::Aircraft,
            strength: if near_total >= 3 { 3 } else { 2 },
            text: format!(
                "{near_total} other flights nearby kept good positioning at the same time"
            ),
        });
    } else {
        f.push(Finding {
            family: "other_flights",
            side: Side::Aircraft,
            strength: 1,
            text: format!(
                "only {shared_total} of {near_total} other flights nearby were degraded at the same time"
            ),
        });
    }
    (near_total, shared_total)
}

fn regional(
    subj: &[Tel],
    deg: &[(f64, f64)],
    evs: &[ievents::Event],
    f: &mut Vec<Finding>,
) -> Result<bool, String> {
    let (Some(a0), Some(a1)) = (
        deg.iter().map(|d| d.0).reduce(f64::min),
        deg.iter().map(|d| d.1).reduce(f64::max),
    ) else {
        return Ok(false);
    };
    let (q0, q1) = (a0 - OVERLAP_S, a1 + OVERLAP_S);
    let mut hit = false;
    for (i, e) in evs.iter().enumerate() {
        let p = ievents::validate(e);
        if !p.is_empty() {
            return Err(format!("regional[{i}]: {}", p.join("; ")));
        }
        let (s, t) = (parse_iso(&e.start_utc)?, parse_iso(&e.end_utc)?);
        if t < q0 || s > q1 {
            continue;
        }
        if !e
            .systems
            .iter()
            .any(|x| matches!(x, ievents::System::Gnss { .. }))
        {
            continue;
        }
        if !matches!(
            e.kind,
            ievents::Kind::Spoofing
                | ievents::Kind::Meaconing
                | ievents::Kind::Jamming
                | ievents::Kind::Outage
        ) {
            continue;
        }
        let near = match &e.location {
            Some(l) => subj.iter().filter(|p| p.t >= q0 && p.t <= q1).any(|p| {
                dist_km(p.lat, p.lon, l.lat_deg, l.lon_deg) <= l.radius_m / 1000.0 + REG_REACH_KM
            }),
            None => e.area.as_deref().is_some_and(|a| !a.trim().is_empty()),
        };
        if near {
            hit = true;
        }
    }
    if hit {
        f.push(Finding {
            family: "regional_reports",
            side: Side::Area,
            strength: 2,
            text: "regional monitoring reported GNSS interference in the area at the time".into(),
        });
    } else {
        f.push(Finding {
            family: "regional_reports",
            side: Side::Aircraft,
            strength: 1,
            text: "regional monitoring covered the flight and reported no interference there"
                .into(),
        });
    }
    Ok(hit)
}

/// The flight's own signals: receiver flags point outward; jumps or fix loss without any flag
/// point weakly at the aircraft (equipment, integration, installation).
fn own_signals(c: &Checks, f: &mut Vec<Finding>) {
    if c.jam > 0 || c.spoof > 0 {
        f.push(Finding {
            family: "receiver_flags",
            side: Side::Area,
            strength: 1,
            text: format!(
                "the receiver flagged jamming in {} and spoofing in {} epochs",
                c.jam, c.spoof
            ),
        });
    } else if c.jumps > 0 || c.no3d > 0 {
        f.push(Finding {
            family: "receiver_flags",
            side: Side::Aircraft,
            strength: 1,
            text: "the flight degraded without any receiver jamming or spoofing flag".into(),
        });
    }
}

/// Combine the findings into the leading side and a confidence, capped by how many families
/// support it.
fn combine(f: &[Finding]) -> (Option<Side>, f64) {
    let score = |s: Side| -> f64 {
        f.iter()
            .filter(|x| x.side == s)
            .map(|x| match x.strength {
                3 => 2.2,
                2 => 1.3,
                _ => 0.5,
            })
            .sum()
    };
    let (a, b) = (score(Side::Area), score(Side::Aircraft));
    if a == 0.0 && b == 0.0 {
        return (None, 0.5);
    }
    let (side, d) = if a >= b {
        (Side::Area, a - b)
    } else {
        (Side::Aircraft, b - a)
    };
    let mut fams: Vec<&str> = f
        .iter()
        .filter(|x| x.side == side)
        .map(|x| x.family)
        .collect();
    fams.sort_unstable();
    fams.dedup();
    let cap = match fams.len() {
        0 | 1 => 0.75,
        2 => 0.9,
        _ => 0.95,
    };
    let p = (1.0 / (1.0 + (-1.6 * d).exp())).min(cap);
    (Some(side), (p * 20.0).floor() / 20.0)
}

/// The canonical SHA-256 of a JSON value (keys sorted, no whitespace).
fn canonical_sha256(v: &Value) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(v).unwrap_or_default().as_slice(),
    ))
}

/// Compare the client's attestation with the recomputed checks. Returns the mismatched fields.
fn compare(att: &Value, c: &Checks, statement: &str) -> Result<Vec<String>, String> {
    if att.get("format").and_then(Value::as_str) != Some("kshana-pro-utm-attestation/1") {
        return Err("attestation: format is not kshana-pro-utm-attestation/1".into());
    }
    let mut bad = vec![];
    let n = c.epochs.max(1) as f64;
    let int = |k: &str, want: usize, bad: &mut Vec<String>| {
        if att.get(k).and_then(Value::as_u64) != Some(want as u64) {
            bad.push(k.to_string());
        }
    };
    int("epochs", c.epochs, &mut bad);
    int("jamming_epochs", c.jam, &mut bad);
    int("spoofing_epochs", c.spoof, &mut bad);
    int("position_jumps", c.jumps, &mut bad);
    let close = |k: &str, want: f64, tol: f64, bad: &mut Vec<String>| {
        if !att
            .get(k)
            .and_then(Value::as_f64)
            .is_some_and(|x| (x - want).abs() <= tol)
        {
            bad.push(k.to_string());
        }
    };
    close("share_no_3d_fix", c.no3d as f64 / n, 1e-3, &mut bad);
    close("longest_gap_s", c.longest_gap_s, 0.11, &mut bad);
    // A client statement less severe than the recomputed one is a mismatch; a more severe one
    // (from checks this method does not repeat: map exposure, Remote ID, contingency) is not.
    let rank = |s: &str| match s {
        "NOMINAL" => 0,
        "DEGRADED" => 1,
        _ => 2,
    };
    let theirs = att.get("statement").and_then(Value::as_str).unwrap_or("");
    if rank(theirs) < rank(statement) {
        bad.push("statement".into());
    }
    Ok(bad)
}

// ------------------------------------------------------------------------------------------
// The method
// ------------------------------------------------------------------------------------------

/// Run the method; the raw (unrounded, unsigned) outcome.
pub fn analyse(r: &FlightRequest, l: &FlightLimits) -> Result<Value, String> {
    if r.telemetry.len() < 2 || r.telemetry.len() > l.max_epochs {
        return Err(format!("telemetry: 2 to {} epochs", l.max_epochs));
    }
    if r.others.len() > l.max_others {
        return Err(format!("at most {} other flights", l.max_others));
    }
    if r.others.iter().map(|o| o.telemetry.len()).sum::<usize>() > l.max_other_epochs {
        return Err(format!(
            "at most {} epochs over the other flights",
            l.max_other_epochs
        ));
    }
    if r.regional
        .as_ref()
        .is_some_and(|v| v.len() > l.max_regional)
    {
        return Err(format!("at most {} regional reports", l.max_regional));
    }
    let op = &r.operation;
    for (k, x) in [
        ("operation.speed_m_s", op.speed_m_s),
        ("operation.contingency_m", op.contingency_m),
        ("operation.dr_growth_m_per_s", op.dr_growth_m_per_s),
    ] {
        if !(x.is_finite() && x > 0.0) {
            return Err(format!("{k} must be a positive number"));
        }
    }
    let subj = parse(&r.telemetry, "telemetry")?;
    let (t0, t1) = (subj[0].t, subj[subj.len() - 1].t);
    if t1 - t0 > l.max_hours * 3600.0 {
        return Err(format!("the flight is longer than {} hours", l.max_hours));
    }
    let c = checks(&subj, op.speed_m_s);
    let gap_dr = op.dr_growth_m_per_s * c.longest_gap_s;
    let mut reasons = vec![];
    let mut suspect = false;
    if c.spoof > 0 {
        suspect = true;
        reasons.push(format!(
            "receiver spoofing state 2 or more in {} epochs",
            c.spoof
        ));
    }
    if c.jumps > 0 {
        suspect = true;
        reasons.push(format!(
            "{} position steps faster than {} m/s",
            c.jumps,
            2.0 * op.speed_m_s + 10.0
        ));
    }
    if gap_dr > op.contingency_m {
        suspect = true;
        reasons.push(
            "dead-reckoning error over the longest fix gap exceeds the contingency buffer".into(),
        );
    }
    let degraded = c.jam > 0 || c.no3d > 0;
    if !suspect && degraded {
        if c.jam > 0 {
            reasons.push(format!(
                "receiver jamming state 2 or more in {} epochs",
                c.jam
            ));
        }
        if c.no3d > 0 {
            reasons.push(format!("{} epochs without a 3-D fix", c.no3d));
        }
    }
    let statement = if suspect {
        "INTEGRITY-SUSPECT"
    } else if degraded {
        "DEGRADED"
    } else {
        "NOMINAL"
    };

    // Area context for a flight that was not nominal.
    let mut others = vec![];
    for (i, o) in r.others.iter().enumerate() {
        let tel = parse(&o.telemetry, &format!("others[{i}].telemetry"))?;
        if tel.is_empty() {
            continue;
        }
        let ch = checks(&tel, op.speed_m_s);
        others.push((tel, ch));
    }
    let distinct = {
        let mut ids: Vec<&str> = r.others.iter().map(|o| o.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    };
    let mut findings = vec![];
    let (mut near, mut shared, mut reg_hit) = (0, 0, false);
    if statement != "NOMINAL" {
        (near, shared) = neighbours(&subj, &c.degraded, &others, &mut findings);
        if let Some(evs) = &r.regional {
            reg_hit = regional(&subj, &c.degraded, evs, &mut findings)?;
        }
        own_signals(&c, &mut findings);
    }
    let (side, conf) = combine(&findings);
    let attribution = match (statement, side) {
        ("NOMINAL", _) => "not_applicable",
        (_, Some(s)) if conf >= DECIDE_AT => match s {
            Side::Area => "area",
            Side::Aircraft => "aircraft",
        },
        _ => "indeterminate",
    };
    let leading = side.map(|s| match s {
        Side::Area => "area",
        Side::Aircraft => "aircraft",
    });
    let reading = match attribution {
        "area" => "the degradation fits a cause shared by the area at the time (interference or a wide-area signal condition); the aircraft is not singled out",
        "aircraft" => "the degradation fits a cause specific to this aircraft (receiver, antenna, installation or integration); other traffic nearby was not affected",
        "indeterminate" => "the evidence supplied does not separate an area cause from an aircraft cause",
        _ => "the flight's positioning was nominal; no attribution is needed",
    };

    let attestation = match &r.attestation {
        Some(a) => {
            let bad = compare(a, &c, statement)?;
            json!({
                "sha256": canonical_sha256(a),
                "agrees": bad.is_empty(),
                "mismatched": bad,
                "statement": a.get("statement"),
            })
        }
        None => Value::Null,
    };
    let mut limits = vec![
        "Telemetry checks only: map exposure, Remote ID and the client's dead-reckoning model are the attestation's and are not repeated here.".to_string(),
    ];
    if r.others.is_empty() {
        limits.push("No other flights were supplied; an area cause cannot be told from an aircraft cause by traffic".into());
    } else if near == 0 && statement != "NOMINAL" {
        limits.push("No other flight was near the subject while it was degraded".into());
    }
    if r.regional.is_none() {
        limits.push("No regional interference reports were supplied".into());
    }
    Ok(json!({
        "method_version": METHOD_VERSION,
        "operation": op.id,
        "flight_utc": [iso(t0.floor() as i64), iso(t1.ceil() as i64)],
        "statement": statement,
        "reasons": reasons,
        "telemetry": {
            "epochs": c.epochs,
            "share_no_3d_fix": c.no3d as f64 / c.epochs as f64,
            "longest_gap_s": c.longest_gap_s,
            "gap_dr_error_m": gap_dr,
            "jamming_epochs": c.jam,
            "spoofing_epochs": c.spoof,
            "position_jumps": c.jumps,
            "max_eph_m": c.max_eph,
            "degraded_intervals": c.degraded.len(),
        },
        "attribution": attribution,
        "leading": if attribution == "indeterminate" { json!(leading) } else { Value::Null },
        "confidence": if statement == "NOMINAL" { Value::Null } else { json!(conf) },
        "reading": reading,
        "findings": findings.iter().map(|x| json!({
            "family": x.family,
            "supports": match x.side { Side::Area => "area", Side::Aircraft => "aircraft" },
            "text": x.text,
        })).collect::<Vec<_>>(),
        "context": {
            "other_flights": distinct,
            "other_flights_near": near,
            "other_flights_degraded_with_it": shared,
            "regional_reports": r.regional.as_ref().map(Vec::len),
            "regional_interference": match (&r.regional, reg_hit) {
                (None, _) => Value::Null,
                (Some(_), h) => json!(h),
            },
        },
        "attestation": attestation,
        "limits": limits,
        "decision_support": DECISION_SUPPORT,
    }))
}

/// Run the `flight-integrity` method and return a signed verdict. Not fingerprinted: a
/// statement, an attribution and a confidence in steps of 0.05.
pub fn flight_verdict(
    req: &FlightRequest,
    s: &crate::methods::Signing,
    limits: &FlightLimits,
    utc: &str,
) -> Result<crate::SignedVerdict, String> {
    let v = analyse(req, limits)?;
    crate::methods::finish("flight-integrity", v, s, utc)
}

#[cfg(test)]
#[path = "flight_integrity_tests.rs"]
mod tests;
