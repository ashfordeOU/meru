// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The `rtk-quality` method: how good is an RTK correction service, mountpoint by mountpoint,
//! judged from many monitoring receivers at once (research backlog E15, the hosted part)?
//!
//! A correction-service operator, a network reseller or a large user (a machine-control fleet,
//! a survey firm, an agricultural cooperative) runs monitoring receivers on surveyed marks, each
//! connected to one caster mountpoint, and logs their solutions. One monitor shows whether that
//! receiver got good fixes; many monitors over many mountpoints show whether the **service**
//! did, and why it did not when it did not. Per mountpoint this method returns:
//!
//! * fixed-solution availability with a 95 % (Wilson) interval;
//! * the **wrong-fix rate**: fixed solutions outside the caller's tolerance about the surveyed
//!   mark (or, for a monitor without a surveyed mark, about the median of its own fixed
//!   solutions: self-consistency), with a 95 % interval. A wrong fix is the dangerous failure: the
//!   receiver says "fixed" and is off by a wavelength or more;
//! * the 95th percentile horizontal and vertical error of the correct fixes, and how the
//!   horizontal error grows with baseline length (mm per km) when the monitors allow it;
//! * time to fix after a loss (median and 95th percentile) and correction age (95th percentile,
//!   share of epochs with stale corrections);
//! * the caller's targets, each `met`, `not_met` or `not_shown` (the interval straddles it).
//!
//! Across the network it finds **outage episodes** (no fixed solution for a while) and reads
//! their scope from which monitors shared them: one monitor (local: site, receiver, sky view or
//! its link), one mountpoint's monitors (the base, the caster or the network solution for that
//! mountpoint) or monitors on several mountpoints at once (a wide-area cause or a service-wide
//! outage), and whether corrections kept arriving fresh while it lasted (a signal-side cause)
//! or went stale (a feed or caster cause). The scope rules, the episode thresholds and the
//! per-monitor records stay in the service; what leaves is the outcome.
//!
//! Nothing here locates a transmitter or estimates where interference comes from; episodes are
//! read from the monitors' own solutions only. Evidence class MODELLED.

use crate::cause::Time;
use crate::server::iso;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

/// Method identifier written into every outcome. A change to any rule is a new version.
pub const METHOD_VERSION: &str = "rtk-quality/1";

/// Shortest stretch without a fixed solution counted as an outage episode, seconds.
const MIN_OUTAGE_S: f64 = 60.0;
/// A gap between epochs longer than this (and longer than five sample intervals) is missing
/// data, not a loss of fix.
const DATA_GAP_S: f64 = 30.0;
/// Share of a mountpoint's reporting monitors that must share an outage for it to be read as the
/// mountpoint's (at least two monitors).
const MOUNTPOINT_SHARE: f64 = 0.6;
/// Share of all reporting monitors, over at least two mountpoints, for a wide-area reading.
const WIDE_SHARE: f64 = 0.5;
/// Share of the affected monitors' epochs in an episode with stale corrections for the episode
/// to be read as stale.
const STALE_SHARE: f64 = 0.5;
/// Fewest monitors with distinct baselines for a baseline-growth estimate.
const MIN_FOR_PPM: usize = 3;

// ------------------------------------------------------------------------------------------
// Request
// ------------------------------------------------------------------------------------------

/// A time window.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub start_utc: Time,
    pub end_utc: Time,
}

/// A caster mountpoint: where its base (or the network's virtual base) is.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mountpoint {
    pub id: String,
    /// The base position (for a network mountpoint, the nominal or virtual base position).
    pub lat_deg: f64,
    pub lon_deg: f64,
    /// `single_base` or `network`; echoed.
    #[serde(default)]
    pub kind: Option<String>,
}

/// A monitoring receiver.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Monitor {
    pub id: String,
    /// The mountpoint it takes corrections from.
    pub mountpoint: String,
    pub lat_deg: f64,
    pub lon_deg: f64,
    /// True (default) when the errors are relative to a surveyed mark; false when the monitor
    /// has none and its errors are judged against the median of its own fixed solutions.
    #[serde(default = "yes")]
    pub surveyed: bool,
}

fn yes() -> bool {
    true
}

/// One monitor's solutions, column by column. `fix` holds one character per epoch: `F` fixed,
/// `f` float, `D` code differential, `S` standalone, `N` no solution.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Series {
    pub monitor: String,
    /// Time of the first epoch.
    pub t0: Time,
    /// Epoch times as seconds after `t0`, increasing.
    pub t_s: Vec<f64>,
    pub fix: String,
    /// East, north and up error about the surveyed mark, millimetres (absent where the receiver
    /// gave no solution: `null`).
    pub e_mm: Vec<Option<f64>>,
    pub n_mm: Vec<Option<f64>>,
    #[serde(default)]
    pub u_mm: Option<Vec<Option<f64>>>,
    /// Age of the corrections the solution used, seconds (`null` where not reported).
    #[serde(default)]
    pub age_s: Option<Vec<Option<f64>>>,
}

/// What counts as a correct fix and as stale corrections.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tolerance {
    /// Horizontal error above which a fixed solution is wrong, metres (default 0.10).
    #[serde(default = "d_h")]
    pub h_m: f64,
    /// Vertical error above which a fixed solution is wrong, metres (default 0.20).
    #[serde(default = "d_v")]
    pub v_m: f64,
    /// Correction age above which corrections are stale, seconds (default 10).
    #[serde(default = "d_age")]
    pub stale_age_s: f64,
}

fn d_h() -> f64 {
    0.10
}
fn d_v() -> f64 {
    0.20
}
fn d_age() -> f64 {
    10.0
}

impl Default for Tolerance {
    fn default() -> Self {
        Tolerance {
            h_m: d_h(),
            v_m: d_v(),
            stale_age_s: d_age(),
        }
    }
}

/// The service levels the caller wants checked (all optional).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    /// Lowest acceptable fixed-solution availability (0–1).
    #[serde(default)]
    pub min_fix_availability: Option<f64>,
    /// Highest acceptable wrong-fix rate among fixed solutions (0–1).
    #[serde(default)]
    pub max_wrong_fix_rate: Option<f64>,
    /// Highest acceptable 95th percentile horizontal error of correct fixes, metres.
    #[serde(default)]
    pub max_h95_m: Option<f64>,
    /// Highest acceptable 95th percentile time to fix after a loss, seconds.
    #[serde(default)]
    pub max_ttf95_s: Option<f64>,
}

/// Request for the `rtk-quality` method.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RtkQualityRequest {
    /// A label, echoed.
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub window: Option<Window>,
    #[serde(default)]
    pub tolerance: Tolerance,
    #[serde(default)]
    pub targets: Targets,
    pub mountpoints: Vec<Mountpoint>,
    pub monitors: Vec<Monitor>,
    pub series: Vec<Series>,
}

/// Request limits, checked before any work.
#[derive(Clone, Debug)]
pub struct RtkQualityLimits {
    pub max_mountpoints: usize,
    pub max_monitors: usize,
    /// Most epochs over all series.
    pub max_epochs: usize,
    /// Longest window, days.
    pub max_window_days: f64,
}

impl Default for RtkQualityLimits {
    fn default() -> Self {
        RtkQualityLimits {
            max_mountpoints: 1_000,
            max_monitors: 5_000,
            max_epochs: 2_000_000,
            max_window_days: 31.0,
        }
    }
}

// ------------------------------------------------------------------------------------------
// Statistics helpers
// ------------------------------------------------------------------------------------------

/// The 95 % Wilson score interval of `k` successes in `n` trials.
pub fn wilson95(k: usize, n: usize) -> (f64, f64) {
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

/// Nearest-rank percentile of unsorted values (`None` when empty).
fn pct(v: &[f64], p: f64) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    let mut s = v.to_vec();
    s.sort_by(f64::total_cmp);
    let k = ((p / 100.0) * s.len() as f64).ceil().max(1.0) as usize - 1;
    Some(s[k.min(s.len() - 1)])
}

fn median(v: &[f64]) -> Option<f64> {
    pct(v, 50.0)
}

/// Great-circle distance, kilometres.
fn dist_km(a: (f64, f64), b: (f64, f64)) -> f64 {
    let (la1, lo1, la2, lo2) = (
        a.0.to_radians(),
        a.1.to_radians(),
        b.0.to_radians(),
        b.1.to_radians(),
    );
    let h = ((la2 - la1) / 2.0).sin().powi(2)
        + la1.cos() * la2.cos() * ((lo2 - lo1) / 2.0).sin().powi(2);
    2.0 * 6371.0088 * h.sqrt().min(1.0).asin()
}

// ------------------------------------------------------------------------------------------
// Per-monitor analysis
// ------------------------------------------------------------------------------------------

/// One epoch after parsing.
#[derive(Clone, Copy, Debug)]
struct Ep {
    t: f64,
    fixed: bool,
    e: Option<f64>,
    n: Option<f64>,
    u: Option<f64>,
    age: Option<f64>,
}

/// What one monitor contributes.
#[derive(Clone, Debug, Default)]
struct MonStats {
    epochs: usize,
    fixed: usize,
    wrong: usize,
    h_ok: Vec<f64>,
    v_ok: Vec<f64>,
    ttf: Vec<f64>,
    ages: Vec<f64>,
    stale: usize,
    /// Outage intervals `[start, end]` (no fixed solution for at least [`MIN_OUTAGE_S`]).
    outages: Vec<(f64, f64)>,
    /// Epoch times with stale corrections (for episode reading).
    stale_t: Vec<f64>,
    /// Epoch times with a reported age (for episode reading).
    aged_t: Vec<f64>,
    first: f64,
    last: f64,
}

fn parse_series(s: &Series, win: Option<(f64, f64)>) -> Result<Vec<Ep>, String> {
    let n = s.t_s.len();
    let fix: Vec<char> = s.fix.chars().collect();
    let who = &s.monitor;
    if fix.len() != n || s.e_mm.len() != n || s.n_mm.len() != n {
        return Err(format!(
            "series '{who}': t_s, fix, e_mm and n_mm must have the same length"
        ));
    }
    if s.u_mm.as_ref().is_some_and(|u| u.len() != n)
        || s.age_s.as_ref().is_some_and(|a| a.len() != n)
    {
        return Err(format!(
            "series '{who}': u_mm and age_s must have the length of t_s"
        ));
    }
    let t0 = s.t0.secs().map_err(|e| format!("series '{who}' t0: {e}"))?;
    let mut out = Vec::with_capacity(n);
    let mut prev = f64::NEG_INFINITY;
    for i in 0..n {
        let dt = s.t_s[i];
        if !dt.is_finite() || dt <= prev {
            return Err(format!(
                "series '{who}': t_s must be finite and increasing (epoch {i})"
            ));
        }
        prev = dt;
        let fixed = match fix[i] {
            'F' => true,
            'f' | 'D' | 'S' | 'N' => false,
            c => {
                return Err(format!(
                    "series '{who}': fix code '{c}' at epoch {i} (expected F, f, D, S or N)"
                ))
            }
        };
        let fin = |x: Option<f64>| x.filter(|v| v.is_finite());
        let t = t0 + dt;
        if win.is_some_and(|(a, b)| t < a || t > b) {
            continue;
        }
        let age = s.age_s.as_ref().and_then(|a| fin(a[i]));
        if age.is_some_and(|a| a < 0.0) {
            return Err(format!("series '{who}': negative age_s at epoch {i}"));
        }
        out.push(Ep {
            t,
            fixed,
            e: fin(s.e_mm[i]),
            n: fin(s.n_mm[i]),
            u: s.u_mm.as_ref().and_then(|u| fin(u[i])),
            age,
        });
    }
    Ok(out)
}

fn analyse_monitor(eps: &[Ep], surveyed: bool, tol: &Tolerance) -> MonStats {
    let mut st = MonStats {
        epochs: eps.len(),
        first: eps.first().map(|e| e.t).unwrap_or(0.0),
        last: eps.last().map(|e| e.t).unwrap_or(0.0),
        ..MonStats::default()
    };
    // The reference: the surveyed mark (0, 0, 0), or the median of the monitor's own fixes.
    let (re, rn, ru) = if surveyed {
        (0.0, 0.0, 0.0)
    } else {
        let col = |f: fn(&Ep) -> Option<f64>| {
            let v: Vec<f64> = eps.iter().filter(|e| e.fixed).filter_map(f).collect();
            median(&v).unwrap_or(0.0)
        };
        (col(|e| e.e), col(|e| e.n), col(|e| e.u))
    };
    let (tol_h, tol_v) = (tol.h_m * 1000.0, tol.v_m * 1000.0);
    for e in eps {
        if let Some(a) = e.age {
            st.ages.push(a);
            st.aged_t.push(e.t);
            if a > tol.stale_age_s {
                st.stale += 1;
                st.stale_t.push(e.t);
            }
        }
        if !e.fixed {
            continue;
        }
        st.fixed += 1;
        let (Some(de), Some(dn)) = (e.e, e.n) else {
            continue;
        };
        let h = ((de - re).powi(2) + (dn - rn).powi(2)).sqrt();
        let v = e.u.map(|u| (u - ru).abs());
        if h > tol_h || v.is_some_and(|v| v > tol_v) {
            st.wrong += 1;
        } else {
            st.h_ok.push(h / 1000.0);
            if let Some(v) = v {
                st.v_ok.push(v / 1000.0);
            }
        }
    }
    // Losses of fix and outages. A data gap ends a stretch without counting as a loss.
    let gaps: Vec<f64> = eps.windows(2).map(|w| w[1].t - w[0].t).collect();
    let step = median(&gaps).unwrap_or(1.0);
    let gap_limit = DATA_GAP_S.max(5.0 * step);
    // Stretch without a fixed solution: (time of the last fix before, or the first epoch).
    let mut lost_at: Option<f64> = eps.first().filter(|e| !e.fixed).map(|e| e.t);
    let mut last_t = f64::NEG_INFINITY;
    let mut last_fix_t: Option<f64> = None;
    for e in eps {
        if e.t - last_t > gap_limit && last_t.is_finite() {
            // Missing data: close any open stretch at the last epoch seen, without a fix time.
            if let Some(s) = lost_at.take() {
                if last_t - s >= MIN_OUTAGE_S {
                    st.outages.push((s, last_t));
                }
            }
            if !e.fixed {
                lost_at = Some(e.t);
            }
        } else if !e.fixed && lost_at.is_none() {
            lost_at = Some(last_fix_t.unwrap_or(e.t));
        }
        if e.fixed {
            if let Some(s) = lost_at.take() {
                st.ttf.push(e.t - s);
                if e.t - s >= MIN_OUTAGE_S {
                    st.outages.push((s, e.t));
                }
            }
            last_fix_t = Some(e.t);
        }
        last_t = e.t;
    }
    if let Some(s) = lost_at {
        if last_t - s >= MIN_OUTAGE_S {
            st.outages.push((s, last_t));
        }
    }
    st
}

// ------------------------------------------------------------------------------------------
// Episodes across the network
// ------------------------------------------------------------------------------------------

/// One outage interval of one monitor.
struct Out<'a> {
    monitor: &'a str,
    mountpoint: &'a str,
    s: f64,
    e: f64,
}

/// Monitors with data covering `[s, e]` (at least partly), per mountpoint.
fn reporting<'a>(
    stats: &BTreeMap<&str, (&'a str, MonStats)>,
    s: f64,
    e: f64,
) -> HashMap<&'a str, usize> {
    let mut m = HashMap::new();
    for (mp, st) in stats.values() {
        if st.epochs > 0 && st.first <= e && st.last >= s {
            *m.entry(*mp).or_insert(0) += 1;
        }
    }
    m
}

fn episodes(stats: &BTreeMap<&str, (&str, MonStats)>) -> Vec<Value> {
    let mut outs: Vec<Out> = stats
        .iter()
        .flat_map(|(m, (mp, st))| {
            st.outages.iter().map(move |&(s, e)| Out {
                monitor: m,
                mountpoint: mp,
                s,
                e,
            })
        })
        .collect();
    outs.sort_by(|a, b| a.s.total_cmp(&b.s));
    // Cluster overlapping intervals into episodes.
    let mut clusters: Vec<Vec<&Out>> = vec![];
    let mut end = f64::NEG_INFINITY;
    for o in &outs {
        if o.s <= end && !clusters.is_empty() {
            clusters.last_mut().unwrap().push(o);
            end = end.max(o.e);
        } else {
            clusters.push(vec![o]);
            end = o.e;
        }
    }
    let mut res = vec![];
    for c in clusters {
        let s = c.iter().map(|o| o.s).fold(f64::INFINITY, f64::min);
        let e = c.iter().map(|o| o.e).fold(f64::NEG_INFINITY, f64::max);
        // The core: the time most monitors of the cluster were out together.
        let mut affected: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for o in &c {
            let v = affected.entry(o.mountpoint).or_default();
            if !v.contains(&o.monitor) {
                v.push(o.monitor);
            }
        }
        let n_aff: usize = affected.values().map(Vec::len).sum();
        let rep = reporting(stats, s, e);
        let n_rep: usize = rep.values().sum();
        let mp_shared: Vec<&str> = affected
            .iter()
            .filter(|(mp, mons)| {
                let r = rep.get(*mp).copied().unwrap_or(0).max(1);
                mons.len() >= 2 && mons.len() as f64 >= MOUNTPOINT_SHARE * r as f64
            })
            .map(|(mp, _)| *mp)
            .collect();
        let scope = if affected.len() >= 2 && n_aff as f64 >= WIDE_SHARE * n_rep.max(1) as f64 {
            "wide_area"
        } else if !mp_shared.is_empty() {
            "mountpoint"
        } else if n_aff == 1 {
            "monitor"
        } else {
            "several_monitors"
        };
        // Corrections during the episode, over the affected monitors.
        let (mut aged, mut stale) = (0usize, 0usize);
        for mons in affected.values() {
            for m in mons {
                let st = &stats[m].1;
                aged += st.aged_t.iter().filter(|t| **t >= s && **t <= e).count();
                stale += st.stale_t.iter().filter(|t| **t >= s && **t <= e).count();
            }
        }
        let corrections = if aged == 0 {
            "not_reported"
        } else if stale as f64 >= STALE_SHARE * aged as f64 {
            "stale"
        } else {
            "fresh"
        };
        let reading = match (scope, corrections) {
            ("monitor", _) => "local to one monitor: its site, receiver, sky view or link",
            ("several_monitors", _) => {
                "several monitors on different mountpoints without a shared pattern; read each as local"
            }
            ("mountpoint", "stale") => {
                "fits a caster, base-station or correction-feed problem on this mountpoint: corrections went stale"
            }
            ("mountpoint", "fresh") => {
                "fits a problem at or near the base or in the network solution for this mountpoint: corrections kept arriving"
            }
            ("mountpoint", _) => {
                "shared by this mountpoint's monitors; correction age not reported, so feed and signal causes are not separated"
            }
            (_, "stale") => "fits a caster-wide or network-wide service outage: corrections went stale",
            (_, "fresh") => {
                "fits a wide-area signal cause (ionospheric activity, wide-area interference) or a network processing fault: corrections kept arriving"
            }
            _ => "shared across mountpoints; correction age not reported, so feed and signal causes are not separated",
        };
        let mut mps: Vec<&str> = if scope == "mountpoint" {
            mp_shared.clone()
        } else {
            affected.keys().copied().collect()
        };
        mps.sort_unstable();
        res.push(json!({
            "start_utc": iso(s.floor() as i64),
            "end_utc": iso(e.ceil() as i64),
            "duration_s": (e - s).round(),
            "scope": scope,
            "mountpoints": mps,
            "monitors_affected": n_aff,
            "monitors_reporting": n_rep,
            "corrections": corrections,
            "reading": reading,
        }));
    }
    res
}

// ------------------------------------------------------------------------------------------
// Targets
// ------------------------------------------------------------------------------------------

/// A target checked against an interval: `met` when the interval is on the good side,
/// `not_met` when on the bad side, `not_shown` when it straddles the target.
fn check_min(interval: (f64, f64), target: f64) -> &'static str {
    if interval.0 >= target {
        "met"
    } else if interval.1 < target {
        "not_met"
    } else {
        "not_shown"
    }
}

fn check_max(interval: (f64, f64), target: f64) -> &'static str {
    if interval.1 <= target {
        "met"
    } else if interval.0 > target {
        "not_met"
    } else {
        "not_shown"
    }
}

fn check_point_max(x: Option<f64>, target: f64) -> &'static str {
    match x {
        None => "not_shown",
        Some(x) if x <= target => "met",
        Some(_) => "not_met",
    }
}

// ------------------------------------------------------------------------------------------
// The method
// ------------------------------------------------------------------------------------------

fn check_limits(r: &RtkQualityRequest, l: &RtkQualityLimits) -> Result<(), String> {
    if r.mountpoints.is_empty() || r.mountpoints.len() > l.max_mountpoints {
        return Err(format!("1 to {} mountpoints", l.max_mountpoints));
    }
    if r.monitors.is_empty() || r.monitors.len() > l.max_monitors {
        return Err(format!("1 to {} monitors", l.max_monitors));
    }
    let n: usize = r.series.iter().map(|s| s.t_s.len()).sum();
    if n > l.max_epochs {
        return Err(format!("more than {} epochs over all series", l.max_epochs));
    }
    let t = &r.tolerance;
    for (name, x) in [
        ("tolerance.h_m", t.h_m),
        ("tolerance.v_m", t.v_m),
        ("tolerance.stale_age_s", t.stale_age_s),
    ] {
        if !(x.is_finite() && x > 0.0) {
            return Err(format!("{name} must be a positive number"));
        }
    }
    for (name, x) in [
        (
            "targets.min_fix_availability",
            r.targets.min_fix_availability,
        ),
        ("targets.max_wrong_fix_rate", r.targets.max_wrong_fix_rate),
    ] {
        if x.is_some_and(|x| !(0.0..=1.0).contains(&x)) {
            return Err(format!("{name} must be within 0 to 1"));
        }
    }
    for (name, x) in [
        ("targets.max_h95_m", r.targets.max_h95_m),
        ("targets.max_ttf95_s", r.targets.max_ttf95_s),
    ] {
        if x.is_some_and(|x| !(x.is_finite() && x > 0.0)) {
            return Err(format!("{name} must be a positive number"));
        }
    }
    Ok(())
}

/// Run the method; the raw (unrounded, unsigned) outcome.
pub fn analyse(r: &RtkQualityRequest, l: &RtkQualityLimits) -> Result<Value, String> {
    check_limits(r, l)?;
    let win = match &r.window {
        Some(w) => {
            let (a, b) = (w.start_utc.secs()?, w.end_utc.secs()?);
            if b <= a || b - a > l.max_window_days * 86_400.0 {
                return Err(format!(
                    "window must end after it starts and span at most {} days",
                    l.max_window_days
                ));
            }
            Some((a, b))
        }
        None => None,
    };
    let mut mps: BTreeMap<&str, &Mountpoint> = BTreeMap::new();
    for m in &r.mountpoints {
        if !(m.lat_deg.abs() <= 90.0 && m.lon_deg.abs() <= 360.0) {
            return Err(format!("mountpoint '{}': position out of range", m.id));
        }
        if mps.insert(m.id.as_str(), m).is_some() {
            return Err(format!("mountpoint '{}' listed twice", m.id));
        }
    }
    let mut mons: BTreeMap<&str, &Monitor> = BTreeMap::new();
    for m in &r.monitors {
        if !mps.contains_key(m.mountpoint.as_str()) {
            return Err(format!(
                "monitor '{}': unknown mountpoint '{}'",
                m.id, m.mountpoint
            ));
        }
        if !(m.lat_deg.abs() <= 90.0 && m.lon_deg.abs() <= 360.0) {
            return Err(format!("monitor '{}': position out of range", m.id));
        }
        if mons.insert(m.id.as_str(), m).is_some() {
            return Err(format!("monitor '{}' listed twice", m.id));
        }
    }
    let mut stats: BTreeMap<&str, (&str, MonStats)> = BTreeMap::new();
    for s in &r.series {
        let Some(m) = mons.get(s.monitor.as_str()) else {
            return Err(format!("series for unknown monitor '{}'", s.monitor));
        };
        if stats.contains_key(s.monitor.as_str()) {
            return Err(format!("two series for monitor '{}'", s.monitor));
        }
        let eps = parse_series(s, win)?;
        stats.insert(
            m.id.as_str(),
            (
                m.mountpoint.as_str(),
                analyse_monitor(&eps, m.surveyed, &r.tolerance),
            ),
        );
    }
    if stats.values().all(|(_, s)| s.epochs == 0) {
        return Err("no epochs in the window".into());
    }

    // Per mountpoint.
    let tg = &r.targets;
    let mut rows = vec![];
    let (mut tot_e, mut tot_f, mut tot_w) = (0usize, 0usize, 0usize);
    for (id, mp) in &mps {
        let mine: Vec<(&str, &MonStats)> = stats
            .iter()
            .filter(|(_, (m, _))| m == id)
            .map(|(k, (_, s))| (*k, s))
            .collect();
        let epochs: usize = mine.iter().map(|(_, s)| s.epochs).sum();
        let fixed: usize = mine.iter().map(|(_, s)| s.fixed).sum();
        let wrong: usize = mine.iter().map(|(_, s)| s.wrong).sum();
        let stale: usize = mine.iter().map(|(_, s)| s.stale).sum();
        let cat = |f: fn(&MonStats) -> &Vec<f64>| -> Vec<f64> {
            mine.iter()
                .flat_map(|(_, s)| f(s).iter().copied())
                .collect()
        };
        let (h, v, ttf, ages) = (
            cat(|s| &s.h_ok),
            cat(|s| &s.v_ok),
            cat(|s| &s.ttf),
            cat(|s| &s.ages),
        );
        tot_e += epochs;
        tot_f += fixed;
        tot_w += wrong;
        let avail = wilson95(fixed, epochs);
        let wrong_i = wilson95(wrong, fixed);
        let h95 = pct(&h, 95.0);
        let ttf95 = pct(&ttf, 95.0);
        // Baselines and the growth of horizontal error with them.
        let base = (mp.lat_deg, mp.lon_deg);
        let pts: Vec<(f64, f64)> = mine
            .iter()
            .filter_map(|(m, s)| {
                let mon = mons[m];
                let b = dist_km(base, (mon.lat_deg, mon.lon_deg));
                pct(&s.h_ok, 95.0).map(|x| (b, x * 1000.0))
            })
            .collect();
        let baselines: Vec<f64> = mine
            .iter()
            .map(|(m, _)| dist_km(base, (mons[m].lat_deg, mons[m].lon_deg)))
            .collect();
        let ppm = growth(&pts);
        let mut targets = serde_json::Map::new();
        if let Some(t) = tg.min_fix_availability {
            targets.insert("min_fix_availability".into(), json!(check_min(avail, t)));
        }
        if let Some(t) = tg.max_wrong_fix_rate {
            let st = if fixed == 0 {
                "not_shown"
            } else {
                check_max(wrong_i, t)
            };
            targets.insert("max_wrong_fix_rate".into(), json!(st));
        }
        if let Some(t) = tg.max_h95_m {
            targets.insert("max_h95_m".into(), json!(check_point_max(h95, t)));
        }
        if let Some(t) = tg.max_ttf95_s {
            targets.insert("max_ttf95_s".into(), json!(check_point_max(ttf95, t)));
        }
        rows.push(json!({
            "id": id,
            "kind": mp.kind,
            "monitors": mine.len(),
            "self_consistency_monitors": mine.iter().filter(|(m, _)| !mons[m].surveyed).count(),
            "epochs": epochs,
            "fix_availability": if epochs > 0 { json!(fixed as f64 / epochs as f64) } else { Value::Null },
            "fix_availability_95": if epochs > 0 { json!([avail.0, avail.1]) } else { Value::Null },
            "fixed_epochs": fixed,
            "wrong_fixes": wrong,
            "wrong_fix_rate": if fixed > 0 { json!(wrong as f64 / fixed as f64) } else { Value::Null },
            "wrong_fix_rate_95": if fixed > 0 { json!([wrong_i.0, wrong_i.1]) } else { Value::Null },
            "h95_m": h95,
            "v95_m": pct(&v, 95.0),
            "h_growth_mm_per_km": ppm,
            "baseline_km": if baselines.is_empty() { Value::Null } else {
                json!([baselines.iter().copied().fold(f64::INFINITY, f64::min), baselines.iter().copied().fold(0.0, f64::max)])
            },
            "fix_acquisitions": ttf.len(),
            "ttf50_s": median(&ttf),
            "ttf95_s": ttf95,
            "correction_age95_s": pct(&ages, 95.0),
            "stale_share": if ages.is_empty() { Value::Null } else { json!(stale as f64 / ages.len() as f64) },
            "targets": targets,
        }));
    }
    let eps = episodes(&stats);
    let count = |s: &str| eps.iter().filter(|e| e["scope"] == s).count();
    let net_wrong = wilson95(tot_w, tot_f);
    // The mountpoints most in need of attention: highest upper bound on the wrong-fix rate.
    let mut worst: Vec<(f64, &str)> = rows
        .iter()
        .filter_map(|r| Some((r["wrong_fix_rate_95"].get(1)?.as_f64()?, r["id"].as_str()?)))
        .collect();
    worst.sort_by(|a, b| b.0.total_cmp(&a.0));
    Ok(json!({
        "method_version": METHOD_VERSION,
        "subject": r.subject,
        "tolerance": {"h_m": r.tolerance.h_m, "v_m": r.tolerance.v_m, "stale_age_s": r.tolerance.stale_age_s},
        "network": {
            "mountpoints": mps.len(),
            "monitors": stats.len(),
            "epochs": tot_e,
            "fix_availability": if tot_e > 0 { json!(tot_f as f64 / tot_e as f64) } else { Value::Null },
            "wrong_fixes": tot_w,
            "wrong_fix_rate_95": [net_wrong.0, net_wrong.1],
            "episodes": {
                "monitor": count("monitor"),
                "several_monitors": count("several_monitors"),
                "mountpoint": count("mountpoint"),
                "wide_area": count("wide_area"),
            },
            "highest_wrong_fix_bound": worst.iter().take(5).map(|w| w.1).collect::<Vec<_>>(),
        },
        "mountpoints": rows,
        "episodes": eps,
        "limits": [
            "Judged from the monitors' own solutions; a wrong fix is a fixed solution outside the stated tolerance about the surveyed mark, or about the median of the monitor's own fixed solutions where it has no mark (self-consistency, which cannot see a constant offset).",
            "Episode scopes are readings of which monitors shared an outage and whether corrections stayed fresh; they do not locate any transmitter or interference source.",
            "Targets are checked against 95 % intervals where the statistic has one; not_shown means the data cannot separate the result from the target.",
        ],
        "evidence": "MODELLED: checked on synthetic networks with known faults; not validated against an operator's incident records.",
    }))
}

/// Least-squares slope of h95 (mm) against baseline (km), when enough distinct baselines.
fn growth(pts: &[(f64, f64)]) -> Option<f64> {
    if pts.len() < MIN_FOR_PPM {
        return None;
    }
    let n = pts.len() as f64;
    let (mx, my) = (
        pts.iter().map(|p| p.0).sum::<f64>() / n,
        pts.iter().map(|p| p.1).sum::<f64>() / n,
    );
    let sxx: f64 = pts.iter().map(|p| (p.0 - mx).powi(2)).sum();
    if sxx < 1.0 {
        return None;
    }
    let sxy: f64 = pts.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum();
    Some(sxy / sxx)
}

/// Run the `rtk-quality` method and return a signed verdict. Not fingerprinted: the numbers are
/// statistics of the caller's own monitors, and the episode readings are classifications.
pub fn rtk_quality_verdict(
    req: &RtkQualityRequest,
    s: &crate::methods::Signing,
    limits: &RtkQualityLimits,
    utc: &str,
) -> Result<crate::SignedVerdict, String> {
    let v = analyse(req, limits)?;
    crate::methods::finish("rtk-quality", v, s, utc)
}

#[cfg(test)]
#[path = "rtk_quality_tests.rs"]
mod tests;
