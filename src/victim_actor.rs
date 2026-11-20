// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The `victim-actor` method: was a vessel's AIS position the victim of external interference,
//! or does the evidence fit manipulation of the vessel's own reports?
//!
//! A sanctions screen, an insurer or a coastal state holds the AIS track of one vessel (the
//! subject) that misbehaved. Taken alone, the track cannot answer the question: a spoofed
//! receiver and a falsified transponder both produce false positions. This method weighs the
//! subject's track against the tracks of the other vessels in the same area at the same time
//! (interference rarely singles out one ship; a falsified track does), against independent
//! confirmations of where the subject really was (SAR or optical imagery, radar, RF location of
//! its own transmissions, all supplied by the caller), and against regional interference
//! reports (`kshana-pnt-interference-event/1`).
//!
//! Lines of evidence (families): the subject's own track (abrupt capture-like jumps and circles,
//! a track too regular to come from a GNSS receiver, silences while nearby vessels kept
//! reporting), the neighbours (the same anomaly at the same time, the same false position, or an
//! unaffected neighbourhood), the independent confirmations (the reported track false while
//! smooth and plausible, or false while it showed capture-like anomalies) and the regional
//! reports. Each finding supports `victim` or `actor` with a strength; the findings combine into
//! a probability for the leading side, capped by how many families support it, and the answer is
//! `indeterminate` below the decision level.
//!
//! What leaves the service is the outcome: the classification, a confidence in steps of 0.05,
//! a leave-one-family-out confidence interval, the episode window, outcome-level findings and
//! the limits. Weights, thresholds and scores stay here. An engineering reconstruction of the
//! data supplied, not a legal finding; intent is not assessed.

use crate::cause::Time;
use crate::server::iso;
use kshana_pro::ievents;
use serde::Deserialize;
use serde_json::{json, Value};

/// Method identifier written into every outcome. A change to any rule is a new version.
pub const METHOD_VERSION: &str = "victim-actor/1";

/// Lowest confidence at which a side is named.
const DECIDE_AT: f64 = 0.7;

// ------------------------------------------------------------------------------------------
// Request
// ------------------------------------------------------------------------------------------

/// One AIS position report.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub t: Time,
    pub lat_deg: f64,
    pub lon_deg: f64,
    /// Reported speed over ground (knots). Accepted so that a `cause` track can be sent as is;
    /// version 1 judges positions only.
    #[serde(default)]
    pub sog_kn: Option<f64>,
}

/// Another vessel's AIS track in the same area and time.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Neighbour {
    /// The neighbour's identifier (used only to count distinct vessels; not returned).
    #[serde(default)]
    pub id: String,
    pub reported: Vec<Report>,
}

/// Where an independent confirmation of the subject's position comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObsSource {
    /// Satellite SAR detection.
    Sar,
    /// Optical or infrared imagery detection.
    Optical,
    /// Shipborne or airborne radar.
    Radar,
    /// Coastal surveillance radar.
    CoastalRadar,
    /// The location of the subject's own transmissions, determined by the caller's RF system.
    Rf,
    /// Any other position source independent of the subject's GNSS.
    Other,
}

impl ObsSource {
    fn name(self) -> &'static str {
        match self {
            ObsSource::Sar => "sar",
            ObsSource::Optical => "optical",
            ObsSource::Radar => "radar",
            ObsSource::CoastalRadar => "coastal_radar",
            ObsSource::Rf => "rf",
            ObsSource::Other => "other",
        }
    }

    fn default_sigma_m(self) -> f64 {
        match self {
            ObsSource::Sar => 150.0,
            ObsSource::Optical => 100.0,
            ObsSource::Radar => 300.0,
            ObsSource::CoastalRadar => 150.0,
            ObsSource::Rf => 5000.0,
            ObsSource::Other => 1000.0,
        }
    }
}

/// One independent confirmation of where the subject was.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub source: ObsSource,
    /// A label (scene, station, pass); echoed in findings.
    #[serde(default)]
    pub id: String,
    pub t: Time,
    pub lat_deg: f64,
    pub lon_deg: f64,
    /// One-sigma position uncertainty (metres); default by source.
    #[serde(default)]
    pub sigma_m: Option<f64>,
}

/// The time window to analyse.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub start_utc: Time,
    pub end_utc: Time,
}

/// Request for the `victim-actor` method.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VictimActorRequest {
    /// The subject's identifier (MMSI, IMO); echoed, not used.
    #[serde(default)]
    pub subject_id: String,
    /// Window to analyse; default: the extent of the subject's track.
    #[serde(default)]
    pub window: Option<Window>,
    /// The subject's AIS track.
    pub reported: Vec<Report>,
    /// Other vessels' AIS tracks in the same area and time.
    #[serde(default)]
    pub neighbours: Vec<Neighbour>,
    /// Independent confirmations of the subject's position.
    #[serde(default)]
    pub observations: Vec<Observation>,
    /// Regional interference reports. Supplying the list (even empty) states that regional
    /// monitoring covered the window.
    #[serde(default)]
    pub regional: Option<Vec<ievents::Event>>,
}

/// Size limits, checked before any work starts.
#[derive(Clone, Debug)]
pub struct VictimActorLimits {
    /// Most subject positions.
    pub max_track_points: usize,
    /// Most neighbour tracks.
    pub max_neighbours: usize,
    /// Most neighbour positions in total.
    pub max_neighbour_points: usize,
    /// Most observations.
    pub max_observations: usize,
    /// Most regional reports.
    pub max_events: usize,
    /// Longest window (seconds).
    pub max_window_s: f64,
}

impl Default for VictimActorLimits {
    fn default() -> Self {
        VictimActorLimits {
            max_track_points: 20_000,
            max_neighbours: 200,
            max_neighbour_points: 200_000,
            max_observations: 1_000,
            max_events: 500,
            max_window_s: 7.0 * 86_400.0,
        }
    }
}

/// Check the request's sizes.
pub fn check_limits(req: &VictimActorRequest, lim: &VictimActorLimits) -> Result<(), String> {
    if req.reported.len() > lim.max_track_points {
        return Err(format!(
            "too many reported positions: at most {}",
            lim.max_track_points
        ));
    }
    if req.neighbours.len() > lim.max_neighbours {
        return Err(format!(
            "too many neighbour tracks: at most {}",
            lim.max_neighbours
        ));
    }
    let n: usize = req.neighbours.iter().map(|x| x.reported.len()).sum();
    if n > lim.max_neighbour_points {
        return Err(format!(
            "too many neighbour positions: at most {} in total",
            lim.max_neighbour_points
        ));
    }
    if req.observations.len() > lim.max_observations {
        return Err(format!(
            "too many observations: at most {}",
            lim.max_observations
        ));
    }
    if req
        .regional
        .as_ref()
        .is_some_and(|r| r.len() > lim.max_events)
    {
        return Err(format!(
            "too many regional interference reports: at most {}",
            lim.max_events
        ));
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------
// Internals (never returned)
// ------------------------------------------------------------------------------------------

const VMAX_KN: f64 = 50.0;
const JUMP_MIN_KM: f64 = 1.0;
const JUMP_MAX_DT_S: f64 = 3600.0;
const EPISODE_GAP_S: f64 = 1800.0;
const CIRCLE_WINDOW: usize = 20;
const CIRCLE_STRIDE: usize = 10;
const CIRCLE_R_KM: (f64, f64) = (0.5, 20.0);
const CIRCLE_MAX_CV: f64 = 0.15;
const CIRCLE_MAX_STEP_DEG: f64 = 90.0;
const CIRCLE_MIN_WIND_DEG: f64 = 270.0;
const CIRCLE_MIN_KN: f64 = 2.0;
const NEAR_KM: f64 = 100.0;
const NEAR_DT_S: f64 = 1800.0;
const OVERLAP_S: f64 = 900.0;
const MIN_NEARBY: usize = 3;
const AFFECTED_SHARE: f64 = 0.2;
const CONVERGE_KM: f64 = 0.2;
const CONVERGE_DT_S: f64 = 600.0;
const REG_SPAN_S: f64 = 1800.0;
const REG_MIN_REPORTS: usize = 20;
const REG_MAX_RMS_M: f64 = 0.5;
const REG_MIN_MOVE_KM: f64 = 2.0;
const GAP_S: f64 = 1800.0;
const GAP_NEAR_KM: f64 = 50.0;
const GAP_MIN_NEIGHBOUR_REPORTS: usize = 3;
const OBS_MAX_GAP_S: f64 = 900.0;
const OBS_MIN_KM: f64 = 1.0;
const OBS_SIGMAS: f64 = 5.0;
const REG_REACH_KM: f64 = 50.0;

#[derive(Clone, Copy, Debug)]
struct Pt {
    t: f64,
    lat: f64,
    lon: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Strength {
    Weak,
    Moderate,
    Strong,
}

impl Strength {
    fn w(self) -> f64 {
        match self {
            Strength::Weak => 0.7,
            Strength::Moderate => 1.4,
            Strength::Strong => 2.4,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Strength::Weak => "weak",
            Strength::Moderate => "moderate",
            Strength::Strong => "strong",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Family {
    Track,
    Neighbours,
    Independent,
    Regional,
}

impl Family {
    fn name(self) -> &'static str {
        match self {
            Family::Track => "subject_track",
            Family::Neighbours => "nearby_vessels",
            Family::Independent => "independent_observations",
            Family::Regional => "regional_reports",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Victim,
    Actor,
}

impl Side {
    fn name(self) -> &'static str {
        match self {
            Side::Victim => "victim",
            Side::Actor => "actor",
        }
    }
    fn sign(self) -> f64 {
        match self {
            Side::Victim => 1.0,
            Side::Actor => -1.0,
        }
    }
}

struct Finding {
    family: Family,
    /// `None`: context that says what happened but favours neither side.
    side: Option<Side>,
    strength: Strength,
    text: String,
    from: f64,
    to: f64,
    observed: Vec<(&'static str, f64)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Jump,
    Circle,
}

#[derive(Clone, Copy, Debug)]
struct Anomaly {
    kind: Kind,
    from: f64,
    to: f64,
    /// The last report before the anomaly.
    anchor: (f64, f64),
    /// The largest jump (km) or the circle radius (km).
    size_km: f64,
}

fn dist_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = 6371.0088;
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dp = p2 - p1;
    let dl = (lon2 - lon1).to_radians();
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * r * a.sqrt().min(1.0).asin()
}

fn wrap180(x: f64) -> f64 {
    let y = (x + 180.0).rem_euclid(360.0) - 180.0;
    if y == -180.0 {
        180.0
    } else {
        y
    }
}

fn points(reps: &[Report], what: &str) -> Result<Vec<Pt>, String> {
    let mut v = Vec::with_capacity(reps.len());
    for (i, r) in reps.iter().enumerate() {
        let t = r.t.secs().map_err(|e| format!("{what}[{i}]: {e}"))?;
        if !r.lat_deg.is_finite()
            || !r.lon_deg.is_finite()
            || r.lat_deg.abs() > 90.0
            || r.lon_deg.abs() > 180.0
        {
            return Err(format!("{what}[{i}]: position out of range"));
        }
        v.push(Pt {
            t,
            lat: r.lat_deg,
            lon: r.lon_deg,
        });
    }
    v.sort_by(|a, b| a.t.total_cmp(&b.t));
    Ok(v)
}

fn plausible(a: &Pt, b: &Pt) -> bool {
    let dt = b.t - a.t;
    if dt > JUMP_MAX_DT_S {
        return true;
    }
    let d = dist_km(a.lat, a.lon, b.lat, b.lon);
    d < JUMP_MIN_KM || d / 1.852 / (dt.max(1.0) / 3600.0) <= VMAX_KN
}

fn circle(w: &[Pt]) -> Option<f64> {
    if w.windows(2).any(|q| q[1].t - q[0].t > EPISODE_GAP_S) {
        return None;
    }
    let n = w.len() as f64;
    let lat0 = w.iter().map(|p| p.lat).sum::<f64>() / n;
    let lon0 = w.iter().map(|p| p.lon).sum::<f64>() / n;
    let km_deg = 6371.0088 * std::f64::consts::PI / 180.0;
    let k = lat0.to_radians().cos();
    let xy: Vec<(f64, f64)> = w
        .iter()
        .map(|p| (wrap180(p.lon - lon0) * k * km_deg, (p.lat - lat0) * km_deg))
        .collect();
    let radii: Vec<f64> = xy.iter().map(|(x, y)| x.hypot(*y)).collect();
    let r = radii.iter().sum::<f64>() / n;
    if !(CIRCLE_R_KM.0..=CIRCLE_R_KM.1).contains(&r) {
        return None;
    }
    let sd = (radii.iter().map(|x| (x - r).powi(2)).sum::<f64>() / n).sqrt();
    if sd / r > CIRCLE_MAX_CV {
        return None;
    }
    let (mut net, mut abs, mut max_step) = (0.0f64, 0.0f64, 0.0f64);
    for q in xy.windows(2) {
        let d = wrap180((q[1].1.atan2(q[1].0) - q[0].1.atan2(q[0].0)).to_degrees());
        net += d;
        abs += d.abs();
        max_step = max_step.max(d.abs());
    }
    if max_step > CIRCLE_MAX_STEP_DEG || net.abs() < CIRCLE_MIN_WIND_DEG || net.abs() < 0.8 * abs {
        return None;
    }
    let path: f64 = w
        .windows(2)
        .map(|q| dist_km(q[0].lat, q[0].lon, q[1].lat, q[1].lon))
        .sum();
    let kn = path / 1.852 / ((w[w.len() - 1].t - w[0].t).max(1.0) / 3600.0);
    (kn >= CIRCLE_MIN_KN).then_some(r)
}

/// Capture-like anomalies of one track: jumps and circles, merged into episodes.
fn anomalies(tr: &[Pt]) -> Vec<Anomaly> {
    let mut raw: Vec<Anomaly> = Vec::new();
    for q in tr.windows(2) {
        if !plausible(&q[0], &q[1]) {
            raw.push(Anomaly {
                kind: Kind::Jump,
                from: q[1].t,
                to: q[1].t,
                anchor: (q[0].lat, q[0].lon),
                size_km: dist_km(q[0].lat, q[0].lon, q[1].lat, q[1].lon),
            });
        }
    }
    if tr.len() >= CIRCLE_WINDOW {
        let mut s = 0;
        while s + CIRCLE_WINDOW <= tr.len() {
            let w = &tr[s..s + CIRCLE_WINDOW];
            if let Some(r) = circle(w) {
                let a = if s > 0 { tr[s - 1] } else { tr[s] };
                raw.push(Anomaly {
                    kind: Kind::Circle,
                    from: w[0].t,
                    to: w[w.len() - 1].t,
                    anchor: (a.lat, a.lon),
                    size_km: r,
                });
            }
            s += CIRCLE_STRIDE;
        }
    }
    raw.sort_by(|a, b| a.from.total_cmp(&b.from));
    let mut out: Vec<Anomaly> = Vec::new();
    for a in raw {
        match out.last_mut() {
            Some(l) if l.kind == a.kind && a.from - l.to <= EPISODE_GAP_S => {
                l.to = l.to.max(a.to);
                l.size_km = l.size_km.max(a.size_km);
            }
            _ => out.push(a),
        }
    }
    out
}

fn span(it: impl Iterator<Item = (f64, f64)>) -> Option<(f64, f64)> {
    it.fold(None, |acc, (a, b)| match acc {
        None => Some((a, b)),
        Some((x, y)) => Some((x.min(a), y.max(b))),
    })
}

/// Position on a track at `t`, linear between reports no more than `max_gap` apart.
fn interp(tr: &[Pt], t: f64, max_gap: f64) -> Option<(f64, f64)> {
    let i = tr.partition_point(|p| p.t <= t);
    if i == 0 || i >= tr.len() {
        // At the ends: the nearest report when it is within a quarter of the gap.
        let p = if i == 0 { tr.first()? } else { tr.last()? };
        return ((p.t - t).abs() <= max_gap / 4.0).then_some((p.lat, p.lon));
    }
    let (a, b) = (&tr[i - 1], &tr[i]);
    if b.t - a.t > max_gap {
        return None;
    }
    let f = if b.t > a.t {
        (t - a.t) / (b.t - a.t)
    } else {
        0.0
    };
    Some((
        a.lat + f * (b.lat - a.lat),
        wrap180(a.lon + f * wrap180(b.lon - a.lon)),
    ))
}

/// The RMS (metres) of a straight constant-velocity line fitted to a window, in a local plane.
fn line_rms_m(w: &[Pt]) -> f64 {
    let n = w.len() as f64;
    let (lat0, lon0, t0) = (w[0].lat, w[0].lon, w[0].t);
    let k = lat0.to_radians().cos();
    let m = 6_371_008.8 * std::f64::consts::PI / 180.0;
    let pts: Vec<(f64, f64, f64)> = w
        .iter()
        .map(|p| (p.t - t0, wrap180(p.lon - lon0) * k * m, (p.lat - lat0) * m))
        .collect();
    let mt = pts.iter().map(|p| p.0).sum::<f64>() / n;
    let stt: f64 = pts.iter().map(|p| (p.0 - mt).powi(2)).sum();
    let mut ss = 0.0;
    for c in [1usize, 2] {
        let get = |p: &(f64, f64, f64)| if c == 1 { p.1 } else { p.2 };
        let my = pts.iter().map(get).sum::<f64>() / n;
        let sty: f64 = pts.iter().map(|p| (p.0 - mt) * (get(p) - my)).sum();
        let b = if stt > 0.0 { sty / stt } else { 0.0 };
        ss += pts
            .iter()
            .map(|p| (get(p) - my - b * (p.0 - mt)).powi(2))
            .sum::<f64>();
    }
    (ss / n).sqrt()
}

struct Ctx {
    subj: Vec<Pt>,
    neigh: Vec<(String, Vec<Pt>)>,
    w0: f64,
    w1: f64,
}

/// Run the method and return the outcome (uncoarsened, unsigned).
pub fn analyse(req: &VictimActorRequest, lim: &VictimActorLimits) -> Result<Value, String> {
    check_limits(req, lim)?;
    let all = points(&req.reported, "reported")?;
    if all.len() < 3 {
        return Err("reported: at least three positions are needed".into());
    }
    let (w0, w1) = match &req.window {
        Some(w) => (w.start_utc.secs()?, w.end_utc.secs()?),
        None => (all[0].t, all[all.len() - 1].t),
    };
    if w1 <= w0 {
        return Err("window: end must be after start".into());
    }
    if w1 - w0 > lim.max_window_s {
        return Err(format!(
            "window too long: at most {:.0} days",
            lim.max_window_s / 86_400.0
        ));
    }
    let subj: Vec<Pt> = all.into_iter().filter(|p| p.t >= w0 && p.t <= w1).collect();
    if subj.len() < 3 {
        return Err("reported: fewer than three positions inside the window".into());
    }
    let mut neigh = Vec::new();
    for (i, n) in req.neighbours.iter().enumerate() {
        let pts: Vec<Pt> = points(&n.reported, &format!("neighbours[{i}].reported"))?
            .into_iter()
            .filter(|p| p.t >= w0 - NEAR_DT_S && p.t <= w1 + NEAR_DT_S)
            .collect();
        let id = if n.id.trim().is_empty() {
            format!("#{i}")
        } else {
            n.id.trim().to_string()
        };
        neigh.push((id, pts));
    }
    let mut obs = Vec::new();
    for (i, o) in req.observations.iter().enumerate() {
        let t = o.t.secs().map_err(|e| format!("observations[{i}]: {e}"))?;
        if !o.lat_deg.is_finite()
            || !o.lon_deg.is_finite()
            || o.lat_deg.abs() > 90.0
            || o.lon_deg.abs() > 180.0
        {
            return Err(format!("observations[{i}]: position out of range"));
        }
        let sigma = match o.sigma_m {
            Some(s) if s.is_finite() && s > 0.0 => s,
            Some(_) => return Err(format!("observations[{i}].sigma_m must be positive")),
            None => o.source.default_sigma_m(),
        };
        if t >= w0 && t <= w1 {
            obs.push((o, t, sigma));
        }
    }
    let c = Ctx {
        subj,
        neigh,
        w0,
        w1,
    };
    let mut f: Vec<Finding> = Vec::new();

    // 1. The subject's own track.
    let anom = anomalies(&c.subj);
    let anom_span = span(anom.iter().map(|a| (a.from, a.to)));
    for k in [Kind::Jump, Kind::Circle] {
        let a: Vec<&Anomaly> = anom.iter().filter(|a| a.kind == k).collect();
        if a.is_empty() {
            continue;
        }
        let (s0, s1) = span(a.iter().map(|x| (x.from, x.to))).unwrap_or((w0, w1));
        let size = a.iter().map(|x| x.size_km).fold(0.0, f64::max);
        let (text, key) = match k {
            Kind::Jump => (
                "The reported track jumped by more than a ship can move",
                "largest_jump_km",
            ),
            Kind::Circle => (
                "The reported track circled at a near-constant radius",
                "circle_radius_km",
            ),
        };
        f.push(Finding {
            family: Family::Track,
            side: Some(Side::Victim),
            strength: Strength::Weak,
            text: text.into(),
            from: s0,
            to: s1,
            observed: vec![("episodes", a.len() as f64), (key, size)],
        });
    }
    regularity(&c, &mut f);
    gaps(&c, &mut f);

    // 2. Independent observations.
    let mut disagree: Vec<(f64, f64, bool, &'static str)> = Vec::new(); // t, km, during anomaly, source
    let mut agree = 0usize;
    let mut unmatched = 0usize;
    for (o, t, sigma) in &obs {
        let Some((la, lo)) = interp(&c.subj, *t, OBS_MAX_GAP_S) else {
            unmatched += 1;
            continue;
        };
        let d = dist_km(la, lo, o.lat_deg, o.lon_deg);
        if d > (OBS_SIGMAS * sigma / 1000.0).max(OBS_MIN_KM) {
            let during = anom
                .iter()
                .any(|a| *t >= a.from - 600.0 && *t <= a.to + 600.0);
            disagree.push((*t, d, during, o.source.name()));
        } else {
            agree += 1;
        }
    }
    let track_false = !disagree.is_empty();
    if track_false {
        let smooth: Vec<_> = disagree.iter().filter(|d| !d.2).collect();
        let during: Vec<_> = disagree.iter().filter(|d| d.2).collect();
        let mut srcs: Vec<&str> = disagree.iter().map(|d| d.3).collect();
        srcs.sort();
        srcs.dedup();
        if !smooth.is_empty() {
            let (a, b) = span(smooth.iter().map(|d| (d.0, d.0))).unwrap_or((w0, w1));
            let km = smooth.iter().map(|d| d.1).fold(0.0, f64::max);
            f.push(Finding {
                family: Family::Independent,
                side: Some(Side::Actor),
                strength: if smooth.len() >= 2 {
                    Strength::Strong
                } else {
                    Strength::Moderate
                },
                text: format!(
                    "Independent observations ({}) put the vessel away from its reported position while the reported track was smooth and plausible",
                    srcs.join(", ")
                ),
                from: a,
                to: b,
                observed: vec![
                    ("observations_disagreeing", smooth.len() as f64),
                    ("largest_offset_km", km),
                ],
            });
        }
        if !during.is_empty() {
            let (a, b) = span(during.iter().map(|d| (d.0, d.0))).unwrap_or((w0, w1));
            let km = during.iter().map(|d| d.1).fold(0.0, f64::max);
            // The track is false there, which a spoofed receiver and a falsified transponder
            // both produce: context, favouring neither side.
            f.push(Finding {
                family: Family::Independent,
                side: None,
                strength: Strength::Weak,
                text: "Independent observations put the vessel away from its reported position while the reported track showed capture-like anomalies".into(),
                from: a,
                to: b,
                observed: vec![
                    ("observations_disagreeing", during.len() as f64),
                    ("largest_offset_km", km),
                ],
            });
        }
    }

    // 3. Nearby vessels.
    let onset = anom_span
        .map(|s| s.0)
        .or_else(|| disagree.iter().map(|d| d.0).reduce(f64::min));
    let mut nearby_n: Option<usize> = None;
    let mut affected_n = 0usize;
    if let Some(t_a) = onset {
        let anchor = anom
            .first()
            .map(|a| a.anchor)
            .or_else(|| interp(&c.subj, t_a, f64::INFINITY))
            .unwrap_or((c.subj[0].lat, c.subj[0].lon));
        let (a0, a1) = anom_span
            .unwrap_or_else(|| span(disagree.iter().map(|d| (d.0, d.0))).unwrap_or((t_a, t_a)));
        let mut nearby = 0usize;
        let mut affected = 0usize;
        for (_, tr) in &c.neigh {
            let near = tr.iter().any(|p| {
                (p.t - t_a).abs() <= NEAR_DT_S
                    && dist_km(p.lat, p.lon, anchor.0, anchor.1) <= NEAR_KM
            });
            if !near {
                continue;
            }
            nearby += 1;
            if anomalies(tr)
                .iter()
                .any(|x| x.from <= a1 + OVERLAP_S && x.to >= a0 - OVERLAP_S)
            {
                affected += 1;
            }
        }
        nearby_n = Some(nearby);
        affected_n = affected;
        let obs = vec![
            ("nearby_vessels", nearby as f64),
            ("nearby_vessels_affected", affected as f64),
        ];
        if !anom.is_empty() && affected >= 2 && affected as f64 >= AFFECTED_SHARE * nearby as f64 {
            f.push(Finding {
                family: Family::Neighbours,
                side: Some(Side::Victim),
                strength: Strength::Strong,
                text: "Nearby vessels showed the same kind of anomaly at the same time".into(),
                from: a0,
                to: a1,
                observed: obs,
            });
        } else if !anom.is_empty() && affected >= 1 {
            f.push(Finding {
                family: Family::Neighbours,
                side: Some(Side::Victim),
                strength: Strength::Moderate,
                text: "Another nearby vessel showed the same kind of anomaly at the same time"
                    .into(),
                from: a0,
                to: a1,
                observed: obs,
            });
        } else if affected == 0 && nearby >= MIN_NEARBY {
            f.push(Finding {
                family: Family::Neighbours,
                side: Some(Side::Actor),
                strength: Strength::Moderate,
                text: "No nearby vessel showed an anomaly while the subject's reports went wrong"
                    .into(),
                from: a0,
                to: a1,
                observed: obs,
            });
        }
        // The same false position as other vessels.
        let mut shared: std::collections::BTreeSet<&str> = Default::default();
        for p in c.subj.iter().filter(|p| {
            anom.iter()
                .any(|a| p.t >= a.from - 1.0 && p.t <= a.to + EPISODE_GAP_S)
        }) {
            for (id, tr) in &c.neigh {
                if tr.iter().any(|q| {
                    (q.t - p.t).abs() <= CONVERGE_DT_S
                        && dist_km(p.lat, p.lon, q.lat, q.lon) <= CONVERGE_KM
                }) {
                    shared.insert(id.as_str());
                }
            }
        }
        if shared.len() >= 2 {
            f.push(Finding {
                family: Family::Neighbours,
                side: Some(Side::Victim),
                strength: Strength::Strong,
                text: "During the anomaly the subject reported the same position as other vessels"
                    .into(),
                from: a0,
                to: a1,
                observed: vec![("vessels_at_same_position", shared.len() as f64)],
            });
        }
    }

    // 4. Regional reports.
    let mut regional_hit = false;
    if let Some(evs) = &req.regional {
        regional_hit = regional(&c, evs, onset, anom_span, &mut f)?;
    }

    Ok(outcome(
        req,
        &c,
        f,
        Summary {
            track_false,
            agree,
            unmatched,
            observations: obs.len(),
            nearby: nearby_n,
            affected: affected_n,
            regional_hit,
        },
    ))
}

/// A track too regular to come from a GNSS receiver: over a half-hour window with enough
/// reports and movement, the positions sit on a constant-velocity line to well under a metre.
fn regularity(c: &Ctx, f: &mut Vec<Finding>) {
    let tr = &c.subj;
    let mut hits: Vec<(f64, f64, f64)> = Vec::new();
    let mut i = 0;
    while i < tr.len() {
        let Some(j) = (i + 1..tr.len()).find(|&j| tr[j].t - tr[i].t >= REG_SPAN_S) else {
            break;
        };
        let w = &tr[i..=j];
        if w.len() >= REG_MIN_REPORTS
            && w.windows(2).all(|q| plausible(&q[0], &q[1]))
            && dist_km(w[0].lat, w[0].lon, w[w.len() - 1].lat, w[w.len() - 1].lon)
                >= REG_MIN_MOVE_KM
        {
            let rms = line_rms_m(w);
            if rms <= REG_MAX_RMS_M {
                hits.push((w[0].t, w[w.len() - 1].t, rms));
            }
        }
        // Windows overlap: the next starts a sixth of a window later.
        let next = tr[i].t + REG_SPAN_S / 6.0;
        i = (i + 1..tr.len())
            .find(|&k| tr[k].t >= next)
            .unwrap_or(tr.len());
    }
    if let Some((a, b)) = span(hits.iter().map(|h| (h.0, h.1))) {
        let rms = hits.iter().map(|h| h.2).fold(0.0, f64::max);
        f.push(Finding {
            family: Family::Track,
            side: Some(Side::Actor),
            strength: Strength::Moderate,
            text: "The reported track was too regular for positions from a GNSS receiver at sea"
                .into(),
            from: a,
            to: b,
            observed: vec![("windows", hits.len() as f64), ("largest_line_rms_m", rms)],
        });
    }
}

/// Silences of the subject while nearby vessels kept reporting.
fn gaps(c: &Ctx, f: &mut Vec<Finding>) {
    let tr = &c.subj;
    for q in tr.windows(2) {
        let (a, b) = (&q[0], &q[1]);
        if b.t - a.t < GAP_S {
            continue;
        }
        let heard = c
            .neigh
            .iter()
            .filter(|(_, n)| {
                n.iter()
                    .filter(|p| {
                        p.t > a.t && p.t < b.t && dist_km(p.lat, p.lon, a.lat, a.lon) <= GAP_NEAR_KM
                    })
                    .count()
                    >= GAP_MIN_NEIGHBOUR_REPORTS
            })
            .count();
        if heard >= 2 {
            f.push(Finding {
                family: Family::Track,
                side: Some(Side::Actor),
                strength: Strength::Weak,
                text: "The subject's reports stopped while nearby vessels kept being received"
                    .into(),
                from: a.t,
                to: b.t,
                observed: vec![
                    ("silence_min", (b.t - a.t) / 60.0),
                    ("nearby_vessels_received", heard as f64),
                ],
            });
        }
    }
}

/// Regional interference reports at the subject's positions and times. Returns whether any
/// relevant report was found.
fn regional(
    c: &Ctx,
    evs: &[ievents::Event],
    onset: Option<f64>,
    anom_span: Option<(f64, f64)>,
    f: &mut Vec<Finding>,
) -> Result<bool, String> {
    let (a0, a1) = anom_span
        .or_else(|| onset.map(|t| (t, t)))
        .unwrap_or((c.w0, c.w1));
    let (q0, q1) = (a0 - OVERLAP_S, a1 + OVERLAP_S);
    let here: Vec<(f64, f64)> = c
        .subj
        .iter()
        .filter(|p| p.t >= q0 - NEAR_DT_S && p.t <= q1)
        .map(|p| (p.lat, p.lon))
        .collect();
    let mut hits: Vec<(bool, bool, usize, f64, f64)> = Vec::new(); // located, corroborated, observers, t0, t1
    for (i, e) in evs.iter().enumerate() {
        let p = ievents::validate(e);
        if !p.is_empty() {
            return Err(format!("regional[{i}]: {}", p.join("; ")));
        }
        let (s, t) = (
            crate::cause::parse_iso(&e.start_utc)?,
            crate::cause::parse_iso(&e.end_utc)?,
        );
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
        let located = match &e.location {
            Some(l) => {
                let reach = l.radius_m / 1000.0 + REG_REACH_KM;
                if !here
                    .iter()
                    .any(|(la, lo)| dist_km(*la, *lo, l.lat_deg, l.lon_deg) <= reach)
                {
                    continue;
                }
                true
            }
            None if e.area.as_deref().is_some_and(|a| !a.trim().is_empty()) => false,
            None => continue,
        };
        hits.push((located, e.corroborated, e.observers.len(), s, t));
    }
    if hits.is_empty() {
        if onset.is_some() {
            f.push(Finding {
                family: Family::Regional,
                side: Some(Side::Actor),
                strength: Strength::Weak,
                text: "Regional monitoring covered the episode and reported no interference there"
                    .into(),
                from: q0,
                to: q1,
                observed: vec![("regional_reports", evs.len() as f64)],
            });
        }
        return Ok(false);
    }
    let located = hits.iter().any(|h| h.0);
    let strength = if !located {
        Strength::Weak
    } else if hits.iter().any(|h| h.1 || h.2 >= 2) {
        Strength::Strong
    } else {
        Strength::Moderate
    };
    let (s0, s1) = span(hits.iter().map(|h| (h.3, h.4))).unwrap_or((q0, q1));
    f.push(Finding {
        family: Family::Regional,
        side: Some(Side::Victim),
        strength,
        text: "Regional reports describe GNSS interference at the subject's position and time"
            .into(),
        from: s0,
        to: s1,
        observed: vec![("matching_reports", hits.len() as f64)],
    });
    Ok(true)
}

struct Summary {
    track_false: bool,
    agree: usize,
    unmatched: usize,
    observations: usize,
    nearby: Option<usize>,
    affected: usize,
    regional_hit: bool,
}

fn signed(x: &Finding) -> f64 {
    x.side.map_or(0.0, |s| s.sign() * x.strength.w())
}

/// Probability of `side` from the findings, capped by how many families support it, rounded
/// down to 0.05.
fn side_confidence(f: &[&Finding], side: Side) -> f64 {
    let score: f64 = f.iter().map(|x| signed(x)).sum::<f64>() * side.sign();
    let p = 1.0 / (1.0 + (-score).exp());
    let mut fams: Vec<Family> = f
        .iter()
        .filter(|x| x.side == Some(side))
        .map(|x| x.family)
        .collect();
    fams.sort();
    fams.dedup();
    let cap = match fams.len() {
        0 => 0.5,
        1 => 0.65,
        2 => 0.85,
        _ => 0.95,
    };
    (p.min(cap) * 20.0 + 1e-9).floor() / 20.0
}

fn outcome(req: &VictimActorRequest, c: &Ctx, mut f: Vec<Finding>, s: Summary) -> Value {
    let all: Vec<&Finding> = f.iter().collect();
    let score: f64 = all.iter().map(|x| signed(x)).sum();
    let lead = if score >= 0.0 {
        Side::Victim
    } else {
        Side::Actor
    };
    let conf = if score == 0.0 {
        0.5
    } else {
        side_confidence(&all, lead)
    };
    let has_anomaly =
        !f.is_empty() && (s.track_false || f.iter().any(|x| x.family == Family::Track));
    let decided = has_anomaly && score != 0.0 && conf >= DECIDE_AT;
    let classification = if decided {
        lead.name()
    } else {
        "indeterminate"
    };

    // Leave-one-family-out interval for the leading side.
    let mut fams: Vec<Family> = f.iter().map(|x| x.family).collect();
    fams.sort();
    fams.dedup();
    let (mut lo, mut hi) = (conf, conf);
    for fam in &fams {
        let rest: Vec<&Finding> = f.iter().filter(|x| x.family != *fam).collect();
        let c2 = side_confidence(&rest, lead);
        lo = lo.min(c2);
        hi = hi.max(c2);
    }

    let win = span(f.iter().map(|x| (x.from, x.to)));
    f.sort_by(|a, b| b.strength.cmp(&a.strength).then(a.from.total_cmp(&b.from)));
    let evidence: Vec<Value> = f
        .iter()
        .map(|x| {
            let mut o = serde_json::Map::new();
            for (k, v) in &x.observed {
                o.insert((*k).into(), json!(v));
            }
            json!({
                "finding": x.text,
                "family": x.family.name(),
                "supports": x.side.map_or("neither", Side::name),
                "strength": x.strength.name(),
                "window": {"start_utc": iso(x.from.floor() as i64), "end_utc": iso(x.to.ceil() as i64)},
                "observed": Value::Object(o),
            })
        })
        .collect();

    let mut limits: Vec<String> = vec![
        "MODELLED: rules checked on synthetic episodes with known truth; not validated on a labelled set of real incidents".into(),
        "An engineering reconstruction of the data supplied, not a legal finding; intent is not assessed".into(),
        "'actor' means the evidence fits manipulation of the vessel's own AIS reports; 'victim' means it fits external interference with the vessel's position".into(),
    ];
    match s.nearby {
        None => {}
        Some(n) if n < MIN_NEARBY && s.affected == 0 => limits.push(format!(
            "Fewer than {MIN_NEARBY} vessels were near the subject during the episode; the neighbourhood comparison is weak"
        )),
        _ => {}
    }
    if req.neighbours.is_empty() {
        limits.push("No neighbour tracks were supplied; whether the anomaly was shared could not be assessed".into());
    }
    if s.observations == 0 {
        limits.push("No independent observation of the subject's position was supplied".into());
    } else if s.unmatched > 0 {
        limits.push(format!(
            "{} observation(s) fell where the reported track had no position to compare",
            s.unmatched
        ));
    }
    if req.regional.is_none() {
        limits.push("No regional interference reports were supplied".into());
    }
    if !has_anomaly {
        limits.push("No anomaly was found in the data supplied".into());
    }

    let mut v = json!({
        "method": METHOD_VERSION,
        "classification": classification,
        "subject_id": req.subject_id,
        "anomaly_found": has_anomaly,
        "window": win.filter(|_| has_anomaly).map(|(a, b)| json!({"start_utc": iso(a.floor() as i64), "end_utc": iso(b.ceil() as i64)})),
        "analysed": {
            "start_utc": iso(c.w0.floor() as i64),
            "end_utc": iso(c.w1.ceil() as i64),
            "reported_positions": c.subj.len(),
            "neighbour_tracks": c.neigh.len(),
            "observations": s.observations,
            "regional_reports": req.regional.as_ref().map(|r| r.len()),
        },
        "questions": {
            "reported_track": if s.track_false {
                "false"
            } else if s.agree >= 2 {
                "consistent_with_observations"
            } else {
                "undetermined"
            },
            "shared_with_nearby_vessels": match s.nearby {
                Some(_) if s.affected > 0 => "yes",
                Some(n) if n >= MIN_NEARBY => "no",
                _ => "undetermined",
            },
            "regional_interference": match (&req.regional, s.regional_hit) {
                (None, _) => "not_supplied",
                (Some(_), true) => "reported",
                (Some(_), false) => "not_reported",
            },
        },
        "evidence": evidence,
        "limits": limits,
    });
    if decided {
        v["confidence"] = json!(conf);
        v["confidence_interval"] =
            json!({"low": lo, "high": hi, "basis": "leave_one_evidence_family_out"});
    } else if has_anomaly && score != 0.0 {
        v["leading_hypothesis"] = json!(lead.name());
        v["leading_confidence"] = json!(conf);
        v["confidence_interval"] =
            json!({"low": lo, "high": hi, "basis": "leave_one_evidence_family_out"});
    }
    v
}

#[cfg(test)]
#[path = "victim_actor_tests.rs"]
mod tests;
