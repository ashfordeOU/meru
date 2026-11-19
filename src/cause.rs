// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The `cause` method: what caused a position episode of a vessel or an aircraft?
//!
//! A marine insurer, a coastal state or a sanctions screen holds a reported track (AIS or
//! ADS-B) that went wrong. On its own that track cannot settle the question, because the track
//! is the thing in dispute. This method weighs it against whatever else the caller has —
//! independent tracks (radar, SAR, optical, multilateration, LRIT, a second receiver,
//! satellite or coastal AIS relays), the onboard GNSS receiver's observables (C/N0, AGC, fix,
//! position solutions, clock) and regional interference reports (the unified
//! `kshana-pnt-interference-event/1` format) — and answers one of:
//!
//! * external interference (jamming);
//! * external spoofing;
//! * self-reported falsification of the track (the platform's own AIS/ADS-B manipulated);
//! * equipment fault;
//! * insufficient evidence.
//!
//! The method is transparent physics and consistency, not a learned model: kinematic
//! plausibility of the reported track, cross-source disagreement patterns (which sources are
//! independent of the platform's GNSS, which merely relay its own reports, and which receivers
//! agree with which), signal-level signatures (broad C/N0 loss with the receiver gain pulled
//! down, uniform C/N0 rise, clock steps, loss of fix under normal signals) and regional
//! correlation. Each finding supports or weighs against causes; the findings combine into a
//! posterior that is capped by how many independent lines of evidence agree.
//!
//! What leaves the service is the outcome: the classification, a confidence rounded to 0.05,
//! the time window, and the findings described at outcome level. The weights, thresholds and
//! per-class scores stay here.

use crate::server::iso;
use kshana_pro::ievents;
use serde::Deserialize;
use serde_json::{json, Value};

/// Method identifier written into every outcome. A change to any rule is a new version.
pub const METHOD_VERSION: &str = "cause/1";

/// Lowest confidence at which a cause is named; below it the answer is insufficient evidence.
const DECIDE_AT: f64 = 0.6;

// ------------------------------------------------------------------------------------------
// Request
// ------------------------------------------------------------------------------------------

/// A time: ISO-8601 UTC (`2026-11-20T10:00:00Z`, fractional seconds allowed) or Unix seconds.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum Time {
    Unix(f64),
    Iso(String),
}

impl Time {
    pub fn secs(&self) -> Result<f64, String> {
        match self {
            Time::Unix(x) if x.is_finite() => Ok(*x),
            Time::Unix(_) => Err("time is not a finite number".into()),
            Time::Iso(s) => parse_iso(s),
        }
    }
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.fff]Z` to Unix seconds.
pub fn parse_iso(s: &str) -> Result<f64, String> {
    let b = s.as_bytes();
    let bad = || format!("time '{s}': expected YYYY-MM-DDTHH:MM:SS[.fff]Z or Unix seconds");
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || !s.ends_with('Z')
    {
        return Err(bad());
    }
    let n = |a: usize, l: usize| {
        s.get(a..a + l)
            .filter(|x| x.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|x| x.parse::<i64>().ok())
            .ok_or_else(bad)
    };
    let (y, mo, d, h, mi, se) = (
        n(0, 4)?,
        n(5, 2)?,
        n(8, 2)?,
        n(11, 2)?,
        n(14, 2)?,
        n(17, 2)?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return Err(bad());
    }
    let frac = &s[19..s.len() - 1];
    let f = if frac.is_empty() {
        0.0
    } else {
        match frac.strip_prefix('.') {
            Some(r) if !r.is_empty() && r.len() <= 9 && r.bytes().all(|c| c.is_ascii_digit()) => {
                format!("0.{r}").parse::<f64>().map_err(|_| bad())?
            }
            _ => return Err(bad()),
        }
    };
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (mo + if mo > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok(((era * 146_097 + doe - 719_468) * 86_400 + h * 3600 + mi * 60 + se) as f64 + f)
}

/// What kind of platform the episode concerns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Vessel,
    Aircraft,
}

/// One position report. A report without a position (AIS lat 91 / lon 181, ADS-B with no
/// position) is given with `lat_deg` and `lon_deg` omitted or null.
#[derive(Clone, Debug, Deserialize)]
pub struct Fix {
    pub t: Time,
    #[serde(default)]
    pub lat_deg: Option<f64>,
    #[serde(default)]
    pub lon_deg: Option<f64>,
    /// Reported speed over ground (knots), where the report carries one.
    #[serde(default)]
    pub sog_kn: Option<f64>,
}

/// Where an independent track comes from. This decides what its agreement means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Shipborne, airborne or ground radar track (independent of the platform's GNSS).
    Radar,
    /// Coastal surveillance radar (VTS) track.
    CoastalRadar,
    /// Satellite SAR detection.
    Sar,
    /// Optical or infrared imagery detection.
    Optical,
    /// Multilateration (aircraft): position from time differences, not from the aircraft.
    Mlat,
    /// LRIT position reports (a separate GNSS-based terminal on board).
    Lrit,
    /// A second GNSS receiver on board (for example the ECDIS or DP reference).
    SecondaryGnss,
    /// Satellite AIS reception of the subject's own messages (a relay, not a position fix).
    SatAis,
    /// Coastal AIS (or ADS-B ground station) reception of the subject's own messages.
    CoastalAis,
    /// Any other position source independent of the platform's GNSS.
    Other,
}

impl SourceKind {
    fn name(self) -> &'static str {
        match self {
            SourceKind::Radar => "radar",
            SourceKind::CoastalRadar => "coastal_radar",
            SourceKind::Sar => "sar",
            SourceKind::Optical => "optical",
            SourceKind::Mlat => "mlat",
            SourceKind::Lrit => "lrit",
            SourceKind::SecondaryGnss => "secondary_gnss",
            SourceKind::SatAis => "sat_ais",
            SourceKind::CoastalAis => "coastal_ais",
            SourceKind::Other => "other",
        }
    }

    fn category(self) -> Cat {
        match self {
            SourceKind::Lrit | SourceKind::SecondaryGnss => Cat::Separate,
            SourceKind::SatAis | SourceKind::CoastalAis => Cat::Relay,
            _ => Cat::Free,
        }
    }
}

/// An independent track of the same subject.
#[derive(Clone, Debug, Deserialize)]
pub struct IndependentTrack {
    pub source: SourceKind,
    /// A label for the source (station, satellite pass, provider).
    #[serde(default)]
    pub id: String,
    pub positions: Vec<Fix>,
    /// One-sigma position uncertainty of this source (metres), if known.
    #[serde(default)]
    pub sigma_m: Option<f64>,
    /// Relays only: where the receiving station was (for satellites, the footprint centre).
    #[serde(default)]
    pub receiver_lat_deg: Option<f64>,
    #[serde(default)]
    pub receiver_lon_deg: Option<f64>,
    /// Relays only: the station's nominal reception range (km).
    #[serde(default)]
    pub range_km: Option<f64>,
}

/// One epoch of the onboard GNSS receiver's observables.
#[derive(Clone, Debug, Deserialize)]
pub struct Epoch {
    pub t: Time,
    /// Whether the receiver had a position fix.
    #[serde(default)]
    pub fix: Option<bool>,
    /// C/N0 of each tracked satellite (dB-Hz).
    #[serde(default)]
    pub cn0_dbhz: Vec<f64>,
    /// Mean C/N0 (dB-Hz), when per-satellite values are not available.
    #[serde(default)]
    pub cn0_mean_dbhz: Option<f64>,
    /// Satellites tracked (or used).
    #[serde(default)]
    pub n_sats: Option<u32>,
    /// Automatic gain control level (dB). It falls when in-band power rises.
    #[serde(default)]
    pub agc_db: Option<f64>,
    /// The receiver's own position solution.
    #[serde(default)]
    pub lat_deg: Option<f64>,
    #[serde(default)]
    pub lon_deg: Option<f64>,
    /// Receiver clock bias (ns).
    #[serde(default)]
    pub clock_bias_ns: Option<f64>,
}

/// The onboard GNSS receiver log.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Receiver {
    pub epochs: Vec<Epoch>,
    /// Normal mean C/N0 for this installation (dB-Hz), if known; otherwise taken from epochs
    /// before the window (or the first epochs).
    #[serde(default)]
    pub baseline_cn0_dbhz: Option<f64>,
    /// Normal AGC level (dB), if known.
    #[serde(default)]
    pub baseline_agc_db: Option<f64>,
}

/// The time window to analyse.
#[derive(Clone, Debug, Deserialize)]
pub struct Window {
    pub start_utc: Time,
    pub end_utc: Time,
}

/// Request for the `cause` method.
#[derive(Clone, Debug, Deserialize)]
pub struct CauseRequest {
    pub platform: Platform,
    /// The subject's identifier (MMSI, IMO, ICAO 24-bit address, call sign).
    #[serde(default)]
    pub subject_id: String,
    /// Window to analyse; default: the extent of the reported track.
    #[serde(default)]
    pub window: Option<Window>,
    /// The track the platform reported (AIS or ADS-B).
    pub reported: Vec<Fix>,
    #[serde(default)]
    pub independent: Vec<IndependentTrack>,
    #[serde(default)]
    pub receiver: Option<Receiver>,
    /// Regional interference reports. Supplying the list (even empty) states that regional
    /// monitoring covered the window, so an absence of reports counts as weak evidence.
    #[serde(default)]
    pub regional: Option<Vec<ievents::Event>>,
}

/// Size limits for a `cause` request, checked before any work starts.
#[derive(Clone, Debug)]
pub struct CauseLimits {
    /// Most reported positions, and most independent positions in total.
    pub max_track_points: usize,
    /// Most independent tracks.
    pub max_sources: usize,
    /// Most receiver epochs.
    pub max_epochs: usize,
    /// Most per-satellite C/N0 values in one epoch.
    pub max_sats: usize,
    /// Most regional interference reports.
    pub max_events: usize,
    /// Longest window (seconds).
    pub max_window_s: f64,
}

impl Default for CauseLimits {
    fn default() -> Self {
        CauseLimits {
            max_track_points: 20_000,
            max_sources: 32,
            max_epochs: 50_000,
            max_sats: 64,
            max_events: 500,
            max_window_s: 7.0 * 86_400.0,
        }
    }
}

// ------------------------------------------------------------------------------------------
// Internals (never returned)
// ------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    Jamming,
    Spoofing,
    Falsification,
    Fault,
}

const CLASSES: [Class; 4] = [
    Class::Jamming,
    Class::Spoofing,
    Class::Falsification,
    Class::Fault,
];

impl Class {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Class::Jamming => "external_interference_jamming",
            Class::Spoofing => "external_spoofing",
            Class::Falsification => "self_reported_track_falsification",
            Class::Fault => "equipment_fault",
        }
    }
    fn idx(self) -> usize {
        self as usize
    }
}

pub(crate) const INSUFFICIENT: &str = "insufficient_evidence";

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Track,
    CrossSource,
    Signal,
    Regional,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tag {
    TrackFalse,
    TrackTrue,
    RfInterference,
    RfNormal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cat {
    /// Independent of the platform's GNSS.
    Free,
    /// A separate GNSS-based receiver on the same platform.
    Separate,
    /// Relays the platform's own reports.
    Relay,
}

struct Item {
    family: Family,
    finding: String,
    supports: Vec<(Class, Strength)>,
    against: Vec<(Class, Strength)>,
    sources: Vec<String>,
    from: f64,
    to: f64,
    observed: Vec<(&'static str, f64)>,
    anomaly: bool,
    tag: Option<Tag>,
}

impl Item {
    fn strength(&self) -> Strength {
        self.supports
            .iter()
            .chain(self.against.iter())
            .map(|x| x.1)
            .max()
            .unwrap_or(Strength::Weak)
    }
}

use Class::{Falsification as FA, Fault as FT, Jamming as JA, Spoofing as SP};
use Strength::{Moderate as MOD, Strong as STR, Weak as WK};

/// Platform constants.
struct Kin {
    vmax_kn: f64,
    jump_min_km: f64,
    interp_gap_s: f64,
    gap_s: f64,
    rr_km: f64,
    reg_km: f64,
    floor_km: f64,
    frozen_span_s: f64,
    frozen_move_km: f64,
    sog_tol_kn: f64,
    sog_tol_rel: f64,
    sog_dt: (f64, f64),
}

fn kin(p: Platform) -> Kin {
    match p {
        Platform::Vessel => Kin {
            vmax_kn: 50.0,
            jump_min_km: 0.5,
            interp_gap_s: 1800.0,
            gap_s: 1200.0,
            rr_km: 0.25,
            reg_km: 50.0,
            floor_km: 0.15,
            frozen_span_s: 600.0,
            frozen_move_km: 2.0,
            sog_tol_kn: 5.0,
            sog_tol_rel: 0.5,
            sog_dt: (30.0, 900.0),
        },
        Platform::Aircraft => Kin {
            vmax_kn: 750.0,
            jump_min_km: 5.0,
            interp_gap_s: 120.0,
            gap_s: 300.0,
            rr_km: 1.0,
            reg_km: 150.0,
            floor_km: 0.75,
            frozen_span_s: 60.0,
            frozen_move_km: 10.0,
            sog_tol_kn: 50.0,
            sog_tol_rel: 0.3,
            sog_dt: (5.0, 120.0),
        },
    }
}

fn default_sigma_km(k: SourceKind, p: Platform) -> f64 {
    use SourceKind::*;
    match (p, k) {
        (Platform::Vessel, Radar) => 0.3,
        (Platform::Vessel, CoastalRadar) => 0.2,
        (Platform::Vessel, Sar) => 0.5,
        (Platform::Vessel, Optical) => 0.3,
        (Platform::Vessel, Mlat) => 0.3,
        (Platform::Vessel, Lrit) => 0.2,
        (Platform::Vessel, SecondaryGnss) => 0.05,
        (Platform::Vessel, SatAis | CoastalAis) => 0.1,
        (Platform::Vessel, Other) => 1.0,
        (Platform::Aircraft, Mlat) => 0.3,
        (Platform::Aircraft, SecondaryGnss) => 0.3,
        (Platform::Aircraft, SatAis | CoastalAis) => 0.5,
        (Platform::Aircraft, Other) => 2.0,
        (Platform::Aircraft, _) => 1.0,
    }
}

fn default_range_km(k: SourceKind, p: Platform) -> f64 {
    match (k, p) {
        (SourceKind::SatAis, _) => 3000.0,
        (_, Platform::Vessel) => 75.0,
        (_, Platform::Aircraft) => 450.0,
    }
}

#[derive(Clone, Copy, Debug)]
struct Pt {
    t: f64,
    lat: f64,
    lon: f64,
    sog: Option<f64>,
}

const KM_PER_NM: f64 = 1.852;

fn dist_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = 6371.0088;
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dp = p2 - p1;
    let dl = (lon2 - lon1).to_radians();
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * r * a.sqrt().min(1.0).asin()
}

fn bearing_deg(a: &Pt, b: &Pt) -> f64 {
    let (p1, p2) = (a.lat.to_radians(), b.lat.to_radians());
    let dl = (b.lon - a.lon).to_radians();
    let y = dl.sin() * p2.cos();
    let x = p1.cos() * p2.sin() - p1.sin() * p2.cos() * dl.cos();
    y.atan2(x).to_degrees()
}

fn wrap180(x: f64) -> f64 {
    let mut y = (x + 180.0).rem_euclid(360.0) - 180.0;
    if y == -180.0 {
        y = 180.0;
    }
    y
}

/// Position on `track` (sorted by time) at `t`: linear between neighbours no further apart
/// than `max_gap`; otherwise dead-reckoned from the nearest pair of reports on one side, at
/// most a quarter of `max_gap` away.
fn interp(track: &[Pt], t: f64, max_gap: f64) -> Option<(f64, f64)> {
    if track.is_empty() {
        return None;
    }
    let i = track.partition_point(|p| p.t <= t);
    if i > 0 && i < track.len() {
        let (a, b) = (&track[i - 1], &track[i]);
        if b.t - a.t <= max_gap {
            let f = if b.t > a.t {
                (t - a.t) / (b.t - a.t)
            } else {
                0.0
            };
            let dlon = wrap180(b.lon - a.lon);
            return Some((a.lat + f * (b.lat - a.lat), wrap180(a.lon + f * dlon)));
        }
    }
    let near = max_gap / 4.0;
    // Dead reckoning forward from the last reports before t, or back from the first after.
    let pair = |p: usize, q: usize| -> Option<(f64, f64)> {
        let (a, b) = (track.get(p)?, track.get(q)?);
        let anchor = if (t - a.t).abs() < (t - b.t).abs() {
            a
        } else {
            b
        };
        if (t - anchor.t).abs() > near {
            return None;
        }
        if b.t <= a.t || b.t - a.t > max_gap {
            return ((t - anchor.t).abs() <= near / 8.0).then_some((anchor.lat, anchor.lon));
        }
        let f = (t - anchor.t) / (b.t - a.t);
        let dlon = wrap180(b.lon - a.lon);
        Some((
            anchor.lat + f * (b.lat - a.lat),
            wrap180(anchor.lon + f * dlon),
        ))
    };
    let back = if i >= 2 {
        pair(i - 2, i - 1)
    } else if i == 1 {
        pair(0, 0)
    } else {
        None
    };
    back.or_else(|| {
        if i < track.len() {
            pair(i, i + 1)
        } else {
            None
        }
    })
}

fn median(v: &mut [f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    let n = v.len();
    Some(if n % 2 == 1 {
        v[n / 2]
    } else {
        0.5 * (v[n / 2 - 1] + v[n / 2])
    })
}

fn check_pos(lat: f64, lon: f64, what: &str) -> Result<(), String> {
    if !lat.is_finite() || !lon.is_finite() || lat.abs() > 90.0 || lon.abs() > 180.0 {
        return Err(format!("{what}: position out of range"));
    }
    Ok(())
}

/// Convert fixes to points (sorted). Reports without a position are returned as times.
fn to_points(fixes: &[Fix], what: &str) -> Result<(Vec<Pt>, Vec<f64>), String> {
    let mut pts = Vec::with_capacity(fixes.len());
    let mut nulls = vec![];
    for (i, f) in fixes.iter().enumerate() {
        let t = f.t.secs().map_err(|e| format!("{what}[{i}]: {e}"))?;
        match (f.lat_deg, f.lon_deg) {
            (Some(la), Some(lo)) if la.abs() <= 90.0 && lo.abs() <= 180.0 => {
                check_pos(la, lo, &format!("{what}[{i}]"))?;
                // 102.3 kn is AIS "speed not available".
                let sog = f
                    .sog_kn
                    .filter(|s| s.is_finite() && *s >= 0.0 && *s < 102.3);
                pts.push(Pt {
                    t,
                    lat: la,
                    lon: lo,
                    sog,
                });
            }
            // AIS "not available" (91 / 181) or omitted: a report without a position.
            (Some(la), Some(lo)) if (la - 91.0).abs() < 1e-9 || (lo - 181.0).abs() < 1e-9 => {
                nulls.push(t)
            }
            (Some(_), Some(_)) => return Err(format!("{what}[{i}]: position out of range")),
            (None, None) => nulls.push(t),
            _ => {
                return Err(format!(
                    "{what}[{i}]: give both lat_deg and lon_deg, or neither"
                ))
            }
        }
    }
    pts.sort_by(|a, b| a.t.total_cmp(&b.t));
    nulls.sort_by(|a, b| a.total_cmp(b));
    Ok((pts, nulls))
}

/// One comparison of the reported track with an independent position.
struct Cmp {
    t: f64,
    d_km: f64,
    thr_km: f64,
    src: usize,
    lat: f64,
    lon: f64,
}

impl Cmp {
    fn disagrees(&self) -> bool {
        self.d_km > self.thr_km
    }
}

struct CatStats {
    n: usize,
    dis: Vec<usize>,
    max_d: f64,
}

fn cat_stats(cmps: &[Cmp]) -> CatStats {
    let dis: Vec<usize> = (0..cmps.len()).filter(|&i| cmps[i].disagrees()).collect();
    let max_d = dis.iter().map(|&i| cmps[i].d_km).fold(0.0, f64::max);
    CatStats {
        n: cmps.len(),
        dis,
        max_d,
    }
}

impl CatStats {
    fn frac(&self) -> f64 {
        if self.n == 0 {
            0.0
        } else {
            self.dis.len() as f64 / self.n as f64
        }
    }
    /// Enough disagreement to be a finding (not a stray outlier among many agreements).
    fn disagreement(&self) -> bool {
        !self.dis.is_empty() && self.frac() >= 0.15
    }
    fn agreement(&self, min_n: usize) -> bool {
        self.n >= min_n && self.frac() <= 0.1 && !self.disagreement()
    }
}

struct Ep {
    t: f64,
    fix: Option<bool>,
    cn0: Option<f64>,
    std: Option<f64>,
    nsat: Option<f64>,
    agc: Option<f64>,
    pos: Option<(f64, f64)>,
    clock: Option<f64>,
}

fn span(ts: impl Iterator<Item = f64>) -> Option<(f64, f64)> {
    let mut r: Option<(f64, f64)> = None;
    for t in ts {
        r = Some(match r {
            None => (t, t),
            Some((a, b)) => (a.min(t), b.max(t)),
        });
    }
    r
}

fn plat_word(p: Platform) -> &'static str {
    match p {
        Platform::Vessel => "vessel",
        Platform::Aircraft => "aircraft",
    }
}

fn reported_word(p: Platform) -> &'static str {
    match p {
        Platform::Vessel => "AIS",
        Platform::Aircraft => "ADS-B",
    }
}

// ------------------------------------------------------------------------------------------
// The method
// ------------------------------------------------------------------------------------------

/// Check the request against the limits (before any work).
pub fn check_limits(req: &CauseRequest, lim: &CauseLimits) -> Result<(), String> {
    if req.reported.len() > lim.max_track_points {
        return Err(format!(
            "too many reported positions: at most {}",
            lim.max_track_points
        ));
    }
    if req.independent.len() > lim.max_sources {
        return Err(format!(
            "too many independent tracks: at most {}",
            lim.max_sources
        ));
    }
    let ind: usize = req.independent.iter().map(|s| s.positions.len()).sum();
    if ind > lim.max_track_points {
        return Err(format!(
            "too many independent positions: at most {} in total",
            lim.max_track_points
        ));
    }
    if let Some(r) = &req.receiver {
        if r.epochs.len() > lim.max_epochs {
            return Err(format!(
                "too many receiver epochs: at most {}",
                lim.max_epochs
            ));
        }
        if r.epochs.iter().any(|e| e.cn0_dbhz.len() > lim.max_sats) {
            return Err(format!(
                "too many satellites in one epoch: at most {}",
                lim.max_sats
            ));
        }
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

/// Run the method and return the outcome (uncoarsened, unsigned).
pub fn analyse(req: &CauseRequest, lim: &CauseLimits) -> Result<Value, String> {
    check_limits(req, lim)?;
    let k = kin(req.platform);
    let (rep_all, rep_nulls) = to_points(&req.reported, "reported")?;
    if rep_all.len() < 2 {
        return Err("reported: at least two positions are needed".into());
    }
    // The window.
    let (w0, w1) = match &req.window {
        Some(w) => (w.start_utc.secs()?, w.end_utc.secs()?),
        None => (rep_all[0].t, rep_all[rep_all.len() - 1].t),
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
    let inw = |t: f64| t >= w0 && t <= w1;
    let rep: Vec<Pt> = rep_all.iter().copied().filter(|p| inw(p.t)).collect();
    let nulls: Vec<f64> = rep_nulls.iter().copied().filter(|t| inw(*t)).collect();
    if rep.len() < 2 {
        return Err("reported: fewer than two positions inside the window".into());
    }
    // Independent tracks.
    let mut ind: Vec<Src> = vec![];
    for (i, s) in req.independent.iter().enumerate() {
        let (pts, _) = to_points(&s.positions, &format!("independent[{i}].positions"))?;
        let pts: Vec<Pt> = pts.into_iter().filter(|p| inw(p.t)).collect();
        let sigma = match s.sigma_m {
            Some(m) if m.is_finite() && m > 0.0 => (m / 1000.0).clamp(0.01, 50.0),
            Some(_) => return Err(format!("independent[{i}].sigma_m must be positive")),
            None => default_sigma_km(s.source, req.platform),
        };
        let station = match (s.receiver_lat_deg, s.receiver_lon_deg) {
            (Some(la), Some(lo)) => {
                check_pos(la, lo, &format!("independent[{i}] receiver"))?;
                let r = s
                    .range_km
                    .filter(|r| r.is_finite() && *r > 0.0)
                    .unwrap_or_else(|| default_range_km(s.source, req.platform));
                Some((la, lo, r))
            }
            _ => None,
        };
        let label = if s.id.trim().is_empty() {
            s.source.name().to_string()
        } else {
            format!("{} ({})", s.source.name(), s.id.trim())
        };
        ind.push(Src {
            kind: s.source,
            label,
            pts,
            sigma,
            station,
        });
    }

    let c = Ctx {
        req,
        k,
        w0,
        w1,
        rep,
        nulls,
        ind,
        rw: reported_word(req.platform),
        pw: plat_word(req.platform),
    };
    let mut items: Vec<Item> = vec![];
    let rep_cmp = track_findings(&c, &mut items);
    let cross = cross_findings(&c, &rep_cmp, &mut items);
    let has_rx = match req.receiver.as_ref().filter(|r| !r.epochs.is_empty()) {
        Some(rx) => {
            receiver_findings(&c, rx, &rep_cmp, &cross, &mut items)?;
            true
        }
        None => false,
    };
    let n_regional = match &req.regional {
        Some(evs) => {
            regional_findings(&c, evs, &mut items)?;
            evs.len()
        }
        None => 0,
    };
    Ok(outcome(&c, items, has_rx, n_regional))
}

/// An independent track, prepared.
struct Src {
    kind: SourceKind,
    label: String,
    pts: Vec<Pt>,
    sigma: f64,
    /// Relays: receiving station (lat, lon, range km).
    station: Option<(f64, f64, f64)>,
}

/// What the analysis steps share.
struct Ctx<'a> {
    req: &'a CauseRequest,
    k: Kin,
    w0: f64,
    w1: f64,
    rep: Vec<Pt>,
    nulls: Vec<f64>,
    ind: Vec<Src>,
    rw: &'static str,
    pw: &'static str,
}

/// The comparisons with GNSS-independent sources, for the receiver step.
struct Cross {
    free_cmps: Vec<Cmp>,
    free: CatStats,
}

/// Kinematic plausibility of the reported track. Returns the reported positions to compare
/// with other sources (stale repeated positions removed).
fn track_findings(c: &Ctx, items: &mut Vec<Item>) -> Vec<Pt> {
    let (k, rep, nulls, ind, rw, pw, req) = (&c.k, &c.rep, &c.nulls, &c.ind, c.rw, c.pw, c.req);
    // Jumps faster than the platform can move.
    let mut jumps: Vec<(f64, f64)> = vec![];
    let mut is_jump = vec![false; rep.len()];
    for i in 1..rep.len() {
        let d = dist_km(rep[i - 1].lat, rep[i - 1].lon, rep[i].lat, rep[i].lon);
        let dt = rep[i].t - rep[i - 1].t;
        if d >= k.jump_min_km && (dt <= 0.0 || d / KM_PER_NM / (dt / 3600.0) > k.vmax_kn) {
            jumps.push((rep[i].t, d));
            is_jump[i] = true;
        }
    }
    if !jumps.is_empty() {
        items.push(Item {
            family: Family::Track,
            finding: format!(
                "The reported track jumps faster than a {pw} can move ({} jump{})",
                jumps.len(),
                if jumps.len() == 1 { "" } else { "s" }
            ),
            supports: vec![(SP, WK), (FA, WK), (FT, WK)],
            against: vec![(JA, WK)],
            sources: vec![rw.into()],
            from: jumps[0].0,
            to: jumps[jumps.len() - 1].0,
            observed: vec![(
                "largest_jump_km",
                jumps.iter().map(|j| j.1).fold(0.0, f64::max),
            )],
            anomaly: true,
            tag: Some(Tag::TrackFalse),
        });
    }

    // Frozen runs: identical positions repeated over a span.
    let mut frozen = vec![false; rep.len()];
    let mut runs: Vec<(usize, usize)> = vec![];
    let mut a = 0;
    while a < rep.len() {
        let mut b = a;
        while b + 1 < rep.len()
            && (rep[b + 1].lat - rep[a].lat).abs() < 1e-6
            && (rep[b + 1].lon - rep[a].lon).abs() < 1e-6
        {
            b += 1;
        }
        if b - a + 1 >= 6 && rep[b].t - rep[a].t >= k.frozen_span_s {
            runs.push((a, b));
        }
        a = b + 1;
    }
    for &(a, b) in &runs {
        let (t0, t1) = (rep[a].t, rep[b].t);
        let moved = ind
            .iter()
            .flat_map(|s| s.pts.iter())
            .filter(|p| p.t >= t0 && p.t <= t1)
            .map(|p| dist_km(p.lat, p.lon, rep[a].lat, rep[a].lon))
            .fold(0.0, f64::max);
        let says_moving = rep[a..=b]
            .iter()
            .filter_map(|p| p.sog)
            .any(|s| match req.platform {
                Platform::Vessel => s > 1.0,
                Platform::Aircraft => s > 60.0,
            });
        if is_jump[a] && (moved >= k.frozen_move_km || ind.is_empty()) {
            // Entered by a jump: the track was moved to a fixed point and held there.
            items.push(Item {
                family: Family::Track,
                finding: "The reported position jumped to a fixed point and stayed there".into(),
                supports: vec![(SP, MOD)],
                against: vec![],
                sources: vec![rw.into()],
                from: t0,
                to: t1,
                observed: vec![("held_minutes", (t1 - t0) / 60.0)],
                anomaly: true,
                tag: Some(Tag::TrackFalse),
            });
            continue;
        }
        if moved >= k.frozen_move_km || says_moving {
            // A stale position repeated: excluded from the cross-source comparison.
            frozen[a..=b].iter_mut().for_each(|f| *f = true);
            let mut obs = vec![("frozen_minutes", (t1 - t0) / 60.0)];
            if moved > 0.0 {
                obs.push(("independent_movement_km", moved));
            }
            items.push(Item {
                family: Family::Track,
                finding: if moved >= k.frozen_move_km {
                    format!("The reported position stayed frozen while independent sources show the {pw} moving")
                } else {
                    "The reported position stayed frozen while the reports themselves gave a speed".into()
                },
                supports: vec![(FT, MOD), (JA, WK), (SP, WK)],
                against: vec![],
                sources: vec![rw.into()],
                from: t0,
                to: t1,
                observed: obs,
                anomaly: true,
                tag: Some(Tag::TrackFalse),
            });
        }
    }
    let rep_cmp: Vec<Pt> = rep
        .iter()
        .zip(&frozen)
        .filter(|(_, f)| !**f)
        .map(|(p, _)| *p)
        .collect();

    // Reported speed against the speed implied by the positions.
    let (mut n_e, mut n_m, mut mis_t) = (0usize, 0usize, vec![]);
    for i in 1..rep.len() {
        let dt = rep[i].t - rep[i - 1].t;
        if is_jump[i] || frozen[i] || dt < k.sog_dt.0 || dt > k.sog_dt.1 {
            continue;
        }
        let (Some(s1), Some(s2)) = (rep[i - 1].sog, rep[i].sog) else {
            continue;
        };
        let v = dist_km(rep[i - 1].lat, rep[i - 1].lon, rep[i].lat, rep[i].lon)
            / KM_PER_NM
            / (dt / 3600.0);
        let s = 0.5 * (s1 + s2);
        n_e += 1;
        if (v - s).abs() > k.sog_tol_kn.max(k.sog_tol_rel * v.max(s)) {
            n_m += 1;
            mis_t.push(rep[i].t);
        }
    }
    if n_e >= 10 && n_m as f64 >= 0.3 * n_e as f64 {
        items.push(Item {
            family: Family::Track,
            finding:
                "The reported speed does not match the speed implied by the reported positions"
                    .into(),
            supports: vec![(FA, WK), (FT, WK)],
            against: vec![],
            sources: vec![rw.into()],
            from: mis_t[0],
            to: mis_t[mis_t.len() - 1],
            observed: vec![("share_of_segments", n_m as f64 / n_e as f64)],
            anomaly: true,
            tag: None,
        });
    }

    // Circling: the track turns through a full circle in a short time.
    if rep_cmp.len() >= 10 {
        let mut turn = vec![0.0f64; rep_cmp.len()];
        let mut prev_h: Option<f64> = None;
        for i in 1..rep_cmp.len() {
            let (p, q) = (&rep_cmp[i - 1], &rep_cmp[i]);
            let d = dist_km(p.lat, p.lon, q.lat, q.lon);
            if d < 0.05 {
                turn[i] = turn[i - 1];
                continue;
            }
            let dt = q.t - p.t;
            if dt <= 0.0 || d / KM_PER_NM / (dt / 3600.0) > k.vmax_kn {
                // A jump is not a turn.
                turn[i] = turn[i - 1];
                prev_h = None;
                continue;
            }
            let h = bearing_deg(p, q);
            let dturn = prev_h.map(|ph| wrap180(h - ph)).unwrap_or(0.0);
            turn[i] = turn[i - 1] + dturn;
            prev_h = Some(h);
        }
        let mut j = 0;
        let mut hit: Option<(f64, f64)> = None;
        for i in 0..rep_cmp.len() {
            while rep_cmp[i].t - rep_cmp[j].t > 3600.0 {
                j += 1;
            }
            if i - j + 1 >= 10 && (turn[i] - turn[j]).abs() >= 300.0 {
                hit = Some(match hit {
                    None => (rep_cmp[j].t, rep_cmp[i].t),
                    Some((a, _)) => (a, rep_cmp[i].t),
                });
            }
        }
        if let Some((a, b)) = hit {
            items.push(Item {
                family: Family::Track,
                finding: "The reported track runs in circles, a known pattern of false positions"
                    .into(),
                supports: vec![(SP, MOD)],
                against: vec![],
                sources: vec![rw.into()],
                from: a,
                to: b,
                observed: vec![],
                anomaly: true,
                tag: None,
            });
        }
    }

    // Reports without a position.
    if nulls.len() >= 3 {
        items.push(Item {
            family: Family::Track,
            finding: format!(
                "The {rw} transmitter kept reporting but without a position ({} reports)",
                nulls.len()
            ),
            supports: vec![(JA, MOD), (FT, WK)],
            against: vec![],
            sources: vec![rw.into()],
            from: nulls[0],
            to: nulls[nulls.len() - 1],
            observed: vec![],
            anomaly: true,
            tag: Some(Tag::RfInterference),
        });
    }

    // Silences while the subject was observed independently.
    let mut tx: Vec<f64> = rep
        .iter()
        .map(|p| p.t)
        .chain(nulls.iter().copied())
        .collect();
    tx.sort_by(|a, b| a.total_cmp(b));
    let mut gaps: Vec<(f64, f64)> = vec![];
    for w in tx.windows(2) {
        if w[1] - w[0] >= k.gap_s {
            let seen = ind
                .iter()
                .filter(|s| s.kind.category() != Cat::Relay)
                .flat_map(|s| s.pts.iter())
                .filter(|p| p.t > w[0] && p.t < w[1])
                .count();
            if seen >= 2 {
                gaps.push((w[0], w[1]));
            }
        }
    }
    if !gaps.is_empty() {
        let longest = gaps.iter().map(|g| g.1 - g.0).fold(0.0, f64::max);
        items.push(Item {
            family: Family::Track,
            finding: format!(
                "The {rw} reports fell silent while the {pw} was observed independently"
            ),
            supports: match req.platform {
                Platform::Vessel => vec![(FA, MOD), (FT, WK)],
                Platform::Aircraft => vec![(FA, WK), (FT, WK)],
            },
            against: vec![],
            sources: vec![rw.into()],
            from: gaps[0].0,
            to: gaps[gaps.len() - 1].1,
            observed: vec![("longest_silence_minutes", longest / 60.0)],
            anomaly: true,
            tag: None,
        });
    }
    rep_cmp
}

/// Cross-source disagreement patterns.
fn cross_findings(c: &Ctx, rep_cmp: &[Pt], items: &mut Vec<Item>) -> Cross {
    let (k, ind, pw) = (&c.k, &c.ind, c.pw);
    let (w0, w1) = (c.w0, c.w1);
    let mut cmps: [Vec<Cmp>; 3] = [vec![], vec![], vec![]];
    let cat_i = |c: Cat| match c {
        Cat::Free => 0,
        Cat::Separate => 1,
        Cat::Relay => 2,
    };
    for (si, s) in ind.iter().enumerate() {
        let thr = (3.0 * s.sigma).max(k.floor_km);
        for p in &s.pts {
            if let Some((la, lo)) = interp(rep_cmp, p.t, k.interp_gap_s) {
                cmps[cat_i(s.kind.category())].push(Cmp {
                    t: p.t,
                    d_km: dist_km(la, lo, p.lat, p.lon),
                    thr_km: thr,
                    src: si,
                    lat: p.lat,
                    lon: p.lon,
                });
            }
        }
    }
    let free = cat_stats(&cmps[0]);
    let sep = cat_stats(&cmps[1]);
    let relay = cat_stats(&cmps[2]);
    let src_names = |c: &[Cmp], idx: &[usize]| {
        let mut v: Vec<String> = idx.iter().map(|&i| ind[c[i].src].label.clone()).collect();
        v.sort();
        v.dedup();
        v
    };
    let span_of = |c: &[Cmp], idx: &[usize]| span(idx.iter().map(|&i| c[i].t)).unwrap_or((w0, w1));

    if free.disagreement() {
        let names = src_names(&cmps[0], &free.dis);
        let st = if free.dis.len() >= 3 || names.len() >= 2 {
            STR
        } else if free.dis.len() == 2 {
            MOD
        } else {
            WK
        };
        let (a, b) = span_of(&cmps[0], &free.dis);
        items.push(Item {
            family: Family::CrossSource,
            finding: format!(
                "The reported positions disagree with observations that do not depend on the {pw}'s GNSS"
            ),
            supports: vec![(SP, st), (FA, st)],
            against: vec![(JA, WK)],
            sources: names,
            from: a,
            to: b,
            observed: vec![
                ("max_offset_km", free.max_d),
                ("share_of_observations", free.frac()),
            ],
            anomaly: true,
            tag: Some(Tag::TrackFalse),
        });
    } else if free.agreement(3) {
        let all: Vec<usize> = (0..free.n).collect();
        let st = if free.n >= 5 { STR } else { MOD };
        items.push(Item {
            family: Family::CrossSource,
            finding: format!(
                "The reported positions agree with observations that do not depend on the {pw}'s GNSS"
            ),
            supports: vec![],
            against: vec![(SP, st), (FA, st)],
            sources: src_names(&cmps[0], &all),
            from: w0,
            to: w1,
            observed: vec![],
            anomaly: false,
            tag: Some(Tag::TrackTrue),
        });
    }

    if sep.disagreement() {
        let (a, b) = span_of(&cmps[1], &sep.dis);
        items.push(Item {
            family: Family::CrossSource,
            finding: "A separate GNSS-based position report from the same platform disagrees with the reported track".into(),
            supports: vec![(SP, MOD), (FA, MOD)],
            against: vec![],
            sources: src_names(&cmps[1], &sep.dis),
            from: a,
            to: b,
            observed: vec![("max_offset_km", sep.max_d)],
            anomaly: true,
            tag: Some(Tag::TrackFalse),
        });
    } else if sep.n >= 1 && sep.dis.is_empty() {
        let (fa, fb) = span_of(&cmps[0], &free.dis);
        let overlaps = cmps[1]
            .iter()
            .any(|c| c.t >= fa - 3600.0 && c.t <= fb + 3600.0);
        let all: Vec<usize> = (0..sep.n).collect();
        if free.disagreement() && overlaps {
            items.push(Item {
                family: Family::CrossSource,
                finding:
                    "A second, separate GNSS receiver on board reported the same false positions"
                        .into(),
                supports: vec![(SP, STR)],
                against: vec![(FA, MOD)],
                sources: src_names(&cmps[1], &all),
                from: fa,
                to: fb,
                observed: vec![],
                anomaly: true,
                tag: Some(Tag::TrackFalse),
            });
        } else if free.n == 0 && sep.n >= 2 {
            items.push(Item {
                family: Family::CrossSource,
                finding: "A separate GNSS-based position report from the same platform agrees with the reported track".into(),
                supports: vec![],
                against: vec![(FA, MOD)],
                sources: src_names(&cmps[1], &all),
                from: w0,
                to: w1,
                observed: vec![],
                anomaly: false,
                tag: None,
            });
        }
    }

    if relay.disagreement() {
        let (a, b) = span_of(&cmps[2], &relay.dis);
        items.push(Item {
            family: Family::CrossSource,
            finding: "The same identity was received at a second, different position".into(),
            supports: vec![(FA, MOD), (SP, WK)],
            against: vec![],
            sources: src_names(&cmps[2], &relay.dis),
            from: a,
            to: b,
            observed: vec![("max_offset_km", relay.max_d)],
            anomaly: true,
            tag: Some(Tag::TrackFalse),
        });
    }
    // Reception geometry: a relay station heard positions it cannot hear.
    let mut out_of_range: Vec<(f64, f64, String)> = vec![];
    for s in ind.iter().filter(|s| s.kind.category() == Cat::Relay) {
        let Some((sla, slo, r)) = s.station else {
            continue;
        };
        for p in &s.pts {
            let d = dist_km(p.lat, p.lon, sla, slo);
            if d > 1.3 * r {
                out_of_range.push((p.t, d / r, s.label.clone()));
            }
        }
    }
    if !out_of_range.is_empty() {
        let mut names: Vec<String> = out_of_range.iter().map(|x| x.2.clone()).collect();
        names.sort();
        names.dedup();
        let (a, b) = span(out_of_range.iter().map(|x| x.0)).unwrap_or((w0, w1));
        items.push(Item {
            family: Family::CrossSource,
            finding: "The reports were received by a station out of radio range of the positions they gave".into(),
            supports: if out_of_range.len() >= 3 {
                vec![(SP, STR), (FA, STR)]
            } else {
                vec![(SP, MOD), (FA, MOD)]
            },
            against: vec![(JA, WK)],
            sources: names,
            from: a,
            to: b,
            observed: vec![(
                "furthest_in_station_ranges",
                out_of_range.iter().map(|x| x.1).fold(0.0, f64::max),
            )],
            anomaly: true,
            tag: Some(Tag::TrackFalse),
        });
    }
    let [free_cmps, _, _] = cmps;
    Cross { free_cmps, free }
}

/// Signal-level signatures and the receiver's own positions.
fn receiver_findings(
    c: &Ctx,
    rx: &Receiver,
    rep_cmp: &[Pt],
    cross: &Cross,
    items: &mut Vec<Item>,
) -> Result<(), String> {
    let (k, rw, pw) = (&c.k, c.rw, c.pw);
    let (w0, w1) = (c.w0, c.w1);
    let inw = |t: f64| t >= w0 && t <= w1;
    let mut eps: Vec<Ep> = Vec::with_capacity(rx.epochs.len());
    for (i, e) in rx.epochs.iter().enumerate() {
        let t =
            e.t.secs()
                .map_err(|x| format!("receiver.epochs[{i}]: {x}"))?;
        let fin: Vec<f64> = e
            .cn0_dbhz
            .iter()
            .copied()
            .filter(|c| c.is_finite() && *c > 0.0 && *c < 80.0)
            .collect();
        let cn0 = if fin.is_empty() {
            e.cn0_mean_dbhz.filter(|c| c.is_finite())
        } else {
            Some(fin.iter().sum::<f64>() / fin.len() as f64)
        };
        let std = (fin.len() >= 4).then(|| {
            let m = fin.iter().sum::<f64>() / fin.len() as f64;
            (fin.iter().map(|c| (c - m).powi(2)).sum::<f64>() / (fin.len() - 1) as f64).sqrt()
        });
        let nsat = e
            .n_sats
            .map(|n| n as f64)
            .or((!fin.is_empty()).then_some(fin.len() as f64));
        let pos = match (e.lat_deg, e.lon_deg) {
            (Some(la), Some(lo)) => {
                check_pos(la, lo, &format!("receiver.epochs[{i}]"))?;
                Some((la, lo))
            }
            _ => None,
        };
        eps.push(Ep {
            t,
            fix: e.fix,
            cn0,
            std,
            nsat,
            agc: e.agc_db.filter(|a| a.is_finite()),
            pos,
            clock: e.clock_bias_ns.filter(|c| c.is_finite()),
        });
    }
    eps.sort_by(|a, b| a.t.total_cmp(&b.t));
    // Baseline: epochs before the window, else the first sixth.
    let before = eps.iter().filter(|e| e.t < w0).count();
    let nb = if before >= 5 {
        before
    } else if eps.len() >= 12 {
        (eps.len() / 6).max(5)
    } else {
        0
    };
    let base = &eps[..nb];
    let med = |f: &dyn Fn(&Ep) -> Option<f64>| {
        let mut v: Vec<f64> = base.iter().filter_map(f).collect();
        median(&mut v)
    };
    let b_cn0 = rx.baseline_cn0_dbhz.or_else(|| med(&|e| e.cn0));
    let b_agc = rx.baseline_agc_db.or_else(|| med(&|e| e.agc));
    let b_n = med(&|e| e.nsat);
    let b_std = med(&|e| e.std);
    let mut b_drift = {
        let mut v: Vec<f64> = base
            .windows(2)
            .filter_map(|w| match (w[0].clock, w[1].clock) {
                (Some(a), Some(b)) if w[1].t > w[0].t => Some((b - a) / (w[1].t - w[0].t)),
                _ => None,
            })
            .collect();
        median(&mut v).unwrap_or(0.0)
    };
    if !b_drift.is_finite() {
        b_drift = 0.0;
    }
    let assess: Vec<&Ep> = eps[nb..].iter().filter(|e| inw(e.t)).collect();
    let (mut jam, mut spoof, mut nofix_ok, mut assessed) = (vec![], vec![], vec![], 0usize);
    let (mut jam_agc, mut spoof_uniform, mut worst_drop, mut most_lost) = (0, 0, 0.0f64, 0.0f64);
    let mut agc_seen = false;
    if b_cn0.is_some() || b_agc.is_some() || b_n.is_some() {
        for e in &assess {
            if e.cn0.is_none() && e.agc.is_none() && e.nsat.is_none() && e.fix.is_none() {
                continue;
            }
            assessed += 1;
            let d_cn0 = match (e.cn0, b_cn0) {
                (Some(c), Some(b)) => Some(c - b),
                _ => None,
            };
            let d_agc = match (e.agc, b_agc) {
                (Some(a), Some(b)) => {
                    agc_seen = true;
                    Some(a - b)
                }
                _ => None,
            };
            let lost = match (e.nsat, b_n) {
                (Some(n), Some(b)) if b > 0.0 => (b - n) / b,
                _ => 0.0,
            };
            let drop = d_cn0.is_some_and(|d| d <= -6.0);
            let satloss = lost >= 0.5;
            let agc_big = d_agc.is_some_and(|d| d <= -4.0);
            let agc_mild = d_agc.is_some_and(|d| d <= -1.0 && d > -4.0);
            let rise = d_cn0.is_some_and(|d| d >= 3.0);
            let uniform = e
                .std
                .is_some_and(|s| s <= 2.0 && b_std.is_none_or(|b| s <= 0.5 * b));
            let spoof_like = (rise && (uniform || agc_mild))
                || (uniform && d_cn0.is_some_and(|d| d >= -1.0) && b_std.is_some_and(|b| b >= 3.0));
            let jam_like = !spoof_like
                && (drop
                    || satloss
                    || agc_big
                    || (e.fix == Some(false)
                        && e.cn0.is_none()
                        && d_agc.is_some_and(|d| d <= -2.0)));
            if spoof_like {
                spoof.push(e.t);
                if uniform {
                    spoof_uniform += 1;
                }
            } else if jam_like {
                jam.push(e.t);
                if agc_big {
                    jam_agc += 1;
                }
                if let Some(d) = d_cn0 {
                    worst_drop = worst_drop.max(-d);
                }
                most_lost = most_lost.max(lost);
            } else if e.fix == Some(false)
                && d_cn0.is_some_and(|d| d.abs() < 3.0)
                && !satloss
                && d_agc.is_none_or(|d| d > -1.0)
            {
                nofix_ok.push(e.t);
            }
        }
    }
    if jam.len() >= 3 {
        let (a, b) = (jam[0], jam[jam.len() - 1]);
        let mut obs = vec![];
        if worst_drop > 0.0 {
            obs.push(("cn0_drop_db", worst_drop));
        }
        if most_lost > 0.0 {
            obs.push(("share_of_satellites_lost", most_lost));
        }
        if jam_agc * 2 >= jam.len() {
            items.push(Item {
                family: Family::Signal,
                finding: "GNSS signals were drowned out: signal-to-noise fell across the sky while in-band power rose (the receiver's gain was pulled down)".into(),
                supports: vec![(JA, STR)],
                against: vec![(FA, MOD), (FT, MOD)],
                sources: vec!["receiver".into()],
                from: a,
                to: b,
                observed: obs,
                anomaly: true,
                tag: Some(Tag::RfInterference),
            });
        } else if agc_seen {
            items.push(Item {
                family: Family::Signal,
                finding: "GNSS signal levels fell while in-band power stayed normal, consistent with an antenna or cable problem".into(),
                supports: vec![(FT, MOD), (JA, WK)],
                against: vec![(FA, WK)],
                sources: vec!["receiver".into()],
                from: a,
                to: b,
                observed: obs,
                anomaly: true,
                tag: None,
            });
        } else {
            items.push(Item {
                family: Family::Signal,
                finding: "GNSS signal-to-noise fell broadly and satellites were lost".into(),
                supports: vec![(JA, MOD), (FT, WK)],
                against: vec![(FA, WK)],
                sources: vec!["receiver".into()],
                from: a,
                to: b,
                observed: obs,
                anomaly: true,
                tag: Some(Tag::RfInterference),
            });
        }
    }
    if spoof.len() >= 3 {
        let uniform = spoof_uniform * 2 >= spoof.len();
        items.push(Item {
            family: Family::Signal,
            finding: if uniform {
                "GNSS signals became stronger and unnaturally uniform across satellites, as from a single transmitter".into()
            } else {
                "GNSS signals became stronger than normal for this installation".into()
            },
            supports: vec![(SP, if uniform { STR } else { MOD })],
            against: vec![(JA, WK), (FA, MOD), (FT, WK)],
            sources: vec!["receiver".into()],
            from: spoof[0],
            to: spoof[spoof.len() - 1],
            observed: vec![],
            anomaly: true,
            tag: Some(Tag::RfInterference),
        });
    }
    if nofix_ok.len() >= 3 {
        items.push(Item {
            family: Family::Signal,
            finding: "The receiver lost its position fix while GNSS signals were normal".into(),
            supports: vec![(FT, STR)],
            against: vec![(JA, MOD), (SP, WK)],
            sources: vec!["receiver".into()],
            from: nofix_ok[0],
            to: nofix_ok[nofix_ok.len() - 1],
            observed: vec![],
            anomaly: true,
            tag: None,
        });
    }
    // Clock steps (millisecond resets are normal receiver behaviour and are ignored).
    let mut steps: Vec<(f64, f64)> = vec![];
    for w in assess.windows(2) {
        let (Some(c0), Some(c1)) = (w[0].clock, w[1].clock) else {
            continue;
        };
        let dt = w[1].t - w[0].t;
        if dt <= 0.0 || dt > 60.0 {
            continue;
        }
        let r = c1 - c0 - b_drift * dt;
        let ms = (r / 1.0e6).round() * 1.0e6;
        if r.abs() > 1000.0 && (r - ms).abs() > 1000.0 {
            steps.push((w[1].t, r.abs()));
        }
    }
    if !steps.is_empty() {
        items.push(Item {
            family: Family::Signal,
            finding: "The receiver clock stepped by more than its normal behaviour explains".into(),
            supports: vec![(SP, MOD), (FT, WK)],
            against: vec![],
            sources: vec!["receiver".into()],
            from: steps[0].0,
            to: steps[steps.len() - 1].0,
            observed: vec![(
                "largest_step_us",
                steps.iter().map(|s| s.1).fold(0.0, f64::max) / 1000.0,
            )],
            anomaly: true,
            tag: Some(Tag::RfInterference),
        });
    }
    // The receiver's own positions.
    let rxp: Vec<Pt> = eps
        .iter()
        .filter(|e| e.fix != Some(false) && inw(e.t))
        .filter_map(|e| {
            e.pos.map(|(la, lo)| Pt {
                t: e.t,
                lat: la,
                lon: lo,
                sog: None,
            })
        })
        .collect();
    let mut rx_jumps: Vec<f64> = vec![];
    for w in rxp.windows(2) {
        let d = dist_km(w[0].lat, w[0].lon, w[1].lat, w[1].lon);
        let dt = w[1].t - w[0].t;
        if d >= k.jump_min_km && (dt <= 0.0 || d / KM_PER_NM / (dt / 3600.0) > k.vmax_kn) {
            rx_jumps.push(w[1].t);
        }
    }
    if !rx_jumps.is_empty() {
        items.push(Item {
            family: Family::Signal,
            finding: format!(
                "The receiver's own position solution jumped faster than a {pw} can move"
            ),
            supports: vec![(SP, MOD), (FT, WK)],
            against: vec![(FA, WK)],
            sources: vec!["receiver".into()],
            from: rx_jumps[0],
            to: rx_jumps[rx_jumps.len() - 1],
            observed: vec![],
            anomaly: true,
            tag: Some(Tag::RfInterference),
        });
    }
    if !rxp.is_empty() {
        let rx_gap = k.interp_gap_s.min(600.0);
        let (mut fd, mut follows_rep, mut follows_ind) = (0usize, 0usize, 0usize);
        let mut fspan: Vec<f64> = vec![];
        for &i in &cross.free.dis {
            let c = &cross.free_cmps[i];
            let (Some((rla, rlo)), Some((pla, plo))) = (
                interp(&rxp, c.t, rx_gap),
                interp(rep_cmp, c.t, k.interp_gap_s),
            ) else {
                continue;
            };
            fd += 1;
            fspan.push(c.t);
            if dist_km(rla, rlo, pla, plo) <= k.rr_km.max(c.thr_km / 3.0) {
                follows_rep += 1;
            } else if dist_km(rla, rlo, c.lat, c.lon) <= c.thr_km {
                follows_ind += 1;
            }
        }
        let (fa, fb) = span(fspan.iter().copied()).unwrap_or((w0, w1));
        if fd >= 2 && follows_rep as f64 >= 0.6 * fd as f64 {
            items.push(Item {
                family: Family::Signal,
                finding: format!("The onboard GNSS receiver itself produced the false positions that the {rw} broadcast carried"),
                supports: vec![(SP, STR)],
                against: vec![(FA, STR)],
                sources: vec!["receiver".into()],
                from: fa,
                to: fb,
                observed: vec![],
                anomaly: true,
                tag: Some(Tag::TrackFalse),
            });
        } else if fd >= 2 && follows_ind as f64 >= 0.6 * fd as f64 {
            items.push(Item {
                family: Family::Signal,
                finding: format!("The {rw} broadcast departs from the onboard GNSS receiver, whose positions agree with the independent observations"),
                supports: vec![(FA, STR)],
                against: vec![(SP, STR), (JA, MOD)],
                sources: vec!["receiver".into()],
                from: fa,
                to: fb,
                observed: vec![],
                anomaly: true,
                tag: Some(Tag::TrackFalse),
            });
        } else if !cross.free.disagreement() {
            let mut n = 0usize;
            let mut dis: Vec<(f64, f64)> = vec![];
            for p in &rxp {
                if let Some((la, lo)) = interp(rep_cmp, p.t, k.interp_gap_s) {
                    n += 1;
                    let d = dist_km(la, lo, p.lat, p.lon);
                    if d > k.rr_km {
                        dis.push((p.t, d));
                    }
                }
            }
            if n >= 3 && dis.len() as f64 >= 0.3 * n as f64 {
                items.push(Item {
                    family: Family::Signal,
                    finding: format!(
                        "The {rw} broadcast departs from the onboard GNSS receiver's own positions"
                    ),
                    supports: vec![(FA, MOD), (FT, WK)],
                    against: vec![(SP, WK)],
                    sources: vec!["receiver".into()],
                    from: dis[0].0,
                    to: dis[dis.len() - 1].0,
                    observed: vec![("max_offset_km", dis.iter().map(|x| x.1).fold(0.0, f64::max))],
                    anomaly: true,
                    tag: Some(Tag::TrackFalse),
                });
            }
        }
    }
    if nb > 0 && assessed >= 10 && jam.is_empty() && spoof.is_empty() {
        items.push(Item {
            family: Family::Signal,
            finding: "GNSS signal levels stayed normal for this installation throughout".into(),
            supports: vec![(FA, WK), (FT, WK)],
            against: vec![(JA, STR), (SP, WK)],
            sources: vec!["receiver".into()],
            from: w0,
            to: w1,
            observed: vec![],
            anomaly: false,
            tag: Some(Tag::RfNormal),
        });
    }
    Ok(())
}

/// Correlation with regional interference reports.
fn regional_findings(c: &Ctx, evs: &[ievents::Event], items: &mut Vec<Item>) -> Result<(), String> {
    let (k, rep, ind) = (&c.k, &c.rep, &c.ind);
    let (w0, w1) = (c.w0, c.w1);
    let anomaly_span = span(
        items
            .iter()
            .filter(|i| i.anomaly)
            .flat_map(|i| [i.from, i.to]),
    );
    let (a0, a1) = anomaly_span.unwrap_or((w0, w1));
    let (q0, q1) = (a0 - 900.0, a1 + 900.0);
    let here: Vec<(f64, f64)> = rep
        .iter()
        .map(|p| (p.t, p.lat, p.lon))
        .chain(
            ind.iter()
                .filter(|s| s.kind.category() == Cat::Free)
                .flat_map(|s| s.pts.iter().map(|p| (p.t, p.lat, p.lon))),
        )
        .filter(|(t, _, _)| *t >= q0 && *t <= q1)
        .map(|(_, la, lo)| (la, lo))
        .collect();
    // (kind group, located, observers, corroborated, t0, t1)
    let mut hits: Vec<(u8, bool, Vec<String>, bool, f64, f64)> = vec![];
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
        let group = match e.kind {
            ievents::Kind::Jamming | ievents::Kind::Outage => 0u8,
            ievents::Kind::Spoofing | ievents::Kind::Meaconing => 1,
            ievents::Kind::Unknown => 2,
            ievents::Kind::StationFault => continue,
        };
        let located = match &e.location {
            Some(l) if !here.is_empty() => {
                let reach = l.radius_m / 1000.0 + k.reg_km;
                if !here
                    .iter()
                    .any(|(la, lo)| dist_km(*la, *lo, l.lat_deg, l.lon_deg) <= reach)
                {
                    continue;
                }
                true
            }
            Some(_) => false,
            None if e.area.as_deref().is_some_and(|a| !a.trim().is_empty()) => false,
            None => continue,
        };
        hits.push((group, located, e.observers.clone(), e.corroborated, s, t));
    }
    for (g, name, class) in [(0u8, "jamming", JA), (1u8, "spoofing", SP)] {
        let hs: Vec<_> = hits.iter().filter(|h| h.0 == g).collect();
        if hs.is_empty() {
            continue;
        }
        let mut obs: Vec<String> = hs.iter().flat_map(|h| h.2.iter().cloned()).collect();
        obs.sort();
        obs.dedup();
        let located = hs.iter().any(|h| h.1);
        let st = if !located {
            WK
        } else if hs.iter().any(|h| h.3) || obs.len() >= 2 {
            STR
        } else {
            MOD
        };
        let (a, b) = span(hs.iter().flat_map(|h| [h.4, h.5])).unwrap_or((q0, q1));
        items.push(Item {
            family: Family::Regional,
            finding: format!(
                "Regional monitoring reported {name} {} at the time ({} report{}, {} observer{})",
                if located { "nearby" } else { "in the area" },
                hs.len(),
                if hs.len() == 1 { "" } else { "s" },
                obs.len(),
                if obs.len() == 1 { "" } else { "s" }
            ),
            supports: vec![(class, st)],
            against: vec![(FA, WK), (FT, WK)],
            sources: vec!["regional".into()],
            from: a.max(w0),
            to: b.min(w1),
            observed: vec![],
            anomaly: false,
            tag: Some(Tag::RfInterference),
        });
    }
    let unk: Vec<_> = hits.iter().filter(|h| h.0 == 2).collect();
    if !unk.is_empty() {
        items.push(Item {
            family: Family::Regional,
            finding: "Regional monitoring reported interference of unknown kind at the time".into(),
            supports: vec![(JA, WK), (SP, WK)],
            against: vec![],
            sources: vec!["regional".into()],
            from: w0,
            to: w1,
            observed: vec![],
            anomaly: false,
            tag: Some(Tag::RfInterference),
        });
    }
    if hits.is_empty() {
        items.push(Item {
            family: Family::Regional,
            finding: "Regional monitoring reported no interference near the platform at the time"
                .into(),
            supports: vec![(FA, WK), (FT, WK)],
            against: vec![(JA, WK), (SP, WK)],
            sources: vec!["regional".into()],
            from: q0.max(w0),
            to: q1.min(w1),
            observed: vec![],
            anomaly: false,
            tag: None,
        });
    }
    Ok(())
}

/// Combine the findings into the outcome.
fn outcome(c: &Ctx, mut items: Vec<Item>, has_rx: bool, n_regional: usize) -> Value {
    let (rep, nulls, ind, rw, pw, req) = (&c.rep, &c.nulls, &c.ind, c.rw, c.pw, c.req);
    let (w0, w1) = (c.w0, c.w1);
    let mut score = [0.0f64; 4];
    for it in &items {
        for (c, s) in &it.supports {
            score[c.idx()] += s.w();
        }
        for (c, s) in &it.against {
            score[c.idx()] -= s.w();
        }
    }
    let mx = score.iter().cloned().fold(f64::MIN, f64::max);
    let ex: Vec<f64> = score.iter().map(|s| (s - mx).exp()).collect();
    let z: f64 = ex.iter().sum();
    let mut order: Vec<usize> = (0..4).collect();
    order.sort_by(|a, b| ex[*b].total_cmp(&ex[*a]));
    let top = CLASSES[order[0]];
    let runner = CLASSES[order[1]];
    let p_top = ex[order[0]] / z;
    let mut fam_set: Vec<u8> = items
        .iter()
        .filter(|i| i.supports.iter().any(|(c, _)| *c == top))
        .map(|i| i.family as u8)
        .collect();
    fam_set.sort();
    fam_set.dedup();
    let cap = match fam_set.len() {
        0 | 1 => 0.7,
        2 => 0.85,
        _ => 0.95,
    };
    let conf = (p_top.min(cap) * 20.0 + 1e-9).floor() / 20.0;
    let has_anomaly = items.iter().any(|i| i.anomaly);
    let decided = has_anomaly && conf >= DECIDE_AT;
    let classification = if decided { top.name() } else { INSUFFICIENT };
    let band = |c: f64| {
        if c >= 0.85 {
            "high"
        } else if c >= 0.7 {
            "medium"
        } else {
            "low"
        }
    };

    // The episode window: anomalies supporting the named cause (or all anomalies).
    let win = span(
        items
            .iter()
            .filter(|i| i.anomaly && (!decided || i.supports.iter().any(|(c, _)| *c == top)))
            .flat_map(|i| [i.from, i.to]),
    );

    let has_tag = |t: Tag| items.iter().any(|i| i.tag == Some(t));
    let track = if has_tag(Tag::TrackFalse) {
        "false"
    } else if has_tag(Tag::TrackTrue) {
        "consistent_with_independent_sources"
    } else {
        "undetermined"
    };
    let rf = if has_tag(Tag::RfInterference) {
        "indicated"
    } else if has_tag(Tag::RfNormal) {
        "not_indicated"
    } else {
        "undetermined"
    };
    let origin = match (decided, top) {
        (false, _) => "undetermined",
        (true, JA | SP) => "external",
        (true, FA) => match req.platform {
            Platform::Vessel => "own_ship",
            Platform::Aircraft => "own_aircraft",
        },
        (true, FT) => "equipment",
    };

    items.sort_by(|a, b| {
        b.strength()
            .cmp(&a.strength())
            .then(a.from.total_cmp(&b.from))
    });
    let evidence: Vec<Value> = items
        .iter()
        .map(|i| {
            let mut sup: Vec<&str> = i.supports.iter().map(|(c, _)| c.name()).collect();
            sup.dedup();
            let ag: Vec<&str> = i.against.iter().map(|(c, _)| c.name()).collect();
            let mut o = serde_json::Map::new();
            for (key, val) in &i.observed {
                o.insert((*key).into(), json!(val));
            }
            json!({
                "finding": i.finding,
                "strength": i.strength().name(),
                "supports": sup,
                "weighs_against": ag,
                "sources": i.sources,
                "window": {"start_utc": iso(i.from.floor() as i64), "end_utc": iso(i.to.ceil() as i64)},
                "observed": Value::Object(o),
            })
        })
        .collect();

    let mut limits: Vec<String> = vec![
        "MODELLED: rules checked on synthetic episodes with known cause; not validated on a labelled set of real incidents".into(),
        "An engineering reconstruction of the data supplied, not a legal finding; intent is not assessed".into(),
    ];
    if ind.iter().all(|s| s.kind.category() != Cat::Free) {
        limits.push(format!(
            "No position source independent of the {pw}'s GNSS was supplied"
        ));
    }
    if ind.iter().any(|s| s.kind.category() == Cat::Relay) {
        limits.push(format!("Satellite and coastal {rw} receptions repeat the subject's own reports; they are not independent position fixes"));
    }
    if ind.iter().any(|s| s.kind.category() == Cat::Separate) {
        limits.push(
            "LRIT and secondary receivers use GNSS too and share the platform's radio environment"
                .into(),
        );
    }
    if has_rx {
        limits.push("Receiver logs supplied by the platform's operator are only as trustworthy as their chain of custody".into());
    } else {
        limits.push(
            "No GNSS receiver observables were supplied; signal-level signatures were not assessed"
                .into(),
        );
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
        "platform": pw,
        "subject_id": req.subject_id,
        "window": win.map(|(a, b)| json!({"start_utc": iso(a.floor() as i64), "end_utc": iso(b.ceil() as i64)})),
        "analysed": {
            "start_utc": iso(w0.floor() as i64),
            "end_utc": iso(w1.ceil() as i64),
            "reported_positions": rep.len(),
            "reports_without_position": nulls.len(),
            "independent_sources": ind.iter().map(|s| s.kind.name()).collect::<std::collections::BTreeSet<_>>(),
            "receiver_epochs": req.receiver.as_ref().map(|r| r.epochs.len()).unwrap_or(0),
            "regional_reports": n_regional,
        },
        "questions": {
            "reported_track": track,
            "rf_interference": rf,
            "origin": origin,
        },
        "evidence": evidence,
        "limits": limits,
    });
    if decided {
        v["confidence"] = json!(conf);
        v["confidence_band"] = json!(band(conf));
        v["runner_up"] = json!(runner.name());
    } else if has_anomaly {
        v["leading_hypothesis"] = json!(top.name());
        v["leading_confidence"] = json!(conf);
        v["runner_up"] = json!(runner.name());
    }
    v
}

#[cfg(test)]
#[path = "cause_tests.rs"]
mod tests;
