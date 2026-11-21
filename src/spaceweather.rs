// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The `spaceweather` method: a hosted space-weather advisory for GNSS users, per location and
//! per positioning service, from **live ionosphere inputs** and **per-region thresholds**
//! (research backlog E35, the hosted part of B3502).
//!
//! The Kshana Pro client runs a local advisor on public indices (Kp from GFZ and NOAA SWPC, the
//! NOAA G scale, a climatological scintillation level). What it cannot have locally is what this
//! method adds:
//!
//! * **live inputs**, read from a directory a separate fetcher keeps current
//!   (`MERU_SPACEWX_SOURCE`): the NOAA SWPC planetary K-index product (`kp/*.json`), maps of the
//!   rate of TEC index ROTI from reference-station networks (`roti/*.json`,
//!   `meru-roti-map/1`) and amplitude scintillation S4 from monitoring stations (`s4/*.json`,
//!   `meru-s4-obs/1`). Which networks feed the last two is to confirm;
//! * **per-region thresholds**: the levels at which ROTI, S4 and Kp degrade RTK, PPP and
//!   single-frequency positioning differ between the equatorial anomaly, mid latitudes, the
//!   auroral oval and the polar cap, and an operator can calibrate them for named regions
//!   (`MERU_SPACEWX_REGIONS`). The default table stays in the service.
//!
//! Per location: the region (named or by geomagnetic band), the level of each indicator and the
//! overall level (`quiet`, `moderate`, `high`), the indicator that drove it, the status per
//! service (`go`, `caution`, `no_go`), the NOAA G scale, the inputs used with their age, and how
//! long the advisory stays valid. Inputs too old are not used and the advisory says so.
//!
//! Advisory only: not a forecast of any receiver's behaviour and not an operational instruction.
//! Evidence class MODELLED: the default thresholds follow published climatology, simplified,
//! and are not calibrated against observed receiver outcomes in any region.

use crate::cause::Time;
use crate::server::iso;
use kshana_pro::kshana::env_baseline::dipole_latitude_deg;
use kshana_pro::kshana::igrf::magnetic_field;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Method identifier written into every outcome. A change to any rule is a new version.
pub const METHOD_VERSION: &str = "spaceweather/1";

/// What every verdict says about itself.
pub const STATEMENT: &str = "A space-weather advisory from the inputs named. Not a forecast of \
any receiver's behaviour and not an operational instruction.";

/// A Kp value is used for this long after its 3-hour interval starts, seconds.
const KP_VALID_S: f64 = 6.0 * 3600.0;
/// A ROTI map or an S4 observation is used for this long after its epoch, seconds.
const LIVE_VALID_S: f64 = 30.0 * 60.0;
/// The advisory from live data holds for this long after `at`, and never past the moment its
/// newest live input stops being current ([`LIVE_VALID_S`] after its epoch), seconds.
const LIVE_HOLD_S: f64 = 15.0 * 60.0;
/// The advisory from Kp alone holds for this long after `at`, and never past [`KP_VALID_S`] after
/// the Kp interval's start, seconds.
const KP_HOLD_S: f64 = 3.0 * 3600.0;
/// A ROTI cell or an S4 station counts for a location within this distance, km.
const NEAR_KM: f64 = 400.0;
/// Newest files of each kind read on each call.
const MAX_FILES: usize = 16;

// ------------------------------------------------------------------------------------------
// Request
// ------------------------------------------------------------------------------------------

/// A location to advise on.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub id: String,
    pub lat_deg: f64,
    pub lon_deg: f64,
}

/// A positioning service the advisory speaks to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    /// Carrier-phase RTK with a base or a network.
    Rtk,
    /// Precise point positioning.
    Ppp,
    /// Single-frequency code positioning (with or without SBAS).
    SingleFrequency,
}

impl Service {
    fn name(self) -> &'static str {
        match self {
            Service::Rtk => "rtk",
            Service::Ppp => "ppp",
            Service::SingleFrequency => "single_frequency",
        }
    }
}

/// Request for the `spaceweather` method.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceWxRequest {
    pub locations: Vec<Location>,
    /// The time to advise for (default now). Inputs after it are not used.
    #[serde(default)]
    pub at_utc: Option<Time>,
    /// Services to advise on (default all).
    #[serde(default)]
    pub services: Option<Vec<Service>>,
}

/// Request limits.
#[derive(Clone, Debug)]
pub struct SpaceWxLimits {
    pub max_locations: usize,
    /// How far back `at_utc` may reach, days.
    pub max_lookback_days: f64,
}

impl Default for SpaceWxLimits {
    fn default() -> Self {
        SpaceWxLimits {
            max_locations: 200,
            max_lookback_days: 30.0,
        }
    }
}

/// Levels at which an indicator counts as moderate and high.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    /// ROTI, TECU per minute.
    pub roti_moderate: f64,
    pub roti_high: f64,
    /// S4 (dimensionless).
    pub s4_moderate: f64,
    pub s4_high: f64,
    /// Kp at which mid-latitude gradients start to upset RTK (moderate) and upset it (high).
    pub kp_moderate: f64,
    pub kp_high: f64,
}

/// A named region with its own thresholds (`MERU_SPACEWX_REGIONS`, `[[region]]`).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Region {
    pub name: String,
    pub lat_min: f64,
    pub lat_max: f64,
    pub lon_min: f64,
    pub lon_max: f64,
    #[serde(flatten)]
    pub thresholds: Thresholds,
    /// Where the thresholds come from (for example the campaign that calibrated them); echoed.
    pub basis: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegionFile {
    region: Vec<Region>,
}

/// Parse a regions file.
pub fn parse_regions(text: &str) -> Result<Vec<Region>, String> {
    let f: RegionFile = toml::from_str(text).map_err(|e| format!("regions: {e}"))?;
    for r in &f.region {
        let t = &r.thresholds;
        if !(r.lat_min < r.lat_max && r.lon_min < r.lon_max)
            || !(t.roti_moderate < t.roti_high
                && t.s4_moderate < t.s4_high
                && t.kp_moderate < t.kp_high)
        {
            return Err(format!(
                "region '{}': box minimum below maximum, and every moderate threshold below its high",
                r.name
            ));
        }
    }
    Ok(f.region)
}

/// Where the live inputs are and the regional calibrations.
#[derive(Clone, Debug, Default)]
pub struct SpaceWxConfig {
    /// Directory with `kp/`, `roti/` and `s4/`. `None`: the method is not offered.
    pub source_dir: Option<PathBuf>,
    /// Named regions with their own thresholds (searched in order before the default bands).
    pub regions: Vec<Region>,
}

// ------------------------------------------------------------------------------------------
// Inputs
// ------------------------------------------------------------------------------------------

/// One Kp value: start of its 3-hour interval, value.
#[derive(Clone, Copy, Debug)]
struct Kp {
    t: f64,
    kp: f64,
}

#[derive(Clone, Debug, Deserialize)]
struct RotiCell {
    lat_deg: f64,
    lon_deg: f64,
    roti_tecu_per_min: f64,
}

#[derive(Clone, Debug, Deserialize)]
struct RotiMap {
    format: String,
    epoch_utc: String,
    cells: Vec<RotiCell>,
}

#[derive(Clone, Debug, Deserialize)]
struct S4Station {
    #[serde(default)]
    #[allow(dead_code)]
    id: String,
    lat_deg: f64,
    lon_deg: f64,
    s4: f64,
}

#[derive(Clone, Debug, Deserialize)]
struct S4Obs {
    format: String,
    epoch_utc: String,
    stations: Vec<S4Station>,
}

/// The newest `.json` files of a kind, newest first.
fn newest(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|r| {
            r.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "json" || x == "txt"))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v.reverse();
    v.truncate(MAX_FILES);
    v
}

/// SWPC `time_tag` (`2026-11-13T00:00:00`, `2026-11-13 00:00:00.000`) as Unix seconds.
fn swpc_time(s: &str) -> Result<f64, String> {
    let s = s.trim().replace(' ', "T");
    let s = s.split('.').next().unwrap_or("");
    let s = if s.ends_with('Z') {
        s.to_string()
    } else {
        format!("{s}Z")
    };
    crate::cause::parse_iso(&s)
}

/// Parse a Kp file: the SWPC JSON product, or the GFZ Niemegk text file
/// (`Kp_ap_Ap_SN_F107_since_1932.txt` layout: `YYYY MM DD days days_m Bsr dB Kp1 … Kp8 …`, header
/// lines starting with `#`, missing Kp as -1). Kp_i covers the i-th three hours of the UT day.
fn parse_kp_any(text: &str) -> Result<Vec<Kp>, String> {
    if text.trim_start().starts_with('[') {
        return parse_kp(text);
    }
    let mut out = vec![];
    for l in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 15 {
            return Err("Kp: a GFZ line has fewer than 15 columns".into());
        }
        let day = crate::cause::parse_iso(&format!("{}-{}-{}T00:00:00Z", f[0], f[1], f[2]))
            .map_err(|e| format!("Kp: {e}"))?;
        for i in 0..8 {
            let kp: f64 = f[7 + i].parse().map_err(|_| "Kp: bad GFZ Kp value")?;
            if (0.0..=9.0).contains(&kp) {
                out.push(Kp {
                    t: day + 10_800.0 * i as f64,
                    kp,
                });
            }
        }
    }
    Ok(out)
}

/// Parse the SWPC planetary K-index product: a list of objects (`time_tag`, `Kp`) or the older
/// list of rows with a header row.
fn parse_kp(text: &str) -> Result<Vec<Kp>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("Kp: {e}"))?;
    let rows = v.as_array().ok_or("Kp: not a list")?;
    let mut out = vec![];
    for r in rows {
        let (t, k) = match r {
            Value::Object(o) => (o.get("time_tag"), o.get("Kp").or_else(|| o.get("kp"))),
            Value::Array(a) => (a.first(), a.get(1)),
            _ => (None, None),
        };
        let (Some(t), Some(k)) = (t.and_then(Value::as_str), k) else {
            continue;
        };
        let Ok(t) = swpc_time(t) else { continue };
        let k = match k {
            Value::Number(n) => n.as_f64(),
            Value::String(s) => s.trim().parse().ok(),
            _ => None,
        };
        if let Some(kp) = k.filter(|x| (0.0..=9.0).contains(x)) {
            out.push(Kp { t, kp });
        }
    }
    Ok(out)
}

/// The inputs in force at `at`.
#[derive(Default)]
struct Inputs {
    kp: Option<Kp>,
    roti: Option<(f64, Vec<RotiCell>)>,
    s4: Option<(f64, Vec<S4Station>)>,
    digest: Sha256,
    files: usize,
}

fn load(dir: &Path, at: f64) -> Result<Inputs, String> {
    let mut inp = Inputs::default();
    // The newest Kp at or before `at` across the newest files (file names need not sort by
    // time: an archive file can sort before a newer daily file).
    let mut kp_best: Option<(Kp, String)> = None;
    for p in newest(&dir.join("kp")) {
        let text = std::fs::read_to_string(&p).map_err(|e| format!("Kp input: {e}"))?;
        let best = parse_kp_any(&text)?
            .into_iter()
            .filter(|k| k.t <= at)
            .max_by(|a, b| a.t.total_cmp(&b.t));
        if let Some(k) = best {
            if kp_best.as_ref().is_none_or(|(c, _)| k.t > c.t) {
                kp_best = Some((k, text));
            }
        }
    }
    if let Some((k, text)) = kp_best {
        inp.kp = Some(k);
        inp.digest.update(text.as_bytes());
        inp.files += 1;
    }
    for p in newest(&dir.join("roti")) {
        let text = std::fs::read_to_string(&p).map_err(|e| format!("ROTI input: {e}"))?;
        let m: RotiMap = serde_json::from_str(&text).map_err(|e| format!("ROTI input: {e}"))?;
        if m.format != "meru-roti-map/1" {
            return Err(format!("ROTI input: unknown format '{}'", m.format));
        }
        let t = crate::cause::parse_iso(&m.epoch_utc)?;
        if t <= at {
            inp.roti = Some((t, m.cells));
            inp.digest.update(text.as_bytes());
            inp.files += 1;
            break;
        }
    }
    for p in newest(&dir.join("s4")) {
        let text = std::fs::read_to_string(&p).map_err(|e| format!("S4 input: {e}"))?;
        let m: S4Obs = serde_json::from_str(&text).map_err(|e| format!("S4 input: {e}"))?;
        if m.format != "meru-s4-obs/1" {
            return Err(format!("S4 input: unknown format '{}'", m.format));
        }
        let t = crate::cause::parse_iso(&m.epoch_utc)?;
        if t <= at {
            inp.s4 = Some((t, m.stations));
            inp.digest.update(text.as_bytes());
            inp.files += 1;
            break;
        }
    }
    Ok(inp)
}

// ------------------------------------------------------------------------------------------
// Regions and levels
// ------------------------------------------------------------------------------------------

/// The default bands. Ordered by how the band is found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Band {
    Equatorial,
    Mid,
    Auroral,
    PolarCap,
}

impl Band {
    fn name(self) -> &'static str {
        match self {
            Band::Equatorial => "equatorial",
            Band::Mid => "mid_latitude",
            Band::Auroral => "auroral",
            Band::PolarCap => "polar_cap",
        }
    }
    /// The default thresholds per band (MODELLED, after published climatology, simplified).
    fn thresholds(self) -> Thresholds {
        match self {
            Band::Equatorial => Thresholds {
                roti_moderate: 0.5,
                roti_high: 2.0,
                s4_moderate: 0.3,
                s4_high: 0.6,
                kp_moderate: 6.0,
                kp_high: 8.0,
            },
            Band::Mid => Thresholds {
                roti_moderate: 0.25,
                roti_high: 0.8,
                s4_moderate: 0.25,
                s4_high: 0.5,
                kp_moderate: 5.0,
                kp_high: 7.0,
            },
            Band::Auroral | Band::PolarCap => Thresholds {
                roti_moderate: 0.5,
                roti_high: 1.5,
                s4_moderate: 0.3,
                s4_high: 0.6,
                kp_moderate: 4.0,
                kp_high: 6.0,
            },
        }
    }
}

/// Decimal year of a Unix time (for the geomagnetic model).
fn year_of(t: f64) -> f64 {
    1970.0 + t / (365.2425 * 86_400.0)
}

/// The band of a location: equatorial by modified dip latitude, auroral by the Kp-dependent
/// oval boundary in geomagnetic latitude, polar cap above it.
fn band(lat: f64, lon: f64, kp: f64, year: f64) -> (Band, f64, f64) {
    let gmlat = dipole_latitude_deg(lat, lon, year);
    let inc = magnetic_field(lat, lon, 0.0, year).inclination_deg;
    let modip = (inc.to_radians() / lat.to_radians().cos().max(1e-6).sqrt())
        .atan()
        .to_degrees();
    let boundary = 66.0 - 2.0 * kp.max(0.0);
    let a = gmlat.abs();
    let b = if modip.abs() <= 30.0 {
        Band::Equatorial
    } else if a >= 80.0 {
        Band::PolarCap
    } else if a >= boundary - 3.0 {
        Band::Auroral
    } else {
        Band::Mid
    };
    (b, gmlat, modip)
}

fn level_of(x: f64, moderate: f64, high: f64) -> u8 {
    if x >= high {
        2
    } else if x >= moderate {
        1
    } else {
        0
    }
}

fn level_name(l: u8) -> &'static str {
    ["quiet", "moderate", "high"][l.min(2) as usize]
}

/// NOAA G scale from Kp.
fn g_scale(kp: f64) -> u8 {
    match kp {
        k if k >= 9.0 => 5,
        k if k >= 7.67 => 4,
        k if k >= 6.67 => 3,
        k if k >= 5.67 => 2,
        k if k >= 4.67 => 1,
        _ => 0,
    }
}

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

/// Status of a service at an overall level: RTK and PPP rely on carrier phase and suffer
/// first; single-frequency code positioning only at high.
fn status(s: Service, level: u8, band: Band) -> &'static str {
    match (s, level) {
        (_, 0) => "go",
        (Service::Rtk, 1) | (Service::Ppp, 1) => "caution",
        (Service::Rtk, _) | (Service::Ppp, _) => "no_go",
        (Service::SingleFrequency, 1) => "go",
        (Service::SingleFrequency, _) if band == Band::Equatorial => "no_go",
        (Service::SingleFrequency, _) => "caution",
    }
}

// ------------------------------------------------------------------------------------------
// The method
// ------------------------------------------------------------------------------------------

/// Run the method at time `now` (Unix seconds); the raw (unrounded, unsigned) outcome.
pub fn analyse(
    r: &SpaceWxRequest,
    l: &SpaceWxLimits,
    cfg: &SpaceWxConfig,
    now: f64,
) -> Result<Value, String> {
    let dir = cfg
        .source_dir
        .as_ref()
        .ok_or("spaceweather is not offered by this service (no live inputs configured)")?;
    if r.locations.is_empty() || r.locations.len() > l.max_locations {
        return Err(format!("1 to {} locations", l.max_locations));
    }
    for p in &r.locations {
        if !(p.lat_deg.abs() <= 90.0 && p.lon_deg.abs() <= 360.0) {
            return Err(format!("location '{}': position out of range", p.id));
        }
    }
    let at = match &r.at_utc {
        Some(t) => t.secs()?,
        None => now,
    };
    if at > now + 60.0 || at < now - l.max_lookback_days * 86_400.0 {
        return Err(format!(
            "at_utc must not be in the future or more than {} days back (this is not a forecast)",
            l.max_lookback_days
        ));
    }
    let services = r
        .services
        .clone()
        .unwrap_or_else(|| vec![Service::Rtk, Service::Ppp, Service::SingleFrequency]);
    let inp = load(dir, at)?;
    let kp = inp.kp.filter(|k| at - k.t <= KP_VALID_S);
    let roti = inp.roti.as_ref().filter(|(t, _)| at - t <= LIVE_VALID_S);
    let s4 = inp.s4.as_ref().filter(|(t, _)| at - t <= LIVE_VALID_S);
    if kp.is_none() && roti.is_none() && s4.is_none() {
        return Err("no current space-weather inputs for that time".into());
    }
    let year = year_of(at);
    let mut rows = vec![];
    for p in &r.locations {
        let (b, gmlat, modip) = band(p.lat_deg, p.lon_deg, kp.map_or(0.0, |k| k.kp), year);
        // Region boxes are in -180..180; locations may be given in 0..360 (350 is -10).
        let lon = (p.lon_deg + 180.0).rem_euclid(360.0) - 180.0;
        let named = cfg.regions.iter().find(|g| {
            p.lat_deg >= g.lat_min && p.lat_deg <= g.lat_max && lon >= g.lon_min && lon <= g.lon_max
        });
        let th = named.map_or_else(|| b.thresholds(), |g| g.thresholds);
        let here = (p.lat_deg, p.lon_deg);
        let mut ind = serde_json::Map::new();
        let mut levels: Vec<(u8, &str)> = vec![];
        if let Some(k) = kp {
            // Kp speaks to the auroral oval and to storm-time gradients outside the equatorial
            // band; equatorial scintillation is not a Kp effect.
            let lv = if b == Band::Equatorial {
                level_of(k.kp, th.kp_high, 10.0)
            } else {
                level_of(k.kp, th.kp_moderate, th.kp_high)
            };
            levels.push((lv, "kp"));
            ind.insert(
                "kp".into(),
                json!({"value": k.kp, "age_s": at - k.t, "level": level_name(lv)}),
            );
        }
        if let Some((t, cells)) = roti {
            let near = cells
                .iter()
                .map(|c| (dist_km(here, (c.lat_deg, c.lon_deg)), c.roti_tecu_per_min))
                .filter(|(d, x)| *d <= NEAR_KM && x.is_finite())
                .min_by(|a, b| a.0.total_cmp(&b.0));
            if let Some((d, x)) = near {
                let lv = level_of(x, th.roti_moderate, th.roti_high);
                levels.push((lv, "roti"));
                ind.insert("roti".into(), json!({"value_tecu_per_min": x, "distance_km": d, "age_s": at - t, "level": level_name(lv)}));
            }
        }
        if let Some((t, sts)) = s4 {
            let near = sts
                .iter()
                .map(|c| (dist_km(here, (c.lat_deg, c.lon_deg)), c.s4))
                .filter(|(d, x)| *d <= NEAR_KM && x.is_finite())
                .min_by(|a, b| a.0.total_cmp(&b.0));
            if let Some((d, x)) = near {
                let lv = level_of(x, th.s4_moderate, th.s4_high);
                levels.push((lv, "s4"));
                ind.insert(
                    "s4".into(),
                    json!({"value": x, "distance_km": d, "age_s": at - t, "level": level_name(lv)}),
                );
            }
        }
        let (level, driver) = levels
            .iter()
            .max_by_key(|(l, _)| *l)
            .copied()
            .unwrap_or((0, "none"));
        // Nothing above quiet: no indicator drives the level (max_by_key returned the last of
        // the equal quiet ones).
        let driver = if level == 0 { "none" } else { driver };
        let live = ind.contains_key("roti") || ind.contains_key("s4");
        // The advisory holds for the hold time from `at`, but never past the moment its newest
        // input stops being current (inputs are already at most LIVE_VALID_S / KP_VALID_S old,
        // so the old `newest.max(at)` always gave `at`).
        let valid_until = if live {
            let newest = [roti.map(|r| r.0), s4.map(|s| s.0)]
                .into_iter()
                .flatten()
                .fold(f64::NEG_INFINITY, f64::max);
            (at + LIVE_HOLD_S).min(newest + LIVE_VALID_S)
        } else {
            let kp_end = kp.map_or(f64::INFINITY, |k| k.t + KP_VALID_S);
            (at + KP_HOLD_S).min(kp_end)
        };
        let mut st = serde_json::Map::new();
        for s in &services {
            st.insert(s.name().into(), json!(status(*s, level, b)));
        }
        rows.push(json!({
            "id": p.id,
            "region": named.map_or_else(|| b.name().to_string(), |g| g.name.clone()),
            "thresholds": if named.is_some() { "regional_calibration" } else { "default_band" },
            "thresholds_basis": named.map(|g| g.basis.clone()),
            "geomagnetic_lat_deg": gmlat,
            "modip_deg": modip,
            "indicators": ind,
            "level": level_name(level),
            "driver": driver,
            "live_data": live,
            "services": st,
            "valid_until_utc": iso(valid_until.floor() as i64),
        }));
    }
    let mut limits = vec![];
    if roti.is_none() && s4.is_none() {
        limits.push("No live ROTI or S4 input was current: the advisory rests on Kp alone, a proxy that does not see equatorial scintillation.".to_string());
    }
    if kp.is_none() {
        limits.push(
            "No current Kp value: the auroral oval boundary is placed for quiet conditions."
                .to_string(),
        );
    }
    limits.push("Default thresholds are MODELLED from published climatology, simplified; regional calibrations are named where used.".into());
    Ok(json!({
        "method_version": METHOD_VERSION,
        "at_utc": iso(at.floor() as i64),
        "g_scale": kp.map(|k| format!("G{}", g_scale(k.kp))),
        "inputs": {
            "kp_utc": kp.map(|k| iso(k.t as i64)),
            "roti_map_utc": roti.map(|r| iso(r.0 as i64)),
            "s4_obs_utc": s4.map(|s| iso(s.0 as i64)),
            "files": inp.files,
            "sha256": hex::encode(inp.digest.finalize()),
        },
        "locations": rows,
        "limits": limits,
        "statement": STATEMENT,
    }))
}

/// Run the `spaceweather` method and return a signed verdict. Not fingerprinted: levels and
/// statuses, and input values that are the same for every caller.
pub fn spaceweather_verdict(
    req: &SpaceWxRequest,
    s: &crate::methods::Signing,
    limits: &SpaceWxLimits,
    cfg: &SpaceWxConfig,
    now: f64,
    utc: &str,
) -> Result<crate::SignedVerdict, String> {
    let v = analyse(req, limits, cfg, now)?;
    crate::methods::finish("spaceweather", v, s, utc)
}

#[cfg(test)]
#[path = "spaceweather_tests.rs"]
mod tests;
