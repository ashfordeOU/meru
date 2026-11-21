// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The `parametric-trigger` method: a hosted, neutral oracle for a parametric GNSS-outage
//! trigger (research backlog E28, B2801 hosted part).
//!
//! A parametric cover pays on an index, not on an adjusted loss, so the index must come from
//! someone neither party controls. The Kshana Pro client evaluates a trigger definition on the
//! user's own station series (`kshana-pro insurance trigger`); this method evaluates the same
//! definition on the **service's station archive** (independently operated monitoring stations,
//! configured with `MERU_ORACLE_STATIONS`) and returns a signed record of the trigger's state:
//! `fired`, `not_fired` or `insufficient_data`, the events, the outage index, the data coverage,
//! and digests of the definition and of the data used, so anyone holding the verdict can tell
//! later exactly what was evaluated. A caller may instead supply its own series
//! (`source: "caller"`); the verdict then says so, and is no more neutral than that data.
//!
//! The rules follow the Pro trigger (baseline per site, degraded samples, missing data never
//! degraded, site episodes, k-of-n sites at once, merged events, minimum duration, each event's
//! index `index_db_h` in dB·h; the period's `period_index` is the share of observed hours that
//! were degraded, dimensionless), with one oracle rule on top: an episode at one station that no nearby station shares,
//! while at least two nearby stations kept normal data, is **excluded as uncorroborated** (a
//! station fault must not fire a cover). The distances and counts of that rule stay in the
//! service.
//!
//! No payout, amount or cover term is evaluated here: this is an index and a trigger state, not
//! insurance advice, not a claim decision and not an interpretation of any policy. Ashforde has
//! no insurer partners. Evidence class MODELLED.

use crate::cause::Time;
use crate::server::iso;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Method identifier written into every outcome. A change to any rule is a new version.
pub const METHOD_VERSION: &str = "parametric-trigger/1";

/// What every verdict says about itself.
pub const STATEMENT: &str = "An outage index and a trigger state under the stated definition. \
Not insurance or financial advice, not a claim decision, not a payout calculation and not an \
interpretation of any policy wording.";

/// Stations within this distance of each other corroborate each other, km.
const NEIGH_KM: f64 = 100.0;
/// Fewest nearby stations with normal data for an unshared episode to be excluded.
const MIN_NORMAL_NEIGHBOURS: usize = 2;
/// Below this share of observed site-hours, a trigger that did not fire is `insufficient_data`.
const MIN_COVERAGE: f64 = 0.5;

// ------------------------------------------------------------------------------------------
// Request
// ------------------------------------------------------------------------------------------

/// The area whose stations count.
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Area {
    pub lat_deg: f64,
    pub lon_deg: f64,
    pub radius_km: f64,
}

fn d_min_sites() -> usize {
    1
}
fn d_gap() -> f64 {
    120.0
}
fn d_merge() -> f64 {
    10.0
}

/// The trigger definition (the Pro trigger's fields).
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerDef {
    /// Degraded: C/N0 below the site baseline minus this, dB.
    pub cn0_drop_db: f64,
    /// Sites degraded at once.
    #[serde(default = "d_min_sites")]
    pub min_sites: usize,
    /// An event this long or longer fires, minutes.
    pub min_duration_min: f64,
    /// A longer gap in a site's data ends an episode, seconds.
    #[serde(default = "d_gap")]
    pub max_gap_s: f64,
    /// Episodes and events closer than this merge, minutes.
    #[serde(default = "d_merge")]
    pub merge_gap_min: f64,
}

/// A caller-supplied site series (`source: "caller"`).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteSeries {
    pub site: String,
    pub lat_deg: f64,
    pub lon_deg: f64,
    #[serde(default)]
    pub baseline_dbhz: Option<f64>,
    /// Who operates the station (counts independent operators; not returned).
    #[serde(default)]
    pub operator: Option<String>,
    /// Sample times, Unix seconds.
    pub t_unix: Vec<f64>,
    /// Site-level C/N0 per sample, dB-Hz. How it was formed matters to the index: the mean of
    /// dB-Hz values and the dB-Hz of the mean power differ (the second is the higher, by up to
    /// several dB when satellites differ widely). Use the same statistic the station archive
    /// holds (which one is to confirm); the trigger's `cn0_drop_db` applies to that statistic.
    pub cn0_dbhz: Vec<f64>,
}

/// Where the station data comes from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The service's station archive (the neutral oracle).
    #[default]
    Service,
    /// The series in the request.
    Caller,
}

/// Request for the `parametric-trigger` method.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerRequest {
    /// The caller's identifier for the definition, echoed.
    #[serde(default)]
    pub definition_id: Option<String>,
    pub period_start_utc: Time,
    pub period_end_utc: Time,
    pub area: Area,
    pub trigger: TriggerDef,
    #[serde(default)]
    pub source: Source,
    #[serde(default)]
    pub series: Vec<SiteSeries>,
    /// Archived events to backtest against, each with the basis it is documented on.
    #[serde(default)]
    pub backtest: Vec<ArchivedEvent>,
}

/// An archived outage event and where it is documented (a report, a notice, a dataset). The
/// basis is the caller's; it is echoed so the verdict says what each event rests on.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchivedEvent {
    pub id: String,
    pub start_utc: Time,
    pub end_utc: Time,
    pub basis: String,
}

/// Request limits, checked before any work.
#[derive(Clone, Debug)]
pub struct TriggerLimits {
    /// Longest period, days.
    pub max_period_days: f64,
    pub max_sites: usize,
    /// Most samples over all sites.
    pub max_samples: usize,
    pub max_radius_km: f64,
}

impl Default for TriggerLimits {
    fn default() -> Self {
        TriggerLimits {
            max_period_days: 92.0,
            max_sites: 500,
            max_samples: 5_000_000,
            max_radius_km: 2_000.0,
        }
    }
}

/// The station archive (`MERU_ORACLE_STATIONS`).
#[derive(Clone, Debug)]
pub struct OracleConfig {
    /// Directory holding `stations.toml` and the station CSV files. `None`: only
    /// `source: "caller"` is offered.
    pub stations_dir: Option<PathBuf>,
    /// Most bytes per station file.
    pub max_file_bytes: u64,
}

impl Default for OracleConfig {
    fn default() -> Self {
        OracleConfig {
            stations_dir: None,
            max_file_bytes: 64 * 1024 * 1024,
        }
    }
}

/// One station of the archive (`stations.toml`, `[[station]]`).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveStation {
    id: String,
    lat_deg: f64,
    lon_deg: f64,
    operator: String,
    /// CSV `utc,cn0_dbhz` (ISO-8601 or Unix seconds), relative to the archive directory.
    file: String,
    #[serde(default)]
    baseline_dbhz: Option<f64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    station: Vec<ArchiveStation>,
}

// ------------------------------------------------------------------------------------------
// The evaluation
// ------------------------------------------------------------------------------------------

/// One site's samples in the period.
#[derive(Clone, Debug)]
struct Site {
    id: String,
    lat: f64,
    lon: f64,
    operator: String,
    baseline: Option<f64>,
    s: Vec<(f64, f64)>,
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

fn parse_csv(text: &str, who: &str, p0: f64, p1: f64) -> Result<Vec<(f64, f64)>, String> {
    let mut v = vec![];
    for (i, l) in text.lines().enumerate() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') || (i == 0 && l.starts_with("utc")) {
            continue;
        }
        let (a, b) = l
            .split_once(',')
            .ok_or_else(|| format!("{who}: line {}: expected utc,cn0_dbhz", i + 1))?;
        let t = match a.trim().parse::<f64>() {
            Ok(x) => x,
            Err(_) => crate::cause::parse_iso(a.trim())
                .map_err(|e| format!("{who}: line {}: {e}", i + 1))?,
        };
        let c: f64 = b
            .trim()
            .parse()
            .map_err(|_| format!("{who}: line {}: bad C/N0", i + 1))?;
        if t >= p0 && t <= p1 && c.is_finite() {
            v.push((t, c));
        }
    }
    // The evaluation walks samples in time order.
    v.sort_by(|a, b| a.0.total_cmp(&b.0));
    Ok(v)
}

fn load_archive(cfg: &OracleConfig, p0: f64, p1: f64) -> Result<Vec<Site>, String> {
    let dir = cfg.stations_dir.as_ref().ok_or(
        "the station archive is not offered by this service (no stations configured); send source \"caller\" with your own series",
    )?;
    let reg = std::fs::read_to_string(dir.join("stations.toml"))
        .map_err(|e| format!("station archive unavailable: {e}"))?;
    let a: Archive = toml::from_str(&reg).map_err(|e| format!("station archive: {e}"))?;
    let mut out = vec![];
    for st in a.station {
        if st.file.contains("..") || st.file.starts_with('/') {
            return Err(format!("station archive: bad file name for {}", st.id));
        }
        let path = dir.join(&st.file);
        let len = std::fs::metadata(&path)
            .map_err(|e| format!("station archive: {}: {e}", st.id))?
            .len();
        if len > cfg.max_file_bytes {
            return Err(format!(
                "station archive: {} above the file size cap",
                st.id
            ));
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("station archive: {}: {e}", st.id))?;
        out.push(Site {
            s: parse_csv(&text, &st.id, p0, p1)?,
            id: st.id,
            lat: st.lat_deg,
            lon: st.lon_deg,
            operator: st.operator,
            baseline: st.baseline_dbhz,
        });
    }
    Ok(out)
}

fn caller_sites(r: &TriggerRequest, p0: f64, p1: f64) -> Result<Vec<Site>, String> {
    let mut out = vec![];
    for s in &r.series {
        if !(s.lat_deg.abs() <= 90.0 && s.lon_deg.abs() <= 360.0) {
            return Err(format!(
                "series '{}': lat_deg within ±90 and lon_deg within ±360",
                s.site
            ));
        }
        if s.t_unix.len() != s.cn0_dbhz.len() {
            return Err(format!(
                "series '{}': t_unix and cn0_dbhz must have the same length",
                s.site
            ));
        }
        let mut v: Vec<(f64, f64)> = s
            .t_unix
            .iter()
            .zip(&s.cn0_dbhz)
            .filter(|(t, c)| t.is_finite() && c.is_finite() && **t >= p0 && **t <= p1)
            .map(|(t, c)| (*t, *c))
            .collect();
        // The evaluation walks samples in time order; callers may send them in any order.
        v.sort_by(|a, b| a.0.total_cmp(&b.0));
        out.push(Site {
            id: s.site.clone(),
            lat: s.lat_deg,
            lon: s.lon_deg,
            operator: s.operator.clone().unwrap_or_else(|| s.site.clone()),
            baseline: s.baseline_dbhz,
            s: v,
        });
    }
    Ok(out)
}

fn median(v: &mut [f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    Some(v[v.len() / 2])
}

/// One site's evaluation.
struct Eval {
    baseline: f64,
    observed_h: f64,
    degraded_h: f64,
    /// Episodes `[start, end]`.
    episodes: Vec<(f64, f64)>,
    /// (time, dB below baseline, hours) of each degraded sample, for the index.
    deficit: Vec<(f64, f64, f64)>,
}

fn evaluate(site: &Site, d: &TriggerDef) -> Option<Eval> {
    if site.s.is_empty() {
        return None;
    }
    let baseline = site
        .baseline
        .or_else(|| median(&mut site.s.iter().map(|x| x.1).collect::<Vec<_>>()))?;
    let thr = baseline - d.cn0_drop_db;
    let (mut obs, mut deg) = (0.0, 0.0);
    let mut eps: Vec<(f64, f64)> = vec![];
    let mut open: Option<(f64, f64)> = None;
    let mut deficit = vec![];
    for (i, &(t, c)) in site.s.iter().enumerate() {
        let next = site.s.get(i + 1).map(|x| x.0);
        let dt = next
            .map(|n| n - t)
            .filter(|g| *g <= d.max_gap_s)
            .unwrap_or(0.0);
        obs += dt;
        let gap_after = next.is_none_or(|n| n - t > d.max_gap_s);
        if c < thr {
            deg += dt;
            deficit.push((t, baseline - c, dt / 3600.0));
            let e = open.get_or_insert((t, t));
            e.1 = t + dt;
        }
        if c >= thr || gap_after {
            if let Some(e) = open.take() {
                let e = if e.1 <= e.0 { (e.0, e.0) } else { e };
                eps.push(e);
            }
        }
    }
    // Merge episodes closer than the merge gap.
    let merge = d.merge_gap_min * 60.0;
    let mut merged: Vec<(f64, f64)> = vec![];
    for e in eps {
        match merged.last_mut() {
            Some(l) if e.0 - l.1 <= merge => l.1 = l.1.max(e.1),
            _ => merged.push(e),
        }
    }
    Some(Eval {
        baseline,
        observed_h: obs / 3600.0,
        degraded_h: deg / 3600.0,
        episodes: merged,
        deficit,
    })
}

/// Whether a site has data inside `[a, b]` and whether it is degraded there.
fn state_in(site: &Site, ev: &Eval, a: f64, b: f64) -> (bool, bool) {
    let data = site.s.iter().any(|x| x.0 >= a && x.0 <= b);
    let degraded = ev.episodes.iter().any(|e| e.0 <= b && e.1 >= a);
    (data, degraded)
}

fn check(r: &TriggerRequest, l: &TriggerLimits) -> Result<(f64, f64), String> {
    if r.backtest.len() > 200 {
        return Err("at most 200 archived events".into());
    }
    for b in &r.backtest {
        if b.id.is_empty() || b.id.len() > 64 || b.basis.trim().is_empty() || b.basis.len() > 300 {
            return Err(format!(
                "backtest '{}': an id (1 to 64 characters) and a documented basis (1 to 300) are required",
                b.id
            ));
        }
    }
    let (p0, p1) = (r.period_start_utc.secs()?, r.period_end_utc.secs()?);
    if p1 <= p0 || p1 - p0 > l.max_period_days * 86_400.0 {
        return Err(format!(
            "the period must end after it starts and span at most {} days",
            l.max_period_days
        ));
    }
    let a = &r.area;
    if !(a.lat_deg.abs() <= 90.0
        && a.lon_deg.abs() <= 360.0
        && a.radius_km > 0.0
        && a.radius_km <= l.max_radius_km)
    {
        return Err(format!(
            "area: a position and a radius above 0 and at most {} km",
            l.max_radius_km
        ));
    }
    let d = &r.trigger;
    for (k, x) in [
        ("trigger.cn0_drop_db", d.cn0_drop_db),
        ("trigger.min_duration_min", d.min_duration_min),
        ("trigger.max_gap_s", d.max_gap_s),
    ] {
        if !(x.is_finite() && x > 0.0) {
            return Err(format!("{k} must be a positive number"));
        }
    }
    if !(d.merge_gap_min.is_finite() && d.merge_gap_min >= 0.0) || d.min_sites == 0 {
        return Err("trigger.merge_gap_min must be 0 or more and min_sites at least 1".into());
    }
    match r.source {
        Source::Service if !r.series.is_empty() => {
            return Err("series are only read with source \"caller\"".into())
        }
        Source::Caller if r.series.is_empty() => {
            return Err("source \"caller\" needs series".into())
        }
        _ => {}
    }
    if r.series.len() > l.max_sites {
        return Err(format!("at most {} series", l.max_sites));
    }
    if r.series.iter().map(|s| s.t_unix.len()).sum::<usize>() > l.max_samples {
        return Err(format!("at most {} samples", l.max_samples));
    }
    Ok((p0, p1))
}

/// Canonical SHA-256 of a JSON value.
fn sha(v: &Value) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(v).unwrap_or_default()))
}

/// Run the method; the raw (unrounded, unsigned) outcome.
pub fn analyse(r: &TriggerRequest, l: &TriggerLimits, cfg: &OracleConfig) -> Result<Value, String> {
    let (p0, p1) = check(r, l)?;
    let all = match r.source {
        Source::Service => load_archive(cfg, p0, p1)?,
        Source::Caller => caller_sites(r, p0, p1)?,
    };
    let centre = (r.area.lat_deg, r.area.lon_deg);
    let sites: Vec<Site> = all
        .into_iter()
        .filter(|s| dist_km(centre, (s.lat, s.lon)) <= r.area.radius_km)
        .collect();
    if sites.len() > l.max_sites || sites.iter().map(|s| s.s.len()).sum::<usize>() > l.max_samples {
        return Err("the area holds more stations or samples than one call may evaluate".into());
    }
    let d = &r.trigger;
    let evals: Vec<Option<Eval>> = sites.iter().map(|s| evaluate(s, d)).collect();

    // The oracle rule: an unshared episode with at least two normal neighbours is excluded.
    let mut kept: Vec<Vec<(f64, f64)>> = vec![vec![]; sites.len()];
    let mut excluded = 0usize;
    for (i, s) in sites.iter().enumerate() {
        let Some(ev) = &evals[i] else { continue };
        for &(a, b) in &ev.episodes {
            let (mut normal, mut shared) = (0usize, 0usize);
            for (j, o) in sites.iter().enumerate() {
                if j == i || dist_km((s.lat, s.lon), (o.lat, o.lon)) > NEIGH_KM {
                    continue;
                }
                let Some(oe) = &evals[j] else { continue };
                match state_in(o, oe, a, b) {
                    (_, true) => shared += 1,
                    (true, false) => normal += 1,
                    _ => {}
                }
            }
            if shared == 0 && normal >= MIN_NORMAL_NEIGHBOURS {
                excluded += 1;
            } else {
                kept[i].push((a, b));
            }
        }
    }

    // k-of-n sweep over the kept episodes.
    let mut edges: Vec<(f64, i32)> = kept
        .iter()
        .flatten()
        .flat_map(|&(a, b)| [(a, 1), (b, -1)])
        .collect();
    edges.sort_by(|x, y| x.0.total_cmp(&y.0).then(y.1.cmp(&x.1)));
    let mut raw: Vec<(f64, f64)> = vec![];
    let (mut n, mut start) = (0i32, None);
    for (t, k) in edges {
        n += k;
        if n >= d.min_sites as i32 && start.is_none() {
            start = Some(t);
        } else if n < d.min_sites as i32 {
            if let Some(s) = start.take() {
                raw.push((s, t));
            }
        }
    }
    let merge = d.merge_gap_min * 60.0;
    let mut events: Vec<(f64, f64)> = vec![];
    for e in raw {
        match events.last_mut() {
            Some(l) if e.0 - l.1 <= merge => l.1 = l.1.max(e.1),
            _ => events.push(e),
        }
    }
    let ev_rows: Vec<Value> = events
        .iter()
        .map(|&(a, b)| {
            let mut idx = 0.0;
            let mut n_sites = 0usize;
            for (i, ev) in evals.iter().enumerate() {
                let Some(ev) = ev else { continue };
                if kept[i].iter().any(|e| e.0 <= b && e.1 >= a) {
                    n_sites += 1;
                    idx += ev
                        .deficit
                        .iter()
                        .filter(|x| x.0 >= a && x.0 <= b)
                        .map(|x| x.1 * x.2)
                        .sum::<f64>();
                }
            }
            let dur = (b - a) / 60.0;
            json!({
                "start_utc": iso(a.floor() as i64),
                "end_utc": iso(b.ceil() as i64),
                "duration_min": dur,
                "sites": n_sites,
                "index_db_h": idx,
                "fires": dur >= d.min_duration_min,
            })
        })
        .collect();
    let fired = ev_rows.iter().filter(|e| e["fires"] == true).count();
    // The backtest: each archived event against the fired events (overlap within the merge
    // gap); fired events no archived event explains.
    let fired_iv: Vec<(usize, f64, f64)> = events
        .iter()
        .enumerate()
        .filter(|(i, _)| ev_rows[*i]["fires"] == true)
        .map(|(i, e)| (i, e.0, e.1))
        .collect();
    let mut explained = vec![false; fired_iv.len()];
    let mut bt_rows = vec![];
    for b in &r.backtest {
        let (a, z) = (b.start_utc.secs()?, b.end_utc.secs()?);
        if z < a {
            return Err(format!("backtest '{}': ends before it starts", b.id));
        }
        let hits: Vec<usize> = fired_iv
            .iter()
            .enumerate()
            .filter(|(_, (_, s, e))| *s <= z + merge && *e >= a - merge)
            .map(|(k, (i, _, _))| {
                explained[k] = true;
                *i
            })
            .collect();
        let covered = a >= p0 && z <= p1;
        bt_rows.push(json!({
            "id": b.id,
            "basis": b.basis,
            "in_period": covered,
            "matched": !hits.is_empty(),
            "fired_events": hits,
        }));
    }
    let backtest = if r.backtest.is_empty() {
        Value::Null
    } else {
        let in_p: Vec<&Value> = bt_rows.iter().filter(|b| b["in_period"] == true).collect();
        json!({
            "archived_events": bt_rows.len(),
            "in_period": in_p.len(),
            "matched": in_p.iter().filter(|b| b["matched"] == true).count(),
            "missed": in_p.iter().filter(|b| b["matched"] == false).count(),
            "fired_unexplained": explained.iter().filter(|x| !**x).count(),
            "events": bt_rows,
        })
    };
    let observed: f64 = evals.iter().flatten().map(|e| e.observed_h).sum();
    let degraded: f64 = evals.iter().flatten().map(|e| e.degraded_h).sum();
    let period_h = (p1 - p0) / 3600.0;
    let coverage = if sites.is_empty() {
        0.0
    } else {
        (observed / (sites.len() as f64 * period_h)).min(1.0)
    };
    let state = if fired > 0 {
        "fired"
    } else if coverage < MIN_COVERAGE || sites.len() < d.min_sites {
        "insufficient_data"
    } else {
        "not_fired"
    };
    let mut ops: Vec<&str> = sites.iter().map(|s| s.operator.as_str()).collect();
    ops.sort_unstable();
    ops.dedup();
    // Digests: the definition as evaluated, and the data used (site ids, positions, baselines and
    // samples in order).
    let definition = json!({
        "method_version": METHOD_VERSION,
        "period": [iso(p0 as i64), iso(p1 as i64)],
        "area": r.area,
        "trigger": r.trigger,
        "source": match r.source { Source::Service => "service_archive", Source::Caller => "caller_supplied" },
    });
    let mut h = Sha256::new();
    for (s, ev) in sites.iter().zip(&evals) {
        h.update(s.id.as_bytes());
        h.update(s.lat.to_le_bytes());
        h.update(s.lon.to_le_bytes());
        if let Some(e) = ev {
            h.update(e.baseline.to_le_bytes());
        }
        for (t, c) in &s.s {
            h.update(t.to_le_bytes());
            h.update(c.to_le_bytes());
        }
    }
    Ok(json!({
        "method_version": METHOD_VERSION,
        "definition_id": r.definition_id,
        "definition_sha256": sha(&definition),
        "data_sha256": hex::encode(h.finalize()),
        "source": definition["source"],
        "period": definition["period"],
        "state": state,
        "events": ev_rows,
        "events_fired": fired,
        "backtest": backtest,
        "period_index": if observed > 0.0 { json!(degraded / observed) } else { Value::Null },
        "coverage": {
            "stations": sites.len(),
            "stations_with_data": evals.iter().flatten().count(),
            "independent_operators": ops.len(),
            "observed_site_hours": observed,
            "share_of_period": coverage,
            "episodes_excluded_uncorroborated": excluded,
        },
        "limits": [
            "Missing data is never degraded; low coverage is itself a source of basis risk.",
            "An episode at one station that nearby stations with normal data did not share is excluded as uncorroborated.",
            "The index measures signal degradation at the stations; it is not a measure of any insured party's loss.",
        ],
        "statement": STATEMENT,
    }))
}

/// Run the `parametric-trigger` method and return a signed verdict. Not fingerprinted: an
/// oracle's record must read the same for every party.
pub fn trigger_verdict(
    req: &TriggerRequest,
    s: &crate::methods::Signing,
    limits: &TriggerLimits,
    cfg: &OracleConfig,
    utc: &str,
) -> Result<crate::SignedVerdict, String> {
    let v = analyse(req, limits, cfg)?;
    crate::methods::finish("parametric-trigger", v, s, utc)
}

#[cfg(test)]
#[path = "parametric_oracle_tests.rs"]
mod tests;
