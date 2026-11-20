// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! Observation archives by domain, answered as aggregates only (research backlog E26, B2603).
//!
//! The monitoring network keeps long-running archives that give a hosted service its value:
//! interference incidents, eLoran additional secondary factors (ASF), LF noise, OSNMA
//! authentication failures, AIS-versus-RF position mismatches, clock holdover, and station key
//! performance indicators. Raw rows never leave: they name stations, places and times that belong
//! to the feeders, and a copy of the rows would be a copy of the archive.
//!
//! * `POST /verdict/archive/ingest` (operator licences in `MERU_ARCHIVE_WRITERS`): records
//!   `{domain, t, lat_deg, lon_deg, source, values, tag?}` appended to one JSON Lines file per
//!   domain under `MERU_ARCHIVE_DIR`. Each domain accepts its own value names only.
//! * `POST /verdict/archive-query` (any licence, rate limited, audited, metered like every
//!   method): `{domain, value, area {lat_deg, lon_deg, radius_km ≥ 10}, from_utc, to_utc
//!   (at least an hour, at most 366 days), group (none, day, week, month), tag?}` answers a signed
//!   verdict with, per group, the count, mean, median, 95th percentile and maximum, rounded like
//!   every verdict. A group with fewer than [`MIN_RECORDS`] records or [`MIN_SOURCES`] distinct
//!   sources is `suppressed` (its numbers withheld), so a query cannot single out one station or
//!   one event. No answer carries a row, a source, a position or a timestamp finer than the group.
//!
//! There is no export route; `/verdict/archive/export` and `/verdict/archive/rows` are honeypots.
//! Residual risk: differencing overlapping queries can narrow down groups; the minimum area,
//! window and counts, output rounding and the query-pattern audit slow it. Evidence class
//! MODELLED (aggregates of what was ingested; the archives' sources and quality are the feeders').

use crate::cause::Time;
use crate::server::iso;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Method identifier written into every outcome.
pub const METHOD_VERSION: &str = "archive-query/1";
/// Fewest records in a group for its numbers to be given.
pub const MIN_RECORDS: usize = 5;
/// Fewest distinct sources in a group for its numbers to be given.
pub const MIN_SOURCES: usize = 2;
/// Smallest query radius, km.
pub const MIN_RADIUS_KM: f64 = 10.0;

/// The domains and the value names each accepts.
pub const DOMAINS: &[(&str, &[&str])] = &[
    ("incidents", &["duration_s", "severity"]),
    ("asf", &["asf_ns"]),
    ("lf_noise", &["noise_dbuv_m"]),
    ("osnma_failures", &["failed", "auth_failures"]),
    ("ais_rf", &["mismatch_m"]),
    ("holdover", &["holdover_s", "drift_ns"]),
    ("station_kpi", &["availability", "latency_s"]),
];

fn domain(d: &str) -> Option<&'static [&'static str]> {
    DOMAINS.iter().find(|(k, _)| *k == d).map(|x| x.1)
}

/// One archived record.
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub domain: String,
    /// Unix seconds.
    pub t: f64,
    pub lat_deg: f64,
    pub lon_deg: f64,
    /// The feeder or station that reported it (counted, never returned).
    pub source: String,
    pub values: BTreeMap<String, f64>,
    /// A category within the domain (for example the incident kind or the eLoran station).
    #[serde(default)]
    pub tag: Option<String>,
}

/// An ingest request: records as above, with times in ISO-8601 or Unix seconds.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestRecord {
    pub domain: String,
    pub t: Time,
    pub lat_deg: f64,
    pub lon_deg: f64,
    pub source: String,
    pub values: BTreeMap<String, f64>,
    #[serde(default)]
    pub tag: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestRequest {
    pub records: Vec<IngestRecord>,
}

fn ident_ok(s: &str, n: usize) -> bool {
    !s.is_empty()
        && s.len() <= n
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/'))
}

fn check_record(r: &IngestRecord) -> Result<Record, String> {
    let names = domain(&r.domain).ok_or_else(|| format!("unknown domain '{}'", r.domain))?;
    if !(r.lat_deg.abs() <= 90.0 && r.lon_deg.abs() <= 180.0) {
        return Err("position out of range".into());
    }
    if !ident_ok(&r.source, 64) || r.tag.as_ref().is_some_and(|t| !ident_ok(t, 64)) {
        return Err("source and tag: 1 to 64 characters of A-Z a-z 0-9 . _ - : /".into());
    }
    if r.values.is_empty() {
        return Err("a record needs at least one value".into());
    }
    for (k, v) in &r.values {
        if !names.contains(&k.as_str()) {
            return Err(format!(
                "domain '{}' has no value '{k}' (its values: {})",
                r.domain,
                names.join(", ")
            ));
        }
        if !v.is_finite() {
            return Err(format!("value '{k}' is not a finite number"));
        }
    }
    Ok(Record {
        domain: r.domain.clone(),
        t: r.t.secs()?,
        lat_deg: r.lat_deg,
        lon_deg: r.lon_deg,
        source: r.source.clone(),
        values: r.values.clone(),
        tag: r.tag.clone(),
    })
}

/// The archive store.
#[derive(Clone, Debug, Default)]
pub struct ArchiveConfig {
    /// Directory of one `<domain>.jsonl` per domain. `None`: archives not offered.
    pub dir: Option<PathBuf>,
    /// Token IDs of the operator licences that may ingest.
    pub writers: Vec<String>,
}

/// Serialises appends.
#[derive(Default)]
pub struct ArchiveLock(Mutex<()>);

/// Append records (all checked first: all or none).
pub fn ingest(dir: &Path, lock: &ArchiveLock, req: &IngestRequest) -> Result<usize, String> {
    if req.records.is_empty() || req.records.len() > 10_000 {
        return Err("1 to 10,000 records".into());
    }
    let recs: Vec<Record> = req
        .records
        .iter()
        .enumerate()
        .map(|(i, r)| check_record(r).map_err(|e| format!("records[{i}]: {e}")))
        .collect::<Result<_, _>>()?;
    let _g = lock.0.lock().map_err(|_| "archive lock poisoned")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("archive: {e}"))?;
    let mut by: BTreeMap<&str, Vec<&Record>> = BTreeMap::new();
    for r in &recs {
        by.entry(r.domain.as_str()).or_default().push(r);
    }
    for (d, rs) in by {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(format!("{d}.jsonl")))
            .map_err(|e| format!("archive: {e}"))?;
        for r in rs {
            writeln!(
                f,
                "{}",
                serde_json::to_string(r).map_err(|e| e.to_string())?
            )
            .map_err(|e| format!("archive: {e}"))?;
        }
        f.sync_all().map_err(|e| format!("archive: {e}"))?;
    }
    Ok(recs.len())
}

/// Query area.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Area {
    pub lat_deg: f64,
    pub lon_deg: f64,
    pub radius_km: f64,
}

/// How a query is grouped in time.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    #[default]
    None,
    Day,
    Week,
    Month,
}

/// Request for the `archive-query` method.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryRequest {
    pub domain: String,
    pub value: String,
    pub area: Area,
    pub from_utc: Time,
    pub to_utc: Time,
    #[serde(default)]
    pub group: Group,
    #[serde(default)]
    pub tag: Option<String>,
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

fn group_key(t: f64, g: Group) -> String {
    let d = iso(t.floor() as i64);
    match g {
        Group::None => "all".into(),
        Group::Day => d[..10].to_string(),
        Group::Month => d[..7].to_string(),
        Group::Week => {
            // Weeks start on Monday (1970-01-05 was a Monday).
            let days = (t / 86_400.0).floor() as i64;
            let monday = days - (days - 4).rem_euclid(7);
            iso(monday * 86_400)[..10].to_string()
        }
    }
}

fn pct(s: &[f64], p: f64) -> f64 {
    let k = ((p / 100.0) * s.len() as f64).ceil().max(1.0) as usize - 1;
    s[k.min(s.len() - 1)]
}

/// Run a query over the archive; the raw (unrounded, unsigned) outcome.
pub fn query(r: &QueryRequest, cfg: &ArchiveConfig) -> Result<Value, String> {
    let dir = cfg
        .dir
        .as_ref()
        .ok_or("archives are not offered by this service")?;
    let names = domain(&r.domain).ok_or_else(|| {
        format!(
            "unknown domain '{}' (known: {})",
            r.domain,
            DOMAINS.iter().map(|d| d.0).collect::<Vec<_>>().join(", ")
        )
    })?;
    if !names.contains(&r.value.as_str()) {
        return Err(format!(
            "domain '{}' has no value '{}' (its values: {})",
            r.domain,
            r.value,
            names.join(", ")
        ));
    }
    if !(r.area.radius_km >= MIN_RADIUS_KM && r.area.radius_km <= 3000.0)
        || !(r.area.lat_deg.abs() <= 90.0 && r.area.lon_deg.abs() <= 180.0)
    {
        return Err(format!(
            "area: a position and a radius of {MIN_RADIUS_KM} to 3,000 km"
        ));
    }
    let (a, z) = (r.from_utc.secs()?, r.to_utc.secs()?);
    if z - a < 3600.0 || z - a > 366.0 * 86_400.0 {
        return Err("the window must span at least an hour and at most 366 days".into());
    }
    let path = dir.join(format!("{}.jsonl", r.domain));
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("archive: {e}")),
    };
    let centre = (r.area.lat_deg, r.area.lon_deg);
    let mut groups: BTreeMap<String, (Vec<f64>, std::collections::BTreeSet<String>)> =
        BTreeMap::new();
    for l in text.lines().filter(|l| !l.trim().is_empty()) {
        let rec: Record = serde_json::from_str(l).map_err(|e| format!("archive: {e}"))?;
        if rec.t < a || rec.t >= z || dist_km(centre, (rec.lat_deg, rec.lon_deg)) > r.area.radius_km
        {
            continue;
        }
        if r.tag.is_some() && rec.tag != r.tag {
            continue;
        }
        let Some(v) = rec.values.get(&r.value) else {
            continue;
        };
        let g = groups.entry(group_key(rec.t, r.group)).or_default();
        g.0.push(*v);
        g.1.insert(rec.source);
    }
    let mut rows = vec![];
    let mut suppressed = 0usize;
    for (k, (mut v, src)) in groups {
        if v.len() < MIN_RECORDS || src.len() < MIN_SOURCES {
            suppressed += 1;
            rows.push(json!({"group": k, "suppressed": true}));
            continue;
        }
        v.sort_by(f64::total_cmp);
        let mean = v.iter().sum::<f64>() / v.len() as f64;
        rows.push(json!({
            "group": k,
            "count": v.len(),
            "sources": src.len(),
            "mean": mean,
            "p50": pct(&v, 50.0),
            "p95": pct(&v, 95.0),
            "max": v[v.len() - 1],
        }));
    }
    Ok(json!({
        "method_version": METHOD_VERSION,
        "domain": r.domain,
        "value": r.value,
        "tag": r.tag,
        "area": {"lat_deg": r.area.lat_deg, "lon_deg": r.area.lon_deg, "radius_km": r.area.radius_km},
        "window": [iso(a as i64), iso(z as i64)],
        "group": match r.group { Group::None => "none", Group::Day => "day", Group::Week => "week", Group::Month => "month" },
        "groups": rows,
        "groups_suppressed": suppressed,
        "suppression_rule": format!("a group with fewer than {MIN_RECORDS} records or {MIN_SOURCES} sources is withheld"),
        "statement": "Aggregates of the archive only: no record, source, position or exact time is returned.",
    }))
}

/// Run the `archive-query` method and return a signed verdict. Not fingerprinted.
pub fn query_verdict(
    req: &QueryRequest,
    s: &crate::methods::Signing,
    cfg: &ArchiveConfig,
    utc: &str,
) -> Result<crate::SignedVerdict, String> {
    let v = query(req, cfg)?;
    crate::methods::finish("archive-query", v, s, utc)
}

#[cfg(test)]
#[path = "archives_tests.rs"]
mod tests;
