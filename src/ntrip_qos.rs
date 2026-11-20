// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The `ntrip-qos` method: a hosted quality-of-service scorecard for NTRIP casters and their
//! mountpoints, from observation summaries contributed by feeders (research backlog E15, the
//! hosted part of B1501; the open engine's caster monitor produces the summaries).
//!
//! Give to get: only contributor licences (`MERU_CONTRIBUTORS`, token ID to the sources each
//! feeds) may call it, every call contributes the caller's own summaries to the store
//! (`MERU_NTRIP_QOS_STORE`, append-only JSON Lines), and only then does it answer: per mountpoint
//! and per caster, the caller's score and its components, and where at least
//! [`MIN_POPULATION`] distinct sources have observed the same mountpoint (or caster) in the last
//! [`POPULATION_DAYS`] days, the population's percentiles and the caller's rank. Below that the
//! population is suppressed. No other source is ever named or returned.
//!
//! A summary covers one source's view of one mountpoint over a window: latency percentiles,
//! completeness (share of expected messages received), staleness events (gaps longer than the
//! source's staleness limit), the seconds stale, and uptime. The score (0–100) weighs latency,
//! completeness, staleness and uptime; the weights and breakpoints stay in the service. Evidence
//! class MODELLED: a score of what the contributing monitors saw, not of the caster's internals.

use crate::cause::Time;
use crate::server::iso;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// Method identifier written into every outcome.
pub const METHOD_VERSION: &str = "ntrip-qos/1";
/// Fewest distinct sources for population figures.
pub const MIN_POPULATION: usize = 5;
/// Days of contributions the population is drawn from.
pub const POPULATION_DAYS: f64 = 30.0;

/// One source's summary of one mountpoint over a window.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    /// The contributing source (one of the caller's).
    pub source: String,
    /// The caster's host name or label.
    pub caster: String,
    pub mountpoint: String,
    pub window_start_utc: Time,
    pub window_end_utc: Time,
    pub latency_ms_p50: f64,
    pub latency_ms_p95: f64,
    /// Share of the expected messages received, 0–1.
    pub completeness: f64,
    /// Gaps longer than the source's staleness limit.
    pub staleness_events: u32,
    #[serde(default)]
    pub stale_s: f64,
    /// Share of the window the stream was up, 0–1.
    pub uptime: f64,
}

/// Request for the `ntrip-qos` method.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtripQosRequest {
    pub summaries: Vec<Summary>,
}

/// The store of contributions.
#[derive(Clone, Debug, Default)]
pub struct NtripQosConfig {
    /// Append-only JSON Lines file. `None`: the method is not offered.
    pub store: Option<PathBuf>,
}

/// Serialises appends.
#[derive(Default)]
pub struct StoreLock(Mutex<()>);

/// A stored contribution (times resolved).
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Stored {
    source: String,
    caster: String,
    mountpoint: String,
    start: f64,
    end: f64,
    lat_p95: f64,
    completeness: f64,
    stale_per_h: f64,
    uptime: f64,
}

fn clamp01(x: f64) -> f64 {
    x.clamp(0.0, 1.0)
}

/// The score, 0–100, and its components.
fn score(s: &Stored) -> f64 {
    let lat = clamp01(1.0 - (s.lat_p95 - 1000.0) / 4000.0);
    let comp = clamp01((s.completeness - 0.9) / 0.1);
    let stale = 1.0 / (1.0 + s.stale_per_h);
    let up = clamp01((s.uptime - 0.95) / 0.05);
    100.0 * (0.25 * lat + 0.30 * comp + 0.20 * stale + 0.25 * up)
}

fn ident_ok(s: &str, n: usize) -> bool {
    !s.is_empty()
        && s.len() <= n
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/'))
}

fn check(s: &Summary) -> Result<Stored, String> {
    let who = format!("{}/{}", s.caster, s.mountpoint);
    if !ident_ok(&s.source, 64) || !ident_ok(&s.caster, 128) || !ident_ok(&s.mountpoint, 64) {
        return Err(format!(
            "{who}: source, caster and mountpoint are identifiers"
        ));
    }
    let (a, z) = (s.window_start_utc.secs()?, s.window_end_utc.secs()?);
    if z - a < 600.0 || z - a > 31.0 * 86_400.0 {
        return Err(format!("{who}: the window must span 10 minutes to 31 days"));
    }
    let ok = |x: f64| x.is_finite() && x >= 0.0;
    if !(ok(s.latency_ms_p50) && ok(s.latency_ms_p95) && s.latency_ms_p50 <= s.latency_ms_p95)
        || !(0.0..=1.0).contains(&s.completeness)
        || !(0.0..=1.0).contains(&s.uptime)
        || !ok(s.stale_s)
    {
        return Err(format!(
            "{who}: latencies non-negative with p50 ≤ p95, completeness and uptime within 0 to 1"
        ));
    }
    Ok(Stored {
        source: s.source.clone(),
        caster: s.caster.clone(),
        mountpoint: s.mountpoint.clone(),
        start: a,
        end: z,
        lat_p95: s.latency_ms_p95,
        completeness: s.completeness,
        stale_per_h: s.staleness_events as f64 / ((z - a) / 3600.0),
        uptime: s.uptime,
    })
}

fn population(scores: &BTreeMap<String, f64>, mine: f64) -> Value {
    if scores.len() < MIN_POPULATION {
        return json!({"suppressed": true, "sources": null,
            "reason": format!("fewer than {MIN_POPULATION} sources observed it in the last {POPULATION_DAYS} days")});
    }
    let mut v: Vec<f64> = scores.values().copied().collect();
    v.sort_by(f64::total_cmp);
    let q = |p: f64| v[((p * v.len() as f64).ceil() as usize).clamp(1, v.len()) - 1];
    json!({
        "sources": v.len(),
        "p10": q(0.10), "p25": q(0.25), "p50": q(0.50), "p75": q(0.75), "p90": q(0.90),
        "rank": v.iter().filter(|x| **x < mine).count() as f64 / v.len() as f64,
    })
}

/// Contribute the caller's summaries and answer the scorecard (raw outcome). `own` are the
/// caller's sources; `now` bounds the population window.
pub fn analyse(
    r: &NtripQosRequest,
    cfg: &NtripQosConfig,
    lock: &StoreLock,
    own: &[String],
    now: f64,
) -> Result<Value, String> {
    let path = cfg
        .store
        .as_ref()
        .ok_or("ntrip-qos is not offered by this service (no store configured)")?;
    if r.summaries.is_empty() || r.summaries.len() > 2_000 {
        return Err("1 to 2,000 summaries".into());
    }
    let mine: Vec<Stored> = r
        .summaries
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if !own.contains(&s.source) {
                return Err(format!(
                    "summaries[{i}]: '{}' is not one of your sources",
                    s.source
                ));
            }
            check(s).map_err(|e| format!("summaries[{i}]: {e}"))
        })
        .collect::<Result<_, _>>()?;
    let _g = lock.0.lock().map_err(|_| "store lock poisoned")?;
    // Give: append.
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("store: {e}"))?;
    for m in &mine {
        writeln!(
            f,
            "{}",
            serde_json::to_string(m).map_err(|e| e.to_string())?
        )
        .map_err(|e| format!("store: {e}"))?;
    }
    f.sync_all().map_err(|e| format!("store: {e}"))?;
    // Get: the population, latest contribution per (source, caster, mountpoint) in the window.
    let text = std::fs::read_to_string(path).map_err(|e| format!("store: {e}"))?;
    let mut latest: BTreeMap<(String, String, String), Stored> = BTreeMap::new();
    for l in text.lines().filter(|l| !l.trim().is_empty()) {
        let s: Stored = serde_json::from_str(l).map_err(|e| format!("store: {e}"))?;
        if s.end < now - POPULATION_DAYS * 86_400.0 {
            continue;
        }
        let k = (s.source.clone(), s.caster.clone(), s.mountpoint.clone());
        if latest.get(&k).is_none_or(|o| o.end <= s.end) {
            latest.insert(k, s);
        }
    }
    // Population per mountpoint and per caster (a source's caster score: mean of its mountpoints).
    let mut mp_pop: BTreeMap<(String, String), BTreeMap<String, f64>> = BTreeMap::new();
    let mut caster_acc: BTreeMap<String, BTreeMap<String, Vec<f64>>> = BTreeMap::new();
    for ((src, c, m), s) in &latest {
        let sc = score(s);
        mp_pop
            .entry((c.clone(), m.clone()))
            .or_default()
            .insert(src.clone(), sc);
        caster_acc
            .entry(c.clone())
            .or_default()
            .entry(src.clone())
            .or_default()
            .push(sc);
    }
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let caster_pop: BTreeMap<String, BTreeMap<String, f64>> = caster_acc
        .iter()
        .map(|(c, by)| {
            (
                c.clone(),
                by.iter().map(|(s, v)| (s.clone(), mean(v))).collect(),
            )
        })
        .collect();
    // The caller's own figures (this call's summaries; several sources on one mountpoint are
    // averaged).
    let mut own_mp: BTreeMap<(String, String), Vec<&Stored>> = BTreeMap::new();
    for m in &mine {
        own_mp
            .entry((m.caster.clone(), m.mountpoint.clone()))
            .or_default()
            .push(m);
    }
    let mut mps = vec![];
    let mut own_caster: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for ((c, m), v) in &own_mp {
        let sc = mean(&v.iter().map(|s| score(s)).collect::<Vec<_>>());
        own_caster.entry(c.clone()).or_default().push(sc);
        let avg = |f: fn(&Stored) -> f64| mean(&v.iter().map(|s| f(s)).collect::<Vec<_>>());
        mps.push(json!({
            "caster": c,
            "mountpoint": m,
            "score": sc,
            "components": {
                "latency_ms_p95": avg(|s| s.lat_p95),
                "completeness": avg(|s| s.completeness),
                "staleness_events_per_h": avg(|s| s.stale_per_h),
                "uptime": avg(|s| s.uptime),
            },
            "window": [iso(v.iter().map(|s| s.start).fold(f64::INFINITY, f64::min) as i64),
                iso(v.iter().map(|s| s.end).fold(f64::NEG_INFINITY, f64::max) as i64)],
            "population": population(&mp_pop[&(c.clone(), m.clone())], sc),
        }));
    }
    let casters: Vec<Value> = own_caster
        .iter()
        .map(|(c, v)| {
            let sc = mean(v);
            json!({"caster": c, "mountpoints": v.len(), "score": sc,
                "population": population(&caster_pop[c], sc)})
        })
        .collect();
    let distinct: BTreeSet<&str> = latest.keys().map(|k| k.0.as_str()).collect();
    Ok(json!({
        "method_version": METHOD_VERSION,
        "contributed": mine.len(),
        "mountpoints": mps,
        "casters": casters,
        "store_sources": distinct.len(),
        "statement": "A score of what the contributing monitors saw, not of the caster's internals. Population figures are suppressed below five sources; no other source is named.",
    }))
}

#[cfg(test)]
#[path = "ntrip_qos_tests.rs"]
mod tests;
