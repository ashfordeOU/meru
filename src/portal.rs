// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The versioned verdict API, the insurer portal and contributor-only population benchmarks
//! (research backlog E25, B2506).
//!
//! * **Versions.** `/verdict/<method>` (and its alias `/v1/verdict/<method>`) is version 1: the
//!   signed verdict as it has always been returned, unchanged. `/v2/verdict/<method>` is version
//!   2: the same signed verdict inside an envelope that names the API version, the method version
//!   and the deprecation status. Both are served together. `GET /versions` publishes the policy:
//!   a version is served for at least five years after its successor is released, and its sunset
//!   date is announced in `/versions` before it ends.
//! * **Insurer portal** (`POST /verdict/scorecard`, licences listed in `MERU_INSURER_PORTAL`): an
//!   underwriter sends the signed verdicts a policyholder has shared with it (this service's
//!   verdicts only, each checked against its key) and gets a signed scorecard for the subject:
//!   per method, how many verdicts, over which period, and their outcomes. A summary of evidence,
//!   never an underwriting, pricing or claims decision; no insurer partners are implied.
//! * **Contributor benchmarks** (`POST /verdict/benchmark`, contributors listed in
//!   `MERU_CONTRIBUTORS` with the archive sources they feed): where one of the contributor's own
//!   sources stands in the population of an archive domain: the population's percentiles over
//!   sources and the source's percentile rank. Only for contributors (give to get), only for their
//!   own sources, and suppressed below five sources; no other source's figure is returned.

use crate::archives::{ArchiveConfig, Area, Record};
use crate::cause::Time;
use crate::verdict::{verify, SignedVerdict};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// When version 2 was released, and the earliest date version 1 may end (five years later).
pub const V2_RELEASED: &str = "2026-11-20";
pub const V1_SUNSET_NOT_BEFORE: &str = "2031-11-20";

/// The published version policy (`GET /versions`).
pub fn versions() -> Value {
    json!({
        "versions": [
            {"version": 1, "paths": ["/verdict/<method>", "/v1/verdict/<method>"], "status": "supported",
                "sunset_not_before": V1_SUNSET_NOT_BEFORE, "sunset_announced": null},
            {"version": 2, "paths": ["/v2/verdict/<method>"], "status": "current", "released": V2_RELEASED},
        ],
        "policy": "A version is served for at least five years after its successor is released. A sunset date is announced here before a version ends. Signed verdicts are the same in every version; only the envelope differs.",
    })
}

/// The version 2 envelope around a signed verdict.
pub fn v2_envelope(v: &SignedVerdict) -> Value {
    json!({
        "api_version": 2,
        "method": v.method,
        "method_version": v.verdict.get("method_version").or_else(|| v.verdict.get("method")),
        "deprecation": null,
        "verdict": v,
    })
}

// ------------------------------------------------------------------------------------------
// Insurer portal
// ------------------------------------------------------------------------------------------

/// A scorecard request: the subject and the verdicts its holder shared.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScorecardRequest {
    /// The subject (a vessel, a fleet, a receiver model), as the insurer names it; echoed.
    pub subject: String,
    pub verdicts: Vec<SignedVerdict>,
}

/// The outcome field each method's verdicts are summarised by.
fn outcome(v: &SignedVerdict) -> Option<String> {
    let o = &v.verdict;
    for k in [
        "classification",
        "statement",
        "state",
        "attribution",
        "finding",
    ] {
        if let Some(s) = o.get(k).and_then(Value::as_str) {
            if s.len() <= 40 {
                return Some(format!("{k}:{s}"));
            }
        }
    }
    None
}

/// Build the scorecard (raw outcome).
pub fn scorecard(r: &ScorecardRequest, service_key: &str) -> Result<Value, String> {
    if r.subject.trim().is_empty() || r.subject.len() > 128 {
        return Err("subject: 1 to 128 characters".into());
    }
    if r.verdicts.is_empty() || r.verdicts.len() > 500 {
        return Err("1 to 500 verdicts".into());
    }
    let mut by: BTreeMap<String, (usize, String, String, BTreeMap<String, usize>)> =
        BTreeMap::new();
    let mut hashes = vec![];
    for (i, v) in r.verdicts.iter().enumerate() {
        let p = verify(v, service_key);
        if !p.is_empty() {
            return Err(format!(
                "verdicts[{i}]: not a verdict of this service: {}",
                p.join("; ")
            ));
        }
        hashes.push(v.verdict_sha256.clone());
        let e = by.entry(v.method.clone()).or_insert((
            0,
            v.utc.clone(),
            v.utc.clone(),
            BTreeMap::new(),
        ));
        e.0 += 1;
        if v.utc < e.1 {
            e.1 = v.utc.clone();
        }
        if v.utc > e.2 {
            e.2 = v.utc.clone();
        }
        if let Some(o) = outcome(v) {
            *e.3.entry(o).or_insert(0) += 1;
        }
    }
    hashes.sort();
    hashes.dedup();
    Ok(json!({
        "method_version": "scorecard/1",
        "subject": r.subject,
        "verdicts": hashes.len(),
        "methods": by.iter().map(|(m, (n, a, z, o))| json!({
            "method": m, "verdicts": n, "first_utc": a, "last_utc": z, "outcomes": o,
        })).collect::<Vec<_>>(),
        "verdict_sha256": hashes,
        "statement": "A summary of the signed evidence the holder shared. Not an underwriting, pricing or claims decision and not insurance advice.",
    }))
}

// ------------------------------------------------------------------------------------------
// Contributor benchmarks
// ------------------------------------------------------------------------------------------

/// Fewest sources in the population for a benchmark.
pub const MIN_POPULATION: usize = 5;

/// A benchmark request.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkRequest {
    pub domain: String,
    pub value: String,
    pub area: Area,
    pub from_utc: Time,
    pub to_utc: Time,
    /// The contributor's own source to place in the population.
    pub source: String,
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

/// Place a contributor's own source in the population (raw outcome). `own` are the sources the
/// contributor feeds.
pub fn benchmark(
    r: &BenchmarkRequest,
    cfg: &ArchiveConfig,
    own: &[String],
) -> Result<Value, String> {
    if !own.contains(&r.source) {
        return Err("benchmarks are given only for a source the contributor feeds".into());
    }
    let dir = cfg
        .dir
        .as_ref()
        .ok_or("archives are not offered by this service")?;
    if !crate::archives::DOMAINS
        .iter()
        .any(|(d, v)| *d == r.domain && v.contains(&r.value.as_str()))
    {
        return Err(format!(
            "unknown domain or value '{}/{}'",
            r.domain, r.value
        ));
    }
    if !(r.area.radius_km >= crate::archives::MIN_RADIUS_KM && r.area.radius_km <= 3000.0) {
        return Err("area radius: 10 to 3,000 km".into());
    }
    let (a, z) = (r.from_utc.secs()?, r.to_utc.secs()?);
    if z - a < 86_400.0 || z - a > 366.0 * 86_400.0 {
        return Err("the window must span 1 to 366 days".into());
    }
    let text = std::fs::read_to_string(dir.join(format!("{}.jsonl", r.domain))).unwrap_or_default();
    let mut per: BTreeMap<String, (f64, usize)> = BTreeMap::new();
    for l in text.lines().filter(|l| !l.trim().is_empty()) {
        let rec: Record = serde_json::from_str(l).map_err(|e| format!("archive: {e}"))?;
        if rec.t < a
            || rec.t >= z
            || dist_km((r.area.lat_deg, r.area.lon_deg), (rec.lat_deg, rec.lon_deg))
                > r.area.radius_km
        {
            continue;
        }
        if let Some(v) = rec.values.get(&r.value) {
            let e = per.entry(rec.source).or_insert((0.0, 0));
            e.0 += v;
            e.1 += 1;
        }
    }
    let mut means: Vec<f64> = per.values().map(|(s, n)| s / *n as f64).collect();
    if means.len() < MIN_POPULATION {
        return Ok(
            json!({"method_version": "benchmark/1", "domain": r.domain, "value": r.value,
            "suppressed": true, "reason": format!("fewer than {MIN_POPULATION} sources in the population")}),
        );
    }
    let mine = per
        .get(&r.source)
        .map(|(s, n)| s / *n as f64)
        .ok_or("the source has no records in this area and window")?;
    means.sort_by(f64::total_cmp);
    let q = |p: f64| means[((p * means.len() as f64).ceil() as usize).clamp(1, means.len()) - 1];
    let below = means.iter().filter(|m| **m < mine).count();
    Ok(json!({
        "method_version": "benchmark/1",
        "domain": r.domain,
        "value": r.value,
        "source": r.source,
        "population_sources": means.len(),
        "population": {"p10": q(0.10), "p25": q(0.25), "p50": q(0.50), "p75": q(0.75), "p90": q(0.90)},
        "own_mean": mine,
        "own_percentile_rank": below as f64 / means.len() as f64,
        "statement": "Where the contributor's own source stands in the population of sources; no other source's figure is returned.",
    }))
}

#[cfg(test)]
#[path = "portal_tests.rs"]
mod tests;
