// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The `timing-correlation` method: cross-grandmaster and cross-operator correlation of timing
//! offsets (research backlog E19, B1903).
//!
//! Each site (a GNSS-disciplined grandmaster, a PRTC, a base station's timing receiver) reports
//! the offset of its GNSS time against an independent local reference (its own holdover
//! oscillator, a caesium, time from another path). A slow-drift attack moves GNSS time a little at
//! a time, slowly enough that one site's offset stays inside its alarm limit for a long while.
//! Many sites drifting together, at the same rate, is much easier to see than one site drifting:
//! the noise of the combined drift estimate falls with the number of sites.
//!
//! The method estimates each site's drift (the slope of its offset in a sliding window, less its
//! own baseline slope), and tests the sites in groups (each region cluster, each operator, all
//! sites) for a common drift, so a correlated drift is detected earlier than by any single site.
//! Each episode is read by **scope** from which sites shared it:
//!
//! * `regional_drift`: sites of two or more operators in one region, others not: fits a regional
//!   spoofing or interference cause (no source is located);
//! * `constellation_wide`: most sites everywhere: fits an upstream constellation time anomaly;
//! * `operator_wide`: the sites of one operator, others in the same regions not: fits the
//!   operator's own distribution or configuration;
//! * `single_site`.
//!
//! Answer: the episodes (start, detection time by the group test and by the earliest single site,
//! drift rate, sites and operators affected, scope, reading) and a NOC alert feed (one alert per
//! episode with a severity), signed. The window, thresholds and grouping rules stay in the
//! service. Evidence class MODELLED: checked in simulation, not against operators' incident logs.

use crate::cause::Time;
use crate::server::iso;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Method identifier written into every outcome.
pub const METHOD_VERSION: &str = "timing-correlation/1";

/// Sliding window for the drift estimate, seconds.
const WINDOW_S: f64 = 120.0;
/// Step between windows, seconds.
const STEP_S: f64 = 5.0;
/// Baseline span at the start of each series, seconds.
const BASELINE_S: f64 = 300.0;
/// Detection threshold on the drift z-score, held for two consecutive windows.
const Z_DETECT: f64 = 6.0;
/// A site counts as affected when its own z-score reaches this in an episode.
const Z_AFFECTED: f64 = 3.0;
/// Sites within this distance form a region cluster, km.
const REGION_KM: f64 = 300.0;
/// Share of all sites for a constellation-wide reading.
const WIDE_SHARE: f64 = 0.8;

// ------------------------------------------------------------------------------------------
// Request
// ------------------------------------------------------------------------------------------

/// A timing site.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub id: String,
    /// The operator (network) it belongs to.
    pub operator: String,
    pub lat_deg: f64,
    pub lon_deg: f64,
}

/// One site's offsets: GNSS time minus the local reference, nanoseconds, at `t0 + i * dt_s`
/// (`null` where none).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Series {
    pub site: String,
    pub t0: Time,
    pub dt_s: f64,
    pub offset_ns: Vec<Option<f64>>,
}

/// Request for the `timing-correlation` method.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationRequest {
    #[serde(default)]
    pub subject: Option<String>,
    pub sites: Vec<Site>,
    pub series: Vec<Series>,
}

/// Request limits.
#[derive(Clone, Debug)]
pub struct CorrelationLimits {
    pub max_sites: usize,
    pub max_samples: usize,
}

impl Default for CorrelationLimits {
    fn default() -> Self {
        CorrelationLimits {
            max_sites: 500,
            max_samples: 2_000_000,
        }
    }
}

// ------------------------------------------------------------------------------------------
// Drift estimates
// ------------------------------------------------------------------------------------------

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

/// Least-squares slope and its standard error over the points.
fn slope(pts: &[(f64, f64)]) -> Option<(f64, f64)> {
    let n = pts.len() as f64;
    if pts.len() < 10 {
        return None;
    }
    let (mx, my) = (
        pts.iter().map(|p| p.0).sum::<f64>() / n,
        pts.iter().map(|p| p.1).sum::<f64>() / n,
    );
    let sxx: f64 = pts.iter().map(|p| (p.0 - mx).powi(2)).sum();
    if sxx <= 0.0 {
        return None;
    }
    let b = pts.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum::<f64>() / sxx;
    let rss: f64 = pts
        .iter()
        .map(|p| (p.1 - my - b * (p.0 - mx)).powi(2))
        .sum();
    let se = (rss / (n - 2.0) / sxx).sqrt().max(1e-9);
    Some((b, se))
}

/// One site's drift test per window end: (window end, drift above baseline, standard error).
struct SiteDrift {
    windows: BTreeMap<i64, (f64, f64)>,
}

fn site_drift(t0: f64, dt: f64, y: &[Option<f64>]) -> SiteDrift {
    let pts: Vec<(f64, f64)> = y
        .iter()
        .enumerate()
        .filter_map(|(i, v)| v.filter(|x| x.is_finite()).map(|v| (t0 + i as f64 * dt, v)))
        .collect();
    let mut windows = BTreeMap::new();
    let Some(first) = pts.first().map(|p| p.0) else {
        return SiteDrift { windows };
    };
    let base: Vec<(f64, f64)> = pts
        .iter()
        .copied()
        .filter(|p| p.0 < first + BASELINE_S)
        .collect();
    let b0 = slope(&base).map(|s| s.0).unwrap_or(0.0);
    let last = pts.last().map(|p| p.0).unwrap_or(first);
    let mut end = first + BASELINE_S + WINDOW_S;
    let mut lo = 0usize;
    while end <= last + 1e-9 {
        while lo < pts.len() && pts[lo].0 < end - WINDOW_S {
            lo += 1;
        }
        let hi = pts.partition_point(|p| p.0 <= end);
        if let Some((b, se)) = slope(&pts[lo..hi]) {
            windows.insert(end.round() as i64, (b - b0, se));
        }
        end += STEP_S;
    }
    SiteDrift { windows }
}

/// The first window end where `z` holds for two consecutive windows.
fn first_alarm(zs: &[(i64, f64)]) -> Option<i64> {
    zs.windows(2)
        .find(|w| {
            w[0].1.abs() >= Z_DETECT
                && w[1].1.abs() >= Z_DETECT
                && w[0].1.signum() == w[1].1.signum()
        })
        .map(|w| w[1].0)
}

/// A group's combined z-score per window end.
fn group_z(members: &[&SiteDrift]) -> Vec<(i64, f64)> {
    let mut ends: BTreeSet<i64> = BTreeSet::new();
    for m in members {
        ends.extend(m.windows.keys().copied());
    }
    ends.into_iter()
        .filter_map(|e| {
            let v: Vec<(f64, f64)> = members
                .iter()
                .filter_map(|m| m.windows.get(&e).copied())
                .collect();
            if v.len() < 2 {
                return None;
            }
            let n = v.len() as f64;
            let mean = v.iter().map(|x| x.0).sum::<f64>() / n;
            let se = v.iter().map(|x| x.1 * x.1).sum::<f64>().sqrt() / n;
            // The drift must be common: most members on the same side.
            let same = v.iter().filter(|x| x.0.signum() == mean.signum()).count() as f64 / n;
            Some((e, if same >= 0.7 { mean / se } else { 0.0 }))
        })
        .collect()
}

// ------------------------------------------------------------------------------------------
// The method
// ------------------------------------------------------------------------------------------

/// Run the method; the raw (unrounded, unsigned) outcome.
pub fn analyse(r: &CorrelationRequest, l: &CorrelationLimits) -> Result<Value, String> {
    if r.sites.len() < 2 || r.sites.len() > l.max_sites {
        return Err(format!("2 to {} sites", l.max_sites));
    }
    if r.series.iter().map(|s| s.offset_ns.len()).sum::<usize>() > l.max_samples {
        return Err(format!("at most {} samples", l.max_samples));
    }
    let mut sites: BTreeMap<&str, &Site> = BTreeMap::new();
    for s in &r.sites {
        if !(s.lat_deg.abs() <= 90.0 && s.lon_deg.abs() <= 180.0) || s.operator.is_empty() {
            return Err(format!("site '{}': position and operator required", s.id));
        }
        if sites.insert(&s.id, s).is_some() {
            return Err(format!("site '{}' listed twice", s.id));
        }
    }
    let mut drift: BTreeMap<&str, SiteDrift> = BTreeMap::new();
    for s in &r.series {
        if !sites.contains_key(s.site.as_str()) {
            return Err(format!("series for unknown site '{}'", s.site));
        }
        if !(0.1..=60.0).contains(&s.dt_s) {
            return Err(format!(
                "series '{}': dt_s must be within 0.1 to 60 s",
                s.site
            ));
        }
        if drift
            .insert(&s.site, site_drift(s.t0.secs()?, s.dt_s, &s.offset_ns))
            .is_some()
        {
            return Err(format!("two series for site '{}'", s.site));
        }
    }
    let ids: Vec<&str> = drift.keys().copied().collect();
    // Region clusters (single linkage within REGION_KM).
    let mut region: BTreeMap<&str, usize> = BTreeMap::new();
    let mut next = 0usize;
    for id in &ids {
        if region.contains_key(id) {
            continue;
        }
        let mut stack = vec![*id];
        region.insert(id, next);
        while let Some(a) = stack.pop() {
            for b in &ids {
                if !region.contains_key(b) {
                    let (sa, sb) = (sites[a], sites[b]);
                    if dist_km((sa.lat_deg, sa.lon_deg), (sb.lat_deg, sb.lon_deg)) <= REGION_KM {
                        region.insert(b, next);
                        stack.push(b);
                    }
                }
            }
        }
        next += 1;
    }
    // Groups: each region, each operator, all.
    let mut groups: Vec<(String, Vec<&str>)> = vec![("all".into(), ids.clone())];
    for g in 0..next {
        groups.push((
            format!("region-{g}"),
            ids.iter().copied().filter(|i| region[i] == g).collect(),
        ));
    }
    let ops: BTreeSet<&str> = ids.iter().map(|i| sites[i].operator.as_str()).collect();
    for o in &ops {
        groups.push((
            format!("operator:{o}"),
            ids.iter()
                .copied()
                .filter(|i| sites[i].operator == *o)
                .collect(),
        ));
    }
    // Single-site alarms.
    let single: BTreeMap<&str, Option<i64>> = ids
        .iter()
        .map(|id| {
            let zs: Vec<(i64, f64)> = drift[id]
                .windows
                .iter()
                .map(|(e, (b, se))| (*e, b / se))
                .collect();
            (*id, first_alarm(&zs))
        })
        .collect();
    // Group alarms → episodes (by earliest group alarm, merged when within a window).
    let mut alarms: Vec<(i64, String)> = groups
        .iter()
        .filter(|(_, m)| m.len() >= 2)
        .filter_map(|(name, m)| {
            let mem: Vec<&SiteDrift> = m.iter().map(|i| &drift[i]).collect();
            first_alarm(&group_z(&mem)).map(|t| (t, name.clone()))
        })
        .collect();
    alarms.sort();
    let mut episodes: Vec<Value> = vec![];
    let mut alerts: Vec<Value> = vec![];
    let mut used_until = i64::MIN;
    for (t, group) in &alarms {
        if *t <= used_until {
            continue;
        }
        // Affected sites: the median of the site's own z-score over the window after detection
        // reaches Z_AFFECTED (a median, so one noisy window does not count).
        let horizon = *t + WINDOW_S as i64;
        let affected: Vec<&str> = ids
            .iter()
            .copied()
            .filter(|id| {
                let mut z: Vec<f64> = drift[id]
                    .windows
                    .range(*t..=horizon)
                    .map(|(_, (b, se))| b / se)
                    .collect();
                if z.is_empty() {
                    return false;
                }
                z.sort_by(f64::total_cmp);
                z[z.len() / 2].abs() >= Z_AFFECTED
            })
            .collect();
        let rate: Vec<f64> = affected
            .iter()
            .filter_map(|id| {
                drift[id]
                    .windows
                    .range(*t..=horizon)
                    .last()
                    .map(|(_, (b, _))| *b)
            })
            .collect();
        let mean_rate = if rate.is_empty() {
            0.0
        } else {
            rate.iter().sum::<f64>() / rate.len() as f64
        };
        let a_ops: BTreeSet<&str> = affected
            .iter()
            .map(|i| sites[i].operator.as_str())
            .collect();
        let a_regions: BTreeSet<usize> = affected.iter().map(|i| region[i]).collect();
        let scope = if affected.len() as f64 >= WIDE_SHARE * ids.len() as f64 && a_ops.len() >= 2 {
            "constellation_wide"
        } else if a_ops.len() == 1 && affected.len() >= 2 {
            // Others of other operators in the same regions unaffected?
            let others = ids.iter().filter(|i| {
                a_regions.contains(&region[*i]) && !a_ops.contains(sites[*i].operator.as_str())
            });
            if others.count() > 0 {
                "operator_wide"
            } else {
                "unresolved"
            }
        } else if a_ops.len() >= 2 && a_regions.len() == 1 {
            "regional_drift"
        } else if affected.len() == 1 {
            "single_site"
        } else {
            "several_sites"
        };
        let reading = match scope {
            "regional_drift" => "sites of several operators in one region drift together while others do not: fits a regional spoofing or interference cause (no source is located)",
            "constellation_wide" => "most sites everywhere drift together: fits an upstream constellation time anomaly",
            "operator_wide" => "the sites of one operator drift together while other operators' sites nearby do not: fits the operator's own distribution or configuration",
            "single_site" => "one site: fits a local cause (its receiver, antenna or reference)",
            _ => "several sites without a clear shared pattern",
        };
        let first_single = affected.iter().filter_map(|i| single[i]).min();
        // 0.5 ns/s reaches 1 µs of time error in about half an hour.
        let severity = if mean_rate.abs() >= 0.5 || scope == "constellation_wide" {
            "critical"
        } else if mean_rate.abs() >= 0.05 {
            "major"
        } else {
            "minor"
        };
        let id = format!("TC-{}", episodes.len() + 1);
        episodes.push(json!({
            "id": id,
            "detected_utc": iso(*t),
            "detected_by_group": group.split(':').next().unwrap_or("group"),
            "earliest_single_site_utc": first_single.map(iso),
            "lead_s": first_single.map(|s| s - t),
            "drift_ns_per_s": mean_rate,
            "sites_affected": affected.len(),
            "operators_affected": a_ops.len(),
            "regions_affected": a_regions.len(),
            "scope": scope,
            "reading": reading,
        }));
        alerts.push(json!({
            "alert_id": id,
            "time_utc": iso(*t),
            "severity": severity,
            "scope": scope,
            "message": format!("{} timing drift of about {:.2} ns/s at {} sites of {} operators", scope.replace('_', " "), mean_rate, affected.len(), a_ops.len()),
        }));
        used_until = horizon + 10 * WINDOW_S as i64;
    }
    Ok(json!({
        "method_version": METHOD_VERSION,
        "subject": r.subject,
        "sites": ids.len(),
        "operators": ops.len(),
        "regions": next,
        "episodes": episodes,
        "noc_alerts": alerts,
        "limits": [
            "Offsets are against each site's own local reference; a drift of that reference shows as a drift of the site.",
            "Scopes are readings of which sites shared a drift; nothing here locates a transmitter or an interference source.",
        ],
        "evidence": "MODELLED: checked in simulation (synthetic drifts across sites); not against operators' incident logs.",
    }))
}

/// Run the `timing-correlation` method and return a signed verdict. Not fingerprinted.
pub fn correlation_verdict(
    req: &CorrelationRequest,
    s: &crate::methods::Signing,
    limits: &CorrelationLimits,
    utc: &str,
) -> Result<crate::SignedVerdict, String> {
    let v = analyse(req, limits)?;
    crate::methods::finish("timing-correlation", v, s, utc)
}

#[cfg(test)]
#[path = "timing_correlation_tests.rs"]
mod tests;
