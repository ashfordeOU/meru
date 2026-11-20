// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The `feeder-trust` method: how far can each feeder of a crowd-sourced GNSS monitoring
//! network be trusted (research backlog E26; the item text is to confirm)?
//!
//! A monitoring network takes observation batches from many feeders (`kshana.obs/1`, signed
//! with `kshana-obs-provenance/1` sidecars and checked by `kshana-pro obs-provenance verify`).
//! A signature proves who sent a batch, not that its observations are true. This method judges
//! the observations' behaviour across the network over a window:
//!
//! * **provenance**: the share of the feeder's batches that verified as signed, rejected
//!   batches, breaks in its batch sequence (from the caller's `obs-provenance verify` output);
//! * **corroboration**: when the feeder raised an interference alarm, did a nearby feeder with
//!   data raise one too; when most nearby feeders alarmed, did it;
//! * **duplicates**: two feeders sending the same stream (a copied or replayed feed, or one
//!   station posing as two);
//! * **continuity**: the share of the window the feeder reported.
//!
//! Per feeder: `trusted`, `probation`, `untrusted` or `insufficient_overlap`, a trust score in
//! steps of 0.05, the reasons and the counts behind them. The weights and thresholds stay in the
//! service. The method judges reports against each other; it never estimates where an
//! interference source is. Evidence class MODELLED.

use crate::cause::Time;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Method identifier written into every outcome. A change to any rule is a new version.
pub const METHOD_VERSION: &str = "feeder-trust/1";

/// Feeders within this distance corroborate each other, km.
const NEAR_KM: f64 = 150.0;
/// Fewest alarm bins (own) or nearby-alarm bins for a corroboration figure.
const MIN_BINS: usize = 5;
/// Fewest bins two streams share before they are compared for duplication.
const MIN_DUP_BINS: usize = 50;

// ------------------------------------------------------------------------------------------
// Request
// ------------------------------------------------------------------------------------------

/// A feeder's provenance summary (from `kshana-pro obs-provenance verify --json`).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub batches: usize,
    pub signed: usize,
    #[serde(default)]
    pub unsigned: usize,
    #[serde(default)]
    pub rejected: usize,
    #[serde(default)]
    pub sequence_breaks: usize,
}

/// A feeder and its station.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feeder {
    pub id: String,
    pub lat_deg: f64,
    pub lon_deg: f64,
    #[serde(default)]
    pub provenance: Option<Provenance>,
}

/// One feeder's binned reports: one character per bin from `t0` (`1` alarm, `0` no alarm,
/// `-` no data) and, optionally, the mean C/N0 per bin (`null` where none).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stream {
    pub feeder: String,
    pub alarm: String,
    #[serde(default)]
    pub cn0_mean: Option<Vec<Option<f64>>>,
}

/// Request for the `feeder-trust` method.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeederRequest {
    /// The network's label, echoed.
    #[serde(default)]
    pub network: Option<String>,
    /// Start of the first bin.
    pub t0: Time,
    /// Bin length, seconds (60 to 3,600).
    pub bin_s: f64,
    pub feeders: Vec<Feeder>,
    pub streams: Vec<Stream>,
}

/// Request limits.
#[derive(Clone, Debug)]
pub struct FeederLimits {
    pub max_feeders: usize,
    /// Most bins per stream.
    pub max_bins: usize,
    /// Most bins over all streams.
    pub max_total_bins: usize,
}

impl Default for FeederLimits {
    fn default() -> Self {
        FeederLimits {
            max_feeders: 2_000,
            max_bins: 20_000,
            max_total_bins: 4_000_000,
        }
    }
}

// ------------------------------------------------------------------------------------------
// The method
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

/// One bin: `Some(alarm)` or `None` (no data).
type Bins = Vec<Option<bool>>;

/// A stream's bins and its C/N0, when given.
type Parsed<'a> = (Bins, Option<&'a Vec<Option<f64>>>);

fn bins(s: &Stream) -> Result<Bins, String> {
    s.alarm
        .chars()
        .enumerate()
        .map(|(i, c)| match c {
            '1' => Ok(Some(true)),
            '0' => Ok(Some(false)),
            '-' => Ok(None),
            c => Err(format!(
                "stream '{}': bin {i} is '{c}' (expected 1, 0 or -)",
                s.feeder
            )),
        })
        .collect()
}

/// Whether two streams are the same feed: identical alarms over many shared bins with several
/// alarms, and C/N0 identical where both give it.
fn duplicate(a: &Parsed, b: &Parsed) -> bool {
    let n = a.0.len().min(b.0.len());
    let mut shared = 0usize;
    let mut alarms = 0usize;
    for i in 0..n {
        match (a.0[i], b.0[i]) {
            (Some(x), Some(y)) => {
                if x != y {
                    return false;
                }
                shared += 1;
                alarms += x as usize;
            }
            (None, None) => {}
            _ => return false,
        }
    }
    let cn0_same = match (a.1, b.1) {
        (Some(x), Some(y)) => {
            let both: Vec<(f64, f64)> = x
                .iter()
                .zip(y)
                .filter_map(|(p, q)| Some(((*p)?, (*q)?)))
                .collect();
            both.len() >= MIN_DUP_BINS / 2 && both.iter().all(|(p, q)| (p - q).abs() < 1e-6)
        }
        // Without C/N0, identical alarm patterns with several alarms are enough.
        _ => true,
    };
    shared >= MIN_DUP_BINS && alarms >= 3 && cn0_same
}

/// Run the method; the raw (unrounded, unsigned) outcome.
pub fn analyse(r: &FeederRequest, l: &FeederLimits) -> Result<Value, String> {
    r.t0.secs()?;
    if !(60.0..=3600.0).contains(&r.bin_s) {
        return Err("bin_s must be within 60 to 3,600 seconds".into());
    }
    if r.feeders.len() < 2 || r.feeders.len() > l.max_feeders {
        return Err(format!("2 to {} feeders", l.max_feeders));
    }
    let total: usize = r.streams.iter().map(|s| s.alarm.len()).sum();
    if total > l.max_total_bins || r.streams.iter().any(|s| s.alarm.len() > l.max_bins) {
        return Err(format!(
            "at most {} bins a stream and {} in all",
            l.max_bins, l.max_total_bins
        ));
    }
    let mut feeders: BTreeMap<&str, &Feeder> = BTreeMap::new();
    for f in &r.feeders {
        if !(f.lat_deg.abs() <= 90.0 && f.lon_deg.abs() <= 360.0) {
            return Err(format!("feeder '{}': position out of range", f.id));
        }
        if let Some(p) = &f.provenance {
            if p.signed + p.unsigned + p.rejected > p.batches {
                return Err(format!(
                    "feeder '{}': signed, unsigned and rejected exceed the batches",
                    f.id
                ));
            }
        }
        if feeders.insert(f.id.as_str(), f).is_some() {
            return Err(format!("feeder '{}' listed twice", f.id));
        }
    }
    let mut streams: BTreeMap<&str, Parsed> = BTreeMap::new();
    for s in &r.streams {
        if !feeders.contains_key(s.feeder.as_str()) {
            return Err(format!("stream for unknown feeder '{}'", s.feeder));
        }
        if s.cn0_mean
            .as_ref()
            .is_some_and(|c| c.len() != s.alarm.len())
        {
            return Err(format!(
                "stream '{}': cn0_mean must have one value per bin",
                s.feeder
            ));
        }
        if streams
            .insert(s.feeder.as_str(), (bins(s)?, s.cn0_mean.as_ref()))
            .is_some()
        {
            return Err(format!("two streams for feeder '{}'", s.feeder));
        }
    }
    let n_bins = streams.values().map(|s| s.0.len()).max().unwrap_or(0);
    if n_bins == 0 {
        return Err("no bins".into());
    }
    let ids: Vec<&str> = feeders.keys().copied().collect();
    // Neighbours.
    let near: BTreeMap<&str, Vec<&str>> = ids
        .iter()
        .map(|a| {
            let fa = feeders[a];
            let v = ids
                .iter()
                .filter(|b| *b != a)
                .filter(|b| {
                    let fb = feeders[*b];
                    dist_km((fa.lat_deg, fa.lon_deg), (fb.lat_deg, fb.lon_deg)) <= NEAR_KM
                })
                .copied()
                .collect();
            (*a, v)
        })
        .collect();
    // Duplicates.
    let mut dups: BTreeMap<&str, usize> = BTreeMap::new();
    let mut dup_pairs = 0usize;
    let sids: Vec<&str> = streams.keys().copied().collect();
    for (i, a) in sids.iter().enumerate() {
        for b in &sids[i + 1..] {
            if duplicate(&streams[a], &streams[b]) {
                dup_pairs += 1;
                *dups.entry(a).or_insert(0) += 1;
                *dups.entry(b).or_insert(0) += 1;
            }
        }
    }
    let at = |id: &str, i: usize| -> Option<bool> {
        streams.get(id).and_then(|s| s.0.get(i).copied().flatten())
    };
    let mut rows = vec![];
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for id in &ids {
        let f = feeders[id];
        let mut reasons: Vec<String> = vec![];
        let mut score: f64 = 1.0;
        let mut untrusted = false;
        // Continuity.
        let data = (0..n_bins).filter(|i| at(id, *i).is_some()).count();
        let continuity = data as f64 / n_bins as f64;
        if continuity < 0.5 {
            score -= 0.15;
            reasons.push(format!(
                "reported in {:.0} % of the window",
                continuity * 100.0
            ));
        }
        // Provenance.
        let mut signed_share = None;
        if let Some(p) = &f.provenance {
            if p.batches > 0 {
                let s = p.signed as f64 / p.batches as f64;
                signed_share = Some(s);
                if p.rejected > 0 {
                    untrusted = true;
                    reasons.push(format!(
                        "{} batches rejected by provenance checks",
                        p.rejected
                    ));
                }
                if s < 0.5 {
                    score -= 0.25;
                    reasons.push("fewer than half of its batches were signed".into());
                } else if s < 0.95 {
                    score -= 0.1;
                    reasons.push("some batches were unsigned".into());
                }
                if p.sequence_breaks > 0 {
                    score -= 0.1;
                    reasons.push(format!(
                        "{} breaks in its batch sequence",
                        p.sequence_breaks
                    ));
                }
            }
        } else {
            score -= 0.15;
            reasons.push("no provenance summary supplied".into());
        }
        // Corroboration.
        let nb = &near[id];
        let (mut own_alarm, mut corroborated) = (0usize, 0usize);
        let (mut crowd_alarm, mut joined) = (0usize, 0usize);
        for i in 0..n_bins {
            let Some(me) = at(id, i) else { continue };
            let others: Vec<bool> = nb.iter().filter_map(|o| at(o, i)).collect();
            if others.is_empty() {
                continue;
            }
            let k = others.iter().filter(|x| **x).count();
            if me {
                own_alarm += 1;
                if k > 0 {
                    corroborated += 1;
                }
            }
            if others.len() >= 2 && k * 2 > others.len() {
                crowd_alarm += 1;
                if me {
                    joined += 1;
                }
            }
        }
        let corroboration = (own_alarm >= MIN_BINS).then(|| corroborated as f64 / own_alarm as f64);
        let sensitivity = (crowd_alarm >= MIN_BINS).then(|| joined as f64 / crowd_alarm as f64);
        if let Some(c) = corroboration {
            let lone = own_alarm - corroborated;
            if c <= 0.2 {
                score -= 0.4;
            } else if c <= 0.7 {
                score -= 0.25;
            }
            if c <= 0.7 {
                reasons.push(format!(
                    "{lone} of its {own_alarm} alarms were not shared by a nearby feeder"
                ));
            }
        }
        if let Some(s) = sensitivity {
            if s < 0.3 {
                score -= 0.3;
                reasons.push(format!(
                    "silent in {:.0} % of the bins when most nearby feeders alarmed",
                    (1.0 - s) * 100.0
                ));
            }
        }
        if let Some(n) = dups.get(id) {
            untrusted = true;
            reasons.push(format!(
                "its stream duplicates {n} other feeder stream{}",
                if *n == 1 { "" } else { "s" }
            ));
        }
        let overlap =
            !nb.is_empty() && (corroboration.is_some() || sensitivity.is_some() || own_alarm == 0);
        let score = (score.clamp(0.0, 1.0) * 20.0).floor() / 20.0;
        let class = if untrusted {
            "untrusted"
        } else if !overlap || nb.iter().all(|o| !streams.contains_key(o)) {
            "insufficient_overlap"
        } else if score >= 0.8 {
            "trusted"
        } else if score >= 0.5 {
            "probation"
        } else {
            "untrusted"
        };
        *counts.entry(class).or_insert(0) += 1;
        rows.push(json!({
            "id": id,
            "class": class,
            "trust_score": if untrusted { 0.0 } else { score },
            "reasons": reasons,
            "continuity": continuity,
            "signed_share": signed_share,
            "nearby_feeders": nb.len(),
            "alarm_bins": own_alarm,
            "alarm_bins_corroborated": corroborated,
            "crowd_alarm_bins": crowd_alarm,
            "crowd_alarm_bins_joined": joined,
        }));
    }
    Ok(json!({
        "method_version": METHOD_VERSION,
        "network": r.network,
        "bins": n_bins,
        "bin_s": r.bin_s,
        "feeders": rows,
        "summary": {
            "trusted": counts.get("trusted").copied().unwrap_or(0),
            "probation": counts.get("probation").copied().unwrap_or(0),
            "untrusted": counts.get("untrusted").copied().unwrap_or(0),
            "insufficient_overlap": counts.get("insufficient_overlap").copied().unwrap_or(0),
            "duplicate_stream_pairs": dup_pairs,
        },
        "limits": [
            "A signature shows who sent a batch, not that its observations are true; corroboration is judged only where nearby feeders reported.",
            "A feeder alone in its area cannot be corroborated and is reported as insufficient_overlap, not as untrusted.",
            "Nothing here estimates where an interference source is.",
        ],
    }))
}

/// Run the `feeder-trust` method and return a signed verdict. Not fingerprinted: classes and
/// scores in steps of 0.05.
pub fn feeder_verdict(
    req: &FeederRequest,
    s: &crate::methods::Signing,
    limits: &FeederLimits,
    utc: &str,
) -> Result<crate::SignedVerdict, String> {
    let v = analyse(req, limits)?;
    crate::methods::finish("feeder-trust", v, s, utc)
}

#[cfg(test)]
#[path = "feeder_trust_tests.rs"]
mod tests;
