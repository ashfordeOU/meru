// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The `gnss-leo-arbitration` method: when a GNSS timing solution and a LEO (low-Earth-orbit
//! PNT) timing solution disagree, which one does the evidence support (research backlog E21,
//! B2106)?
//!
//! **Evaluation evidence only.** The method reads solutions a receiver already produced, after the
//! fact, and says which source the evidence supports in each episode of disagreement, with the
//! evidence. It computes no fused solution, steers no receiver and switches no source; nothing
//! here is a navigation or timing output.
//!
//! Inputs per epoch: each source's time offset against the site's own clock, whether it was
//! valid, and its quality indicators (GNSS: mean C/N0, satellites, authentication; LEO: a quality
//! figure, satellites, authentication). Optionally each source's position, for a disagreement
//! check only.
//!
//! Evidence, in three independent families, per disagreement episode:
//!
//! * **reference**: the site's clock, modelled as a line fitted to the epochs where both sources
//!   agreed before the episode, with an allowance that grows with time since (the caller's clock
//!   stability): the source that departs from the clock's prediction is suspect;
//! * **indicators**: a uniform rise of GNSS C/N0 or a deep drop, lost satellites, an
//!   authentication failure, a low LEO quality figure;
//! * **dynamics**: a step in one source's offset at the start of the episode.
//!
//! The findings combine into a confidence for the suspect source (`gnss`, `leo`) in steps of
//! 0.05, capped by the number of families (one family never decides); below 0.7 the episode is
//! `undetermined`. The integrity statement covers the whole window: how often the sources agreed
//! and by how much, and for how much of the time the evidence identifies a source it supports.
//! Evidence class MODELLED.

use crate::cause::Time;
use crate::server::iso;
use serde::Deserialize;
use serde_json::{json, Value};

/// Method identifier written into every outcome.
pub const METHOD_VERSION: &str = "gnss-leo-arbitration/1";

/// What every verdict says about itself.
pub const STATEMENT: &str = "An after-the-fact assessment of which source the evidence supports. \
Not a navigation or timing output: no fused solution is computed and no source is switched.";

/// Fewest consecutive disagreeing epochs that make an episode.
const MIN_EPISODE: usize = 3;
/// Agreed epochs used for the clock line before an episode.
const BASELINE_EPOCHS: usize = 60;
/// Agreed epochs just before an episode left out of the baseline: a slow pull starts before the
/// sources disagree by the tolerance, and would otherwise bend the baseline.
const GUARD_EPOCHS: usize = 120;
/// Lowest confidence at which a source is named.
const DECIDE_AT: f64 = 0.7;
/// Confidence cap when the findings come from a single family: below [`DECIDE_AT`].
const SINGLE_FAMILY_CAP: f64 = 0.65;

// ------------------------------------------------------------------------------------------
// Request
// ------------------------------------------------------------------------------------------

/// A position, for the disagreement check only.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pos {
    pub lat_deg: f64,
    pub lon_deg: f64,
}

/// The GNSS solution at one epoch.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gnss {
    pub valid: bool,
    /// Time offset against the site's clock, ns.
    #[serde(default)]
    pub time_offset_ns: Option<f64>,
    #[serde(default)]
    pub cn0_mean_dbhz: Option<f64>,
    #[serde(default)]
    pub n_sats: Option<u32>,
    /// Navigation-message authentication (OSNMA, Chimera) passed, when used.
    #[serde(default)]
    pub auth_ok: Option<bool>,
    #[serde(default)]
    pub position: Option<Pos>,
}

/// The LEO solution at one epoch.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Leo {
    pub valid: bool,
    #[serde(default)]
    pub time_offset_ns: Option<f64>,
    /// The provider's quality figure, 0 (worst) to 1 (best).
    #[serde(default)]
    pub quality: Option<f64>,
    #[serde(default)]
    pub n_sats: Option<u32>,
    #[serde(default)]
    pub auth_ok: Option<bool>,
    #[serde(default)]
    pub position: Option<Pos>,
}

/// One epoch.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    pub t: Time,
    pub gnss: Gnss,
    pub leo: Leo,
}

/// Request for the `gnss-leo-arbitration` method.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArbitrationRequest {
    #[serde(default)]
    pub subject: Option<String>,
    /// Time disagreement above which the sources disagree, ns (default 50).
    #[serde(default = "d_tol")]
    pub tolerance_ns: f64,
    /// Position disagreement above which the sources disagree, m (default 100).
    #[serde(default = "d_pos")]
    pub position_tolerance_m: f64,
    /// The site clock's stability: how far its prediction may wander, ns per second since the
    /// last agreement (default 0.05).
    #[serde(default = "d_stab")]
    pub clock_stability_ns_per_s: f64,
    pub epochs: Vec<Epoch>,
}

fn d_tol() -> f64 {
    50.0
}
fn d_pos() -> f64 {
    100.0
}
fn d_stab() -> f64 {
    0.05
}

/// Request limits.
#[derive(Clone, Debug)]
pub struct ArbitrationLimits {
    pub max_epochs: usize,
}

impl Default for ArbitrationLimits {
    fn default() -> Self {
        ArbitrationLimits {
            max_epochs: 200_000,
        }
    }
}

// ------------------------------------------------------------------------------------------
// The method
// ------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Src {
    Gnss,
    Leo,
}

impl Src {
    fn name(self) -> &'static str {
        match self {
            Src::Gnss => "gnss",
            Src::Leo => "leo",
        }
    }
}

struct Finding {
    family: &'static str,
    suspect: Src,
    weight: f64,
    text: String,
}

fn dist_m(a: Pos, b: Pos) -> f64 {
    let (la1, lo1, la2, lo2) = (
        a.lat_deg.to_radians(),
        a.lon_deg.to_radians(),
        b.lat_deg.to_radians(),
        b.lon_deg.to_radians(),
    );
    let h = ((la2 - la1) / 2.0).sin().powi(2)
        + la1.cos() * la2.cos() * ((lo2 - lo1) / 2.0).sin().powi(2);
    2.0 * 6_371_008.8 * h.sqrt().min(1.0).asin()
}

/// Least-squares line through points; (intercept at x0, slope, residual sd).
fn line(pts: &[(f64, f64)], x0: f64) -> Option<(f64, f64, f64)> {
    let n = pts.len() as f64;
    if pts.len() < 5 {
        return None;
    }
    let mx = pts.iter().map(|p| p.0 - x0).sum::<f64>() / n;
    let my = pts.iter().map(|p| p.1).sum::<f64>() / n;
    let sxx: f64 = pts.iter().map(|p| (p.0 - x0 - mx).powi(2)).sum();
    let b = if sxx > 0.0 {
        pts.iter()
            .map(|p| (p.0 - x0 - mx) * (p.1 - my))
            .sum::<f64>()
            / sxx
    } else {
        0.0
    };
    let a = my - b * mx;
    let rss: f64 = pts.iter().map(|p| (p.1 - a - b * (p.0 - x0)).powi(2)).sum();
    Some((a, b, (rss / (n - 2.0).max(1.0)).sqrt()))
}

fn combine(f: &[Finding]) -> (Option<Src>, f64) {
    let sc = |s: Src| {
        f.iter()
            .filter(|x| x.suspect == s)
            .map(|x| x.weight)
            .sum::<f64>()
    };
    let (g, l) = (sc(Src::Gnss), sc(Src::Leo));
    if g == 0.0 && l == 0.0 {
        return (None, 0.5);
    }
    let (s, d) = if g >= l {
        (Src::Gnss, g - l)
    } else {
        (Src::Leo, l - g)
    };
    let mut fams: Vec<&str> = f
        .iter()
        .filter(|x| x.suspect == s)
        .map(|x| x.family)
        .collect();
    fams.sort_unstable();
    fams.dedup();
    // One family alone stays below DECIDE_AT ("one family never decides").
    let cap = match fams.len() {
        0 | 1 => SINGLE_FAMILY_CAP,
        2 => 0.9,
        _ => 0.95,
    };
    let p = (1.0 / (1.0 + (-1.6 * d).exp())).min(cap);
    (Some(s), (p * 20.0).floor() / 20.0)
}

/// Run the method; the raw (unrounded, unsigned) outcome.
pub fn analyse(r: &ArbitrationRequest, l: &ArbitrationLimits) -> Result<Value, String> {
    if r.epochs.len() < 10 || r.epochs.len() > l.max_epochs {
        return Err(format!("10 to {} epochs", l.max_epochs));
    }
    for (k, x) in [
        ("tolerance_ns", r.tolerance_ns),
        ("position_tolerance_m", r.position_tolerance_m),
        ("clock_stability_ns_per_s", r.clock_stability_ns_per_s),
    ] {
        if !(x.is_finite() && x > 0.0) {
            return Err(format!("{k} must be a positive number"));
        }
    }
    let mut ep: Vec<(f64, &Epoch)> = r
        .epochs
        .iter()
        .map(|e| e.t.secs().map(|t| (t, e)))
        .collect::<Result<_, _>>()?;
    ep.sort_by(|a, b| a.0.total_cmp(&b.0));
    // Per epoch: both valid, and do they agree?
    let both: Vec<Option<bool>> = ep
        .iter()
        .map(|(_, e)| {
            let (g, l) = (e.gnss.time_offset_ns?, e.leo.time_offset_ns?);
            if !(e.gnss.valid && e.leo.valid) {
                return None;
            }
            let pos_bad = match (e.gnss.position, e.leo.position) {
                (Some(a), Some(b)) => dist_m(a, b) > r.position_tolerance_m,
                _ => false,
            };
            Some((g - l).abs() <= r.tolerance_ns && !pos_bad)
        })
        .collect();
    // Episodes: runs of at least MIN_EPISODE disagreeing epochs.
    let mut episodes: Vec<(usize, usize)> = vec![];
    let mut i = 0;
    while i < ep.len() {
        if both[i] == Some(false) {
            let s = i;
            while i < ep.len() && both[i] != Some(true) {
                i += 1;
            }
            let n_dis = (s..i).filter(|k| both[*k] == Some(false)).count();
            if n_dis >= MIN_EPISODE {
                episodes.push((s, i - 1));
            }
        } else {
            i += 1;
        }
    }
    let mut rows = vec![];
    let mut supported_epochs = 0usize;
    for &(s, e) in &episodes {
        let mut f: Vec<Finding> = vec![];
        let t_start = ep[s].0;
        // 1. Reference: the clock line from the last agreed epochs before the episode.
        let base: Vec<(f64, f64)> = (0..s)
            .rev()
            .filter(|k| both[*k] == Some(true))
            .skip(GUARD_EPOCHS)
            .take(BASELINE_EPOCHS)
            .filter_map(|k| {
                let (g, l) = (ep[k].1.gnss.time_offset_ns?, ep[k].1.leo.time_offset_ns?);
                Some((ep[k].0, (g + l) / 2.0))
            })
            .collect();
        let last_agree = base.first().map(|b| b.0);
        if let (Some((a, b, sd)), Some(la)) = (line(&base, t_start), last_agree) {
            let mut dev = (0.0f64, 0.0f64, 0usize);
            for (t, x) in &ep[s..=e] {
                let pred = a + b * (t - t_start);
                let allow = 4.0 * sd.max(1.0) + r.clock_stability_ns_per_s * (t - la).max(0.0);
                let gd = x.gnss.time_offset_ns.map(|g| (g - pred).abs() / allow);
                let ld = x.leo.time_offset_ns.map(|l| (l - pred).abs() / allow);
                if let (Some(g), Some(l)) = (gd, ld) {
                    dev.0 += g;
                    dev.1 += l;
                    dev.2 += 1;
                }
            }
            if dev.2 > 0 {
                let (g, l) = (dev.0 / dev.2 as f64, dev.1 / dev.2 as f64);
                if g > 1.0 && l <= 1.0 {
                    f.push(Finding { family: "reference", suspect: Src::Gnss, weight: 2.2,
                        text: "GNSS time departed from the site clock's prediction while LEO time stayed within it".into() });
                } else if l > 1.0 && g <= 1.0 {
                    f.push(Finding { family: "reference", suspect: Src::Leo, weight: 2.2,
                        text: "LEO time departed from the site clock's prediction while GNSS time stayed within it".into() });
                }
            }
        }
        // 2. Indicators, against the agreed baseline.
        let base_cn0: Vec<f64> = (0..s)
            .rev()
            .filter(|k| both[*k] == Some(true))
            .skip(GUARD_EPOCHS)
            .take(BASELINE_EPOCHS)
            .filter_map(|k| ep[k].1.gnss.cn0_mean_dbhz)
            .collect();
        let in_ep = &ep[s..=e];
        let mean = |v: &[f64]| (!v.is_empty()).then(|| v.iter().sum::<f64>() / v.len() as f64);
        let ep_cn0: Vec<f64> = in_ep
            .iter()
            .filter_map(|x| x.1.gnss.cn0_mean_dbhz)
            .collect();
        if let (Some(b), Some(c)) = (mean(&base_cn0), mean(&ep_cn0)) {
            if c - b >= 3.0 {
                f.push(Finding { family: "indicators", suspect: Src::Gnss, weight: 1.3,
                    text: format!("GNSS C/N0 rose by {:.1} dB on average, a sign of a stronger counterfeit signal", c - b) });
            } else if b - c >= 6.0 {
                f.push(Finding {
                    family: "indicators",
                    suspect: Src::Gnss,
                    weight: 1.3,
                    text: format!("GNSS C/N0 fell by {:.1} dB on average", b - c),
                });
            }
        }
        if in_ep.iter().any(|x| x.1.gnss.auth_ok == Some(false)) {
            f.push(Finding {
                family: "indicators",
                suspect: Src::Gnss,
                weight: 1.3,
                text: "GNSS navigation-message authentication failed during the episode".into(),
            });
        }
        if in_ep.iter().any(|x| x.1.leo.auth_ok == Some(false)) {
            f.push(Finding {
                family: "indicators",
                suspect: Src::Leo,
                weight: 1.3,
                text: "LEO authentication failed during the episode".into(),
            });
        }
        let lq: Vec<f64> = in_ep.iter().filter_map(|x| x.1.leo.quality).collect();
        if mean(&lq).is_some_and(|q| q < 0.5) {
            f.push(Finding {
                family: "indicators",
                suspect: Src::Leo,
                weight: 1.3,
                text: "the LEO provider's quality figure was below 0.5".into(),
            });
        }
        // 3. Dynamics: a step at the start of the episode.
        if s > 0 {
            let step = |get: &dyn Fn(&Epoch) -> Option<f64>| -> Option<f64> {
                Some((get(ep[s].1)? - get(ep[s - 1].1)?).abs())
            };
            let gs = step(&|x: &Epoch| x.gnss.time_offset_ns);
            let ls = step(&|x: &Epoch| x.leo.time_offset_ns);
            if let (Some(g), Some(l)) = (gs, ls) {
                if g > r.tolerance_ns && l < r.tolerance_ns / 2.0 {
                    f.push(Finding {
                        family: "dynamics",
                        suspect: Src::Gnss,
                        weight: 1.3,
                        text: format!("GNSS time stepped by {g:.0} ns at the start"),
                    });
                } else if l > r.tolerance_ns && g < r.tolerance_ns / 2.0 {
                    f.push(Finding {
                        family: "dynamics",
                        suspect: Src::Leo,
                        weight: 1.3,
                        text: format!("LEO time stepped by {l:.0} ns at the start"),
                    });
                }
            }
        }
        let (side, conf) = combine(&f);
        let decided = side.filter(|_| conf >= DECIDE_AT);
        let n = e - s + 1;
        if decided.is_some() {
            supported_epochs += n;
        }
        let max_dis = in_ep
            .iter()
            .filter_map(|x| Some((x.1.gnss.time_offset_ns? - x.1.leo.time_offset_ns?).abs()))
            .fold(0.0, f64::max);
        rows.push(json!({
            "start_utc": iso(t_start.floor() as i64),
            "end_utc": iso(ep[e].0.ceil() as i64),
            "epochs": n,
            "max_disagreement_ns": max_dis,
            "suspect": decided.map(Src::name).unwrap_or("undetermined"),
            "evidence_supports": decided.map(|s| match s { Src::Gnss => "leo", Src::Leo => "gnss" }),
            "leading_suspect": if decided.is_none() { side.map(Src::name) } else { None },
            "confidence": conf,
            "findings": f.iter().map(|x| json!({"family": x.family, "against": x.suspect.name(), "text": x.text})).collect::<Vec<_>>(),
        }));
    }
    let valid_both = both.iter().filter(|b| b.is_some()).count();
    let agree = both.iter().filter(|b| **b == Some(true)).count();
    let mut agreed_diff: Vec<f64> = ep
        .iter()
        .zip(&both)
        .filter(|(_, b)| **b == Some(true))
        .filter_map(|((_, e), _)| Some((e.gnss.time_offset_ns? - e.leo.time_offset_ns?).abs()))
        .collect();
    agreed_diff.sort_by(f64::total_cmp);
    let p95 = (!agreed_diff.is_empty())
        .then(|| agreed_diff[((0.95 * agreed_diff.len() as f64).ceil() as usize).max(1) - 1]);
    let disagree_epochs: usize = episodes.iter().map(|(s, e)| e - s + 1).sum();
    Ok(json!({
        "method_version": METHOD_VERSION,
        "subject": r.subject,
        "episodes": rows,
        "integrity": {
            "epochs": ep.len(),
            "epochs_both_valid": valid_both,
            "agreement_share": if valid_both > 0 { json!(agree as f64 / valid_both as f64) } else { Value::Null },
            "agreed_difference_p95_ns": p95,
            "epochs_in_disagreement": disagree_epochs,
            "disagreement_epochs_with_a_supported_source": supported_epochs,
            "statement": if episodes.is_empty() {
                "The sources agreed within the tolerance throughout; no episode needed arbitration.".to_string()
            } else {
                format!("{} disagreement episodes; the evidence supports one source in {} of {} disagreeing epochs.", rows.len(), supported_epochs, disagree_epochs)
            },
        },
        "limits": [
            "The reference is the site's own clock, modelled from epochs where both sources agreed; if both sources were wrong together, the method cannot see it.",
            "Indicators are the receivers' own; a source without indicators is judged by the reference and its dynamics only.",
        ],
        "statement": STATEMENT,
    }))
}

/// Run the method and return a signed verdict. Not fingerprinted.
pub fn arbitration_verdict(
    req: &ArbitrationRequest,
    s: &crate::methods::Signing,
    limits: &ArbitrationLimits,
    utc: &str,
) -> Result<crate::SignedVerdict, String> {
    let v = analyse(req, limits)?;
    crate::methods::finish("gnss-leo-arbitration", v, s, utc)
}

#[cfg(test)]
#[path = "gnss_leo_tests.rs"]
mod tests;
