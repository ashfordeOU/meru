// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The `delay-calibration` method: a GNSS timing receiver's delay, calibrated against a reference
//! receiver whose delays are known, with an uncertainty budget after the GUM (research backlog
//! E19, B1908).
//!
//! The device under test (DUT) and a calibrated reference receiver observe the same satellites,
//! either on a common clock side by side (co-located) or at two sites in common view. For each
//! common track the caller gives the difference of the two receivers' time-transfer results
//! (DUT minus reference, ns), computed with the DUT's delay set to an assumed value. The DUT's
//! calibrated delay is the assumed value plus the mean difference, corrected for the cable and
//! reference-connection delays as measured.
//!
//! Type A: the method rejects outliers robustly and estimates the uncertainty of the mean from
//! batch means, so that correlated noise (multipath repeating day to day, temperature) is not
//! counted as independent (the rejection rule and the batching stay in the service). Type B: the
//! reference receiver's own calibration, the cable and connection measurements, the antenna
//! (caller-stated or a default), and for common view a baseline term. Combined standard
//! uncertainty, expanded with k = 2. Per signal code (for example `C1`, `P1`, `P2`).
//!
//! What it says: the DUT's delay under these conditions, with its uncertainty. Not a statement
//! that the receiver meets any requirement; evidence class MODELLED until compared with a
//! calibration laboratory's result for the same receiver.

use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Method identifier written into every outcome.
pub const METHOD_VERSION: &str = "delay-calibration/1";

/// Robust outlier threshold, in median absolute deviations scaled to a standard deviation.
const OUTLIER_K: f64 = 5.0;
/// Batches for the Type A uncertainty.
const BATCHES: usize = 10;
/// Default antenna term when the caller gives none (standard uncertainty), ns.
const DEFAULT_ANTENNA_U_NS: f64 = 1.0;
/// Common-view baseline term, ns per 1,000 km (to confirm against the laboratory's own budget).
const CV_BASELINE_U_NS_PER_1000KM: f64 = 0.5;

/// A measured quantity with its standard uncertainty, ns.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measured {
    pub value_ns: f64,
    pub u_ns: f64,
}

/// One signal code's data.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeData {
    /// The DUT's delay assumed when the differences were computed, ns.
    pub assumed_delay_ns: f64,
    /// The reference receiver's own calibrated delay for this code (its standard uncertainty is
    /// the reference calibration term).
    pub reference_delay: Measured,
    /// DUT minus reference, per common track, ns.
    pub differences_ns: Vec<f64>,
}

/// The set-up.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setup {
    /// `co_located` (one clock, side by side) or `common_view`.
    pub mode: String,
    /// Baseline between the antennas, km (0 for co-located).
    #[serde(default)]
    pub baseline_km: f64,
    /// DUT antenna cable delay as measured, and the reference connection (clock to DUT) delay.
    pub dut_cable: Measured,
    pub dut_reference_cable: Measured,
    /// The values of those two delays assumed in the differences (so measured − assumed is
    /// corrected).
    pub assumed_dut_cable_ns: f64,
    pub assumed_dut_reference_cable_ns: f64,
    /// Antenna term, standard uncertainty, ns (default 1).
    #[serde(default)]
    pub antenna_u_ns: Option<f64>,
}

/// Request for the `delay-calibration` method.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelayRequest {
    /// The DUT's identifier, echoed.
    pub dut: String,
    pub setup: Setup,
    /// Per signal code.
    pub codes: BTreeMap<String, CodeData>,
}

/// Request limits.
#[derive(Clone, Debug)]
pub struct DelayLimits {
    pub max_codes: usize,
    pub max_tracks: usize,
}

impl Default for DelayLimits {
    fn default() -> Self {
        DelayLimits {
            max_codes: 8,
            max_tracks: 200_000,
        }
    }
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(f64::total_cmp);
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// Robust mean and its Type A standard uncertainty from batch means.
fn type_a(d: &[f64]) -> Result<(f64, f64, usize, usize), String> {
    // Checked before the median: an empty list used to underflow its index (a panic).
    if d.len() < 2 * BATCHES {
        return Err(format!(
            "at least {} usable tracks are needed per code",
            2 * BATCHES
        ));
    }
    let mut s = d.to_vec();
    let med = median(&mut s);
    let mut dev: Vec<f64> = d.iter().map(|x| (x - med).abs()).collect();
    let mad = 1.4826 * median(&mut dev);
    let kept: Vec<f64> = d
        .iter()
        .copied()
        .filter(|x| mad == 0.0 || (x - med).abs() <= OUTLIER_K * mad)
        .collect();
    if kept.len() < 2 * BATCHES {
        return Err(format!(
            "at least {} usable tracks are needed per code",
            2 * BATCHES
        ));
    }
    let n = kept.len();
    let mean = kept.iter().sum::<f64>() / n as f64;
    // Batch means in time order: their spread carries the correlated part of the noise.
    let size = n / BATCHES;
    let bm: Vec<f64> = (0..BATCHES)
        .map(|b| kept[b * size..(b + 1) * size].iter().sum::<f64>() / size as f64)
        .collect();
    let mb = bm.iter().sum::<f64>() / BATCHES as f64;
    let var_b = bm.iter().map(|x| (x - mb).powi(2)).sum::<f64>() / (BATCHES - 1) as f64;
    let u_batch = (var_b / BATCHES as f64).sqrt();
    // Never below the white-noise standard error.
    let var = kept.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
    let u_white = (var / n as f64).sqrt();
    Ok((mean, u_batch.max(u_white), n, d.len() - n))
}

/// Run the method; the raw (unrounded, unsigned) outcome.
pub fn analyse(r: &DelayRequest, l: &DelayLimits) -> Result<Value, String> {
    let s = &r.setup;
    let co = match s.mode.as_str() {
        "co_located" => true,
        "common_view" => false,
        m => return Err(format!("setup.mode '{m}': co_located or common_view")),
    };
    if r.codes.is_empty() || r.codes.len() > l.max_codes {
        return Err(format!("1 to {} codes", l.max_codes));
    }
    if r.codes
        .values()
        .map(|c| c.differences_ns.len())
        .sum::<usize>()
        > l.max_tracks
    {
        return Err(format!("at most {} tracks", l.max_tracks));
    }
    for m in [s.dut_cable, s.dut_reference_cable] {
        if !(m.value_ns.is_finite() && m.u_ns.is_finite() && m.u_ns >= 0.0) {
            return Err("cable delays need finite values and non-negative uncertainties".into());
        }
    }
    if !(s.baseline_km.is_finite() && s.baseline_km >= 0.0) || (!co && s.baseline_km == 0.0) {
        return Err("setup.baseline_km: 0 or more, and above 0 for common view".into());
    }
    let ant = s.antenna_u_ns.unwrap_or(DEFAULT_ANTENNA_U_NS);
    let mut rows = BTreeMap::new();
    for (code, c) in &r.codes {
        if c.differences_ns.iter().any(|x| !x.is_finite()) {
            return Err(format!("code '{code}': differences must be finite"));
        }
        let (mean, ua, n, rejected) =
            type_a(&c.differences_ns).map_err(|e| format!("code '{code}': {e}"))?;
        // The DUT's delay: assumed + mean difference; a cable measured longer than assumed is
        // part of the delay the differences already contain, so it is taken out of the
        // receiver's own delay.
        let cable_corr = (s.dut_cable.value_ns - s.assumed_dut_cable_ns)
            - (s.dut_reference_cable.value_ns - s.assumed_dut_reference_cable_ns);
        let delay = c.assumed_delay_ns + mean - cable_corr;
        let mut budget = vec![
            ("statistics of the comparison", "A", ua),
            (
                "reference receiver calibration",
                "B",
                c.reference_delay.u_ns,
            ),
            ("DUT antenna cable", "B", s.dut_cable.u_ns),
            (
                "reference connection to the DUT",
                "B",
                s.dut_reference_cable.u_ns,
            ),
            ("antenna", "B", ant),
        ];
        if !co {
            budget.push((
                "common-view baseline",
                "B",
                CV_BASELINE_U_NS_PER_1000KM * s.baseline_km / 1000.0,
            ));
        }
        let uc = budget.iter().map(|b| b.2 * b.2).sum::<f64>().sqrt();
        rows.insert(
            code.clone(),
            json!({
                "delay_ns": delay,
                "standard_uncertainty_ns": uc,
                "expanded_uncertainty_ns": 2.0 * uc,
                // Integers are not rounded by the verdict's significant figures: a delay of
                // thousands of ns keeps its resolution.
                "delay_ps": (delay * 1000.0).round() as i64,
                "expanded_uncertainty_ps": (2000.0 * uc).ceil() as i64,
                "coverage_factor": 2,
                "budget": budget.iter().map(|(n, t, u)| json!({"component": n, "type": t, "u_ns": u})).collect::<Vec<_>>(),
                "tracks_used": n,
                "tracks_rejected": rejected,
                "reference_delay_ns": c.reference_delay.value_ns,
            }),
        );
    }
    Ok(json!({
        "method_version": METHOD_VERSION,
        "dut": r.dut,
        "mode": s.mode,
        "baseline_km": s.baseline_km,
        "codes": rows,
        "statement": "The device's delay under these conditions with its uncertainty (GUM, k = 2). Not a statement that it meets any requirement.",
        "evidence": "MODELLED until compared with a calibration laboratory's result for the same receiver.",
    }))
}

/// Run the method and return a signed verdict. Not fingerprinted.
pub fn delay_verdict(
    req: &DelayRequest,
    s: &crate::methods::Signing,
    limits: &DelayLimits,
    utc: &str,
) -> Result<crate::SignedVerdict, String> {
    let v = analyse(req, limits)?;
    crate::methods::finish("delay-calibration", v, s, utc)
}

#[cfg(test)]
#[path = "delay_cal_tests.rs"]
mod tests;
