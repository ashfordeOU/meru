// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The base audit of the `rtk-quality` method (research backlog E15, B1502): is a base's
//! declared position right, and do a network (VRS) mountpoint and a single-base mountpoint agree
//! at the same marks?
//!
//! Crowd-sourced and small commercial bases publish their own coordinates. A base whose declared
//! position is wrong moves every rover that uses it by the same amount: the fixes stay tight and
//! look excellent, and are wrong. A common cause in Europe is a frame or epoch mix-up: a base
//! declared in ETRS89 used by rovers that expect ITRF at the current epoch (or the other way
//! round). The two frames drift apart with the Eurasian plate, about 2.5 cm a year, so by 2026
//! they differ by about 0.9 m.
//!
//! From monitors on surveyed marks (truth in the marks' frame), per mountpoint:
//!
//! * the **common offset**: the median over monitors of each monitor's median fixed-solution
//!   offset from its mark, and how far the monitors scatter about it;
//! * a finding: `consistent`, `base_coordinate_offset` (a shared offset of 2 cm or more that the
//!   monitors agree on: a shifted base), `frame_epoch_mismatch` (the shared offset matches the
//!   ETRS89–ITRF drift at the base for the data's epoch, in either direction), or
//!   `not_assessable` (no surveyed monitor, or monitors that disagree);
//! * the predicted ETRS89–ITRF drift used, from the Eurasian plate rotation of the ITRF2014 plate
//!   motion model (Altamimi et al. 2017, Eurasia ω = (−0.085, −0.531, 0.770) mas/yr), applied from
//!   1989.0; the frames' small translation and scale differences are not modelled (a few cm; the
//!   parameters to confirm against the EUREF memo). Inside Europe only.
//!
//! And for every pair of mountpoints observed at the same marks (a monitor's `mark`), the
//! difference of their offsets: `consistent` within 2 cm horizontally and 4 cm vertically, else
//! `inconsistent`, so a VRS mountpoint and a single base that disagree show which one moved.

use serde_json::{json, Value};

/// Shared horizontal offset at which a base is flagged, metres.
const MIN_OFFSET_H_M: f64 = 0.02;
/// Shared vertical offset at which a base is flagged, metres.
const MIN_OFFSET_V_M: f64 = 0.04;
/// Monitors must agree on the shared offset within this share of it (and 1 cm).
const MAX_SPREAD_SHARE: f64 = 0.5;
/// A shared offset fits the frame drift within this share of the drift (and 5 cm), and within
/// this angle of its direction.
const FRAME_TOL_SHARE: f64 = 0.1;
const FRAME_TOL_M: f64 = 0.05;
const FRAME_TOL_DEG: f64 = 15.0;
/// Pair consistency limits, metres.
const PAIR_H_M: f64 = 0.02;
const PAIR_V_M: f64 = 0.04;

/// ITRF2014-PMM Eurasia rotation pole, mas/yr (Altamimi et al. 2017).
const EURASIA_MAS_YR: [f64; 3] = [-0.085, -0.531, 0.770];

/// The predicted ITRF-minus-ETRS89 displacement (east, north, up, metres) at a point for a
/// decimal year: the Eurasian plate's motion since 1989.0. `None` outside Europe.
pub fn etrs89_itrf_drift(lat_deg: f64, lon_deg: f64, year: f64) -> Option<[f64; 3]> {
    if !(34.0..=72.0).contains(&lat_deg) || !(-25.0..=45.0).contains(&lon_deg) {
        return None;
    }
    let mas = std::f64::consts::PI / (180.0 * 3600.0 * 1000.0);
    let w = EURASIA_MAS_YR.map(|x| x * mas);
    let (la, lo) = (lat_deg.to_radians(), lon_deg.to_radians());
    let r = 6_371_000.0;
    let x = [
        r * la.cos() * lo.cos(),
        r * la.cos() * lo.sin(),
        r * la.sin(),
    ];
    let v = [
        w[1] * x[2] - w[2] * x[1],
        w[2] * x[0] - w[0] * x[2],
        w[0] * x[1] - w[1] * x[0],
    ];
    let e = -lo.sin() * v[0] + lo.cos() * v[1];
    let n = -la.sin() * lo.cos() * v[0] - la.sin() * lo.sin() * v[1] + la.cos() * v[2];
    let u = la.cos() * lo.cos() * v[0] + la.cos() * lo.sin() * v[1] + la.sin() * v[2];
    let dt = year - 1989.0;
    Some([e * dt, n * dt, u * dt])
}

/// What the audit needs about one monitor.
pub struct MonitorOffset<'a> {
    pub mountpoint: &'a str,
    pub mark: &'a str,
    pub surveyed: bool,
    /// Median fixed-solution offset from the mark (east, north, up, metres), when it had fixes.
    pub median: Option<[f64; 3]>,
}

/// What the audit needs about one mountpoint.
pub struct Base<'a> {
    pub id: &'a str,
    pub kind: Option<&'a str>,
    pub lat_deg: f64,
    pub lon_deg: f64,
}

fn med(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

fn common(offs: &[[f64; 3]]) -> [f64; 3] {
    [0, 1, 2].map(|k| med(offs.iter().map(|o| o[k]).collect()))
}

fn hz(o: &[f64; 3]) -> f64 {
    o[0].hypot(o[1])
}

/// The per-mountpoint audit and the pair consistency.
pub fn audit(bases: &[Base], mons: &[MonitorOffset], year: f64) -> (Vec<Value>, Vec<Value>) {
    let mut rows = vec![];
    for b in bases {
        let offs: Vec<[f64; 3]> = mons
            .iter()
            .filter(|m| m.mountpoint == b.id && m.surveyed)
            .filter_map(|m| m.median)
            .collect();
        let drift = etrs89_itrf_drift(b.lat_deg, b.lon_deg, year);
        if offs.is_empty() {
            rows.push(json!({"mountpoint": b.id, "finding": "not_assessable",
                "reading": "no monitor on a surveyed mark had fixed solutions on this mountpoint"}));
            continue;
        }
        let c = common(&offs);
        let spread = offs
            .iter()
            .map(|o| hz(&[o[0] - c[0], o[1] - c[1], 0.0]))
            .fold(0.0, f64::max);
        let (h, v) = (hz(&c), c[2].abs());
        let agree = spread <= (MAX_SPREAD_SHARE * h).max(0.01);
        let frame = drift.and_then(|d| {
            let dh = hz(&d);
            [1.0, -1.0].into_iter().find(|s| {
                let diff = hz(&[c[0] - s * d[0], c[1] - s * d[1], 0.0]);
                let ang = (c[0] * s * d[0] + c[1] * s * d[1]) / (h * dh).max(1e-9);
                diff <= (FRAME_TOL_SHARE * dh).max(FRAME_TOL_M)
                    && ang.clamp(-1.0, 1.0).acos().to_degrees() <= FRAME_TOL_DEG
            })
        });
        let (finding, reading) = if !agree && offs.len() >= 2 {
            (
                "not_assessable",
                "the monitors disagree about a shared offset; read them one by one".to_string(),
            )
        } else if let Some(s) = frame.filter(|_| h >= MIN_OFFSET_H_M) {
            (
                "frame_epoch_mismatch",
                format!(
                    "the shared offset matches the ETRS89–ITRF drift at the base for {year:.1}: {}",
                    if s > 0.0 {
                        "rover solutions sit at ITRF-epoch positions while the marks are in ETRS89 (or the base is declared in ITRF and the rovers expect ETRS89)"
                    } else {
                        "the base is declared in ETRS89 while the marks are in ITRF at the current epoch"
                    }
                ),
            )
        } else if h >= MIN_OFFSET_H_M || v >= MIN_OFFSET_V_M {
            (
                "base_coordinate_offset",
                "every monitor on this mountpoint is moved by the same amount: the base's declared position is wrong by about this offset; its wrong-fix figures include it".to_string(),
            )
        } else {
            (
                "consistent",
                "no shared offset of 2 cm horizontally or 4 cm vertically".to_string(),
            )
        };
        rows.push(json!({
            "mountpoint": b.id,
            "kind": b.kind,
            "monitors_used": offs.len(),
            "offset_m": {"e": c[0], "n": c[1], "u": c[2]},
            "horizontal_m": h,
            "spread_m": spread,
            "finding": finding,
            "reading": reading,
            "etrs89_itrf_drift_m": drift.map(|d| json!({"e": d[0], "n": d[1], "u": d[2], "horizontal": hz(&d), "year": year})),
        }));
    }
    // Pairs of mountpoints seen at the same marks.
    let mut pairs = vec![];
    for (i, a) in bases.iter().enumerate() {
        for b in &bases[i + 1..] {
            let mut diffs = vec![];
            for ma in mons.iter().filter(|m| m.mountpoint == a.id && m.surveyed) {
                for mb in mons
                    .iter()
                    .filter(|m| m.mountpoint == b.id && m.surveyed && m.mark == ma.mark)
                {
                    if let (Some(x), Some(y)) = (ma.median, mb.median) {
                        diffs.push([x[0] - y[0], x[1] - y[1], x[2] - y[2]]);
                    }
                }
            }
            if diffs.is_empty() {
                continue;
            }
            let d = common(&diffs);
            let ok = hz(&d) <= PAIR_H_M && d[2].abs() <= PAIR_V_M;
            pairs.push(json!({
                "a": a.id, "a_kind": a.kind, "b": b.id, "b_kind": b.kind,
                "shared_marks": diffs.len(),
                "difference_m": {"e": d[0], "n": d[1], "u": d[2]},
                "horizontal_m": hz(&d),
                "consistent": ok,
            }));
        }
    }
    (rows, pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drift_is_about_two_and_a_half_cm_a_year_north_east_in_europe() {
        let d = etrs89_itrf_drift(52.0, 5.0, 1990.0).unwrap();
        let h = d[0].hypot(d[1]);
        assert!((0.020..0.030).contains(&h), "{d:?}");
        assert!(d[0] > 0.0 && d[1] > 0.0, "{d:?}");
        let d26 = etrs89_itrf_drift(52.0, 5.0, 2026.9).unwrap();
        let h26 = d26[0].hypot(d26[1]);
        assert!((0.8..1.0).contains(&h26), "{h26}");
        assert!(etrs89_itrf_drift(-30.0, 150.0, 2026.0).is_none());
    }
}
