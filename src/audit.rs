// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! Query-pattern auditing: detect a licensee sweeping a method's input space to rebuild it.
//!
//! The probe detector in [`crate::limits`] counts distinct requests an hour; a patient copier
//! stays under it. This module looks at *where* in the input space a licence's requests fall,
//! over days, in the spirit of PRADA (Juuti et al., 2019): real users cluster around real
//! stations, areas and geometries; an extraction campaign spreads its queries evenly so a
//! surrogate can be fitted. It flags four signatures:
//!
//! * `low_discrepancy`: a Sobol or Halton sequence (centred L2 discrepancy far below what
//!   independent uniform points give);
//! * `stratified`: a Latin hypercube (every varying input takes `n` distinct, evenly spread values);
//! * `grid`: a full-factorial grid (few, evenly spaced values per input, most combinations used);
//! * `uniform_fill`: many independent uniform points (discrepancy as random, coarse cells
//!   filled), the slow form of the same campaign.
//!
//! **Cross-licence correlation**: the same statistics on the union of every licence's points
//! with the same request shape. A sweep split over several licences (each one too small, or
//! too innocent-looking, alone) is caught when the union is space-filling. Licences whose
//! points make the union less uniform (a bystander with ordinary, clustered requests of the
//! same shape) are dropped one at a time first, so they are not named.
//!
//! **Request features.** A request (JSON) is reduced to a *shape* (the method plus the sorted
//! list of numeric field paths; arrays longer than [`LONG_ARRAY`] become their length and the
//! mean and spread of each numeric field) and a vector of numbers. Requests are compared only
//! with requests of the same shape. String values (names, identifiers) are ignored.
//!
//! **What is kept (privacy).** Per call, in memory only: the licence's token ID, the time, the
//! shape hash and the numbers rounded to [`AUDIT_SIGFIGS`] significant figures. Nothing is
//! written to disk except alerts (to the meter log), which carry the shape hash, statistics and
//! token IDs, never field names or values. Points older than [`AuditConfig::window_s`] (default
//! 7 days) are dropped, and each shape keeps at most [`AuditConfig::max_points_per_group`].
//! A restart starts the audit afresh.
//!
//! **Actions.** An alert is written to the meter log and stderr. The licence is then *suspect*
//! for [`AuditConfig::suspect_s`]: its verdicts are delayed by [`AuditConfig::delay_ms`] and,
//! when [`AuditConfig::pause`] is set, its calls are refused. A per-licence cap on new coarse
//! input cells a day ([`AuditConfig::max_new_cells_per_day`], off by default) is the per-input-
//! region limit. False positives are possible (a one-parameter trade study of 40 evenly spaced
//! values looks like a sweep), so the default is alert and delay, not refuse.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

/// Arrays longer than this are summarised (length, mean, spread) rather than indexed.
pub const LONG_ARRAY: usize = 16;
/// Significant figures kept on audited numbers.
pub const AUDIT_SIGFIGS: u32 = 4;
/// Most input dimensions analysed (those with the most distinct values).
pub const MAX_DIMS: usize = 12;
/// Coarse bins per dimension for cell coverage and the per-region cap.
pub const COARSE_BINS: usize = 4;
/// Most points used in one statistic (the most recent).
pub const MAX_ANALYSED: usize = 1024;
/// Most points (the most recent) and licences (the most active) in a cross-licence judgement.
pub const MAX_CROSS: usize = 512;
pub const MAX_CROSS_LICENCES: usize = 12;

/// Audit settings.
#[derive(Clone, Debug)]
pub struct AuditConfig {
    /// How long points are kept (s).
    pub window_s: i64,
    /// Most points kept per request shape.
    pub max_points_per_group: usize,
    /// Most request shapes kept (oldest dropped).
    pub max_groups: usize,
    /// Fewest distinct points before a set is judged.
    pub min_points: usize,
    /// `low_discrepancy` when the discrepancy ratio (to independent uniform points) is at most this.
    pub cd_ratio_max: f64,
    /// `stratified` when every varying input has at least this fraction of distinct values ...
    pub distinct_frac_min: f64,
    /// ... and no gap wider than this many times the even spacing.
    pub max_gap_max: f64,
    /// `uniform_fill`: at least this many distinct points, ...
    pub uniform_min_points: usize,
    /// ... a discrepancy ratio at most this ...
    pub uniform_cd_ratio_max: f64,
    /// ... and at least this fraction of the coarse cells it could reach.
    pub uniform_cell_fill_min: f64,
    /// Re-judge a shape every this many new points.
    pub check_every: usize,
    /// How long a flagged licence stays suspect (s).
    pub suspect_s: i64,
    /// Delay added to a suspect licence's verdicts (ms).
    pub delay_ms: u64,
    /// Refuse a suspect licence's calls (429) instead of only delaying them.
    pub pause: bool,
    /// Per licence, most new coarse input cells a UTC day (0 = no cap).
    pub max_new_cells_per_day: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            window_s: 7 * 86_400,
            max_points_per_group: 4096,
            max_groups: 20_000,
            min_points: 32,
            cd_ratio_max: 0.35,
            distinct_frac_min: 0.9,
            max_gap_max: 2.5,
            uniform_min_points: 96,
            uniform_cd_ratio_max: 1.6,
            uniform_cell_fill_min: 0.6,
            check_every: 8,
            suspect_s: 86_400,
            delay_ms: 3000,
            pause: false,
            max_new_cells_per_day: 0,
        }
    }
}

/// The request features: shape hash, field paths and the numbers (unrounded).
#[derive(Clone, Debug, PartialEq)]
pub struct Features {
    pub shape: String,
    pub paths: Vec<String>,
    pub values: Vec<f64>,
}

fn walk(v: &Value, path: &str, out: &mut BTreeMap<String, f64>) {
    match v {
        Value::Number(n) => {
            out.insert(path.to_string(), n.as_f64().unwrap_or(0.0));
        }
        Value::Bool(b) => {
            out.insert(path.to_string(), if *b { 1.0 } else { 0.0 });
        }
        Value::Object(m) => {
            for (k, x) in m {
                walk(x, &format!("{path}.{k}"), out);
            }
        }
        Value::Array(a) if a.len() <= LONG_ARRAY => {
            for (i, x) in a.iter().enumerate() {
                walk(x, &format!("{path}[{i}]"), out);
            }
        }
        Value::Array(a) => {
            // Summarise: the length and, per numeric field inside, mean and spread.
            out.insert(format!("{path}[]#len"), a.len() as f64);
            let mut acc: BTreeMap<String, Vec<f64>> = BTreeMap::new();
            for x in a {
                let mut inner = BTreeMap::new();
                walk(x, "", &mut inner);
                for (k, val) in inner {
                    acc.entry(k).or_default().push(val);
                }
            }
            for (k, xs) in acc {
                let n = xs.len() as f64;
                let mean = xs.iter().sum::<f64>() / n;
                let sd = (xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n).sqrt();
                out.insert(format!("{path}[]{k}#mean"), mean);
                out.insert(format!("{path}[]{k}#sd"), sd);
            }
        }
        _ => {}
    }
}

/// Reduce a request to its features (see the module notes).
pub fn features(method: &str, request: &Value) -> Features {
    let mut m = BTreeMap::new();
    walk(request, "", &mut m);
    let paths: Vec<String> = m.keys().cloned().collect();
    let mut h = Sha256::new();
    h.update(method.as_bytes());
    for p in &paths {
        h.update(b"\n");
        h.update(p.as_bytes());
    }
    Features {
        shape: hex::encode(h.finalize())[..16].to_string(),
        paths,
        values: m
            .values()
            .map(|x| if x.is_finite() { *x } else { 0.0 })
            .collect(),
    }
}

/// The coarse input cell of a request: its shape and every number on a log scale in steps of
/// about 3 %, hashed. Requests in the same cell are near
/// neighbours; the fingerprint ([`crate::fingerprint`]) is constant within a cell.
pub fn coarse_cell(method: &str, request: &Value) -> [u8; 32] {
    let f = features(method, request);
    let mut h = Sha256::new();
    h.update(b"meru-cell/1\n");
    h.update(f.shape.as_bytes());
    for x in &f.values {
        let c = if *x == 0.0 {
            0i64
        } else {
            let l = (x.abs().ln() * 32.0).round() as i64; // ~3 % steps
            if *x > 0.0 {
                l * 2 + 1
            } else {
                l * 2 - 1
            }
        };
        h.update(c.to_le_bytes());
    }
    h.finalize().into()
}

/// Statistics of one point set (distinct points, normalised per varying input).
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Stats {
    /// Distinct points judged.
    pub n: usize,
    /// Varying inputs analysed.
    pub dims: usize,
    /// Centred L2 discrepancy squared over its expectation for independent uniform points.
    pub cd_ratio: f64,
    /// Smallest fraction of distinct values per varying input (1 = every point has its own).
    pub distinct_frac: f64,
    /// Largest gap between sorted values of any varying input, times `n - 1` (1 for evenly
    /// spaced values; about `ln n` for independent uniform ones).
    pub max_gap: f64,
    /// Coarse cells filled over those reachable (`min(n, bins^dims)`).
    pub cell_fill: f64,
    /// Coefficient of variation of nearest-neighbour distances (grids ~0, sweeps low).
    pub nn_cv: f64,
    /// Full-factorial grid signature found.
    pub grid: bool,
}

impl Stats {
    /// The signatures this set shows under `cfg`, strongest first.
    pub fn rules(&self, cfg: &AuditConfig) -> Vec<&'static str> {
        let mut r = vec![];
        if self.n < cfg.min_points || self.dims == 0 {
            return r;
        }
        if self.grid {
            r.push("grid");
        }
        if self.cd_ratio <= cfg.cd_ratio_max {
            r.push("low_discrepancy");
        }
        if self.distinct_frac >= cfg.distinct_frac_min && self.max_gap <= cfg.max_gap_max {
            r.push("stratified");
        }
        if self.n >= cfg.uniform_min_points
            && self.dims >= 2
            && self.cd_ratio <= cfg.uniform_cd_ratio_max
            && self.cell_fill >= cfg.uniform_cell_fill_min
        {
            r.push("uniform_fill");
        }
        r
    }
}

/// Normalise distinct points: keep varying inputs (most distinct values first, at most
/// [`MAX_DIMS`]), scale each to [0, 1] by its range.
fn normalise(points: &[Vec<f64>]) -> Vec<Vec<f64>> {
    let mut uniq: Vec<&Vec<f64>> = vec![];
    let mut seen = HashSet::new();
    for p in points {
        let key: Vec<u64> = p.iter().map(|x| x.to_bits()).collect();
        if seen.insert(key) {
            uniq.push(p);
        }
    }
    if uniq.is_empty() {
        return vec![];
    }
    let d = uniq[0].len();
    let mut dims: Vec<(usize, usize)> = (0..d)
        .filter_map(|k| {
            let mut vals: Vec<u64> = uniq.iter().map(|p| p[k].to_bits()).collect();
            vals.sort_unstable();
            vals.dedup();
            (vals.len() > 1).then_some((k, vals.len()))
        })
        .collect();
    dims.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    dims.truncate(MAX_DIMS);
    let ranges: Vec<(usize, f64, f64)> = dims
        .iter()
        .map(|(k, _)| {
            let lo = uniq.iter().map(|p| p[*k]).fold(f64::INFINITY, f64::min);
            let hi = uniq.iter().map(|p| p[*k]).fold(f64::NEG_INFINITY, f64::max);
            (*k, lo, hi)
        })
        .collect();
    uniq.iter()
        .map(|p| {
            ranges
                .iter()
                .map(|(k, lo, hi)| (p[*k] - lo) / (hi - lo))
                .collect()
        })
        .collect()
}

/// Centred L2 discrepancy squared (Hickernell 1998).
pub fn cd2(x: &[Vec<f64>]) -> f64 {
    let n = x.len();
    if n == 0 {
        return 0.0;
    }
    let d = x[0].len();
    let nf = n as f64;
    let mut s1 = 0.0;
    for p in x {
        let mut prod = 1.0;
        for &u in p {
            let a = (u - 0.5).abs();
            prod *= 1.0 + 0.5 * a - 0.5 * a * a;
        }
        s1 += prod;
    }
    let mut s2 = 0.0;
    for p in x {
        for q in x {
            let mut prod = 1.0;
            for (a, b) in p.iter().zip(q) {
                prod *= 1.0 + 0.5 * (a - 0.5).abs() + 0.5 * (b - 0.5).abs() - 0.5 * (a - b).abs();
            }
            s2 += prod;
        }
    }
    (13.0f64 / 12.0).powi(d as i32) - 2.0 / nf * s1 + s2 / (nf * nf)
}

/// Expected centred L2 discrepancy squared of `n` independent uniform points in `d` dimensions.
pub fn cd2_random(n: usize, d: usize) -> f64 {
    ((1.25f64).powi(d as i32) - (13.0f64 / 12.0).powi(d as i32)) / n.max(1) as f64
}

fn grid_signature(x: &[Vec<f64>]) -> bool {
    let n = x.len();
    let d = x.first().map(|p| p.len()).unwrap_or(0);
    if d == 0 {
        return false;
    }
    let mut cells = 1.0f64;
    for k in 0..d {
        let mut v: Vec<f64> = x.iter().map(|p| p[k]).collect();
        v.sort_by(|a, b| a.total_cmp(b));
        v.dedup_by(|a, b| (*a - *b).abs() < 1e-9);
        let m = v.len();
        if m < 3 || m * 2 > n {
            return false;
        }
        let step = 1.0 / (m - 1) as f64;
        if v.windows(2)
            .any(|w| ((w[1] - w[0]) - step).abs() > 0.02 * step + 1e-6)
        {
            return false;
        }
        cells *= m as f64;
    }
    n as f64 >= 0.7 * cells
}

/// Judge a set of points (numbers, one vector per call; repeats are counted once).
pub fn stats(points: &[Vec<f64>]) -> Stats {
    let x = normalise(points);
    let n = x.len();
    let d = x.first().map(|p| p.len()).unwrap_or(0);
    if n < 2 || d == 0 {
        return Stats {
            n,
            dims: d,
            cd_ratio: f64::INFINITY,
            distinct_frac: 0.0,
            max_gap: f64::INFINITY,
            cell_fill: 0.0,
            nn_cv: 0.0,
            grid: false,
        };
    }
    let cd_ratio = cd2(&x) / cd2_random(n, d);
    let (mut distinct_frac, mut max_gap) = (1.0f64, 0.0f64);
    for k in 0..d {
        let mut v: Vec<f64> = x.iter().map(|p| p[k]).collect();
        v.sort_by(|a, b| a.total_cmp(b));
        v.dedup();
        distinct_frac = distinct_frac.min(v.len() as f64 / n as f64);
        let g = v.windows(2).map(|w| w[1] - w[0]).fold(0.0, f64::max);
        max_gap = max_gap.max(g * (n - 1) as f64);
    }
    let cd = d.min(6);
    let reach = (COARSE_BINS as f64).powi(cd as i32).min(n as f64);
    let cells: HashSet<Vec<usize>> = x
        .iter()
        .map(|p| {
            p[..cd]
                .iter()
                .map(|u| ((u * COARSE_BINS as f64) as usize).min(COARSE_BINS - 1))
                .collect()
        })
        .collect();
    let nn: Vec<f64> = (0..n)
        .map(|i| {
            (0..n)
                .filter(|j| *j != i)
                .map(|j| {
                    x[i].iter()
                        .zip(&x[j])
                        .map(|(a, b)| (a - b).powi(2))
                        .sum::<f64>()
                        .sqrt()
                })
                .fold(f64::INFINITY, f64::min)
        })
        .collect();
    let mean = nn.iter().sum::<f64>() / n as f64;
    let sd = (nn.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n as f64).sqrt();
    Stats {
        n,
        dims: d,
        cd_ratio,
        distinct_frac,
        max_gap,
        cell_fill: cells.len() as f64 / reach,
        nn_cv: if mean > 0.0 { sd / mean } else { 0.0 },
        grid: grid_signature(&x),
    }
}

/// An extraction alert.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Alert {
    /// `single_licence`, `cross_licence`, `honeypot` or `region_cap`.
    pub kind: String,
    pub method: String,
    /// Request shape hash (no field names).
    pub shape: String,
    /// Token IDs involved.
    pub licences: Vec<String>,
    /// Signatures found (`grid`, `low_discrepancy`, `stratified`, `uniform_fill`).
    pub rules: Vec<String>,
    pub stats: Option<Stats>,
}

/// What the audit says about one call.
#[derive(Debug, Default)]
pub struct Verdict {
    /// New alerts raised by this call.
    pub alerts: Vec<Alert>,
    /// The licence is suspect (delay, or refuse when pausing).
    pub suspect: bool,
    /// Refuse the call (pause, or the per-region cap).
    pub refuse: Option<String>,
}

type Points = Vec<Vec<f64>>;
type ByLicence = BTreeMap<String, Points>;

struct Point {
    t: i64,
    licence: Arc<str>,
    v: Vec<f64>,
}

#[derive(Default)]
struct Group {
    method: String,
    points: VecDeque<Point>,
    since_check: usize,
    last_t: i64,
}

#[derive(Default)]
struct LicenceState {
    suspect_until: i64,
    day: i64,
    day_cells: HashSet<u64>,
    /// (shape, kind) already alerted, with the time.
    alerted: HashMap<(String, String), i64>,
}

#[derive(Default)]
struct State {
    groups: HashMap<String, Group>,
    licences: HashMap<Arc<str>, LicenceState>,
}

/// The query-pattern auditor (in memory; thread safe).
pub struct Auditor {
    pub cfg: AuditConfig,
    st: Mutex<State>,
}

impl Auditor {
    pub fn new(cfg: AuditConfig) -> Self {
        Auditor {
            cfg,
            st: Mutex::new(State::default()),
        }
    }

    /// Whether `licence` is suspect at `now`.
    pub fn is_suspect(&self, licence: &str, now: i64) -> bool {
        let st = self.st.lock().unwrap_or_else(|e| e.into_inner());
        st.licences
            .get(licence)
            .is_some_and(|l| now < l.suspect_until)
    }

    /// Mark a licence suspect (a honeypot hit) and return the alert.
    pub fn flag(&self, licence: &str, kind: &str, method: &str, now: i64) -> Alert {
        let mut st = self.st.lock().unwrap_or_else(|e| e.into_inner());
        let l = st.licences.entry(Arc::from(licence)).or_default();
        l.suspect_until = l.suspect_until.max(now + self.cfg.suspect_s);
        Alert {
            kind: kind.into(),
            method: method.into(),
            shape: String::new(),
            licences: vec![licence.into()],
            rules: vec![],
            stats: None,
        }
    }

    /// Record one admitted call and judge the licence and its request shape.
    pub fn observe(&self, licence: &str, method: &str, request: &Value, now: i64) -> Verdict {
        let f = features(method, request);
        let v: Vec<f64> = f
            .values
            .iter()
            .map(|x| crate::outputs::round_sig(*x, AUDIT_SIGFIGS))
            .collect();
        let cfg = &self.cfg;
        let mut out = Verdict::default();
        let mut st = self.st.lock().unwrap_or_else(|e| e.into_inner());
        let lic: Arc<str> = st
            .licences
            .get_key_value(licence)
            .map(|(k, _)| Arc::clone(k))
            .unwrap_or_else(|| Arc::from(licence));
        // Per-input-region cap: new coarse cells a day.
        {
            let cell = coarse_cell(method, request);
            let c = u64::from_le_bytes(cell[..8].try_into().unwrap_or([0; 8]));
            let l = st.licences.entry(Arc::clone(&lic)).or_default();
            let day = now.div_euclid(86_400);
            if l.day != day {
                l.day = day;
                l.day_cells.clear();
            }
            if cfg.max_new_cells_per_day > 0
                && !l.day_cells.contains(&c)
                && l.day_cells.len() >= cfg.max_new_cells_per_day
            {
                out.refuse = Some(format!(
                    "this licence has reached its daily limit of {} distinct input regions (resets 00:00 UTC)",
                    cfg.max_new_cells_per_day
                ));
                let key = (f.shape.clone(), "region_cap".to_string());
                if let std::collections::hash_map::Entry::Vacant(e) = l.alerted.entry(key) {
                    e.insert(now);
                    out.alerts.push(Alert {
                        kind: "region_cap".into(),
                        method: method.into(),
                        shape: f.shape.clone(),
                        licences: vec![licence.into()],
                        rules: vec![],
                        stats: None,
                    });
                }
                return out;
            }
            l.day_cells.insert(c);
        }
        // Keep the point.
        if !st.groups.contains_key(&f.shape) && st.groups.len() >= cfg.max_groups {
            if let Some(oldest) = st
                .groups
                .iter()
                .min_by_key(|(_, g)| g.last_t)
                .map(|(k, _)| k.clone())
            {
                st.groups.remove(&oldest);
            }
        }
        let g = st.groups.entry(f.shape.clone()).or_default();
        g.method = method.into();
        g.last_t = now;
        g.points.push_back(Point {
            t: now,
            licence: Arc::clone(&lic),
            v,
        });
        while g.points.front().is_some_and(|p| p.t <= now - cfg.window_s)
            || g.points.len() > cfg.max_points_per_group
        {
            g.points.pop_front();
        }
        g.since_check += 1;
        let due = g.since_check >= cfg.check_every;
        if due {
            g.since_check = 0;
        }
        // Copy what is judged, then judge without holding the lock.
        let (own, by): (Points, ByLicence) = if due {
            let recent: Vec<&Point> = g.points.iter().rev().take(MAX_ANALYSED).collect();
            let own = recent
                .iter()
                .filter(|p| *p.licence == *licence)
                .map(|p| p.v.clone())
                .collect();
            let mut by: BTreeMap<String, Vec<Vec<f64>>> = BTreeMap::new();
            for p in recent.iter().take(MAX_CROSS) {
                by.entry(p.licence.to_string())
                    .or_default()
                    .push(p.v.clone());
            }
            // The licences with the most points, at most MAX_CROSS_LICENCES.
            if by.len() > MAX_CROSS_LICENCES {
                let mut sizes: Vec<(usize, String)> =
                    by.iter().map(|(k, v)| (v.len(), k.clone())).collect();
                sizes.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
                let keep: HashSet<String> = sizes
                    .into_iter()
                    .take(MAX_CROSS_LICENCES)
                    .map(|x| x.1)
                    .collect();
                by.retain(|k, _| keep.contains(k));
            }
            (own, by)
        } else {
            (vec![], BTreeMap::new())
        };
        drop(st);
        let mut alerts = vec![];
        if due {
            let s = stats(&own);
            let rules = s.rules(cfg);
            if !rules.is_empty() {
                alerts.push(Alert {
                    kind: "single_licence".into(),
                    method: method.into(),
                    shape: f.shape.clone(),
                    licences: vec![licence.into()],
                    rules: rules.iter().map(|r| r.to_string()).collect(),
                    stats: Some(s),
                });
            }
            if by.len() >= 2 {
                if let Some(a) = cross_licence(&by, method, &f.shape, cfg) {
                    alerts.push(a);
                }
            }
        }
        let mut st = self.st.lock().unwrap_or_else(|e| e.into_inner());
        // Raise each (shape, kind, licence) once per window; mark the licences suspect.
        for a in alerts {
            let mut fresh = false;
            for id in &a.licences {
                let l = st.licences.entry(Arc::from(id.as_str())).or_default();
                let key = (a.shape.clone(), a.kind.clone());
                let new = l.alerted.get(&key).is_none_or(|t| *t <= now - cfg.window_s);
                if new {
                    l.alerted.insert(key, now);
                    fresh = true;
                }
                l.suspect_until = l.suspect_until.max(now + cfg.suspect_s);
            }
            if fresh {
                out.alerts.push(a);
            }
        }
        let l = st.licences.entry(lic).or_default();
        out.suspect = now < l.suspect_until;
        if out.suspect && cfg.pause {
            out.refuse = Some(
                "this licence is paused after unusual request patterns; contact Ashforde if this is unexpected"
                    .into(),
            );
        }
        out
    }
}

/// Judge several licences' points of one shape together. Start from every licence with at
/// least 3 points and drop, one at a time, the licence whose removal makes the rest most
/// uniform, while that helps; if what remains (two licences or more) is space-filling, those
/// licences are named. A bystander with ordinary, clustered requests of the same shape makes
/// the union less uniform, so it is dropped and not named.
fn cross_licence(by: &ByLicence, method: &str, shape: &str, cfg: &AuditConfig) -> Option<Alert> {
    let mut members: Vec<&str> = by
        .iter()
        .filter(|(_, v)| v.len() >= 3)
        .map(|(k, _)| k.as_str())
        .collect();
    let union =
        |m: &[&str]| -> Vec<Vec<f64>> { m.iter().flat_map(|k| by[*k].iter().cloned()).collect() };
    let mut s = stats(&union(&members));
    while members.len() > 2 && s.rules(cfg).is_empty() {
        let best = (0..members.len())
            .map(|i| {
                let mut m = members.clone();
                m.remove(i);
                (i, stats(&union(&m)))
            })
            .min_by(|a, b| a.1.cd_ratio.total_cmp(&b.1.cd_ratio))?;
        if best.1.cd_ratio >= s.cd_ratio {
            break;
        }
        members.remove(best.0);
        s = best.1;
    }
    let rules = s.rules(cfg);
    if members.len() < 2 || rules.is_empty() {
        return None;
    }
    // Name only the licences the pattern needs: without one of them the rest is clearly less
    // uniform (discrepancy ratio not 20 % better) or too small to judge.
    let named: Vec<String> = members
        .iter()
        .filter(|id| {
            let rest: Vec<&str> = members.iter().filter(|m| m != id).copied().collect();
            let w = stats(&union(&rest));
            w.n < cfg.min_points || w.cd_ratio >= 0.8 * s.cd_ratio
        })
        .map(|m| m.to_string())
        .collect();
    if named.len() < 2 {
        return None;
    }
    Some(Alert {
        kind: "cross_licence".into(),
        method: method.into(),
        shape: shape.into(),
        licences: named,
        rules: rules.iter().map(|r| r.to_string()).collect(),
        stats: Some(s),
    })
}

/// Sobol points in up to 6 dimensions (Joe–Kuo direction numbers), skipping the origin.
/// Used by the tests and the red-team harness to play the copier.
pub fn sobol(n: usize, d: usize) -> Vec<Vec<f64>> {
    // (s, a, m) for dimensions 2..=6 (new-joe-kuo-6.21201).
    const P: [(u32, u32, [u32; 4]); 5] = [
        (1, 0, [1, 0, 0, 0]),
        (2, 1, [1, 3, 0, 0]),
        (3, 1, [1, 3, 1, 0]),
        (3, 2, [1, 1, 1, 0]),
        (4, 1, [1, 1, 3, 3]),
    ];
    const BITS: usize = 32;
    let d = d.clamp(1, 6);
    let mut v: Vec<[u32; 32]> = vec![[0; 32]; d];
    for (i, x) in v[0].iter_mut().enumerate() {
        *x = 1 << (31 - i);
    }
    for (k, (s, a, m)) in P.iter().enumerate().take(d - 1) {
        let s = *s as usize;
        let vk = &mut v[k + 1];
        for i in 0..s {
            vk[i] = m[i] << (31 - i);
        }
        for i in s..BITS {
            let mut x = vk[i - s] ^ (vk[i - s] >> s);
            for j in 1..s {
                x ^= ((a >> (s - 1 - j)) & 1) * vk[i - j];
            }
            vk[i] = x;
        }
    }
    let mut x = vec![0u32; d];
    let mut out = Vec::with_capacity(n);
    for i in 1..=n as u64 {
        let c = (i - 1).trailing_ones() as usize;
        for k in 0..d {
            x[k] ^= v[k][c];
        }
        out.push(x.iter().map(|b| *b as f64 / 4_294_967_296.0).collect());
    }
    out
}

#[cfg(test)]
#[path = "audit_tests.rs"]
pub(crate) mod tests;
