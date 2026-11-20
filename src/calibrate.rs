// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! `calibrate`: general parametric calibration of a simulator against telemetry.
//!
//! The F1 self-calibration verdict (`selfcal`) serves one model family: radio timing reference
//! simulators in the Kshana Pro scenario format. This method generalises the same verdict to
//! any simulator whose behaviour depends on a set of named parameters: a power, thermal, clock,
//! attitude or propulsion model, or a whole mission performance simulator. A caller gives the
//! parameters (prior, prior uncertainty, bounds), the telemetry (`observable`, `t_s`, `value`,
//! `sigma`) and the model in one of two forms:
//!
//! * **`expression`**: a closed-form model per observable, an arithmetic expression in `t`
//!   (seconds) and the parameters, evaluated in the service ([`Expr`]);
//! * **`design`**: runs of the caller's own simulator at chosen parameter sets (its predictions
//!   per observable, as `[t_s, value]` series). The service builds a quadratic response surface
//!   per observation over the design, adds the surface's leave-one-out error to each
//!   observation's uncertainty, and keeps the parameters inside the design's range (a response
//!   surface is not extrapolated). Any black-box simulator can be calibrated this way without
//!   the service running it.
//!
//! # Method (stays in the service)
//!
//! Damped Gauss–Newton (Levenberg–Marquardt) on the whitened residuals plus the prior
//! residuals, in transformed coordinates that respect the bounds (logistic between two bounds,
//! exponential against one). Uncertainty: the a-priori covariance of the whitened problem in
//! physical coordinates (a parameter on a bound gets the data's local sensitivity, and is
//! listed in `at_bound`), inflated by the reduced chi^½ when it exceeds 1 (the `selfcal`
//! convention). Fidelity before and after: 100 × the share of observations within
//! tolerance (the caller's per-observable tolerance, else 2 sigma).
//!
//! # Verdict
//!
//! The shape `selfcal` returns, which the Arksa simulator recalibration client reads:
//! `converged`, `stop_reason`, `passes`, `fidelity_first`, `fidelity_last`, `posterior`
//! (`{name, value, std_err}`), `lineage` (`head`, `entries`, `recording_digest`,
//! `model_digest`, `key_id`, `tag`), and further `chi2_reduced_first`, `chi2_reduced_last`,
//! `n_obs`, `correlation`, `at_bound`, `not_constrained` (parameters whose posterior is not
//! narrower than 90 % of the prior) and, for a design, `surface`. Residuals, Jacobians, the
//! response surface and the iteration trace stay in the service.
//!
//! Evidence class: **MODELLED**. Calibrated parameters are what best explains the telemetry
//! supplied under the model supplied; they are not validated.

use crate::methods::Signing;
use crate::verdict::SignedVerdict;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

// ── Request ─────────────────────────────────────────────────────────────────

/// One parameter to calibrate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamSpec {
    pub name: String,
    /// Prior mean (also the start, unless `initial` is given).
    #[serde(default)]
    pub prior: Option<f64>,
    /// Prior standard uncertainty. Absent: a flat prior (the data alone decide).
    #[serde(default)]
    pub prior_sigma: Option<f64>,
    #[serde(default)]
    pub lower: Option<f64>,
    #[serde(default)]
    pub upper: Option<f64>,
    /// Start value (default: the prior, else the middle of the bounds).
    #[serde(default)]
    pub initial: Option<f64>,
}

/// One telemetry sample.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub observable: String,
    pub t_s: f64,
    pub value: f64,
    /// Standard uncertainty of the sample.
    pub sigma: f64,
}

/// One run of the caller's simulator for a `design` model.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignRun {
    /// The parameter values of the run (every calibrated parameter).
    pub params: BTreeMap<String, f64>,
    /// Predictions per observable: `[t_s, value]`, ascending in time.
    pub predictions: BTreeMap<String, Vec<[f64; 2]>>,
}

/// The model.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum ModelSpec {
    /// A closed-form expression per observable, in `t` and the parameters.
    Expression {
        observables: BTreeMap<String, String>,
    },
    /// Runs of the caller's simulator over a design of parameter sets.
    Design { runs: Vec<DesignRun> },
}

/// Options.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalOptions {
    #[serde(default = "d_iter")]
    pub max_iter: usize,
}

fn d_iter() -> usize {
    50
}

impl Default for CalOptions {
    fn default() -> Self {
        CalOptions { max_iter: 50 }
    }
}

/// A calibration request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrateRequest {
    /// A label echoed in the verdict (for example the mission and plugin).
    #[serde(default)]
    pub subject: Option<String>,
    pub parameters: Vec<ParamSpec>,
    pub model: ModelSpec,
    pub observations: Vec<Observation>,
    /// Fidelity tolerance per observable (default 2 sigma per sample).
    #[serde(default)]
    pub tolerances: BTreeMap<String, f64>,
    #[serde(default)]
    pub options: CalOptions,
}

/// Request limits, checked before any work.
#[derive(Clone, Debug)]
pub struct CalibrateLimits {
    pub max_params: usize,
    pub max_obs: usize,
    /// Most `observations × parameters` (the Jacobian size).
    pub max_jacobian: usize,
    pub max_runs: usize,
    /// Most prediction points over all runs.
    pub max_run_points: usize,
    pub max_expr_len: usize,
    pub max_iter: usize,
}

impl Default for CalibrateLimits {
    fn default() -> Self {
        CalibrateLimits {
            max_params: 32,
            max_obs: 20_000,
            max_jacobian: 200_000,
            max_runs: 256,
            max_run_points: 500_000,
            max_expr_len: 2_000,
            max_iter: 100,
        }
    }
}

// ── Expressions ─────────────────────────────────────────────────────────────

/// A compiled arithmetic expression over `t`, `pi` and named variables. Grammar:
/// `+ - * / ^` (right-associative power), unary minus, parentheses, numbers, and the
/// functions `exp ln log10 sqrt abs sin cos tan asin acos atan tanh sinh cosh` (one argument)
/// and `min max pow atan2` (two). No other identifiers, no loops, no side effects.
#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Num(f64),
    /// Index into the variable vector (0 = `t`, then the parameters in order).
    Var(usize),
    Neg(Box<Expr>),
    Bin(char, Box<Expr>, Box<Expr>),
    F1(&'static str, Box<Expr>),
    F2(&'static str, Box<Expr>, Box<Expr>),
}

const F1: [&str; 14] = [
    "exp", "ln", "log10", "sqrt", "abs", "sin", "cos", "tan", "asin", "acos", "atan", "tanh",
    "sinh", "cosh",
];
const F2: [&str; 4] = ["min", "max", "pow", "atan2"];
const MAX_NODES: usize = 1_000;
const MAX_DEPTH: usize = 64;

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    vars: &'a [String],
    nodes: usize,
    depth: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }
    fn peek(&mut self) -> Option<u8> {
        self.ws();
        self.s.get(self.i).copied()
    }
    fn node(&mut self, e: Expr) -> Result<Expr, String> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(format!("expression above {MAX_NODES} nodes"));
        }
        Ok(e)
    }
    fn expr(&mut self) -> Result<Expr, String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("expression nested too deeply".into());
        }
        let mut a = self.term()?;
        while let Some(c @ (b'+' | b'-')) = self.peek() {
            self.i += 1;
            let b = self.term()?;
            a = self.node(Expr::Bin(c as char, Box::new(a), Box::new(b)))?;
        }
        self.depth -= 1;
        Ok(a)
    }
    fn term(&mut self) -> Result<Expr, String> {
        let mut a = self.unary()?;
        while let Some(c @ (b'*' | b'/')) = self.peek() {
            self.i += 1;
            let b = self.unary()?;
            a = self.node(Expr::Bin(c as char, Box::new(a), Box::new(b)))?;
        }
        Ok(a)
    }
    fn unary(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some(b'-') => {
                self.i += 1;
                let a = self.unary()?;
                self.node(Expr::Neg(Box::new(a)))
            }
            Some(b'+') => {
                self.i += 1;
                self.unary()
            }
            _ => self.power(),
        }
    }
    fn power(&mut self) -> Result<Expr, String> {
        let a = self.atom()?;
        if self.peek() == Some(b'^') {
            self.i += 1;
            let b = self.unary()?;
            return self.node(Expr::Bin('^', Box::new(a), Box::new(b)));
        }
        Ok(a)
    }
    fn atom(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some(b'(') => {
                self.i += 1;
                let e = self.expr()?;
                if self.peek() != Some(b')') {
                    return Err("missing ')'".into());
                }
                self.i += 1;
                Ok(e)
            }
            Some(c) if c.is_ascii_digit() || c == b'.' => {
                let st = self.i;
                while self.i < self.s.len()
                    && (self.s[self.i].is_ascii_digit() || self.s[self.i] == b'.')
                {
                    self.i += 1;
                }
                if self.i < self.s.len() && matches!(self.s[self.i], b'e' | b'E') {
                    let save = self.i;
                    self.i += 1;
                    if self.i < self.s.len() && matches!(self.s[self.i], b'+' | b'-') {
                        self.i += 1;
                    }
                    if self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
                        while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
                            self.i += 1;
                        }
                    } else {
                        self.i = save;
                    }
                }
                let txt = std::str::from_utf8(&self.s[st..self.i]).unwrap_or("");
                let v: f64 = txt.parse().map_err(|_| format!("bad number '{txt}'"))?;
                self.node(Expr::Num(v))
            }
            Some(c) if c.is_ascii_alphabetic() || c == b'_' => {
                let st = self.i;
                while self.i < self.s.len()
                    && (self.s[self.i].is_ascii_alphanumeric() || self.s[self.i] == b'_')
                {
                    self.i += 1;
                }
                let id = std::str::from_utf8(&self.s[st..self.i]).unwrap_or("");
                if self.peek() == Some(b'(') {
                    self.i += 1;
                    let a = self.expr()?;
                    let f = if let Some(f) = F1.iter().find(|f| **f == id) {
                        self.node(Expr::F1(f, Box::new(a)))?
                    } else if let Some(f) = F2.iter().find(|f| **f == id) {
                        if self.peek() != Some(b',') {
                            return Err(format!("{id}() takes two arguments"));
                        }
                        self.i += 1;
                        let b = self.expr()?;
                        self.node(Expr::F2(f, Box::new(a), Box::new(b)))?
                    } else {
                        return Err(format!("unknown function '{id}'"));
                    };
                    if self.peek() != Some(b')') {
                        return Err(format!("missing ')' after {id}("));
                    }
                    self.i += 1;
                    return Ok(f);
                }
                if id == "pi" {
                    return self.node(Expr::Num(std::f64::consts::PI));
                }
                match self.vars.iter().position(|v| v == id) {
                    Some(k) => self.node(Expr::Var(k)),
                    None => Err(format!(
                        "unknown name '{id}' (use t, pi or a parameter name)"
                    )),
                }
            }
            Some(c) => Err(format!("unexpected '{}'", c as char)),
            None => Err("unexpected end of expression".into()),
        }
    }
}

impl Expr {
    /// Compile `src` over the variables `vars` (`vars[0]` is conventionally `t`).
    pub fn parse(src: &str, vars: &[String]) -> Result<Expr, String> {
        let mut p = Parser {
            s: src.as_bytes(),
            i: 0,
            vars,
            nodes: 0,
            depth: 0,
        };
        let e = p.expr()?;
        if p.peek().is_some() {
            return Err(format!("unexpected text at position {}", p.i));
        }
        Ok(e)
    }

    /// Evaluate with the variable values `x`.
    pub fn eval(&self, x: &[f64]) -> f64 {
        match self {
            Expr::Num(v) => *v,
            Expr::Var(k) => x[*k],
            Expr::Neg(a) => -a.eval(x),
            Expr::Bin(op, a, b) => {
                let (a, b) = (a.eval(x), b.eval(x));
                match op {
                    '+' => a + b,
                    '-' => a - b,
                    '*' => a * b,
                    '/' => a / b,
                    _ => a.powf(b),
                }
            }
            Expr::F1(f, a) => {
                let a = a.eval(x);
                match *f {
                    "exp" => a.exp(),
                    "ln" => a.ln(),
                    "log10" => a.log10(),
                    "sqrt" => a.sqrt(),
                    "abs" => a.abs(),
                    "sin" => a.sin(),
                    "cos" => a.cos(),
                    "tan" => a.tan(),
                    "asin" => a.asin(),
                    "acos" => a.acos(),
                    "atan" => a.atan(),
                    "tanh" => a.tanh(),
                    "sinh" => a.sinh(),
                    _ => a.cosh(),
                }
            }
            Expr::F2(f, a, b) => {
                let (a, b) = (a.eval(x), b.eval(x));
                match *f {
                    "min" => a.min(b),
                    "max" => a.max(b),
                    "pow" => a.powf(b),
                    _ => a.atan2(b),
                }
            }
        }
    }
}

// ── Bounds transform ────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Tr {
    Free,
    Lower(f64),
    Upper(f64),
    Both(f64, f64),
}

impl Tr {
    fn of(lo: Option<f64>, hi: Option<f64>) -> Tr {
        match (lo, hi) {
            (None, None) => Tr::Free,
            (Some(l), None) => Tr::Lower(l),
            (None, Some(h)) => Tr::Upper(h),
            (Some(l), Some(h)) => Tr::Both(l, h),
        }
    }
    /// Physical value of the internal coordinate.
    fn x(self, z: f64) -> f64 {
        match self {
            Tr::Free => z,
            Tr::Lower(l) => l + z.exp(),
            Tr::Upper(h) => h - z.exp(),
            Tr::Both(l, h) => l + (h - l) / (1.0 + (-z).exp()),
        }
    }
    /// Internal coordinate of a physical value strictly inside the bounds.
    fn z(self, x: f64) -> f64 {
        match self {
            Tr::Free => x,
            Tr::Lower(l) => (x - l).ln(),
            Tr::Upper(h) => (h - x).ln(),
            Tr::Both(l, h) => {
                let u = (x - l) / (h - l);
                (u / (1.0 - u)).ln()
            }
        }
    }
    /// Pull `x` strictly inside the bounds.
    fn inside(self, x: f64) -> f64 {
        match self {
            Tr::Free => x,
            Tr::Lower(l) => x.max(l + 1e-9 * l.abs().max(1.0)),
            Tr::Upper(h) => x.min(h - 1e-9 * h.abs().max(1.0)),
            Tr::Both(l, h) => {
                let m = 1e-6 * (h - l);
                x.clamp(l + m, h - m)
            }
        }
    }
    /// The value lies at (numerically on) a bound.
    fn at_bound(self, z: f64) -> bool {
        match self {
            Tr::Free => false,
            Tr::Lower(_) | Tr::Upper(_) => z < -12.0,
            Tr::Both(..) => z.abs() > 9.0,
        }
    }
}

// ── The model in evaluable form ─────────────────────────────────────────────

enum Model {
    /// One expression per observation (shared per observable).
    Expr(Vec<Expr>, Vec<usize>),
    /// A response surface per observation: coefficients over the basis of normalised
    /// parameters; the centre and half-range of each parameter; the basis degree.
    Surface {
        coef: Vec<Vec<f64>>,
        centre: Vec<f64>,
        half: Vec<f64>,
        degree: Degree,
    },
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Degree {
    Linear,
    Diagonal,
    Full,
}

impl Degree {
    fn name(self) -> &'static str {
        match self {
            Degree::Linear => "linear",
            Degree::Diagonal => "quadratic (no cross terms)",
            Degree::Full => "quadratic",
        }
    }
    fn terms(self, p: usize) -> usize {
        match self {
            Degree::Linear => 1 + p,
            Degree::Diagonal => 1 + 2 * p,
            Degree::Full => 1 + 2 * p + p * (p - 1) / 2,
        }
    }
}

fn basis(u: &[f64], d: Degree) -> Vec<f64> {
    let mut b = vec![1.0];
    b.extend_from_slice(u);
    if d != Degree::Linear {
        b.extend(u.iter().map(|v| v * v));
    }
    if d == Degree::Full {
        for i in 0..u.len() {
            for j in i + 1..u.len() {
                b.push(u[i] * u[j]);
            }
        }
    }
    b
}

impl Model {
    fn predict(&self, x: &[f64], obs: &[Observation], out: &mut [f64]) {
        match self {
            Model::Expr(exprs, which) => {
                let mut v = Vec::with_capacity(x.len() + 1);
                v.push(0.0);
                v.extend_from_slice(x);
                for (i, o) in obs.iter().enumerate() {
                    v[0] = o.t_s;
                    out[i] = exprs[which[i]].eval(&v);
                }
            }
            Model::Surface {
                coef,
                centre,
                half,
                degree,
            } => {
                let u: Vec<f64> = x
                    .iter()
                    .zip(centre.iter().zip(half))
                    .map(|(v, (c, h))| (v - c) / h)
                    .collect();
                let b = basis(&u, *degree);
                for (i, c) in coef.iter().enumerate() {
                    out[i] = c.iter().zip(&b).map(|(a, b)| a * b).sum();
                }
            }
        }
    }
}

/// Linear interpolation in an ascending `[t, v]` series; `None` outside it.
fn interp(series: &[[f64; 2]], t: f64) -> Option<f64> {
    let first = series.first()?;
    let last = series.last()?;
    if t < first[0] - 1e-9 || t > last[0] + 1e-9 {
        return None;
    }
    let k = series.partition_point(|p| p[0] < t);
    if k == 0 {
        return Some(first[1]);
    }
    if k >= series.len() {
        return Some(last[1]);
    }
    let (a, b) = (series[k - 1], series[k]);
    if b[0] == a[0] {
        return Some(b[1]);
    }
    Some(a[1] + (b[1] - a[1]) * (t - a[0]) / (b[0] - a[0]))
}

fn invert(a: &[Vec<f64>]) -> Option<Vec<Vec<f64>>> {
    let n = a.len();
    let mut m: Vec<Vec<f64>> = a
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let mut row = r.clone();
            row.extend((0..n).map(|j| if i == j { 1.0 } else { 0.0 }));
            row
        })
        .collect();
    for c in 0..n {
        let p = (c..n).max_by(|&x, &y| m[x][c].abs().total_cmp(&m[y][c].abs()))?;
        let scale = m.iter().map(|r| r[c].abs()).fold(0.0, f64::max).max(1e-300);
        if m[p][c].abs() < 1e-13 * scale {
            return None;
        }
        m.swap(c, p);
        let d = m[c][c];
        m[c].iter_mut().for_each(|v| *v /= d);
        let pivot = m[c].clone();
        for (r, row) in m.iter_mut().enumerate() {
            if r != c {
                let f = row[c];
                if f != 0.0 {
                    row.iter_mut().zip(&pivot).for_each(|(v, p)| *v -= f * p);
                }
            }
        }
    }
    Some(m.into_iter().map(|r| r[n..].to_vec()).collect())
}

/// What the surface adds to the verdict: its kind, the run count, and its error.
struct SurfaceInfo {
    degree: Degree,
    runs: usize,
    /// RMS over observations of the leave-one-out error relative to the sample sigma.
    loo_rel_rms: f64,
}

/// Build the response surfaces over a design. Returns the model, each observation's added
/// standard uncertainty (leave-one-out error), the design box per parameter and the info.
#[allow(clippy::type_complexity)]
fn build_surface(
    names: &[String],
    runs: &[DesignRun],
    obs: &[Observation],
) -> Result<(Model, Vec<f64>, Vec<(f64, f64)>, SurfaceInfo), String> {
    let p = names.len();
    let n = runs.len();
    let degree = [Degree::Full, Degree::Diagonal, Degree::Linear]
        .into_iter()
        .find(|d| n > d.terms(p))
        .ok_or_else(|| {
            format!(
                "a design for {p} parameters needs at least {} runs (it has {n})",
                Degree::Linear.terms(p) + 1
            )
        })?;
    let mut lo = vec![f64::INFINITY; p];
    let mut hi = vec![f64::NEG_INFINITY; p];
    let mut xs = vec![];
    for (k, r) in runs.iter().enumerate() {
        let extra: Vec<&String> = r.params.keys().filter(|k| !names.contains(k)).collect();
        if !extra.is_empty() {
            return Err(format!("run {k}: unknown parameter '{}'", extra[0]));
        }
        let x: Vec<f64> = names
            .iter()
            .map(|nm| {
                r.params
                    .get(nm)
                    .copied()
                    .filter(|v| v.is_finite())
                    .ok_or_else(|| format!("run {k}: no finite value for parameter '{nm}'"))
            })
            .collect::<Result<_, _>>()?;
        for j in 0..p {
            lo[j] = lo[j].min(x[j]);
            hi[j] = hi[j].max(x[j]);
        }
        xs.push(x);
    }
    for j in 0..p {
        if hi[j] - lo[j] <= 0.0 {
            return Err(format!("the design does not vary parameter '{}'", names[j]));
        }
    }
    let centre: Vec<f64> = (0..p).map(|j| 0.5 * (lo[j] + hi[j])).collect();
    let half: Vec<f64> = (0..p).map(|j| 0.5 * (hi[j] - lo[j])).collect();
    let b: Vec<Vec<f64>> = xs
        .iter()
        .map(|x| {
            let u: Vec<f64> = (0..p).map(|j| (x[j] - centre[j]) / half[j]).collect();
            basis(&u, degree)
        })
        .collect();
    let q = b[0].len();
    let mut btb = vec![vec![0.0; q]; q];
    for row in &b {
        for i in 0..q {
            for j in 0..q {
                btb[i][j] += row[i] * row[j];
            }
        }
    }
    let inv = invert(&btb).ok_or(
        "the design is degenerate for a response surface (runs too alike; spread the parameter values)",
    )?;
    // P = (BᵀB)⁻¹Bᵀ (q × n); leverage h_kk = b_k · P[:, k].
    let pm: Vec<Vec<f64>> = (0..q)
        .map(|i| {
            (0..n)
                .map(|k| (0..q).map(|j| inv[i][j] * b[k][j]).sum())
                .collect()
        })
        .collect();
    let lev: Vec<f64> = (0..n)
        .map(|k| (0..q).map(|i| b[k][i] * pm[i][k]).sum())
        .collect();
    let mut coef = Vec::with_capacity(obs.len());
    let mut extra = Vec::with_capacity(obs.len());
    let mut rel2 = 0.0;
    for (i, o) in obs.iter().enumerate() {
        let y: Vec<f64> = runs
            .iter()
            .enumerate()
            .map(|(k, r)| {
                r.predictions
                    .get(&o.observable)
                    .and_then(|s| interp(s, o.t_s))
                    .ok_or_else(|| {
                        format!(
                            "run {k} makes no prediction of '{}' at t = {} s (observation {i})",
                            o.observable, o.t_s
                        )
                    })
            })
            .collect::<Result<_, _>>()?;
        let c: Vec<f64> = (0..q)
            .map(|r| (0..n).map(|k| pm[r][k] * y[k]).sum())
            .collect();
        let mut s2 = 0.0;
        let mut m = 0usize;
        for k in 0..n {
            let fit: f64 = c.iter().zip(&b[k]).map(|(a, b)| a * b).sum();
            if 1.0 - lev[k] > 1e-9 {
                s2 += ((y[k] - fit) / (1.0 - lev[k])).powi(2);
                m += 1;
            }
        }
        let e = if m > 0 { (s2 / m as f64).sqrt() } else { 0.0 };
        rel2 += (e / o.sigma).powi(2);
        coef.push(c);
        extra.push(e);
    }
    let info = SurfaceInfo {
        degree,
        runs: n,
        loo_rel_rms: (rel2 / obs.len().max(1) as f64).sqrt(),
    };
    let bounds = lo.into_iter().zip(hi).collect();
    Ok((
        Model::Surface {
            coef,
            centre,
            half,
            degree,
        },
        extra,
        bounds,
        info,
    ))
}

// ── Validation ──────────────────────────────────────────────────────────────

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && s != "t"
        && s != "pi"
        && !F1.contains(&s)
        && !F2.contains(&s)
}

/// Check a request against the limits, before any work.
pub fn validate(req: &CalibrateRequest, lim: &CalibrateLimits) -> Result<(), String> {
    let p = req.parameters.len();
    if p == 0 {
        return Err("a request names at least one parameter".into());
    }
    if p > lim.max_params {
        return Err(format!("more than {} parameters", lim.max_params));
    }
    if req.observations.is_empty() {
        return Err("a request carries at least one observation".into());
    }
    if req.observations.len() > lim.max_obs {
        return Err(format!("more than {} observations", lim.max_obs));
    }
    if req.observations.len().saturating_mul(p) > lim.max_jacobian {
        return Err(format!(
            "observations x parameters above {} (send fewer samples or parameters)",
            lim.max_jacobian
        ));
    }
    if req.options.max_iter == 0 || req.options.max_iter > lim.max_iter {
        return Err(format!("options.max_iter must lie in 1..={}", lim.max_iter));
    }
    let mut seen = BTreeSet::new();
    for q in &req.parameters {
        if !valid_name(&q.name) {
            return Err(format!(
                "parameter name '{}' must be a plain identifier (letters, digits, _), not t, pi or a function",
                q.name
            ));
        }
        if !seen.insert(q.name.as_str()) {
            return Err(format!("parameter '{}' appears twice", q.name));
        }
        let fin = |v: Option<f64>| v.is_none_or(f64::is_finite);
        if !(fin(q.prior) && fin(q.prior_sigma) && fin(q.lower) && fin(q.upper) && fin(q.initial)) {
            return Err(format!("parameter '{}': a value is not finite", q.name));
        }
        if q.prior_sigma.is_some_and(|s| s <= 0.0) {
            return Err(format!(
                "parameter '{}': prior_sigma must be positive",
                q.name
            ));
        }
        if q.prior_sigma.is_some() && q.prior.is_none() {
            return Err(format!("parameter '{}': prior_sigma needs a prior", q.name));
        }
        if let (Some(l), Some(h)) = (q.lower, q.upper) {
            if l >= h {
                return Err(format!("parameter '{}': lower must be below upper", q.name));
            }
        }
        if q.prior.is_none() && q.initial.is_none() && (q.lower.is_none() || q.upper.is_none()) {
            return Err(format!(
                "parameter '{}': give a prior, an initial value or both bounds",
                q.name
            ));
        }
    }
    let observables: BTreeSet<&str> = req
        .observations
        .iter()
        .map(|o| o.observable.as_str())
        .collect();
    for o in &req.observations {
        if !(o.t_s.is_finite() && o.value.is_finite() && o.sigma.is_finite() && o.sigma > 0.0) {
            return Err(format!(
                "observation of '{}' at t = {}: t_s, value and a positive sigma must be finite",
                o.observable, o.t_s
            ));
        }
    }
    for (k, v) in &req.tolerances {
        if !(v.is_finite() && *v > 0.0) {
            return Err(format!("tolerance of '{k}' must be positive"));
        }
    }
    match &req.model {
        ModelSpec::Expression { observables: m } => {
            for ob in &observables {
                if !m.contains_key(*ob) {
                    return Err(format!("no model expression for observable '{ob}'"));
                }
            }
            for (k, e) in m {
                if e.len() > lim.max_expr_len {
                    return Err(format!(
                        "expression of '{k}' above {} characters",
                        lim.max_expr_len
                    ));
                }
            }
        }
        ModelSpec::Design { runs } => {
            if runs.len() > lim.max_runs {
                return Err(format!("more than {} design runs", lim.max_runs));
            }
            let pts: usize = runs
                .iter()
                .map(|r| r.predictions.values().map(Vec::len).sum::<usize>())
                .sum();
            if pts > lim.max_run_points {
                return Err(format!(
                    "more than {} prediction points over the design runs",
                    lim.max_run_points
                ));
            }
            for (k, r) in runs.iter().enumerate() {
                for (ob, s) in &r.predictions {
                    if s.iter().any(|p| !(p[0].is_finite() && p[1].is_finite()))
                        || s.windows(2).any(|w| w[1][0] < w[0][0])
                    {
                        return Err(format!(
                            "run {k}: predictions of '{ob}' must be finite and ascending in time"
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

// ── Lineage ─────────────────────────────────────────────────────────────────

/// HMAC-SHA256 (RFC 2104).
pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = Sha256::new();
    ipad.update(k.map(|b| b ^ 0x36));
    ipad.update(msg);
    let inner = ipad.finalize();
    let mut opad = Sha256::new();
    opad.update(k.map(|b| b ^ 0x5c));
    opad.update(inner);
    opad.finalize().into()
}

fn sha_json(v: &impl Serialize) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(v).unwrap_or_default()))
}

// ── The method ──────────────────────────────────────────────────────────────

/// Fidelity: 100 × the share of observations within tolerance.
fn fidelity(obs: &[Observation], pred: &[f64], tol: &BTreeMap<String, f64>) -> f64 {
    let ok = obs
        .iter()
        .zip(pred)
        .filter(|(o, p)| {
            let t = tol.get(&o.observable).copied().unwrap_or(2.0 * o.sigma);
            (o.value - *p).abs() <= t
        })
        .count();
    100.0 * ok as f64 / obs.len().max(1) as f64
}

fn chi2(obs: &[Observation], pred: &[f64], extra: &[f64]) -> f64 {
    obs.iter()
        .zip(pred)
        .zip(extra)
        .map(|((o, p), e)| (o.value - p).powi(2) / (o.sigma * o.sigma + e * e))
        .sum()
}

/// The result of [`minimise`].
struct Fit {
    z: Vec<f64>,
    iterations: usize,
    converged: bool,
}

/// Levenberg–Marquardt (Marquardt's diagonal scaling, central-difference Jacobian) on
/// `Σ r(z)²`. A step is accepted only when it lowers the cost; converged when the step is
/// negligible, the cost stops changing, or no downhill step exists.
fn minimise<F: Fn(&[f64]) -> Vec<f64>>(f: F, z0: &[f64], max_iter: usize) -> Result<Fit, String> {
    let n = z0.len();
    let mut z = z0.to_vec();
    let mut r = f(&z);
    let cost = |r: &[f64]| r.iter().map(|v| v * v).sum::<f64>();
    let mut lambda = 1e-3;
    let mut it = 0;
    let mut converged = false;
    while it < max_iter {
        it += 1;
        let mut jac = vec![vec![0.0; n]; r.len()];
        for k in 0..n {
            let h = 1e-6 * z[k].abs().max(1e-3);
            let mut zp = z.clone();
            let mut zm = z.clone();
            zp[k] += h;
            zm[k] -= h;
            let (rp, rm) = (f(&zp), f(&zm));
            for i in 0..r.len() {
                jac[i][k] = (rp[i] - rm[i]) / (2.0 * h);
            }
        }
        let mut a = vec![vec![0.0; n]; n];
        let mut g = vec![0.0; n];
        for (row, ri) in jac.iter().zip(&r) {
            for p in 0..n {
                g[p] += row[p] * ri;
                for q in 0..n {
                    a[p][q] += row[p] * row[q];
                }
            }
        }
        let cur = cost(&r);
        let mut accepted = None;
        for _ in 0..40 {
            let mut ad = a.clone();
            for k in 0..n {
                ad[k][k] += lambda * a[k][k].max(1e-12);
            }
            let Some(inv) = invert(&ad) else {
                lambda = (lambda * 10.0).max(1e-6);
                continue;
            };
            let d: Vec<f64> = (0..n)
                .map(|p| -(0..n).map(|q| inv[p][q] * g[q]).sum::<f64>())
                .collect();
            let zn: Vec<f64> = z.iter().zip(&d).map(|(a, b)| a + b).collect();
            let rn = f(&zn);
            if rn.iter().all(|v| v.is_finite()) && cost(&rn) <= cur {
                accepted = Some((zn, rn, d));
                lambda = (lambda / 10.0).max(1e-12);
                break;
            }
            lambda = (lambda * 10.0).max(1e-6);
        }
        let Some((zn, rn, d)) = accepted else {
            converged = true; // no downhill step: at the minimum to working precision
            break;
        };
        let small = d
            .iter()
            .zip(&zn)
            .all(|(di, zi)| di.abs() <= 1e-10 * (zi.abs() + 1e-10));
        let rel = (cur - cost(&rn)).abs() <= 1e-14 * cur.max(1e-300);
        z = zn;
        r = rn;
        if small || rel {
            converged = true;
            break;
        }
    }
    Ok(Fit {
        z,
        iterations: it,
        converged,
    })
}

/// Calibrate and return the verdict body (before rounding and signing).
pub fn calibrate(
    req: &CalibrateRequest,
    lim: &CalibrateLimits,
    lineage_seed: &[u8; 32],
    lineage_key_id: &str,
) -> Result<Value, String> {
    validate(req, lim)?;
    let names: Vec<String> = req.parameters.iter().map(|p| p.name.clone()).collect();
    let p = names.len();
    let obs = &req.observations;
    let m = obs.len();
    // The model, and in a design the surface error per observation and the design box.
    let (model, extra, design_box, surface) = match &req.model {
        ModelSpec::Expression { observables } => {
            let mut vars = vec!["t".to_string()];
            vars.extend(names.iter().cloned());
            let keys: Vec<&String> = observables.keys().collect();
            let exprs: Vec<Expr> = observables
                .iter()
                .map(|(k, e)| Expr::parse(e, &vars).map_err(|err| format!("model of '{k}': {err}")))
                .collect::<Result<_, _>>()?;
            let which: Vec<usize> = obs
                .iter()
                .map(|o| keys.iter().position(|k| **k == o.observable).unwrap_or(0))
                .collect();
            (Model::Expr(exprs, which), vec![0.0; m], None, None)
        }
        ModelSpec::Design { runs } => {
            let (model, extra, bx, info) = build_surface(&names, runs, obs)?;
            (model, extra, Some(bx), Some(info))
        }
    };
    // Effective bounds (a design also bounds each parameter to its range) and transforms.
    let mut trs = Vec::with_capacity(p);
    let mut x0 = Vec::with_capacity(p);
    for (j, q) in req.parameters.iter().enumerate() {
        let (mut lo, mut hi) = (q.lower, q.upper);
        if let Some(bx) = &design_box {
            lo = Some(lo.map_or(bx[j].0, |l| l.max(bx[j].0)));
            hi = Some(hi.map_or(bx[j].1, |h| h.min(bx[j].1)));
            if lo >= hi {
                return Err(format!(
                    "parameter '{}': its bounds do not overlap the design's range [{}, {}]",
                    q.name, bx[j].0, bx[j].1
                ));
            }
        }
        let tr = Tr::of(lo, hi);
        let start = q
            .initial
            .or(q.prior)
            .or_else(|| lo.zip(hi).map(|(l, h)| 0.5 * (l + h)))
            .ok_or_else(|| format!("parameter '{}': no start value", q.name))?;
        x0.push(tr.inside(start));
        trs.push(tr);
    }
    let z0: Vec<f64> = x0.iter().zip(&trs).map(|(x, t)| t.z(*x)).collect();
    let w: Vec<f64> = obs
        .iter()
        .zip(&extra)
        .map(|(o, e)| 1.0 / (o.sigma * o.sigma + e * e).sqrt())
        .collect();
    let priors: Vec<(usize, f64, f64)> = req
        .parameters
        .iter()
        .enumerate()
        .filter_map(|(j, q)| q.prior.zip(q.prior_sigma).map(|(mu, s)| (j, mu, s)))
        .collect();
    let to_x = |z: &[f64]| -> Vec<f64> { z.iter().zip(&trs).map(|(z, t)| t.x(*z)).collect() };
    let mut pred = vec![0.0; m];
    // Whitened residuals (observations, then priors) at physical parameter values.
    let res_x = |x: &[f64]| -> Vec<f64> {
        let mut pr = vec![0.0; m];
        model.predict(x, obs, &mut pr);
        let mut r: Vec<f64> = obs
            .iter()
            .zip(&pr)
            .zip(&w)
            .map(|((o, p), w)| (o.value - p) * w)
            .collect();
        r.extend(priors.iter().map(|(j, mu, s)| (x[*j] - mu) / s));
        r
    };
    let r0 = res_x(&x0);
    if r0.iter().any(|v| !v.is_finite()) {
        return Err(
            "the model is not finite at the start values (check the expressions, priors and bounds)"
                .into(),
        );
    }
    if r0.len() < p {
        return Err(format!(
            "{} observations and priors for {p} parameters: the problem is underdetermined",
            r0.len()
        ));
    }
    model.predict(&x0, obs, &mut pred);
    let fid0 = fidelity(obs, &pred, &req.tolerances);
    let dof = (m as f64 - p as f64 + priors.len() as f64).max(1.0);
    let chi0 = chi2(obs, &pred, &extra) / dof;
    let fit = minimise(|z: &[f64]| res_x(&to_x(z)), &z0, req.options.max_iter)?;
    let x = to_x(&fit.z);
    model.predict(&x, obs, &mut pred);
    let fid1 = fidelity(obs, &pred, &req.tolerances);
    let chi1 = chi2(obs, &pred, &extra) / dof;
    // Uncertainty: the a-priori covariance of the whitened problem in physical coordinates
    // (Jacobian by differences stepping towards the interior of any bound, so a parameter on
    // a bound gets the data's local sensitivity, not the transform's flat edge), inflated by
    // the reduced chi^½ when above 1.
    let rx = res_x(&x);
    let mut jx = vec![vec![0.0; p]; rx.len()];
    for j in 0..p {
        let h = 1e-6 * x[j].abs().max(1e-3);
        let (lo_room, hi_room) = match trs[j] {
            Tr::Free => (true, true),
            Tr::Lower(l) => (x[j] - h > l, true),
            Tr::Upper(u) => (true, x[j] + h < u),
            Tr::Both(l, u) => (x[j] - h > l, x[j] + h < u),
        };
        let shifted = |d: f64| {
            let mut xx = x.clone();
            xx[j] += d;
            res_x(&xx)
        };
        let (a, b, span) = match (lo_room, hi_room) {
            (true, true) => (shifted(h), shifted(-h), 2.0 * h),
            (false, _) => (shifted(h), rx.clone(), h),
            (true, false) => (rx.clone(), shifted(-h), h),
        };
        for i in 0..rx.len() {
            jx[i][j] = (a[i] - b[i]) / span;
        }
    }
    let mut info = vec![vec![0.0; p]; p];
    for row in &jx {
        for a in 0..p {
            for b in 0..p {
                info[a][b] += row[a] * row[b];
            }
        }
    }
    let cov = invert(&info).ok_or(
        "the telemetry and priors do not constrain every parameter (singular information); \
         add a prior or observations that depend on it",
    )?;
    let rss: f64 = rx.iter().map(|v| v * v).sum();
    let infl = (rss / dof).sqrt();
    let infl = if infl.is_finite() { infl.max(1.0) } else { 1.0 };
    let std_err: Vec<f64> = (0..p).map(|j| cov[j][j].max(0.0).sqrt() * infl).collect();
    let corr: Vec<Vec<f64>> = (0..p)
        .map(|i| {
            (0..p)
                .map(|j| {
                    let d = (cov[i][i] * cov[j][j]).sqrt();
                    if d > 0.0 {
                        (cov[i][j] / d).clamp(-1.0, 1.0)
                    } else {
                        0.0
                    }
                })
                .collect()
        })
        .collect();
    let at_bound: Vec<&str> = (0..p)
        .filter(|&j| trs[j].at_bound(fit.z[j]))
        .map(|j| names[j].as_str())
        .collect();
    let not_constrained: Vec<&str> = req
        .parameters
        .iter()
        .enumerate()
        .filter(|(j, q)| q.prior_sigma.is_some_and(|s| std_err[*j] > 0.9 * s))
        .map(|(_, q)| q.name.as_str())
        .collect();
    let posterior: Vec<Value> = (0..p)
        .map(|j| json!({"name": names[j], "value": x[j], "std_err": std_err[j]}))
        .collect();
    // Lineage: the initial and the calibrated state, hash-chained, with a keyed tag.
    let recording_digest = sha_json(obs);
    let model_digest = sha_json(&(&req.model, &req.parameters));
    let entries = [
        json!({"pass": 0, "params": names.iter().zip(&x0).collect::<BTreeMap<_, _>>(), "chi2_reduced": chi0, "fidelity": fid0}),
        json!({"pass": fit.iterations, "params": names.iter().zip(&x).collect::<BTreeMap<_, _>>(), "chi2_reduced": chi1, "fidelity": fid1, "converged": fit.converged}),
    ];
    let mut head = hex::encode(Sha256::digest(
        format!("{recording_digest}{model_digest}").as_bytes(),
    ));
    for e in &entries {
        let mut h = Sha256::new();
        h.update(head.as_bytes());
        h.update(serde_json::to_vec(e).unwrap_or_default());
        head = hex::encode(h.finalize());
    }
    let tag = hex::encode(hmac_sha256(
        lineage_seed,
        format!("{head}|{}|{recording_digest}|{model_digest}", entries.len()).as_bytes(),
    ));
    let stop_reason = if fit.converged {
        "converged"
    } else {
        "max_iter"
    };
    let mut v = json!({
        "converged": fit.converged,
        "stop_reason": stop_reason,
        "passes": fit.iterations,
        "fidelity_first": fid0,
        "fidelity_last": fid1,
        "chi2_reduced_first": chi0,
        "chi2_reduced_last": chi1,
        "n_obs": m,
        "posterior": posterior,
        "correlation": corr,
        "at_bound": at_bound,
        "not_constrained": not_constrained,
        "lineage": {
            "head": head,
            "entries": entries.len(),
            "recording_digest": recording_digest,
            "model_digest": model_digest,
            "key_id": lineage_key_id,
            "tag": tag,
        },
        "notice": "MODELLED. The calibrated parameters best explain the telemetry supplied under the model supplied; they are not validated.",
    });
    if let Some(s) = &req.subject {
        v["subject"] = json!(s);
    }
    if let Some(s) = surface {
        v["surface"] = json!({
            "kind": s.degree.name(),
            "runs": s.runs,
            "loo_error_over_sigma_rms": s.loo_rel_rms,
            "note": "parameters are kept inside the design's range; the surface's leave-one-out error is added to each observation's uncertainty",
        });
    }
    Ok(v)
}

/// Run `calibrate` and return a signed verdict (rounded, outcome only).
pub fn calibrate_verdict(
    req: &CalibrateRequest,
    s: &Signing,
    lim: &CalibrateLimits,
    utc: &str,
) -> Result<SignedVerdict, String> {
    let v = calibrate(req, lim, s.lineage_seed, s.lineage_key_id)?;
    crate::methods::finish("calibrate", v, s, utc)
}

#[cfg(test)]
#[path = "calibrate_tests.rs"]
mod tests;
