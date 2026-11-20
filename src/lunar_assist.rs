// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! `lunar-assist`: the generator of long-validity lunar GNSS assistance packages.
//!
//! Lunar receivers mostly cannot decode GNSS navigation data at lunar C/N0, so they need a
//! ground-made ephemeris and clock prediction uploaded to them, valid for a day or more, with
//! an integrity bound (JAXA LNSS asks for "at least 24H as effective age" for more than 60 GPS
//! and Galileo satellites). A caller names the satellites, the validity window, the node
//! spacing, the largest integrity risk it accepts and, optionally, the lunar time definition
//! it maps GNSS time with; the service answers with a signed `ks-lunar-gnss-assist/1` package
//! (the format the Arksa client checks: `arksa-kpro` `lunar_time_assist::assist`).
//!
//! # Method (stays in the service)
//!
//! 1. **Source.** The service holds observed precise GNSS products (SP3, GPST, ECEF; for
//!    example the observed half of IGS ultra-rapid, or rapid products) in a directory it is
//!    configured with. The prediction uses data up to the latest epoch at or before the start
//!    of validity (the *cutoff*); nothing after it.
//! 2. **Orbit.** Per satellite, the last `fit_hours` of positions are rotated to the GCRS
//!    (CIO chain, UT1 and pole from an EOP file when configured, else UT1 = UTC and no polar
//!    motion, applied identically both ways) and fitted by batch least squares with the open
//!    engine's precise force model (EGM2008 to `geopotential_degree`, Sun and Moon, solar
//!    radiation pressure with an estimated coefficient, relativity); the fitted state is
//!    propagated across the package grid and rotated back to ECEF.
//! 3. **Clock.** A quadratic in time fitted over the last `clock_fit_hours` (one 5-sigma
//!    editing pass), extrapolated.
//! 4. **Integrity bound.** The same pipeline is re-run from earlier cutoffs inside the source
//!    history (`backtests`, spaced `backtest_spacing_hours`), and its predictions are compared
//!    with the data that followed: the conservative range error `|dr| + c|dt|` against the
//!    age of the prediction. Per constellation and per age bin, a zero-mean Gaussian
//!    **CDF overbound** is taken at 95 % confidence (each order statistic's exceedance
//!    probability replaced by its one-sided Clopper–Pearson upper bound), the bins are
//!    enveloped by `sigma(age) = s0 + g1·age + g2·age²` with non-negative coefficients, a
//!    satellite whose own errors exceed the pooled bound inflates its own copy, and the
//!    polynomial is shifted to the package's age origin (the start of validity).
//!
//! # What the verdict says about the bound
//!
//! How many backtests and samples it rests on, the largest age it was tested to and whether
//! the package asks for more (then the bound is extrapolated), and the smallest integrity risk
//! the samples can speak to (`lowest_risk_supported`: the 95 % upper bound on an exceedance
//! probability after zero exceedances in the samples). A requested risk below that rests on
//! the Gaussian tail assumption, and the verdict says so (`risk_within_sample_support`).
//!
//! Evidence class: **MODELLED**. Checked on synthetic constellations (tests); not yet scored
//! against later precise products over a long campaign. The package format is a proposal,
//! not a standard. Civil GNSS orbit and clock prediction only.

use crate::lunar_registry::{Registries, RegistryRef};
use crate::methods::Signing;
use crate::outputs::round_sig;
use crate::verdict::{sign, SignedVerdict};
use kshana_pro::kshana::cio::gcrs_to_itrs_matrix;
use kshana_pro::kshana::eop::{EopRecord, EopSeries};
use kshana_pro::kshana::integrator::Tolerance;
use kshana_pro::kshana::precession::{mat_vec, transpose};
use kshana_pro::kshana::precise_od::{
    fit, propagate_samples, EstimatedParams, FitConfig, ForceModel, Observation, PreciseForceModel,
};
use kshana_pro::kshana::rinex::EpochUtc;
use kshana_pro::kshana::sp3::parse_sp3;
use kshana_pro::kshana::timescales::tai_minus_utc;
use kshana_pro::license::signer::sign_checked;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// The format identifier (as the client's `assist::FORMAT`).
pub const FORMAT: &str = "ks-lunar-gnss-assist/1";
/// The interpolation rule a package declares (as the client's `assist::INTERPOLATION`).
pub const INTERPOLATION: &str =
    "positions: 11-point Lagrange over ECEF nodes with per-node Earth-rotation correction (IGS/RTKLIB practice); clocks: linear between nodes";
/// The error metric the bound applies to (as the client's `assist::BOUND_METRIC`).
pub const BOUND_METRIC: &str =
    "conservative range error |dr| + c|dt| (an upper bound on the range error along any line of sight)";
/// Speed of light (m/s).
pub const C_M_S: f64 = 299_792_458.0;
/// Nodes added on each side of the validity window so 11-point interpolation is centred
/// everywhere inside it.
pub const PAD_NODES: u32 = 5;
/// Confidence of the overbound's per-sample exceedance bounds.
pub const CONFIDENCE: f64 = 0.95;
/// GPST = TAI − 19 s; TT = TAI + 32.184 s.
const TT_MINUS_GPST_S: f64 = 51.184;
/// Julian date of 1970-01-01T00:00:00 (the origin of the service's GPST seconds).
const JD_1970: f64 = 2_440_587.5;

// ── Request and package types (field order as the client's; the package signature is over
//    the client's canonical bytes) ─────────────────────────────────────────────────────────

/// A request for a package (as the client's `service::AssistRequest`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistRequest {
    /// Satellites (`G01`, `E11`, ...).
    pub satellites: Vec<String>,
    /// Start of validity (ISO, GPST).
    pub validity_start: String,
    pub validity_hours: f64,
    /// Node spacing wanted (s).
    pub step_s: u32,
    /// Largest acceptable integrity risk per independent sample.
    pub integrity_risk: f64,
    /// The lunar time definition the package should reference, if any.
    #[serde(default)]
    pub lunar_time: Option<LunarTimeWanted>,
}

/// The registry definition a request names.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LunarTimeWanted {
    pub registry_id: String,
    pub registry_version: u32,
    pub definition_id: String,
}

/// A per-satellite integrity bound: `sigma(age) = sigma0_m + growth_m_per_h·age +
/// growth2_m_per_h2·age²` (age in hours since the start of validity) overbounds the error
/// metric, with the stated integrity risk per independent sample.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IntegrityBound {
    pub sigma0_m: f64,
    pub growth_m_per_h: f64,
    #[serde(default)]
    pub growth2_m_per_h2: f64,
    pub integrity_risk: f64,
}

impl IntegrityBound {
    /// `sigma(age)` (m), age in hours (clamped at 0).
    pub fn sigma_m(&self, age_h: f64) -> f64 {
        let a = age_h.max(0.0);
        self.sigma0_m + self.growth_m_per_h * a + self.growth2_m_per_h2 * a * a
    }
}

/// One satellite's product.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SatProduct {
    pub sat: String,
    /// ECEF positions on the package grid (mm).
    pub pos_mm: Vec<[i64; 3]>,
    /// Clock offsets on the package grid (ps).
    pub clock_ps: Vec<i64>,
    pub bound: IntegrityBound,
}

/// The lunar time-scale reference a package carries.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LunarTimeRef {
    pub registry: RegistryRef,
    /// `lunar − GPST` at the start of validity (ps).
    pub lunar_minus_gpst_at_start_ps: i64,
    /// Its combined standard uncertainty (ps).
    pub u_c_ps: i64,
    /// Secular rate `d(lunar)/d(TT) − 1`, in units of 1e-18.
    pub rate_e18: i64,
    pub notice: String,
}

/// The package's own signature.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PackageSignature {
    pub signer: String,
    pub public_key_hex: String,
    pub sha256: String,
    pub signature_hex: String,
}

/// A lunar GNSS assistance package (`ks-lunar-gnss-assist/1`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssistPackage {
    pub format: String,
    pub package_id: String,
    pub producer: String,
    pub prediction_basis: String,
    pub evidence_class: String,
    pub issued: String,
    pub time_system: String,
    pub frame: String,
    pub interpolation: String,
    pub bound_metric: String,
    pub start: String,
    pub step_s: u32,
    pub n_epochs: u32,
    pub validity_start_s: i64,
    pub validity_end_s: i64,
    #[serde(default)]
    pub lunar_time: Option<LunarTimeRef>,
    pub satellites: Vec<SatProduct>,
    #[serde(default)]
    pub signature: Option<PackageSignature>,
}

impl AssistPackage {
    /// The bytes the package signature covers: the package without its signature.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut c = self.clone();
        c.signature = None;
        serde_json::to_vec(&c).unwrap_or_default()
    }

    /// Verify the package signature against `public_key_hex`. Returns the problems.
    pub fn verify_signature(&self, public_key_hex: &str) -> Vec<String> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let Some(s) = &self.signature else {
            return vec!["the package is not signed".into()];
        };
        let bytes = self.canonical_bytes();
        let mut p = vec![];
        if hex::encode(Sha256::digest(&bytes)) != s.sha256 {
            p.push("package hash does not match its signature block".into());
        }
        if !s.public_key_hex.eq_ignore_ascii_case(public_key_hex) {
            p.push("package signed by another key".into());
        }
        let ok = hex::decode(&s.public_key_hex)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| VerifyingKey::from_bytes(&b).ok())
            .zip(
                hex::decode(&s.signature_hex)
                    .ok()
                    .and_then(|b| <[u8; 64]>::try_from(b).ok()),
            )
            .map(|(k, sg)| k.verify(&bytes, &Signature::from_bytes(&sg)).is_ok())
            .unwrap_or(false);
        if !ok {
            p.push("package signature does not verify".into());
        }
        p
    }
}

// ── Configuration and limits ────────────────────────────────────────────────

/// Request limits, checked before any work.
#[derive(Clone, Debug)]
pub struct AssistLimits {
    pub max_satellites: usize,
    pub max_validity_hours: f64,
    pub min_step_s: u32,
    pub max_step_s: u32,
    /// Most nodes (satellites × epochs) a package may carry.
    pub max_nodes: usize,
    /// Largest gap between the end of the source data and the start of validity (h).
    pub max_gap_hours: f64,
}

impl Default for AssistLimits {
    fn default() -> Self {
        AssistLimits {
            max_satellites: 128,
            max_validity_hours: 72.0,
            min_step_s: 30,
            max_step_s: 900,
            max_nodes: 400_000,
            max_gap_hours: 24.0,
        }
    }
}

/// The service's assistance configuration: where the source products are, and the method
/// settings.
#[derive(Clone, Debug)]
pub struct AssistConfig {
    /// Directory of observed SP3 products (GPST). `None`: the method is not offered.
    pub source_dir: Option<PathBuf>,
    /// Earth orientation (finals2000A). `None`: UT1 = UTC, no polar motion.
    pub eop: Option<EopSeries>,
    /// Lunar time registries that can be referenced.
    pub registries: Registries,
    pub fit_hours: f64,
    pub clock_fit_hours: f64,
    pub backtests: usize,
    pub backtest_spacing_hours: f64,
    pub geopotential_degree: usize,
    /// Most source files read (the newest by name).
    pub max_files: usize,
    /// Most bytes per source file.
    pub max_file_bytes: u64,
    /// Worker threads for the per-satellite fits.
    pub threads: usize,
}

impl Default for AssistConfig {
    fn default() -> Self {
        AssistConfig {
            source_dir: None,
            eop: None,
            registries: Registries::default(),
            fit_hours: 24.0,
            clock_fit_hours: 12.0,
            backtests: 4,
            backtest_spacing_hours: 6.0,
            geopotential_degree: 8,
            max_files: 16,
            max_file_bytes: 64 << 20,
            threads: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2)
                .min(8),
        }
    }
}

// ── Time helpers (GPST seconds since 1970-01-01, calendar arithmetic, no leap seconds) ──

fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y } as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Seconds since 1970-01-01T00:00:00 of a calendar epoch (read in its own scale).
pub fn epoch_s(e: &EpochUtc) -> f64 {
    days_from_civil(e.year, e.month, e.day) as f64 * 86_400.0
        + e.hour as f64 * 3600.0
        + e.minute as f64 * 60.0
        + e.second
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.f][Z]` into seconds since 1970 (read in its own scale).
pub fn parse_iso_s(s: &str) -> Result<f64, String> {
    let bad = || format!("bad epoch '{s}' (YYYY-MM-DDTHH:MM:SS)");
    let t = s.trim().trim_end_matches('Z');
    let (d, tm) = t.split_once(['T', ' ']).ok_or_else(bad)?;
    let dp: Vec<&str> = d.split('-').collect();
    let tp: Vec<&str> = tm.split(':').collect();
    if dp.len() != 3 || tp.len() != 3 {
        return Err(bad());
    }
    let e = EpochUtc {
        year: dp[0].parse().map_err(|_| bad())?,
        month: dp[1].parse().map_err(|_| bad())?,
        day: dp[2].parse().map_err(|_| bad())?,
        hour: tp[0].parse().map_err(|_| bad())?,
        minute: tp[1].parse().map_err(|_| bad())?,
        second: tp[2].parse().map_err(|_| bad())?,
    };
    if !(1..=12).contains(&e.month)
        || !(1..=31).contains(&e.day)
        || e.hour > 23
        || e.minute > 59
        || !(0.0..60.0).contains(&e.second)
    {
        return Err(bad());
    }
    Ok(epoch_s(&e))
}

/// `YYYY-MM-DDTHH:MM:SS` of whole seconds since 1970.
pub fn format_s(s: i64) -> String {
    crate::server::iso(s).trim_end_matches('Z').to_string()
}

fn jd_tt_of_gpst(t: f64) -> f64 {
    JD_1970 + (t + TT_MINUS_GPST_S) / 86_400.0
}

/// GPST − UTC (s) at the UTC Julian date `jd_utc` (from the leap-second table).
fn gpst_minus_utc(jd_utc: f64) -> f64 {
    tai_minus_utc(jd_utc) - 19.0
}

// ── Statistics ──────────────────────────────────────────────────────────────

/// The standard normal quantile (Acklam's rational approximation).
pub fn norm_inv(p: f64) -> f64 {
    const A: [f64; 6] = [
        -3.969_683_028_665_376e1,
        2.209_460_984_245_205e2,
        -2.759_285_104_469_687e2,
        1.383_577_518_672_69e2,
        -3.066_479_806_614_716e1,
        2.506_628_277_459_239,
    ];
    const B: [f64; 5] = [
        -5.447_609_879_822_406e1,
        1.615_858_368_580_409e2,
        -1.556_989_798_598_866e2,
        6.680_131_188_771_972e1,
        -1.328_068_155_288_572e1,
    ];
    const C: [f64; 6] = [
        -7.784_894_002_430_293e-3,
        -3.223_964_580_411_365e-1,
        -2.400_758_277_161_838,
        -2.549_732_539_343_734,
        4.374_664_141_464_968,
        2.938_163_982_698_783,
    ];
    const D: [f64; 4] = [
        7.784_695_709_041_462e-3,
        3.224_671_290_700_398e-1,
        2.445_134_137_142_996,
        3.754_408_661_907_416,
    ];
    let p = p.clamp(1e-300, 1.0 - 1e-16);
    let pl = 0.024_25;
    if p < pl {
        let q = (-2.0 * p.ln()).sqrt();
        (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    } else if p <= 1.0 - pl {
        let q = p - 0.5;
        let r = q * q;
        (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
            / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
    } else {
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        -(((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    }
}

fn ln_gamma(x: f64) -> f64 {
    const G: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        let pi = std::f64::consts::PI;
        return (pi / (pi * x).sin()).ln() - ln_gamma(1.0 - x);
    }
    let x = x - 1.0;
    let mut a = G[0];
    let t = x + 7.5;
    for (i, g) in G.iter().enumerate().skip(1) {
        a += g / (x + i as f64);
    }
    0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
}

fn betacf(a: f64, b: f64, x: f64) -> f64 {
    let (qab, qap, qam) = (a + b, a + 1.0, a - 1.0);
    let tiny = 1e-300;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < tiny {
        d = tiny;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=10_000 {
        let m = m as f64;
        let m2 = 2.0 * m;
        for aa in [
            m * (b - m) * x / ((qam + m2) * (a + m2)),
            -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2)),
        ] {
            d = 1.0 + aa * d;
            if d.abs() < tiny {
                d = tiny;
            }
            c = 1.0 + aa / c;
            if c.abs() < tiny {
                c = tiny;
            }
            d = 1.0 / d;
            h *= d * c;
        }
        if (d * c - 1.0).abs() < 1e-15 {
            break;
        }
    }
    h
}

/// Regularised incomplete beta `I_x(a, b)`.
fn betai(a: f64, b: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let bt = (ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b) + a * x.ln() + b * (1.0 - x).ln()).exp();
    if x < (a + 1.0) / (a + b + 2.0) {
        bt * betacf(a, b, x) / a
    } else {
        1.0 - bt * betacf(b, a, 1.0 - x) / b
    }
}

/// `P(X ≤ k)` for `X ~ Binomial(n, p)`.
fn binom_cdf(k: u64, n: u64, p: f64) -> f64 {
    if k >= n {
        return 1.0;
    }
    betai((n - k) as f64, k as f64 + 1.0, 1.0 - p)
}

/// One-sided Clopper–Pearson upper bound at confidence `conf` for `k` events in `n` trials.
pub fn cp_upper(k: u64, n: u64, conf: f64) -> f64 {
    if n == 0 || k >= n {
        return 1.0;
    }
    let alpha = 1.0 - conf;
    let (mut lo, mut hi) = (0.0_f64, 1.0_f64);
    for _ in 0..200 {
        let mid = 0.5 * (lo + hi);
        if binom_cdf(k, n, mid) > alpha {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    0.5 * (lo + hi)
}

/// The smallest two-sided zero-mean Gaussian sigma whose exceedance probability at every
/// sample magnitude is at least that sample's 95 % Clopper–Pearson upper exceedance bound
/// (a CDF overbound of the empirical distribution's tails, exceedance up to 0.32, with
/// confidence). `None` for no samples.
pub fn overbound_sigma(errors: &[f64]) -> Option<f64> {
    let mut e: Vec<f64> = errors
        .iter()
        .map(|x| x.abs())
        .filter(|x| x.is_finite())
        .collect();
    if e.is_empty() {
        return None;
    }
    e.sort_by(|a, b| b.total_cmp(a));
    let n = e.len() as u64;
    let mut s: f64 = 0.0;
    for (i, x) in e.iter().enumerate() {
        // i + 1 samples are at least x.
        let p = cp_upper(i as u64, n, CONFIDENCE);
        // The tails (exceedance up to about one sigma) decide integrity; in the core a tiny
        // quantile divides a confidence margin and would inflate sigma for no safety gain.
        if p > 0.32 {
            break;
        }
        s = s.max(x / norm_inv(1.0 - p / 2.0));
    }
    // The bulk (when every bound saturates) at least covers the largest sample at 1 sigma.
    Some(s.max(e[0] / 3.0).max(1e-3))
}

/// The polynomial `s0 + g1·a + g2·a²` (non-negative coefficients) that lies on or above every
/// `(age, sigma)` point with the least area over `[0, a_max]`: each subset of the three terms
/// is fitted by least squares, scaled up to cover every point, and the smallest area wins.
pub fn envelope(points: &[(f64, f64)], a_max: f64) -> [f64; 3] {
    let mut best: Option<([f64; 3], f64)> = None;
    for mask in 1u8..8 {
        let cols: Vec<usize> = (0..3).filter(|k| mask & (1 << k) != 0).collect();
        // Normal equations on the chosen basis {1, a, a²}.
        let n = cols.len();
        let mut ata = vec![vec![0.0; n]; n];
        let mut atb = vec![0.0; n];
        for &(a, s) in points {
            let row: Vec<f64> = cols.iter().map(|&k| a.powi(k as i32)).collect();
            for p in 0..n {
                atb[p] += row[p] * s;
                for q in 0..n {
                    ata[p][q] += row[p] * row[q];
                }
            }
        }
        let Some(x) = solve_small(ata, atb) else {
            continue;
        };
        if x.iter().any(|v| !(v.is_finite() && *v >= 0.0)) {
            continue;
        }
        let mut c = [0.0; 3];
        for (i, &k) in cols.iter().enumerate() {
            c[k] = x[i];
        }
        let f = |a: f64| c[0] + c[1] * a + c[2] * a * a;
        let scale = points
            .iter()
            .map(|&(a, s)| if f(a) > 0.0 { s / f(a) } else { f64::INFINITY })
            .fold(1.0_f64, f64::max);
        if !scale.is_finite() {
            continue;
        }
        let c = [c[0] * scale, c[1] * scale, c[2] * scale];
        let area = c[0] * a_max + c[1] * a_max * a_max / 2.0 + c[2] * a_max.powi(3) / 3.0;
        if c[0] > 0.0 && best.as_ref().is_none_or(|(_, b)| area < *b) {
            best = Some((c, area));
        }
    }
    best.map(|(c, _)| c).unwrap_or_else(|| {
        // Fallback: a constant at the largest sigma.
        [points.iter().map(|p| p.1).fold(1e-3, f64::max), 0.0, 0.0]
    })
}

/// Gaussian elimination with partial pivoting.
fn solve_small(mut a: Vec<Vec<f64>>, mut b: Vec<f64>) -> Option<Vec<f64>> {
    let n = b.len();
    for i in 0..n {
        let p = (i..n).max_by(|&x, &y| a[x][i].abs().total_cmp(&a[y][i].abs()))?;
        if a[p][i].abs() < 1e-300 {
            return None;
        }
        a.swap(i, p);
        b.swap(i, p);
        for r in i + 1..n {
            let f = a[r][i] / a[i][i];
            let pivot = a[i].clone();
            for (x, y) in a[r][i..].iter_mut().zip(&pivot[i..]) {
                *x -= f * y;
            }
            b[r] -= f * b[i];
        }
    }
    let mut x = vec![0.0; n];
    for i in (0..n).rev() {
        let s: f64 = (i + 1..n).map(|c| a[i][c] * x[c]).sum();
        x[i] = (b[i] - s) / a[i][i];
    }
    Some(x)
}

/// Round `x` up to `sig` significant figures (a bound is never rounded down).
pub fn ceil_sig(x: f64, sig: u32) -> f64 {
    if x <= 0.0 || !x.is_finite() {
        return x;
    }
    let mag = x.log10().floor() as i32;
    let f = 10f64.powi(sig as i32 - 1 - mag);
    let mut r = round_sig((x * f).ceil() / f, sig);
    if r < x {
        r = round_sig(r + 1.0 / f, sig);
    }
    r
}

/// Round `x` down to `sig` significant figures.
pub fn floor_sig(x: f64, sig: u32) -> f64 {
    if x <= 0.0 || !x.is_finite() {
        return x;
    }
    let mag = x.log10().floor() as i32;
    let f = 10f64.powi(sig as i32 - 1 - mag);
    let mut r = round_sig((x * f).floor() / f, sig);
    if r > x {
        r = round_sig(r - 1.0 / f, sig);
    }
    r
}

// ── Source products ─────────────────────────────────────────────────────────

/// One satellite's observed history: `(t, ECEF m)` and `(t, clock s)`, GPST seconds since
/// 1970, ascending, one value per epoch (a later file wins).
#[derive(Clone, Debug, Default)]
pub struct SatSeries {
    pub pos: Vec<(f64, [f64; 3])>,
    pub clk: Vec<(f64, f64)>,
}

/// The merged source products.
#[derive(Clone, Debug, Default)]
pub struct AssistSource {
    /// `(file name, SHA-256)` of every product read.
    pub products: Vec<(String, String)>,
    pub sats: BTreeMap<String, SatSeries>,
}

impl AssistSource {
    /// Merge SP3 texts (`(name, text)`, in order; later entries win on a shared epoch).
    pub fn from_texts(texts: &[(String, String)]) -> Result<Self, String> {
        let mut pos: BTreeMap<String, BTreeMap<i64, [f64; 3]>> = BTreeMap::new();
        let mut clk: BTreeMap<String, BTreeMap<i64, f64>> = BTreeMap::new();
        let mut products = vec![];
        for (name, text) in texts {
            let f = parse_sp3(text).map_err(|e| format!("source {name}: {e}"))?;
            products.push((name.clone(), hex::encode(Sha256::digest(text.as_bytes()))));
            for ep in &f.epochs {
                // Millisecond keys: a shared epoch from two files lands on one key.
                let t = epoch_s(&ep.time);
                let key = (t * 1000.0).round() as i64;
                for st in &ep.sats {
                    if st.pos_m != [0.0, 0.0, 0.0] && st.pos_m.iter().all(|v| v.is_finite()) {
                        pos.entry(st.sat.clone()).or_default().insert(key, st.pos_m);
                    }
                    if !st.clock_is_bad() && st.clock_us.is_finite() {
                        clk.entry(st.sat.clone())
                            .or_default()
                            .insert(key, st.clock_us * 1e-6);
                    }
                }
            }
        }
        let mut sats = BTreeMap::new();
        for (s, p) in pos {
            let c = clk.remove(&s).unwrap_or_default();
            sats.insert(
                s,
                SatSeries {
                    pos: p.into_iter().map(|(k, v)| (k as f64 / 1000.0, v)).collect(),
                    clk: c.into_iter().map(|(k, v)| (k as f64 / 1000.0, v)).collect(),
                },
            );
        }
        Ok(AssistSource { products, sats })
    }

    /// Read the newest `max_files` `*.sp3` files (by name) of `dir`.
    pub fn from_dir(
        dir: &std::path::Path,
        max_files: usize,
        max_bytes: u64,
    ) -> Result<Self, String> {
        let mut names: Vec<PathBuf> = std::fs::read_dir(dir)
            .map_err(|e| format!("assistance source {}: {e}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| x.eq_ignore_ascii_case("sp3"))
            })
            .collect();
        names.sort();
        let skip = names.len().saturating_sub(max_files);
        let mut texts = vec![];
        for p in names.into_iter().skip(skip) {
            let len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(u64::MAX);
            if len > max_bytes {
                return Err(format!(
                    "assistance source {}: file above the size cap",
                    p.display()
                ));
            }
            let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            texts.push((name, text));
        }
        if texts.is_empty() {
            return Err("the assistance source holds no SP3 product".into());
        }
        Self::from_texts(&texts)
    }

    /// SHA-256 over the product names and hashes.
    pub fn digest(&self) -> String {
        let mut h = Sha256::new();
        for (n, s) in &self.products {
            h.update(n.as_bytes());
            h.update(b"\0");
            h.update(s.as_bytes());
            h.update(b"\n");
        }
        hex::encode(h.finalize())
    }
}

// ── The prediction pipeline ─────────────────────────────────────────────────

/// Settings of one prediction run.
#[derive(Clone, Debug)]
struct Pipeline {
    eop: EopSeries,
    fit_s: f64,
    clock_fit_s: f64,
    degree: usize,
}

/// A fitted prediction from one cutoff.
struct Prediction {
    fm: PreciseForceModel,
    t0: f64,
    r0: [f64; 3],
    v0: [f64; 3],
    clk: Option<[f64; 3]>,
    cutoff: f64,
}

/// An Earth-orientation series from a `finals2000A` file body.
pub fn eop_from_finals(body: &str) -> EopSeries {
    EopSeries::from_finals2000a(body)
}

fn zero_eop() -> EopSeries {
    EopSeries::new(vec![EopRecord {
        mjd: 51_544.0,
        ut1_utc_s: 0.0,
        xp_arcsec: 0.0,
        yp_arcsec: 0.0,
        lod_ms: 0.0,
    }])
}

impl Pipeline {
    fn model(&self, t0: f64) -> PreciseForceModel {
        PreciseForceModel::egm2008(self.degree, jd_tt_of_gpst(t0))
            .third_body(true, true)
            .solar_radiation(1.0, 0.02)
            .relativity()
            .with_eop(self.eop.clone())
    }

    /// GCRS → ITRS rotation at GPST `t`.
    fn frame(&self, fm: &PreciseForceModel, t: f64) -> [[f64; 3]; 3] {
        let jd = jd_tt_of_gpst(t);
        let (ut1, xp, yp) = fm.frame_args(jd);
        gcrs_to_itrs_matrix(jd, ut1, xp, yp)
    }

    /// Fit the orbit and clock from the data at or before `cutoff`.
    fn fit(&self, s: &SatSeries, cutoff: f64) -> Result<Prediction, String> {
        let lo = cutoff - self.fit_s - 1e-6;
        let arc: Vec<&(f64, [f64; 3])> = s
            .pos
            .iter()
            .filter(|(t, _)| *t >= lo && *t <= cutoff + 1e-6)
            .collect();
        if arc.len() < 12 || arc[arc.len() - 1].0 - arc[0].0 < 0.6 * self.fit_s {
            return Err(format!(
                "too little orbit data in the {:.0} h before the cutoff",
                self.fit_s / 3600.0
            ));
        }
        let t0 = arc[0].0;
        let fm = self.model(t0);
        let obs: Vec<Observation> = arc
            .iter()
            .map(|(t, p)| Observation {
                t: t - t0,
                pos: mat_vec(&transpose(&self.frame(&fm, *t)), *p),
                sigma: 0.05,
            })
            .collect();
        // Initial velocity: derivative at the first node of the polynomial through the first
        // five nodes (Lagrange).
        let k = obs.len().min(5);
        let ts: Vec<f64> = obs[..k].iter().map(|o| o.t).collect();
        let mut v0 = [0.0; 3];
        for (j, o) in obs[..k].iter().enumerate() {
            let w = lagrange_deriv_weight(&ts, j, ts[0]);
            for (v, p) in v0.iter_mut().zip(o.pos) {
                *v += w * p;
            }
        }
        let cfg = FitConfig {
            estimate_cr: true,
            max_iter: 25,
            outlier_sigma: 5.0,
            tol: Tolerance {
                rtol: 1e-11,
                atol: 1e-6,
                ..Tolerance::default()
            },
            ..FitConfig::default()
        };
        let rep = fit(
            &fm,
            EstimatedParams {
                r0: obs[0].pos,
                v0,
                cr: Some(1.0),
                empirical: None,
            },
            &obs,
            &cfg,
        )
        .ok_or("the orbit fit failed (singular or too few observations)")?;
        if !(rep.rms_3d.is_finite() && rep.rms_3d < 50.0) {
            return Err(format!(
                "the orbit fit does not represent the data (post-fit RMS {:.1} m)",
                rep.rms_3d
            ));
        }
        let mut fmf = fm.clone();
        fmf.set_cr(rep.params.cr.unwrap_or(1.0));
        let clk = fit_clock(&s.clk, cutoff, self.clock_fit_s);
        Ok(Prediction {
            fm: fmf,
            t0,
            r0: rep.params.r0,
            v0: rep.params.v0,
            clk,
            cutoff,
        })
    }

    /// Predicted ECEF positions (m) and clocks (s) at ascending GPST `times` (all ≥ the fit
    /// arc start).
    fn predict(&self, p: &Prediction, times: &[f64]) -> Vec<([f64; 3], Option<f64>)> {
        let rel: Vec<f64> = times.iter().map(|t| t - p.t0).collect();
        let tol = Tolerance {
            rtol: 1e-11,
            atol: 1e-6,
            ..Tolerance::default()
        };
        let gcrs = propagate_samples(&p.fm, p.r0, p.v0, &rel, &tol);
        times
            .iter()
            .zip(gcrs)
            .map(|(t, r)| {
                let ecef = mat_vec(&self.frame(&p.fm, *t), r);
                let c = p.clk.map(|c| {
                    let h = (t - p.cutoff) / 3600.0;
                    c[0] + c[1] * h + c[2] * h * h
                });
                (ecef, c)
            })
            .collect()
    }
}

/// Weight of node `j` in the derivative at `x` of the Lagrange polynomial through `ts`.
fn lagrange_deriv_weight(ts: &[f64], j: usize, x: f64) -> f64 {
    let mut sum = 0.0;
    for m in 0..ts.len() {
        if m == j {
            continue;
        }
        let mut prod = 1.0 / (ts[j] - ts[m]);
        for (l, tl) in ts.iter().enumerate() {
            if l != j && l != m {
                prod *= (x - tl) / (ts[j] - tl);
            }
        }
        sum += prod;
    }
    sum
}

/// Quadratic clock fit over `[cutoff − span, cutoff]` (time in hours from the cutoff), with
/// one 5-sigma editing pass. `None` with fewer than 6 samples.
fn fit_clock(clk: &[(f64, f64)], cutoff: f64, span: f64) -> Option<[f64; 3]> {
    let pts: Vec<(f64, f64)> = clk
        .iter()
        .filter(|(t, _)| *t >= cutoff - span - 1e-6 && *t <= cutoff + 1e-6)
        .map(|(t, c)| ((t - cutoff) / 3600.0, *c))
        .collect();
    let solve = |pts: &[(f64, f64)]| -> Option<[f64; 3]> {
        if pts.len() < 6 {
            return None;
        }
        let mut ata = vec![vec![0.0; 3]; 3];
        let mut atb = vec![0.0; 3];
        for &(h, c) in pts {
            let row = [1.0, h, h * h];
            for p in 0..3 {
                atb[p] += row[p] * c;
                for q in 0..3 {
                    ata[p][q] += row[p] * row[q];
                }
            }
        }
        let x = solve_small(ata, atb)?;
        Some([x[0], x[1], x[2]])
    };
    let c = solve(&pts)?;
    let res: Vec<f64> = pts
        .iter()
        .map(|&(h, v)| v - (c[0] + c[1] * h + c[2] * h * h))
        .collect();
    let rms = (res.iter().map(|r| r * r).sum::<f64>() / res.len() as f64).sqrt();
    let kept: Vec<(f64, f64)> = pts
        .iter()
        .zip(&res)
        .filter(|(_, r)| r.abs() <= 5.0 * rms.max(1e-15))
        .map(|(p, _)| *p)
        .collect();
    if kept.len() < pts.len() {
        solve(&kept)
    } else {
        Some(c)
    }
}

/// One satellite's results: the package nodes, and its backtest samples `(age h, metric m)`.
struct SatResult {
    sat: String,
    nodes: Vec<([f64; 3], f64)>,
    samples: Vec<(f64, f64)>,
}

#[allow(clippy::too_many_arguments)]
fn run_sat(
    pl: &Pipeline,
    sat: &str,
    s: &SatSeries,
    cutoff: f64,
    grid: &[f64],
    backtests: usize,
    spacing_s: f64,
    max_age_s: f64,
) -> Result<SatResult, String> {
    let p = pl.fit(s, cutoff).map_err(|e| format!("{sat}: {e}"))?;
    let mut nodes = vec![];
    for (pos, c) in pl.predict(&p, grid) {
        let c = c.ok_or_else(|| format!("{sat}: too few clock samples before the cutoff"))?;
        nodes.push((pos, c));
    }
    let mut samples = vec![];
    let clk_at = |t: f64| {
        s.clk
            .binary_search_by(|(x, _)| x.total_cmp(&t))
            .ok()
            .map(|i| s.clk[i].1)
    };
    for k in 1..=backtests {
        let ck = cutoff - k as f64 * spacing_s;
        let Ok(bp) = pl.fit(s, ck) else { continue };
        // Checkpoints: data epochs after the backtest cutoff, at least an hour apart.
        let mut checks = vec![];
        let mut last = f64::NEG_INFINITY;
        for (t, _) in &s.pos {
            if *t > ck + 1.0 && *t <= cutoff + 1e-6 && *t - ck <= max_age_s && *t - last >= 3599.0 {
                checks.push(*t);
                last = *t;
            }
        }
        if checks.is_empty() {
            continue;
        }
        let pred = pl.predict(&bp, &checks);
        for (t, (pp, pc)) in checks.iter().zip(pred) {
            let Ok(i) = s.pos.binary_search_by(|(x, _)| x.total_cmp(t)) else {
                continue;
            };
            let truth = s.pos[i].1;
            let (Some(pc), Some(tc)) = (pc, clk_at(*t)) else {
                continue;
            };
            let dr = ((pp[0] - truth[0]).powi(2)
                + (pp[1] - truth[1]).powi(2)
                + (pp[2] - truth[2]).powi(2))
            .sqrt();
            samples.push(((t - ck) / 3600.0, dr + C_M_S * (pc - tc).abs()));
        }
    }
    Ok(SatResult {
        sat: sat.to_string(),
        nodes,
        samples,
    })
}

/// Age bins (h) of width `w` up to `a_max`; returns `(upper edge, overbound sigma, n)`.
fn binned_sigma(samples: &[(f64, f64)], w: f64) -> Vec<(f64, f64, usize)> {
    let mut bins: BTreeMap<i64, Vec<f64>> = BTreeMap::new();
    for &(a, e) in samples {
        bins.entry((a / w).floor().max(0.0) as i64)
            .or_default()
            .push(e);
    }
    // Merge thin bins (< 5 samples) into the next older one.
    let mut out = vec![];
    let mut carry: Vec<f64> = vec![];
    let keys: Vec<i64> = bins.keys().copied().collect();
    for (i, k) in keys.iter().enumerate() {
        carry.extend(bins[k].iter().copied());
        if carry.len() >= 5 || i + 1 == keys.len() {
            if let Some(s) = overbound_sigma(&carry) {
                out.push(((*k + 1) as f64 * w, s, carry.len()));
            }
            carry.clear();
        }
    }
    out
}

// ── The method ─────────────────────────────────────────────────────────────

fn valid_sat_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 3
        && matches!(b[0], b'G' | b'E' | b'R' | b'C' | b'J')
        && b[1].is_ascii_digit()
        && b[2].is_ascii_digit()
}

/// Check a request against the limits, before any work.
pub fn validate(req: &AssistRequest, lim: &AssistLimits) -> Result<(), String> {
    if req.satellites.is_empty() {
        return Err("a request names at least one satellite".into());
    }
    if req.satellites.len() > lim.max_satellites {
        return Err(format!(
            "more than {} satellites in one request",
            lim.max_satellites
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for s in &req.satellites {
        if !valid_sat_id(s) {
            return Err(format!(
                "satellite '{s}' is not a GNSS id (G, E, R, C or J and two digits)"
            ));
        }
        if !seen.insert(s.as_str()) {
            return Err(format!("satellite {s} appears twice"));
        }
    }
    let vs = parse_iso_s(&req.validity_start)?;
    if vs.fract() != 0.0 {
        return Err("validity_start must be a whole second".into());
    }
    if !(req.validity_hours.is_finite() && req.validity_hours > 0.0) {
        return Err("validity_hours must be positive".into());
    }
    if req.validity_hours > lim.max_validity_hours {
        return Err(format!(
            "validity_hours above the limit of {}",
            lim.max_validity_hours
        ));
    }
    if req.step_s < lim.min_step_s || req.step_s > lim.max_step_s {
        return Err(format!(
            "step_s must lie in [{}, {}] s",
            lim.min_step_s, lim.max_step_s
        ));
    }
    if !(req.integrity_risk > 0.0 && req.integrity_risk < 0.5) {
        return Err("integrity_risk must lie in (0, 0.5)".into());
    }
    let n_epochs = grid_epochs(req.validity_hours, req.step_s);
    if n_epochs.saturating_mul(req.satellites.len()) > lim.max_nodes {
        return Err(format!(
            "package too large: more than {} nodes (satellites x epochs); use a coarser step or fewer satellites",
            lim.max_nodes
        ));
    }
    Ok(())
}

fn validity_s(hours: f64) -> i64 {
    (hours * 3600.0).round() as i64
}

fn grid_epochs(hours: f64, step: u32) -> usize {
    let inner = (validity_s(hours) as u64).div_ceil(step as u64) as usize;
    inner + 1 + 2 * PAD_NODES as usize
}

/// The package and the statement on its bound, before rounding and signing.
pub fn build(
    req: &AssistRequest,
    cfg: &AssistConfig,
    lim: &AssistLimits,
    source: &AssistSource,
    issued_utc: &str,
    sigfigs: u32,
) -> Result<(AssistPackage, serde_json::Value), String> {
    // Bounds are rounded up (and the risk down) to what the service's output rounding keeps,
    // so that rounding leaves the signed package unchanged.
    let sig = sigfigs.clamp(1, 3);
    validate(req, lim)?;
    let vstart = parse_iso_s(&req.validity_start)?;
    // The lunar time reference first (cheap, and an unknown definition is a request error).
    let lunar_time = match &req.lunar_time {
        None => None,
        Some(w) => {
            let reg = cfg.registries.find(&w.registry_id, w.registry_version)?;
            reg.get(&w.definition_id)?;
            let o = reg.gpst_offset(&w.definition_id, &format_s(vstart as i64))?;
            Some(LunarTimeRef {
                registry: reg.reference(&w.definition_id),
                lunar_minus_gpst_at_start_ps: (o.offset_s * 1e12).round() as i64,
                u_c_ps: (o.u_c_s * 1e12).round() as i64,
                rate_e18: (o.rate * 1e18).round() as i64,
                notice: reg.notice.clone(),
            })
        }
    };
    let missing: Vec<&str> = req
        .satellites
        .iter()
        .filter(|s| !source.sats.contains_key(s.as_str()))
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "no source data for {} (the package must carry every satellite asked for)",
            missing.join(", ")
        ));
    }
    // The cutoff: the latest source epoch at or before the start of validity, over the
    // satellites asked for.
    let cutoff = req
        .satellites
        .iter()
        .filter_map(|s| {
            source.sats[s.as_str()]
                .pos
                .iter()
                .rev()
                .find(|(t, _)| *t <= vstart + 1e-6)
                .map(|(t, _)| *t)
        })
        .fold(f64::NEG_INFINITY, f64::max);
    if !cutoff.is_finite() {
        return Err("the source holds no data before the start of validity".into());
    }
    let gap_s = vstart - cutoff;
    if gap_s > lim.max_gap_hours * 3600.0 {
        return Err(format!(
            "the source data end {:.1} h before the start of validity (limit {} h); the products are too old",
            gap_s / 3600.0,
            lim.max_gap_hours
        ));
    }
    let step = req.step_s as i64;
    let n_epochs = grid_epochs(req.validity_hours, req.step_s);
    let start = vstart as i64 - PAD_NODES as i64 * step;
    let grid: Vec<f64> = (0..n_epochs)
        .map(|i| (start + i as i64 * step) as f64)
        .collect();
    let max_age_s = gap_s + validity_s(req.validity_hours) as f64 + PAD_NODES as f64 * step as f64;
    let pl = Pipeline {
        eop: cfg.eop.clone().unwrap_or_else(zero_eop),
        fit_s: cfg.fit_hours * 3600.0,
        clock_fit_s: cfg.clock_fit_hours * 3600.0,
        degree: cfg.geopotential_degree,
    };
    if pl.fit_s < 2.0 * PAD_NODES as f64 * lim.max_step_s as f64 / 3600.0 {
        // The grid's first node must lie after the fit arc's start.
        return Err("service misconfigured: fit_hours too short".into());
    }
    // Per-satellite work, in parallel.
    let sats = req.satellites.clone();
    let threads = cfg.threads.max(1).min(sats.len());
    let results: Vec<Result<SatResult, String>> = std::thread::scope(|sc| {
        let chunks: Vec<Vec<String>> = (0..threads)
            .map(|k| sats.iter().skip(k).step_by(threads).cloned().collect())
            .collect();
        let handles: Vec<_> = chunks
            .into_iter()
            .map(|chunk| {
                let pl = &pl;
                let grid = &grid;
                sc.spawn(move || {
                    chunk
                        .iter()
                        .map(|sat| {
                            run_sat(
                                pl,
                                sat,
                                &source.sats[sat.as_str()],
                                cutoff,
                                grid,
                                cfg.backtests,
                                cfg.backtest_spacing_hours * 3600.0,
                                max_age_s,
                            )
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| {
                h.join()
                    .unwrap_or_else(|_| vec![Err("worker panicked".into())])
            })
            .collect()
    });
    let mut done: BTreeMap<String, SatResult> = BTreeMap::new();
    let mut failed = vec![];
    for r in results {
        match r {
            Ok(s) => {
                done.insert(s.sat.clone(), s);
            }
            Err(e) => failed.push(e),
        }
    }
    if !failed.is_empty() {
        failed.sort();
        return Err(format!(
            "cannot predict every satellite asked for: {}",
            failed.join("; ")
        ));
    }
    // The bound, per constellation.
    let a_max = max_age_s / 3600.0;
    let bin_w = (a_max / 8.0).clamp(1.0, 6.0);
    let mut pooled: BTreeMap<char, Vec<(f64, f64)>> = BTreeMap::new();
    for s in done.values() {
        let c = s.sat.chars().next().unwrap_or('?');
        pooled
            .entry(c)
            .or_default()
            .extend(s.samples.iter().copied());
    }
    let mut poly: BTreeMap<char, [f64; 3]> = BTreeMap::new();
    let mut tested_to_h: f64 = 0.0;
    let mut n_samples = 0usize;
    for (c, samples) in &pooled {
        let bins = binned_sigma(samples, bin_w);
        if bins.len() < 2 {
            return Err(format!(
                "the source holds too little history to derive an integrity bound for constellation {c}: \
                 it needs about {:.0} h of data before the start of validity",
                cfg.fit_hours + cfg.backtests as f64 * cfg.backtest_spacing_hours
            ));
        }
        tested_to_h = tested_to_h.max(samples.iter().map(|s| s.0).fold(0.0, f64::max));
        n_samples += samples.len();
        let pts: Vec<(f64, f64)> = bins.iter().map(|b| (b.0, b.1)).collect();
        poly.insert(*c, envelope(&pts, a_max));
    }
    let gap_h = gap_s / 3600.0;
    let risk = floor_sig(req.integrity_risk, sig);
    let mut satellites = vec![];
    for sat in &req.satellites {
        let r = &done[sat.as_str()];
        let c = sat.chars().next().unwrap_or('?');
        let p = poly[&c];
        let f = |a: f64| p[0] + p[1] * a + p[2] * a * a;
        // Inflate for a satellite whose own errors exceed the pooled bound.
        let n_own = r.samples.len() as u64;
        let k_own = norm_inv(1.0 - cp_upper(0, n_own.max(1), CONFIDENCE) / 2.0).max(1.0);
        let infl = r
            .samples
            .iter()
            .map(|&(a, e)| e / (k_own * f(a)))
            .fold(1.0_f64, f64::max);
        // Shift the age origin from the cutoff to the start of validity.
        let (s0, g1, g2) = (p[0] * infl, p[1] * infl, p[2] * infl);
        let bound = IntegrityBound {
            sigma0_m: ceil_sig((s0 + g1 * gap_h + g2 * gap_h * gap_h).max(0.01), sig),
            growth_m_per_h: ceil_sig(g1 + 2.0 * g2 * gap_h, sig),
            growth2_m_per_h2: ceil_sig(g2, sig),
            integrity_risk: risk,
        };
        satellites.push(SatProduct {
            sat: sat.clone(),
            pos_mm: r
                .nodes
                .iter()
                .map(|(p, _)| {
                    [
                        (p[0] * 1e3).round() as i64,
                        (p[1] * 1e3).round() as i64,
                        (p[2] * 1e3).round() as i64,
                    ]
                })
                .collect(),
            clock_ps: r
                .nodes
                .iter()
                .map(|(_, c)| (c * 1e12).round() as i64)
                .collect(),
            bound,
        });
    }
    let lowest = cp_upper(0, n_samples as u64, CONFIDENCE);
    let extrapolated = a_max > tested_to_h + 1e-9;
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(req).unwrap_or_default());
    h.update(source.digest().as_bytes());
    h.update(issued_utc.as_bytes());
    let package_id = format!("ks-la-{}", &hex::encode(h.finalize())[..16]);
    let issued = match parse_iso_s(issued_utc) {
        Ok(u) => format_s((u + gpst_minus_utc(JD_1970 + u / 86_400.0)).round() as i64),
        Err(_) => issued_utc.to_string(),
    };
    let basis = format!(
        "Orbit and clock prediction from observed precise products (data to {} GPST, {:.1} h before validity start); \
         integrity bound from backtested prediction error ({} samples, tested to {:.0} h of age{}). MODELLED.",
        format_s(cutoff.round() as i64),
        gap_h,
        n_samples,
        tested_to_h,
        if extrapolated { "; beyond that the bound is extrapolated" } else { "" }
    );
    let pkg = AssistPackage {
        format: FORMAT.into(),
        package_id,
        producer: "Kshana hosted verdict service".into(),
        prediction_basis: basis,
        evidence_class: "MODELLED".into(),
        issued,
        time_system: "GPST".into(),
        frame: "as the source products (IGS realisation, ECEF)".into(),
        interpolation: INTERPOLATION.into(),
        bound_metric: BOUND_METRIC.into(),
        start: format_s(start),
        step_s: req.step_s,
        n_epochs: n_epochs as u32,
        validity_start_s: PAD_NODES as i64 * step,
        validity_end_s: PAD_NODES as i64 * step + validity_s(req.validity_hours),
        lunar_time,
        satellites,
        signature: None,
    };
    let statement = json!({
        "source": {
            "products": source.products.len(),
            "digest": source.digest(),
            "data_end_gpst": format_s(cutoff.round() as i64),
            "age_at_validity_start_h": gap_h,
        },
        "integrity": {
            "basis": "zero-mean Gaussian CDF overbound of backtested prediction errors (|dr| + c|dt|), 95 % Clopper-Pearson per order statistic, enveloped over age",
            "samples": n_samples,
            "tested_to_age_h": tested_to_h,
            "max_age_h": a_max,
            "extrapolated": extrapolated,
            "lowest_risk_supported": lowest,
            "requested_risk": risk,
            "risk_within_sample_support": risk >= lowest,
            "note": "Below lowest_risk_supported the bound rests on the Gaussian tail assumption, not on the samples. Samples are treated as independent; errors shared across satellites make the statement optimistic.",
        },
        "notice": "MODELLED. Format ks-lunar-gnss-assist/1 is a proposal, not a standard. The lunar time reference, when present, points to a PROVISIONAL registry: no international lunar time definition is adopted.",
    });
    Ok((pkg, statement))
}

/// Run `lunar-assist` and return a signed verdict: the signed package under `"package"` and
/// the statement on its bound. The fits, backtest errors, bins and polynomial internals stay
/// in the service.
pub fn lunar_assist_verdict(
    req: &AssistRequest,
    s: &Signing,
    lim: &AssistLimits,
    cfg: &AssistConfig,
    utc: &str,
) -> Result<SignedVerdict, String> {
    validate(req, lim)?;
    let dir = cfg
        .source_dir
        .as_ref()
        .ok_or("lunar-assist is not offered by this service (no assistance source configured)")?;
    let source = AssistSource::from_dir(dir, cfg.max_files, cfg.max_file_bytes)?;
    let (mut pkg, mut statement) = build(req, cfg, lim, &source, utc, s.sigfigs)?;
    // The package's own signature, by the verdict key: a package travels on to a receiver
    // without the verdict envelope.
    let pk = s.signer.public_key().map_err(|e| format!("signer: {e}"))?;
    let bytes = pkg.canonical_bytes();
    let back: AssistPackage = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if back.canonical_bytes() != bytes {
        return Err("internal: the package does not survive a JSON round trip".into());
    }
    let sig = sign_checked(s.signer, &bytes).map_err(|e| format!("signing failed: {e}"))?;
    pkg.signature = Some(PackageSignature {
        signer: s.key_id.to_string(),
        public_key_hex: hex::encode(pk),
        sha256: hex::encode(Sha256::digest(&bytes)),
        signature_hex: hex::encode(sig),
    });
    crate::outputs::coarsen(&mut statement, s.sigfigs);
    // The package's numbers are integers or already rounded (bounds up, risk down) to the
    // service's significant figures, so the service's rounding leaves it, and its signature, unchanged.
    let mut verdict = statement;
    verdict["package"] = serde_json::to_value(&pkg).map_err(|e| e.to_string())?;
    let check = verdict.clone();
    crate::outputs::coarsen(&mut verdict, s.sigfigs);
    if verdict != check {
        return Err("internal: rounding would change the signed package".into());
    }
    crate::methods::bind_licence(&mut verdict, s);
    sign("lunar-assist", "MODELLED", verdict, s.signer, s.key_id, utc)
}

#[cfg(test)]
#[path = "lunar_assist_tests.rs"]
mod tests;
