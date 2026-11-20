// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! Red-team extraction harness: play a copier against F2 (the survey planner) and measure
//! what it takes, and whether the defences notice.
//!
//! The copier holds one Pro licence, fixes a realistic survey (area, two stations, budget) and
//! sweeps three inputs with a Sobol sequence: the position of the third station (latitude,
//! longitude) and the noise scale. It sends one query every `interval_s` (default 10 minutes),
//! slow enough that the per-licence rate, daily quota and hourly probe detector never refuse
//! it; it reads the signed, rounded, fingerprinted verdicts and fits a surrogate (Gaussian-
//! kernel ridge regression, length scale and ridge chosen by leave-one-out) for the mean
//! protection level after the survey. The report gives, per query budget, the surrogate's
//! normalised RMS error on held-out inputs against the service's unrounded answer, and the
//! budget at which it falls below the threshold.
//!
//! Then the defences: the per-licence limits (how many of the copier's calls they refuse), the
//! query-pattern audit for one licence (the call at which it first alerts), the same sweep
//! split into three licences (the call at which the cross-licence alert fires, and whom it
//! names), ordinary clustered use by three customers (alerts expected: none), the ownership
//! test on 50 of the copier's verdicts passed on, and the ownership test on the surrogate's own
//! (rounded) predictions.
//!
//! Everything runs in process with throwaway keys. Evidence class MODELLED: one copier
//! strategy against one method family; a better copier (another surrogate, adaptive queries)
//! may need fewer queries.

use crate::audit::{sobol, AuditConfig, Auditor};
use crate::fingerprint::{ownership, Epoch, FpKeys, Mark, Suspect, KEYS_FORMAT};
use crate::limits::{LimitConfig, Limiter};
use crate::methods::{raw_outcome, survey_verdict, Binding, Limits, Signing, SurveyRequest};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Harness settings.
#[derive(Clone, Debug)]
pub struct RedTeamConfig {
    /// Query budgets to score (each a prefix of one Sobol sequence).
    pub budgets: Vec<usize>,
    /// Held-out inputs for scoring the surrogate.
    pub test_points: usize,
    /// Normalised RMS error at which the method counts as extracted.
    pub threshold: f64,
    /// Seconds between the copier's queries.
    pub interval_s: i64,
}

impl Default for RedTeamConfig {
    fn default() -> Self {
        RedTeamConfig {
            budgets: vec![16, 32, 64, 128, 256],
            test_points: 64,
            threshold: 0.05,
            interval_s: 600,
        }
    }
}

/// The surrogate at one budget.
#[derive(Clone, Debug, Serialize)]
pub struct BudgetResult {
    /// The verdict number the surrogate predicts.
    pub target: String,
    pub queries: usize,
    /// RMS error over the spread of the true answers on held-out inputs.
    pub nrmse: f64,
    pub extracted: bool,
}

/// What the defences did.
#[derive(Clone, Debug, Serialize)]
pub struct Detection {
    /// Copier calls refused by the per-licence rate, quota and probe detector.
    pub limiter_refusals: usize,
    /// Call (1-based) at which the audit first alerted on the single licence.
    pub single_first_alert_at: Option<usize>,
    pub single_rules: Vec<String>,
    /// Call (1-based, over all three licences) at which the cross-licence alert fired.
    pub split_first_alert_at: Option<usize>,
    pub split_named: Vec<String>,
    /// Single-licence alerts while split (each licence alone).
    pub split_single_alerts: usize,
    /// Alerts on ordinary use by three customers (200 calls).
    pub benign_alerts: usize,
}

/// The ownership test on what the copier holds.
#[derive(Clone, Debug, Serialize)]
pub struct Ownership {
    /// 50 of the copier's verdicts passed on: whom the test names, and the bits behind it.
    pub resold_attributed: Option<String>,
    pub resold_bits: usize,
    pub resold_matches: usize,
    /// The surrogate's own predictions (rounded to 3 figures) at 50 new inputs.
    pub surrogate_attributed: Option<String>,
    pub surrogate_bits: usize,
    pub surrogate_matches: usize,
    pub surrogate_foreign: usize,
}

/// The red-team report.
#[derive(Clone, Debug, Serialize)]
pub struct RedTeamReport {
    pub method: String,
    pub swept_inputs: Vec<String>,
    pub targets: Vec<String>,
    pub surrogate: String,
    pub threshold: f64,
    pub results: Vec<BudgetResult>,
    /// Per target, the smallest budget at which the surrogate's error fell below the threshold.
    pub queries_to_extract: Vec<(String, Option<usize>)>,
    pub detection: Detection,
    pub ownership: Ownership,
    pub evidence_class: String,
    pub notice: String,
}

/// The copier's survey: station C at (lat, lon), noise scale.
fn request(u: &[f64]) -> Value {
    json!({"config": {"area": [54.0, 56.0, 10.0, 13.0], "step_deg": 0.5, "budget": 3,
        "stations": [["A", 57.5, 10.0], ["B", 52.5, 8.5], ["C", 52.0 + 6.0 * u[0], 14.0 + 5.0 * u[1]]],
        "candidates": [], "sigma_floor_m": 15.0, "sigma_scale_m": 30.0 + 60.0 * u[2], "corr_km": 80.0,
        "survey_noise_m": 5.0, "toa_noise_m": 10.0, "k_pl": 5.33, "target_pl_m": 300.0},
        "include_grid": false})
}

/// Ordinary use: three customers, each with a few real configurations asked repeatedly.
fn benign(i: usize, r: &mut Lcg) -> Value {
    let sites = [
        [0.42, 0.40, 0.5],
        [0.55, 0.62, 0.25],
        [0.31, 0.75, 0.5],
        [0.70, 0.22, 0.75],
    ];
    let s = sites[(i / 3) % sites.len()];
    request(&[
        s[0] + (r.next() - 0.5) * 0.01,
        s[1] + (r.next() - 0.5) * 0.01,
        s[2],
    ])
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// The scored outputs: the protection level before the survey (the error model, smooth in the
/// inputs) and after it (the planner's choice of points, which jumps when the choice changes).
pub const TARGETS: [&str; 2] = ["mean_pl_before_m", "mean_pl_after_m"];

fn target(v: &Value, k: &str) -> Result<f64, String> {
    v[k].as_f64()
        .ok_or_else(|| format!("no {k} in the verdict"))
}

/// Invert a symmetric positive definite matrix (Gauss–Jordan with partial pivoting).
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
        let p = (c..n).max_by(|x, y| m[*x][c].abs().total_cmp(&m[*y][c].abs()))?;
        if m[p][c].abs() < 1e-300 {
            return None;
        }
        m.swap(c, p);
        let d = m[c][c];
        m[c].iter_mut().for_each(|x| *x /= d);
        let pivot = m[c].clone();
        for (r, row) in m.iter_mut().enumerate() {
            if r != c {
                let f = row[c];
                if f != 0.0 {
                    row.iter_mut().zip(&pivot).for_each(|(x, p)| *x -= f * p);
                }
            }
        }
    }
    Some(m.into_iter().map(|r| r[n..].to_vec()).collect())
}

/// Gaussian-kernel ridge regression with (length scale, ridge) chosen by leave-one-out.
struct Surrogate {
    x: Vec<Vec<f64>>,
    alpha: Vec<f64>,
    mean: f64,
    ell: f64,
}

impl Surrogate {
    fn k(a: &[f64], b: &[f64], ell: f64) -> f64 {
        let d2: f64 = a.iter().zip(b).map(|(p, q)| (p - q).powi(2)).sum();
        (-d2 / (2.0 * ell * ell)).exp()
    }

    fn fit(x: &[Vec<f64>], y: &[f64]) -> Option<Surrogate> {
        let n = x.len();
        let mean = y.iter().sum::<f64>() / n as f64;
        let yc: Vec<f64> = y.iter().map(|v| v - mean).collect();
        let mut best: Option<(f64, Surrogate)> = None;
        for ell in [0.05, 0.1, 0.2, 0.35, 0.6, 1.0] {
            for lam in [1e-8, 1e-6, 1e-4, 1e-2] {
                let k: Vec<Vec<f64>> = (0..n)
                    .map(|i| {
                        (0..n)
                            .map(|j| Self::k(&x[i], &x[j], ell) + if i == j { lam } else { 0.0 })
                            .collect()
                    })
                    .collect();
                let Some(inv) = invert(&k) else { continue };
                let alpha: Vec<f64> = (0..n)
                    .map(|i| (0..n).map(|j| inv[i][j] * yc[j]).sum())
                    .collect();
                let loo: f64 = (0..n).map(|i| (alpha[i] / inv[i][i]).powi(2)).sum();
                if best.as_ref().is_none_or(|(b, _)| loo < *b) {
                    best = Some((
                        loo,
                        Surrogate {
                            x: x.to_vec(),
                            alpha,
                            mean,
                            ell,
                        },
                    ));
                }
            }
        }
        best.map(|b| b.1)
    }

    fn predict(&self, u: &[f64]) -> f64 {
        self.mean
            + self
                .x
                .iter()
                .zip(&self.alpha)
                .map(|(x, a)| a * Self::k(x, u, self.ell))
                .sum::<f64>()
    }
}

/// Run the exercise.
pub fn run(cfg: &RedTeamConfig) -> Result<RedTeamReport, String> {
    let limits = Limits::default();
    let seed = [0x42u8; 32];
    let keys = FpKeys {
        format: KEYS_FORMAT.into(),
        epochs: vec![Epoch {
            id: "redteam".into(),
            from_unix: 0,
            key_hex: hex::encode(crate::calibrate::hmac_sha256(b"redteam", b"throwaway")),
        }],
    };
    let epoch = &keys.epochs[0];
    let n_max = cfg.budgets.iter().copied().max().unwrap_or(0).max(50);
    let pts = sobol(n_max, 3);
    let t0 = 1_800_000_000i64;

    // The copier's queries, as it receives them (signed, rounded, fingerprinted, bound).
    let mut seen = Vec::with_capacity(n_max);
    let mut suspects = vec![];
    for u in &pts {
        let req = request(u);
        let r: SurveyRequest = serde_json::from_value(req.clone()).map_err(|e| e.to_string())?;
        let bind = Binding {
            token_id: "copier".into(),
            mark: Some(Mark::new(epoch, "copier", "survey-plan", &req)?),
        };
        let s = Signing {
            signer: &seed,
            key_id: "redteam",
            lineage_seed: &seed,
            lineage_key_id: "redteam",
            sigfigs: 3,
            bind: Some(&bind),
        };
        let v = survey_verdict(&r, &s, &limits, false, "2027-01-01T00:00:00Z")?;
        seen.push([
            target(&v.verdict, TARGETS[0])?,
            target(&v.verdict, TARGETS[1])?,
        ]);
        if suspects.len() < 50 {
            suspects.push(Suspect {
                method: "survey-plan".into(),
                request: req,
                verdict: v.verdict,
            });
        }
    }

    // Held-out truth (the service's unrounded answers).
    let mut rng = Lcg(2027);
    let test: Vec<Vec<f64>> = (0..cfg.test_points)
        .map(|_| vec![rng.next(), rng.next(), rng.next()])
        .collect();
    let truth: Vec<Value> = test
        .iter()
        .map(|u| raw_outcome("survey-plan", &request(u), &limits))
        .collect::<Result<_, _>>()?;
    let mut results = vec![];
    let mut queries_to_extract = vec![];
    let mut last = None;
    for (ti, tk) in TARGETS.iter().enumerate() {
        let truth: Vec<f64> = truth
            .iter()
            .map(|v| target(v, tk))
            .collect::<Result<_, _>>()?;
        let tm = truth.iter().sum::<f64>() / truth.len().max(1) as f64;
        let spread = (truth.iter().map(|t| (t - tm).powi(2)).sum::<f64>()
            / truth.len().max(1) as f64)
            .sqrt();
        let y: Vec<f64> = seen.iter().map(|s| s[ti]).collect();
        let mut first = None;
        for &b in &cfg.budgets {
            let s = Surrogate::fit(&pts[..b], &y[..b]).ok_or("surrogate fit failed")?;
            let mse = test
                .iter()
                .zip(&truth)
                .map(|(u, t)| (s.predict(u) - t).powi(2))
                .sum::<f64>()
                / test.len().max(1) as f64;
            let nrmse = mse.sqrt() / spread.max(1e-12);
            let extracted = nrmse <= cfg.threshold;
            if extracted && first.is_none() {
                first = Some(b);
            }
            results.push(BudgetResult {
                target: tk.to_string(),
                queries: b,
                nrmse,
                extracted,
            });
            if ti == 1 {
                last = Some(s);
            }
        }
        queries_to_extract.push((tk.to_string(), first));
    }

    // The defences.
    let limiter = Limiter::new(LimitConfig::default());
    let audit = Auditor::new(AuditConfig::default());
    let (mut refusals, mut first, mut rules) = (0, None, vec![]);
    for (i, u) in pts.iter().enumerate() {
        let req = request(u);
        let t = t0 + i as i64 * cfg.interval_s;
        let h = hex::encode(Sha256::digest(req.to_string().as_bytes()));
        if limiter.admit("copier", &h, t).is_err() {
            refusals += 1;
        }
        let a = audit.observe("copier", "survey-plan", &req, t);
        if first.is_none() && !a.alerts.is_empty() {
            first = Some(i + 1);
            rules = a.alerts[0].rules.clone();
        }
    }
    let split = Auditor::new(AuditConfig::default());
    let (mut sfirst, mut named, mut single) = (None, vec![], 0);
    let third = pts.len().div_ceil(3);
    for (i, u) in pts.iter().enumerate() {
        let lic = ["copier-1", "copier-2", "copier-3"][(i / third).min(2)];
        let a = split.observe(
            lic,
            "survey-plan",
            &request(u),
            t0 + i as i64 * cfg.interval_s,
        );
        for al in a.alerts {
            if al.kind == "cross_licence" {
                sfirst = sfirst.or(Some(i + 1));
                for l in al.licences {
                    if !named.contains(&l) {
                        named.push(l);
                    }
                }
            } else if al.kind == "single_licence" {
                single += 1;
            }
        }
    }
    let ben = Auditor::new(AuditConfig::default());
    let mut r = Lcg(5);
    let mut benign_alerts = 0;
    for i in 0..200 {
        let lic = ["customer-1", "customer-2", "customer-3"][i % 3];
        benign_alerts += ben
            .observe(lic, "survey-plan", &benign(i, &mut r), t0 + i as i64 * 300)
            .alerts
            .len();
    }

    // Ownership: the copier's verdicts passed on; the surrogate's own predictions.
    let cands: Vec<String> = ["copier", "customer-1", "customer-2", "customer-3"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let raw = |m: &str, q: &Value| raw_outcome(m, q, &limits);
    let resold = ownership(&suspects, &keys, &cands, 3, &raw);
    let sur = last.ok_or("no budget")?;
    let mut fresh = vec![];
    for _ in 0..50 {
        let u = [rng.next(), rng.next(), rng.next()];
        let req = request(&u);
        let mut v = raw("survey-plan", &req)?;
        crate::outputs::coarsen(&mut v, 3);
        v["mean_pl_after_m"] = json!(crate::outputs::round_sig(sur.predict(&u), 3));
        fresh.push(Suspect {
            method: "survey-plan".into(),
            request: req,
            verdict: v,
        });
    }
    let sr = ownership(&fresh, &keys, &cands, 3, &raw);
    let top = |r: &crate::fingerprint::OwnershipReport| {
        r.scores
            .iter()
            .find(|s| s.token_id == "copier")
            .map(|s| (s.bits, s.matches))
            .unwrap_or((0, 0))
    };
    Ok(RedTeamReport {
        method: "survey-plan (F2)".into(),
        swept_inputs: vec![
            "station C latitude, 52 to 58 deg".into(),
            "station C longitude, 14 to 19 deg".into(),
            "sigma_scale_m, 30 to 90".into(),
        ],
        targets: TARGETS.iter().map(|t| t.to_string()).collect(),
        surrogate: "Gaussian-kernel ridge regression, length scale and ridge by leave-one-out".into(),
        threshold: cfg.threshold,
        results,
        queries_to_extract,
        detection: Detection {
            limiter_refusals: refusals,
            single_first_alert_at: first,
            single_rules: rules,
            split_first_alert_at: sfirst,
            split_named: named,
            split_single_alerts: single,
            benign_alerts,
        },
        ownership: Ownership {
            resold_attributed: resold.attributed.clone(),
            resold_bits: top(&resold).0,
            resold_matches: top(&resold).1,
            surrogate_attributed: sr.attributed.clone(),
            surrogate_bits: top(&sr).0,
            surrogate_matches: top(&sr).1,
            surrogate_foreign: sr.foreign,
        },
        evidence_class: "MODELLED".into(),
        notice: "One copier strategy (Sobol sweep, kernel ridge surrogate) against one F2 configuration family, in process with throwaway keys. A better copier may need fewer queries. The surrogate scores two outputs; the full verdict has more (the chosen points).".into(),
    })
}

/// A short text summary of a report.
pub fn summary(r: &RedTeamReport) -> String {
    let mut s = format!(
        "red team: {} — surrogate over {} swept inputs\n",
        r.method,
        r.swept_inputs.len()
    );
    for b in &r.results {
        s += &format!(
            "  {:<17} {:>4} queries: normalised RMS error {:.4}{}\n",
            b.target,
            b.queries,
            b.nrmse,
            if b.extracted { "  (extracted)" } else { "" }
        );
    }
    for (t, q) in &r.queries_to_extract {
        s += &format!(
            "  {t}: queries to extract (error <= {}): {}\n",
            r.threshold,
            q.map(|q| q.to_string())
                .unwrap_or_else(|| "not within the budgets tried".into())
        );
    }
    let d = &r.detection;
    s += &format!(
        "  per-licence limits refused {} calls; audit alerted at call {:?} ({:?}); split over three licences: alerted at call {:?}, named {:?}; ordinary use alerts: {}\n",
        d.limiter_refusals, d.single_first_alert_at, d.single_rules, d.split_first_alert_at, d.split_named, d.benign_alerts
    );
    let o = &r.ownership;
    s += &format!(
        "  ownership: 50 passed-on verdicts -> {:?} ({}/{} bits); surrogate predictions -> {:?} ({}/{} bits, {} foreign)\n",
        o.resold_attributed, o.resold_matches, o.resold_bits, o.surrogate_attributed, o.surrogate_matches, o.surrogate_bits, o.surrogate_foreign
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Acceptance (B2704): a report with the query budget at which the surrogate's error falls
    /// below the threshold, and the detectors firing on the sweep.
    #[test]
    fn red_team_report() {
        let r = run(&RedTeamConfig {
            budgets: vec![16, 32, 64, 128],
            test_points: 40,
            ..RedTeamConfig::default()
        })
        .unwrap();
        eprintln!("{}", summary(&r));
        assert_eq!(r.results.len(), 8);
        assert!(r.results.iter().all(|b| b.nrmse.is_finite()));
        for t in TARGETS {
            let e: Vec<f64> = r
                .results
                .iter()
                .filter(|b| b.target == t)
                .map(|b| b.nrmse)
                .collect();
            assert!(e[3] < e[0], "more queries, better surrogate: {t} {e:?}");
        }
        assert_eq!(r.queries_to_extract.len(), 2);
        let d = &r.detection;
        assert_eq!(
            d.limiter_refusals, 0,
            "the slow copier passes the old limits"
        );
        assert!(d.single_first_alert_at.is_some_and(|c| c <= 64), "{d:?}");
        assert!(d.split_first_alert_at.is_some(), "{d:?}");
        let mut n = d.split_named.clone();
        n.sort();
        assert_eq!(n, ["copier-1", "copier-2", "copier-3"]);
        assert_eq!(d.benign_alerts, 0);
        assert_eq!(r.ownership.resold_attributed.as_deref(), Some("copier"));
        let text = serde_json::to_string(&r).unwrap();
        assert!(text.contains("queries_to_extract"));
    }
}
