// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! Keyed per-licence fingerprints, canary regions, key rotation and the ownership test.
//!
//! **What a fingerprint is.** Every verdict number is already rounded to `sigfigs` significant
//! figures ([`crate::outputs`]). For the numbers listed in a method's plan ([`plan`]), the
//! service rounds *up or down* instead of to nearest, and the direction is a keyed bit:
//! HMAC(licence key, method, coarse input cell, quantity family). The licence key is derived
//! from the current epoch key and the licence's token ID. A verdict, a resold copy of it, or a
//! table of numbers copied from many verdicts therefore carries the licence's bit pattern,
//! which we can test ([`ownership`]) by recomputing the unrounded outcome; nobody without the
//! key can tell which way a number was rounded, or remove the pattern, without moving every
//! listed number by up to one unit in its last figure at random.
//!
//! **Bound (stated tolerance).** A fingerprinted number differs from the unrounded outcome by
//! less than one unit in its last significant figure (nearest rounding: at most half a unit).
//! In addition, and only for the numbers in the plan:
//! * where the verdict states a standard uncertainty for the number (`std_err`), the number is
//!   fingerprinted only if one unit in its last figure is at most 0.2 of that uncertainty, so the
//!   change stays inside one fifth of the stated GUM standard uncertainty;
//! * a number is never moved onto, or off, a value with fewer significant figures (0, 1, 0.9,
//!   0.95, 300), so a comparison against any such threshold gives the same answer as the
//!   unfingerprinted output;
//! * one direction is used per quantity family per verdict (for example every coverage figure
//!   of a survey), and a family whose order would change is left at nearest rounding, so
//!   orderings (coverage after ≥ before, picks in order) are kept;
//! * integers, strings, booleans, hashes, angles (`_deg`), classifications, confidences, counts
//!   and fidelity percentages are never fingerprinted; `cause` and `lunar-assist` verdicts are
//!   not fingerprinted at all (a confidence in steps of 0.05; integrity bounds rounded up on
//!   purpose and a package signed on its own).
//!
//! A verdict class (a classification, `converged`, `stop_reason`, pass/fail) is never changed.
//!
//! **Canaries.** About one coarse input cell in [`CANARY_EVERY`] (secret, keyed by the epoch) is a
//! canary cell: there every licence gets the same keyed pattern. A competitor's outputs that
//! match the canary pattern derive from meru answers whichever licence was used, including a
//! sweep spread over several licences. The meter log marks calls that fall in a canary cell.
//!
//! **Keys and rotation.** `MERU_FINGERPRINT_KEYS` names a JSON file of epochs
//! (`{"format": "meru-fingerprint-keys/1", "epochs": [{"id", "from_unix", "key_hex"}]}`); the
//! epoch in force is the latest whose `from_unix` has passed. `meru fingerprint-keys rotate`
//! appends a new random epoch. Old epochs are never deleted: the file is the escrow that later
//! ownership tests need, so keep it in the secret store with a backup, like the signing seed.
//! Without the file no verdict is fingerprinted (nearest rounding, as before).

use crate::audit::coarse_cell;
use crate::calibrate::hmac_sha256;
use crate::outputs::{coarsen, round_sig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

/// One canary cell in this many (on average).
pub const CANARY_EVERY: u32 = 64;
/// Fraction of a stated standard uncertainty one unit in the last figure may reach.
pub const UNC_FRACTION: f64 = 0.2;
/// Key file format.
pub const KEYS_FORMAT: &str = "meru-fingerprint-keys/1";

/// One fingerprinted field of a method's verdict.
#[derive(Clone, Copy, Debug)]
pub struct Field {
    /// Path with `[]` for array elements, e.g. `picks[].coverage`.
    pub pattern: &'static str,
    /// Quantity family (one rounding direction per family per verdict).
    pub family: &'static str,
    /// Each array element is its own family (independent quantities, e.g. parameters).
    pub per_item: bool,
    /// Sibling key holding the number's stated standard uncertainty.
    pub unc: Option<&'static str>,
}

const SURVEY: &[Field] = &[
    Field {
        pattern: "coverage_before",
        family: "coverage",
        per_item: false,
        unc: None,
    },
    Field {
        pattern: "coverage_after",
        family: "coverage",
        per_item: false,
        unc: None,
    },
    Field {
        pattern: "picks[].coverage",
        family: "coverage",
        per_item: false,
        unc: None,
    },
    Field {
        pattern: "mean_pl_before_m",
        family: "pl",
        per_item: false,
        unc: None,
    },
    Field {
        pattern: "mean_pl_after_m",
        family: "pl",
        per_item: false,
        unc: None,
    },
    Field {
        pattern: "picks[].mean_pl_m",
        family: "pl",
        per_item: false,
        unc: None,
    },
];

const POSTERIOR: Field = Field {
    pattern: "posterior[].value",
    family: "posterior",
    per_item: true,
    unc: Some("std_err"),
};

const SELFCAL: &[Field] = &[POSTERIOR];

const CALIBRATE: &[Field] = &[
    POSTERIOR,
    Field {
        pattern: "chi2_reduced_first",
        family: "chi2",
        per_item: false,
        unc: None,
    },
    Field {
        pattern: "chi2_reduced_last",
        family: "chi2",
        per_item: false,
        unc: None,
    },
];

/// The fingerprint plan of a method (by the verdict's `method` name); empty = not fingerprinted.
pub fn plan(method: &str) -> &'static [Field] {
    match method {
        "survey-plan" => SURVEY,
        "selfcal" => SELFCAL,
        "calibrate" => CALIBRATE,
        _ => &[],
    }
}

/// One unit in the last kept figure of `x`.
pub fn quantum(x: f64, sig: u32) -> f64 {
    if x == 0.0 || !x.is_finite() {
        return 0.0;
    }
    10f64.powi(x.abs().log10().floor() as i32 - sig as i32 + 1)
}

fn clean(r: f64, sig: u32) -> f64 {
    format!("{r:.*e}", (sig as usize).saturating_sub(1))
        .parse()
        .unwrap_or(r)
}

/// `x` rounded up (`up`) or down to `sig` significant figures. A number that is already exact
/// at `sig` figures is returned as is (it carries no bit).
pub fn round_dir(x: f64, sig: u32, up: bool) -> f64 {
    let n = round_sig(x, sig);
    if x == 0.0 || !x.is_finite() || (n - x).abs() <= 1e-12 * x.abs() {
        return n;
    }
    let q = quantum(x, sig);
    let r = if up {
        (x / q).ceil() * q
    } else {
        (x / q).floor() * q
    };
    clean(r, sig)
}

fn is_round(v: f64, sig: u32) -> bool {
    v == 0.0 || sig <= 1 || round_sig(v, sig - 1) == v
}

/// A fingerprintable number found in a raw verdict.
#[derive(Clone, Debug)]
pub struct Leaf {
    /// JSON pointer.
    pub pointer: String,
    pub family: String,
    pub x: f64,
    /// Inside the stated uncertainty (or none stated).
    pub tolerable: bool,
}

fn collect(v: &Value, pat: &str, ptr: &str, out: &mut Vec<(String, String, f64)>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                let p = if pat.is_empty() {
                    k.clone()
                } else {
                    format!("{pat}.{k}")
                };
                collect(x, &p, &format!("{ptr}/{k}"), out);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                collect(x, &format!("{pat}[]"), &format!("{ptr}/{i}"), out);
            }
        }
        Value::Number(n) if !(n.is_i64() || n.is_u64()) => {
            out.push((pat.to_string(), ptr.to_string(), n.as_f64().unwrap_or(0.0)));
        }
        _ => {}
    }
}

/// The fingerprintable numbers of a raw (unrounded) verdict of `method`.
pub fn leaves(raw: &Value, method: &str, sig: u32) -> Vec<Leaf> {
    let fields = plan(method);
    if fields.is_empty() {
        return vec![];
    }
    let mut all = vec![];
    collect(raw, "", "", &mut all);
    let mut out = vec![];
    for (pat, ptr, x) in all {
        let Some(f) = fields.iter().find(|f| f.pattern == pat) else {
            continue;
        };
        if !x.is_finite() || x == 0.0 {
            continue;
        }
        let family = if f.per_item {
            // The array index of the item: the last numeric pointer component before the key.
            let idx = ptr.rsplit('/').nth(1).unwrap_or("0").to_string();
            format!("{}[{idx}]", f.family)
        } else {
            f.family.to_string()
        };
        let tolerable = match f.unc {
            None => true,
            Some(k) => {
                let parent = &ptr[..ptr.rfind('/').unwrap_or(0)];
                let s = raw
                    .pointer(&format!("{parent}/{k}"))
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0);
                s.is_finite() && s > 0.0 && quantum(x, sig) <= UNC_FRACTION * s
            }
        };
        out.push(Leaf {
            pointer: ptr,
            family,
            x,
            tolerable,
        });
    }
    out
}

/// Round a raw verdict of `method` to `sig` figures, with the keyed direction `dir(family)`
/// (`Some(true)` up, `Some(false)` down, `None` nearest) on the numbers of the plan, under the
/// rules in the module notes. Every other number is rounded as [`coarsen`] does.
pub fn apply(v: &mut Value, method: &str, sig: u32, dir: &dyn Fn(&str) -> Option<bool>) {
    let ls = leaves(v, method, sig);
    coarsen(v, sig);
    let mut fams: BTreeMap<&str, Vec<&Leaf>> = BTreeMap::new();
    for l in &ls {
        fams.entry(&l.family).or_default().push(l);
    }
    for (fam, items) in fams {
        let Some(up) = dir(fam) else { continue };
        let ys: Vec<f64> = items
            .iter()
            .map(|l| {
                let n = round_sig(l.x, sig);
                let y = round_dir(l.x, sig, up);
                if !l.tolerable || (y != n && (is_round(y, sig) || is_round(n, sig))) {
                    n
                } else {
                    y
                }
            })
            .collect();
        // Keep the family's order (as the unrounded values have it).
        let ordered = (0..items.len()).all(|i| {
            (0..items.len()).all(|j| {
                let (a, b) = (items[i].x, items[j].x);
                !(a < b && ys[i] > ys[j]) && !(a == b && ys[i] != ys[j])
            })
        });
        if !ordered {
            continue;
        }
        for (l, y) in items.iter().zip(ys) {
            if let (Some(slot), Some(num)) =
                (v.pointer_mut(&l.pointer), serde_json::Number::from_f64(y))
            {
                *slot = Value::Number(num);
            }
        }
    }
}

// ── Keys ────────────────────────────────────────────────────────────────────

/// One key epoch.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Epoch {
    pub id: String,
    pub from_unix: i64,
    pub key_hex: String,
}

impl Epoch {
    fn key(&self) -> Result<[u8; 32], String> {
        hex::decode(&self.key_hex)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| format!("fingerprint epoch {}: key_hex is not 64 hex", self.id))
    }
}

/// The fingerprint key file: every epoch, kept for later ownership tests.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FpKeys {
    pub format: String,
    pub epochs: Vec<Epoch>,
}

impl FpKeys {
    pub fn parse(text: &str) -> Result<FpKeys, String> {
        let k: FpKeys = serde_json::from_str(text).map_err(|e| format!("fingerprint keys: {e}"))?;
        if k.format != KEYS_FORMAT {
            return Err(format!("fingerprint keys: format is not {KEYS_FORMAT}"));
        }
        let mut ids = std::collections::HashSet::new();
        for e in &k.epochs {
            e.key()?;
            if !ids.insert(&e.id) {
                return Err(format!("fingerprint keys: epoch {} twice", e.id));
            }
        }
        Ok(k)
    }

    pub fn load(path: &Path) -> Result<FpKeys, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        FpKeys::parse(&text)
    }

    /// The epoch in force at `now`.
    pub fn active(&self, now: i64) -> Option<&Epoch> {
        self.epochs
            .iter()
            .filter(|e| e.from_unix <= now)
            .max_by_key(|e| e.from_unix)
    }

    /// Append a new epoch with a random key, in force from `from_unix`, and write the file
    /// (created if missing, owner-only permissions, replaced atomically). Returns the new id.
    pub fn rotate(path: &Path, from_unix: i64) -> Result<String, String> {
        let mut keys = if path.exists() {
            FpKeys::load(path)?
        } else {
            FpKeys {
                format: KEYS_FORMAT.into(),
                epochs: vec![],
            }
        };
        let mut key = [0u8; 32];
        use std::io::Read;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut key))
            .map_err(|e| format!("random key: {e}"))?;
        let id = format!("e{}-{}", keys.epochs.len() + 1, from_unix);
        keys.epochs.push(Epoch {
            id: id.clone(),
            from_unix,
            key_hex: hex::encode(key),
        });
        let tmp = path.with_extension("tmp");
        let text = serde_json::to_string_pretty(&keys).map_err(|e| e.to_string())?;
        {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            use std::io::Write;
            let mut f = o
                .open(&tmp)
                .map_err(|e| format!("{}: {e}", tmp.display()))?;
            f.write_all(text.as_bytes())
                .and_then(|_| f.sync_all())
                .map_err(|e| format!("{}: {e}", tmp.display()))?;
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(id)
    }
}

/// The keyed directions for one call: licence, epoch, method and coarse input cell.
#[derive(Clone)]
pub struct Mark {
    key: [u8; 32],
    canary: bool,
    method: String,
    cell: [u8; 32],
}

impl Mark {
    /// The mark for `token_id` calling `method` with `request`, under `epoch`.
    pub fn new(
        epoch: &Epoch,
        token_id: &str,
        method: &str,
        request: &Value,
    ) -> Result<Mark, String> {
        Self::for_cell(epoch, token_id, method, coarse_cell(method, request))
    }

    pub fn for_cell(
        epoch: &Epoch,
        token_id: &str,
        method: &str,
        cell: [u8; 32],
    ) -> Result<Mark, String> {
        let ek = epoch.key()?;
        let canary_key = hmac_sha256(&ek, b"meru-fp/1 canary");
        let mut m = method.as_bytes().to_vec();
        m.push(b'|');
        m.extend_from_slice(&cell);
        let c = hmac_sha256(&canary_key, &[b"cell|".as_slice(), &m].concat());
        let canary = u32::from_le_bytes([c[0], c[1], c[2], c[3]]).is_multiple_of(CANARY_EVERY);
        let key = if canary {
            canary_key
        } else {
            hmac_sha256(&ek, format!("meru-fp/1 licence|{token_id}").as_bytes())
        };
        Ok(Mark {
            key,
            canary,
            method: method.into(),
            cell,
        })
    }

    /// Whether the call's input cell is a canary cell.
    pub fn is_canary(&self) -> bool {
        self.canary
    }

    /// The rounding direction of `family` (true = up).
    pub fn up(&self, family: &str) -> bool {
        let mut msg = b"dir|".to_vec();
        msg.extend_from_slice(self.method.as_bytes());
        msg.push(b'|');
        msg.extend_from_slice(&self.cell);
        msg.push(b'|');
        msg.extend_from_slice(family.as_bytes());
        hmac_sha256(&self.key, &msg)[0] & 1 == 1
    }

    /// Round a raw verdict with this mark.
    pub fn apply(&self, v: &mut Value, sig: u32) {
        let m = self.method.clone();
        apply(v, &m, sig, &|f| Some(self.up(f)));
    }
}

// ── Ownership test ──────────────────────────────────────────────────────────

/// One suspect record: the request, and the numbers someone holds for it (a verdict body, or
/// a copy of its outcome).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Suspect {
    /// The verdict `method` name (`survey-plan`, `selfcal`, `calibrate`).
    pub method: String,
    pub request: Value,
    /// The outcome (the `verdict` object of a signed verdict, or the same numbers).
    pub verdict: Value,
}

/// How well one licence (under one epoch) explains the suspect numbers.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Score {
    pub token_id: String,
    pub epoch: String,
    /// Informative family bits outside canary cells.
    pub bits: usize,
    /// Bits matching this licence's key.
    pub matches: usize,
    /// log10 of the chance a licence unrelated to the numbers matches this well or better.
    pub log10_p: f64,
}

/// The ownership test's answer.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct OwnershipReport {
    pub records: usize,
    /// Records whose request could not be recomputed.
    pub skipped: usize,
    /// Distinct (input cell, family) bits observed (numbers rounded one way or the other).
    pub bits: usize,
    /// Fingerprinted families matching neither direction (not meru output, or altered), or
    /// contradicting another record of the same input cell.
    pub foreign: usize,
    /// Best first.
    pub scores: Vec<Score>,
    /// Canary cells seen, bits and matches with the canary pattern (per epoch, best).
    pub canary_bits: usize,
    pub canary_matches: usize,
    pub canary_log10_p: f64,
    /// The licence the numbers are attributed to, when one stands out (see [`ownership`]).
    pub attributed: Option<String>,
    pub notice: String,
}

/// log10 of P(X ≥ m) for X ~ Binomial(n, 1/2).
pub fn log10_tail(n: usize, m: usize) -> f64 {
    if m == 0 || n == 0 {
        return 0.0;
    }
    let ln_c = |k: usize| -> f64 {
        let lf = |x: usize| (1..=x).map(|i| (i as f64).ln()).sum::<f64>();
        lf(n) - lf(k) - lf(n - k)
    };
    let terms: Vec<f64> = (m..=n).map(|k| ln_c(k) - n as f64 * 2f64.ln()).collect();
    let mx = terms.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let s: f64 = terms.iter().map(|t| (t - mx).exp()).sum();
    ((mx + s.ln()) / 10f64.ln()).min(0.0)
}

/// Test which licence suspect numbers came from. `raw(method, request)` recomputes the
/// unrounded outcome (the service's own methods); `candidates` are token IDs (from the meter
/// log). For each record and family, the observed direction is the one whose rounding the
/// suspect numbers match; each (licence, epoch) is scored by how many observed directions its
/// key predicts. A licence is named when it explains at least 90 % of at least 16 bits with a
/// chance below 1e-6 after multiplying by the number of candidates tried, and the runner-up
/// explains clearly less (log10 p at least 4 higher).
pub fn ownership(
    suspects: &[Suspect],
    keys: &FpKeys,
    candidates: &[String],
    sig: u32,
    raw: &dyn Fn(&str, &Value) -> Result<Value, String>,
) -> OwnershipReport {
    // (cell, method, family) -> observed up? for every informative family. Records in the same
    // cell share their bits, so each (cell, family) counts once; a contradiction is foreign.
    let mut seen_bits: BTreeMap<([u8; 32], String, String), bool> = BTreeMap::new();
    let (mut skipped, mut foreign) = (0, 0);
    for s in suspects {
        let Ok(r) = raw(&s.method, &s.request) else {
            skipped += 1;
            continue;
        };
        let cell = coarse_cell(&s.method, &s.request);
        let ls = leaves(&r, &s.method, sig);
        let mut fams: Vec<String> = ls.iter().map(|l| l.family.clone()).collect();
        fams.sort();
        fams.dedup();
        for fam in fams {
            let variant = |up: bool| {
                let mut v = r.clone();
                apply(&mut v, &s.method, sig, &|f| (f == fam).then_some(up));
                v
            };
            let (u, d) = (variant(true), variant(false));
            let ptrs: Vec<&str> = ls
                .iter()
                .filter(|l| l.family == fam)
                .map(|l| l.pointer.as_str())
                .collect();
            let get = |v: &Value, p: &str| v.pointer(p).and_then(Value::as_f64);
            if ptrs.iter().all(|p| get(&u, p) == get(&d, p)) {
                continue;
            }
            let seen: Vec<Option<f64>> = ptrs.iter().map(|p| get(&s.verdict, p)).collect();
            let is = |v: &Value| ptrs.iter().zip(&seen).all(|(p, x)| *x == get(v, p));
            let bit = if is(&u) {
                true
            } else if is(&d) {
                false
            } else {
                foreign += 1;
                continue;
            };
            match seen_bits.entry((cell, s.method.clone(), fam.clone())) {
                std::collections::btree_map::Entry::Vacant(e) => {
                    e.insert(bit);
                }
                std::collections::btree_map::Entry::Occupied(e) => {
                    if *e.get() != bit {
                        foreign += 1;
                    }
                }
            }
        }
    }
    let obs: Vec<([u8; 32], String, String, bool)> = seen_bits
        .into_iter()
        .map(|((c, m, f), b)| (c, m, f, b))
        .collect();
    let mut scores = vec![];
    let (mut canary_bits, mut canary_matches, mut canary_p) = (0, 0, 0.0f64);
    for e in &keys.epochs {
        let (mut cb, mut cm) = (0, 0);
        let mut per: Vec<(usize, usize)> = vec![(0, 0); candidates.len()];
        for (cell, method, fam, up) in &obs {
            // Canary status does not depend on the licence.
            let Ok(m0) = Mark::for_cell(e, "", method, *cell) else {
                continue;
            };
            if m0.is_canary() {
                cb += 1;
                cm += usize::from(m0.up(fam) == *up);
                continue;
            }
            for (i, c) in candidates.iter().enumerate() {
                if let Ok(m) = Mark::for_cell(e, c, method, *cell) {
                    per[i].0 += 1;
                    per[i].1 += usize::from(m.up(fam) == *up);
                }
            }
        }
        let p = log10_tail(cb, cm) + (keys.epochs.len() as f64).log10();
        if cb > 0 && (canary_bits == 0 || p < canary_p) {
            (canary_bits, canary_matches, canary_p) = (cb, cm, p.min(0.0));
        }
        for (i, c) in candidates.iter().enumerate() {
            scores.push(Score {
                token_id: c.clone(),
                epoch: e.id.clone(),
                bits: per[i].0,
                matches: per[i].1,
                log10_p: log10_tail(per[i].0, per[i].1),
            });
        }
    }
    scores.sort_by(|a, b| a.log10_p.total_cmp(&b.log10_p));
    let tries = (scores.len().max(1) as f64).log10();
    let attributed = scores.first().and_then(|b| {
        let second = scores
            .iter()
            .find(|s| s.token_id != b.token_id)
            .map(|s| s.log10_p)
            .unwrap_or(0.0);
        (b.bits >= 16
            && b.matches as f64 >= 0.9 * b.bits as f64
            && b.log10_p + tries < -6.0
            && second - b.log10_p >= 4.0)
            .then(|| b.token_id.clone())
    });
    OwnershipReport {
        records: suspects.len(),
        skipped,
        bits: obs.len(),
        foreign,
        scores,
        canary_bits,
        canary_matches,
        canary_log10_p: canary_p,
        attributed,
        notice: "Statistical evidence: the chance figures assume an unrelated licence matches each bit with probability 1/2. The numbers are recomputed by the service's methods from the requests given; a request that cannot be recomputed is skipped.".into(),
    }
}

#[cfg(test)]
#[path = "fingerprint_tests.rs"]
mod tests;
