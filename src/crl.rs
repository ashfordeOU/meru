// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The revocation list of the product register (research backlog E25, B2505, the hosted part).
//!
//! A product's register entry says it was **scored under method X** (a method of this service
//! at a stated version, with the verdict that holds the score). An entry can stop standing: the
//! score is withdrawn, the method is superseded, the product changed after it was scored, the
//! evidence was found wrong, or the holder asks. This module keeps those revocations and publishes
//! them as a signed list a client checks offline before it relies on an entry:
//!
//! * `POST /verdict/crl/revoke` (revocation endpoint): an operator licence listed in
//!   `MERU_CRL_ADMINS` revokes one entry: `{product_id, scored_under: {method, version},
//!   verdict_sha256?, reason, note?}`. Revocations are appended to `MERU_CRL_LOG` (JSON Lines,
//!   append-only, read back at start) and never removed;
//! * `GET /crl` (list fetch, no licence needed: a revocation list is public): the current list,
//!   format `meru-crl/1`, as a signed verdict (method `crl`, evidence class `RECORD`) that the Pro
//!   verdict client verifies like any verdict: issuer key, sequence number (the number of
//!   revocations), `this_update`, `next_update` (a client treats a list past `next_update` as
//!   stale), the entries sorted, and their SHA-256. The list is re-signed after every revocation
//!   and at least once a day.
//!
//! Wording: an entry is "scored under method X"; nothing here says a product is validated,
//! approved or certified, and a revocation says only that the entry no longer stands. The private
//! `note` stays in the log and is never published.

use crate::verdict::{sign, SignedVerdict};
use kshana_pro::license::signer::LicenceSigner;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Format of the published list.
pub const FORMAT: &str = "meru-crl/1";
/// How long a published list is current, seconds.
pub const VALIDITY_S: i64 = 7 * 86_400;
/// The list is re-signed when it is older than this, seconds.
pub const RESIGN_AFTER_S: i64 = 86_400;

/// Why an entry no longer stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The score was withdrawn by the service.
    ScoreWithdrawn,
    /// The method version it was scored under has been superseded and no longer applies.
    MethodSuperseded,
    /// The product changed (hardware, firmware, configuration) after it was scored.
    ProductChanged,
    /// The evidence the score rested on was found to be wrong.
    EvidenceError,
    /// The key that signed the evidence or the verdict may be compromised.
    KeyCompromise,
    /// The holder of the entry asked for it to be withdrawn.
    HolderRequest,
}

/// The method and version a product was scored under.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoredUnder {
    pub method: String,
    pub version: String,
}

/// A revocation request.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    pub product_id: String,
    pub scored_under: ScoredUnder,
    /// The verdict that held the score (64 hex), when known.
    #[serde(default)]
    pub verdict_sha256: Option<String>,
    pub reason: Reason,
    /// Private note for the log; never published (at most 500 characters).
    #[serde(default)]
    pub note: Option<String>,
}

/// One revocation as published.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revoked {
    pub product_id: String,
    pub scored_under: ScoredUnder,
    #[serde(default)]
    pub verdict_sha256: Option<String>,
    pub reason: Reason,
    pub revoked_utc: String,
}

/// One line of the log: the published part, who revoked, and the private note.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogLine {
    revoked: Revoked,
    by_token_id: String,
    #[serde(default)]
    note: Option<String>,
}

fn ident_ok(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/'))
}

/// Check a revocation request.
pub fn check(r: &RevokeRequest) -> Result<(), String> {
    if !ident_ok(&r.product_id, 128) {
        return Err("product_id: 1 to 128 characters of A-Z a-z 0-9 . _ - : /".into());
    }
    if !ident_ok(&r.scored_under.method, 64) || !ident_ok(&r.scored_under.version, 32) {
        return Err("scored_under: method (1 to 64) and version (1 to 32) characters of A-Z a-z 0-9 . _ - : /".into());
    }
    if let Some(h) = &r.verdict_sha256 {
        if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("verdict_sha256 must be 64 hex".into());
        }
    }
    if r.note.as_ref().is_some_and(|n| n.chars().count() > 500) {
        return Err("note: at most 500 characters".into());
    }
    Ok(())
}

/// Where the revocations are kept, and who may add to them.
#[derive(Clone, Debug, Default)]
pub struct CrlConfig {
    /// The append-only revocation log. `None`: no list is kept (the endpoints answer 404).
    pub log: Option<PathBuf>,
    /// Token IDs of the operator licences that may revoke.
    pub admins: Vec<String>,
}

/// The revocations in memory and the last signed list.
pub struct CrlStore {
    path: PathBuf,
    entries: Vec<Revoked>,
    signed: Option<(i64, SignedVerdict)>,
}

impl CrlStore {
    /// Open (or create) the log and read it back.
    pub fn open(path: &Path) -> Result<CrlStore, String> {
        let mut entries = vec![];
        if path.exists() {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            for (i, l) in text.lines().enumerate() {
                if l.trim().is_empty() {
                    continue;
                }
                let line: LogLine = serde_json::from_str(l)
                    .map_err(|e| format!("{} line {}: {e}", path.display(), i + 1))?;
                entries.push(line.revoked);
            }
        }
        Ok(CrlStore {
            path: path.to_path_buf(),
            entries,
            signed: None,
        })
    }

    /// The revocations, in the order they were made.
    pub fn entries(&self) -> &[Revoked] {
        &self.entries
    }

    /// Record a revocation. Revoking an entry that is already revoked is refused (the list
    /// keeps the first revocation).
    pub fn revoke(
        &mut self,
        r: &RevokeRequest,
        by_token_id: &str,
        utc: &str,
    ) -> Result<Revoked, String> {
        check(r)?;
        if self
            .entries
            .iter()
            .any(|e| e.product_id == r.product_id && e.scored_under == r.scored_under)
        {
            return Err(format!(
                "already revoked: {} scored under {} {}",
                r.product_id, r.scored_under.method, r.scored_under.version
            ));
        }
        let rev = Revoked {
            product_id: r.product_id.clone(),
            scored_under: r.scored_under.clone(),
            verdict_sha256: r.verdict_sha256.as_ref().map(|h| h.to_ascii_lowercase()),
            reason: r.reason,
            revoked_utc: utc.into(),
        };
        let line = serde_json::to_string(&LogLine {
            revoked: rev.clone(),
            by_token_id: by_token_id.into(),
            note: r.note.clone(),
        })
        .map_err(|e| e.to_string())?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("revocation log: {e}"))?;
        writeln!(f, "{line}")
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("revocation log: {e}"))?;
        self.entries.push(rev.clone());
        self.signed = None;
        Ok(rev)
    }

    /// The current signed list, re-signed when there is none or it is older than a day.
    pub fn signed(
        &mut self,
        signer: &dyn LicenceSigner,
        key_id: &str,
        now: i64,
    ) -> Result<SignedVerdict, String> {
        if let Some((t, v)) = &self.signed {
            if now - t < RESIGN_AFTER_S {
                return Ok(v.clone());
            }
        }
        let v = build(&self.entries, signer, key_id, now)?;
        self.signed = Some((now, v.clone()));
        Ok(v)
    }
}

/// The list body (sorted entries, sequence number, validity) for the revocations given.
pub fn body(entries: &[Revoked], key_id: &str, now: i64) -> Value {
    let mut e = entries.to_vec();
    e.sort_by(|a, b| {
        (a.product_id.as_str(), &a.scored_under).cmp(&(b.product_id.as_str(), &b.scored_under))
    });
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&e).unwrap_or_default()));
    json!({
        "format": FORMAT,
        "issuer_key_id": key_id,
        "seq": entries.len(),
        "this_update": crate::server::iso(now),
        "next_update": crate::server::iso(now + VALIDITY_S),
        "entries": e,
        "entries_sha256": digest,
        "statement": "Entries listed here no longer stand: the product is no longer to be described as scored under the method and version given. The list says nothing about products not on it.",
    })
}

/// Build and sign the list.
pub fn build(
    entries: &[Revoked],
    signer: &dyn LicenceSigner,
    key_id: &str,
    now: i64,
) -> Result<SignedVerdict, String> {
    sign(
        "crl",
        "RECORD",
        body(entries, key_id, now),
        signer,
        key_id,
        &crate::server::iso(now),
    )
}

/// Whether a product, scored under a method and version, is revoked on a list a client holds.
/// Checks the list's signature, format and currency first.
pub fn is_revoked(
    list: &SignedVerdict,
    public_key_hex: &str,
    product_id: &str,
    scored_under: &ScoredUnder,
    now: i64,
) -> Result<bool, String> {
    let p = crate::verdict::verify(list, public_key_hex);
    if !p.is_empty() {
        return Err(format!("revocation list does not verify: {}", p.join("; ")));
    }
    let b = &list.verdict;
    if list.method != "crl" || b["format"] != FORMAT {
        return Err("not a meru-crl/1 list".into());
    }
    let next = b["next_update"]
        .as_str()
        .ok_or("revocation list: no next_update")
        .and_then(|s| crate::cause::parse_iso(s).map_err(|_| "revocation list: bad next_update"))?;
    if (now as f64) > next {
        return Err("revocation list is stale (past next_update): fetch a current one".into());
    }
    let entries: Vec<Revoked> = serde_json::from_value(b["entries"].clone())
        .map_err(|e| format!("revocation list: {e}"))?;
    Ok(entries
        .iter()
        .any(|e| e.product_id == product_id && &e.scored_under == scored_under))
}

/// The store behind the endpoints, opened on first use.
#[derive(Default)]
pub struct Crl {
    inner: Mutex<Option<CrlStore>>,
}

impl Crl {
    /// Run `f` on the store (opened from `cfg.log` on first use).
    pub fn with<T>(
        &self,
        cfg: &CrlConfig,
        f: impl FnOnce(&mut CrlStore) -> Result<T, String>,
    ) -> Result<T, String> {
        let path = cfg
            .log
            .as_ref()
            .ok_or("no revocation list is kept by this service")?;
        let mut g = self
            .inner
            .lock()
            .map_err(|_| "revocation list lock poisoned")?;
        if g.is_none() {
            *g = Some(CrlStore::open(path)?);
        }
        f(g.as_mut().expect("opened above"))
    }
}

#[cfg(test)]
#[path = "crl_tests.rs"]
mod tests;
