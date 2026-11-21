// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The hosted revocation list of the product register (research backlog E25, B2505, the hosted
//! part), issued in the open engine's own format, `kshana.register-crl/1`, so the open register
//! tools read it unchanged (`kshana register crl-check crl.json --key <issuer hex>`, and
//! `kshana register view register.json --crl crl.json --crl-key <hex> --date YYYY-MM-DD`).
//!
//! The document, fields in this order, no others:
//! `{"schema","issuer","issued","next_update","revoked":[{"id","revoked","reason"}],"signer","signature"}`.
//! `issued` and `next_update` are calendar dates; each revocation names a register entry by its
//! id (chosen by the register publisher) with the date from which it applies and the reason as
//! the issuer states it. `signer` is the issuer's Ed25519 public key (hex); `signature` is the
//! Ed25519 signature (hex) over `kshana.register-crl/1\n` followed by the compact JSON of the
//! document in that field order with `signature` empty. The issuer key is the service's verdict
//! key, published with its history at `GET /keys`; a reader checks against a key it is given.
//!
//! * `POST /verdict/crl/revoke`: an operator licence listed in `MERU_CRL_ADMINS` revokes one
//!   entry: `{id, revoked?, reason, note?}` (`revoked` defaults to today; `reason` one of six
//!   codes, published as text). Appended to `MERU_CRL_LOG` (JSON Lines, append-only, read back at
//!   start, never edited). The private note and the revoking licence stay in the log.
//! * `GET /crl` (public): the current signed document, re-issued after every revocation and on
//!   each new UTC day; `next_update` is seven days after `issued`.
//! * Each revocation is also appended to the transparency log when one is kept (kind
//!   `crl-revocation/1`, the SHA-256 of the revocation's compact JSON); sequence and hashes are
//!   carried there and in the revoke answer, never inside the document.
//!
//! Wording: a register entry says a product was "scored under method X"; a revocation says only
//! that the entry no longer stands. Nothing here says a product is validated, approved or
//! certified.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use kshana_pro::license::signer::{sign_checked, LicenceSigner};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The open format's schema string (also the first line of the signed bytes).
pub const SCHEMA: &str = "kshana.register-crl/1";
/// Days from `issued` to `next_update`.
pub const VALIDITY_DAYS: i64 = 7;
/// The transparency-log kind of a revocation record.
pub const TLOG_KIND: &str = "crl-revocation/1";
/// The issuer named in the list when `MERU_CRL_ISSUER` is not set.
pub const DEFAULT_ISSUER: &str = "Product register revocation list (issuer name to confirm)";

/// Why an entry no longer stands (published as the text of [`Reason::text`]).
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

impl Reason {
    /// The reason as published in the list.
    pub fn text(self) -> &'static str {
        match self {
            Reason::ScoreWithdrawn => "score withdrawn",
            Reason::MethodSuperseded => "method superseded",
            Reason::ProductChanged => "product changed",
            Reason::EvidenceError => "evidence error",
            Reason::KeyCompromise => "key compromise",
            Reason::HolderRequest => "holder request",
        }
    }
}

/// A revocation request.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    /// The register entry id (1 to 128 of letters, digits, `.`, `-`, `_`).
    pub id: String,
    /// `YYYY-MM-DD` from which the revocation applies; today when absent.
    #[serde(default)]
    pub revoked: Option<String>,
    pub reason: Reason,
    /// Private note for the log; never published (at most 500 characters).
    #[serde(default)]
    pub note: Option<String>,
}

/// One revocation as it appears in the document (field order is part of the format).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub id: String,
    pub revoked: String,
    pub reason: String,
}

/// The signed document, `kshana.register-crl/1` (field order is part of the format).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrlDoc {
    pub schema: String,
    pub issuer: String,
    pub issued: String,
    pub next_update: String,
    pub revoked: Vec<Revocation>,
    pub signer: String,
    pub signature: String,
}

/// One line of the log: the published revocation, the reason code, who revoked, when, and the
/// private note.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogLine {
    revocation: Revocation,
    reason_code: Reason,
    by_token_id: String,
    logged_utc: String,
    #[serde(default)]
    note: Option<String>,
}

/// Whether `s` is a register entry id: 1 to 128 of letters, digits, `.`, `-`, `_`.
pub fn id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Unix seconds of a `YYYY-MM-DD` calendar date at 00:00 UTC, if it is one.
pub fn date_unix(d: &str) -> Option<i64> {
    let b = d.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let t = crate::cause::parse_iso(&format!("{d}T00:00:00Z")).ok()? as i64;
    // Reject dates the parser normalised (for example 2026-02-30).
    (crate::server::iso(t)[..10] == *d).then_some(t)
}

/// The calendar date (`YYYY-MM-DD`) of Unix seconds.
pub fn date_of(t: i64) -> String {
    crate::server::iso(t)[..10].to_string()
}

fn ascii_text_ok(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max && s.chars().all(|c| (' '..='~').contains(&c))
}

/// The bytes the signature covers: the schema line, then the compact JSON of the document with
/// `signature` empty (field present).
pub fn signing_bytes(doc: &CrlDoc) -> Vec<u8> {
    let mut d = doc.clone();
    d.signature = String::new();
    let mut out = format!("{SCHEMA}\n").into_bytes();
    out.extend(serde_json::to_vec(&d).unwrap_or_default());
    out
}

/// SHA-256 (hex) of a revocation's compact JSON (`{"id","revoked","reason"}`): what the
/// transparency log records.
pub fn record_sha256(r: &Revocation) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(r).unwrap_or_default()))
}

/// SHA-256 (hex) of a document as served (its compact JSON).
pub fn doc_sha256(d: &CrlDoc) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(d).unwrap_or_default()))
}

/// Issue and sign a document.
pub fn issue(
    issuer: &str,
    revoked: &[Revocation],
    signer: &dyn LicenceSigner,
    now: i64,
) -> Result<CrlDoc, String> {
    let day = date_unix(&date_of(now)).unwrap_or(now);
    let mut doc = CrlDoc {
        schema: SCHEMA.into(),
        issuer: issuer.into(),
        issued: date_of(day),
        next_update: date_of(day + VALIDITY_DAYS * 86_400),
        revoked: revoked.to_vec(),
        signer: hex::encode(
            signer
                .public_key()
                .map_err(|e| format!("service key unavailable: {e}"))?,
        ),
        signature: String::new(),
    };
    let sig =
        sign_checked(signer, &signing_bytes(&doc)).map_err(|e| format!("signing failed: {e}"))?;
    doc.signature = hex::encode(sig);
    Ok(doc)
}

/// What a reader gets from a list checked against a given issuer key on a given date.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrlView {
    /// The list is past its `next_update`: report it as stale (its revocations still apply).
    pub stale: bool,
    /// The ids revoked on the date (revocations dated later do not apply yet).
    pub revoked_ids: Vec<String>,
}

/// Check a list the way the open reader does: schema, field rules, the signer equals the issuer
/// key given (any other key is refused), the signature; then what applies on `date`.
pub fn check(doc: &CrlDoc, issuer_key_hex: &str, date: &str) -> Result<CrlView, String> {
    if doc.schema != SCHEMA {
        return Err(format!("not a {SCHEMA} list"));
    }
    let (Some(issued), Some(next), Some(on)) = (
        date_unix(&doc.issued),
        date_unix(&doc.next_update),
        date_unix(date),
    ) else {
        return Err("issued, next_update and the view date must be YYYY-MM-DD".into());
    };
    if next < issued {
        return Err("next_update is before issued".into());
    }
    if doc.issuer.trim().is_empty() {
        return Err("issuer is empty".into());
    }
    for r in &doc.revoked {
        if !id_ok(&r.id) || date_unix(&r.revoked).is_none() || r.reason.trim().is_empty() {
            return Err(format!("revocation {}: bad id, date or reason", r.id));
        }
    }
    if !doc.signer.eq_ignore_ascii_case(issuer_key_hex) {
        return Err("the list is signed by another key than the issuer key given".into());
    }
    let key = hex::decode(&doc.signer)
        .ok()
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
        .and_then(|k| VerifyingKey::from_bytes(&k).ok())
        .ok_or("signer: 64 hex of an Ed25519 public key")?;
    let sig = hex::decode(&doc.signature)
        .ok()
        .and_then(|s| <[u8; 64]>::try_from(s).ok())
        .ok_or("signature: 128 hex")?;
    key.verify(&signing_bytes(doc), &Signature::from_bytes(&sig))
        .map_err(|_| "the signature does not verify".to_string())?;
    Ok(CrlView {
        stale: on > next,
        revoked_ids: doc
            .revoked
            .iter()
            .filter(|r| date_unix(&r.revoked).is_some_and(|t| t <= on))
            .map(|r| r.id.clone())
            .collect(),
    })
}

/// Where the revocations are kept, who may add to them, and the issuer named in the list.
#[derive(Clone, Debug, Default)]
pub struct CrlConfig {
    /// The append-only revocation log. `None`: no list is kept (the endpoints answer 404).
    pub log: Option<PathBuf>,
    /// Token IDs of the operator licences that may revoke.
    pub admins: Vec<String>,
    /// The issuer named in the list (`MERU_CRL_ISSUER`, printable ASCII); [`DEFAULT_ISSUER`]
    /// when empty.
    pub issuer: String,
}

/// The revocations in memory and the last issued document.
pub struct CrlStore {
    path: PathBuf,
    entries: Vec<Revocation>,
    issued: Option<CrlDoc>,
}

/// Read a log line in the earlier format (`product_id`, `scored_under`, `revoked_utc`), mapping
/// it to a revocation of the entry id `product_id`.
fn legacy_line(l: &str) -> Option<Revocation> {
    let v: serde_json::Value = serde_json::from_str(l).ok()?;
    let r = v.get("revoked")?;
    let id = r.get("product_id")?.as_str()?;
    let reason: Reason = serde_json::from_value(r.get("reason")?.clone()).ok()?;
    let utc = r.get("revoked_utc")?.as_str()?;
    (id_ok(id) && utc.len() >= 10).then(|| Revocation {
        id: id.into(),
        revoked: utc[..10].into(),
        reason: reason.text().into(),
    })
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
                let r = match serde_json::from_str::<LogLine>(l) {
                    Ok(line) => line.revocation,
                    Err(e) => legacy_line(l)
                        .ok_or_else(|| format!("{} line {}: {e}", path.display(), i + 1))?,
                };
                entries.push(r);
            }
        }
        Ok(CrlStore {
            path: path.to_path_buf(),
            entries,
            issued: None,
        })
    }

    /// The revocations, in the order they were made.
    pub fn entries(&self) -> &[Revocation] {
        &self.entries
    }

    /// Record a revocation. An id already revoked is refused (the list keeps the first).
    pub fn revoke(
        &mut self,
        r: &RevokeRequest,
        by_token_id: &str,
        now: i64,
    ) -> Result<Revocation, String> {
        if !id_ok(&r.id) {
            return Err("id: 1 to 128 characters of A-Z a-z 0-9 . - _".into());
        }
        let revoked = r.revoked.clone().unwrap_or_else(|| date_of(now));
        if date_unix(&revoked).is_none() {
            return Err("revoked: a calendar date YYYY-MM-DD".into());
        }
        if r.note.as_ref().is_some_and(|n| n.chars().count() > 500) {
            return Err("note: at most 500 characters".into());
        }
        if self.entries.iter().any(|e| e.id == r.id) {
            return Err(format!("already revoked: {}", r.id));
        }
        let rev = Revocation {
            id: r.id.clone(),
            revoked,
            reason: r.reason.text().into(),
        };
        let line = serde_json::to_string(&LogLine {
            revocation: rev.clone(),
            reason_code: r.reason,
            by_token_id: by_token_id.into(),
            logged_utc: crate::server::iso(now),
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
        self.issued = None;
        Ok(rev)
    }

    /// The current signed document: re-issued after a revocation and on each new UTC day.
    pub fn current(
        &mut self,
        issuer: &str,
        signer: &dyn LicenceSigner,
        now: i64,
    ) -> Result<CrlDoc, String> {
        let issuer = if issuer.trim().is_empty() {
            DEFAULT_ISSUER
        } else {
            issuer
        };
        if !ascii_text_ok(issuer, 200) {
            return Err("issuer: 1 to 200 printable ASCII characters".into());
        }
        if let Some(d) = &self.issued {
            if d.issued == date_of(now) && d.issuer == issuer {
                return Ok(d.clone());
            }
        }
        let d = issue(issuer, &self.entries, signer, now)?;
        self.issued = Some(d.clone());
        Ok(d)
    }
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
