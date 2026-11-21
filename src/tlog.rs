// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! An append-only transparency log for signed evidence packs (research backlog E25, B2502).
//!
//! A holder of a signed evidence pack (a Kshana dossier, an attestation directory, a verdict)
//! appends the pack's SHA-256 to the log; the log answers with the entry's index, an inclusion
//! proof and a signed tree head. Anyone can later check, offline, that the pack was logged and
//! that the log has only ever grown: the log never returns pack contents, only hashes.
//!
//! * **Merkle tree**, as RFC 6962 / RFC 9162 define it: leaf hash = SHA-256(0x00 ‖ leaf data),
//!   node = SHA-256(0x01 ‖ left ‖ right), split at the largest power of two below the size; the
//!   leaf data is the entry's canonical JSON. Inclusion proofs (audit paths) and consistency proofs
//!   between any two sizes, with their verifiers ([`verify_inclusion`], [`verify_consistency`]).
//! * **Hash chain** on top: chain(i) = SHA-256(0x02 ‖ chain(i−1) ‖ leaf hash(i)), chain(−1) = 32
//!   zero bytes. The log file (`MERU_TLOG_PATH`, JSON Lines) is append-only; at start every line's
//!   leaf hash and chain value are recomputed and a mismatch refuses the log.
//! * **Signed tree head** (`meru-tlog-sth/1`): size, root, chain head, time, as a signed verdict
//!   (method `tlog-sth`, evidence class `RECORD`) the Pro verdict client verifies.
//! * **Anchoring by two authorities**: the tree head is meant to be anchored with two independent
//!   authorities (for example an RFC 3161 time-stamp authority and a public ledger). Which
//!   authorities, and how, is to confirm; this build carries the interface ([`Anchor`]) and two
//!   placeholders that anchor nothing and say so (`not_anchored`) in every tree head.
//!
//! What an entry shows: that this hash was submitted at that time and has been in the log since.
//! It says nothing about whether the pack is correct.

use crate::server::iso;
use crate::verdict::{sign, SignedVerdict};
use kshana_pro::license::signer::LicenceSigner;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Format of a signed tree head body.
pub const STH_FORMAT: &str = "meru-tlog-sth/1";

type H = [u8; 32];

fn sha(parts: &[&[u8]]) -> H {
    let mut s = Sha256::new();
    for p in parts {
        s.update(p);
    }
    s.finalize().into()
}

fn node(l: &H, r: &H) -> H {
    sha(&[&[1u8], l, r])
}

/// The leaf hash of leaf data.
pub fn leaf_hash(data: &[u8]) -> H {
    sha(&[&[0u8], data])
}

/// The largest power of two strictly below `n` (n ≥ 2).
fn split(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// The Merkle tree hash of leaf hashes (RFC 6962 MTH; the empty tree hashes the empty string).
pub fn root(leaves: &[H]) -> H {
    match leaves.len() {
        0 => sha(&[]),
        1 => leaves[0],
        n => {
            let k = split(n);
            node(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// The inclusion proof (audit path) of leaf `m` in the tree of `leaves`.
pub fn inclusion_path(m: usize, leaves: &[H]) -> Vec<H> {
    let n = leaves.len();
    if n <= 1 {
        return vec![];
    }
    let k = split(n);
    if m < k {
        let mut p = inclusion_path(m, &leaves[..k]);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = inclusion_path(m - k, &leaves[k..]);
        p.push(root(&leaves[..k]));
        p
    }
}

/// Verify an inclusion proof (RFC 9162 §2.1.3.2).
pub fn verify_inclusion(index: usize, size: usize, leaf: &H, path: &[H], root_hash: &H) -> bool {
    if index >= size {
        return false;
    }
    let (mut f, mut s) = (index, size - 1);
    let mut r = *leaf;
    for p in path {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            r = node(p, &r);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            r = node(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && &r == root_hash
}

fn subproof(m: usize, leaves: &[H], whole: bool) -> Vec<H> {
    let n = leaves.len();
    if m == n {
        return if whole { vec![] } else { vec![root(leaves)] };
    }
    let k = split(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], whole);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(root(&leaves[..k]));
        p
    }
}

/// The consistency proof between the tree of the first `m` leaves and the tree of all `leaves`.
pub fn consistency_path(m: usize, leaves: &[H]) -> Vec<H> {
    if m == 0 || m >= leaves.len() {
        return vec![];
    }
    subproof(m, leaves, true)
}

/// Verify a consistency proof (RFC 9162 §2.1.4.2).
pub fn verify_consistency(
    first: usize,
    second: usize,
    first_hash: &H,
    second_hash: &H,
    path: &[H],
) -> bool {
    if first == 0 || first > second {
        return false;
    }
    if first == second {
        return path.is_empty() && first_hash == second_hash;
    }
    let mut p: Vec<H> = path.to_vec();
    if first.is_power_of_two() {
        p.insert(0, *first_hash);
    }
    let Some((head, rest)) = p.split_first() else {
        return false;
    };
    let (mut f, mut s) = (first - 1, second - 1);
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let (mut fr, mut sr) = (*head, *head);
    for c in rest {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            fr = node(c, &fr);
            sr = node(c, &sr);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            sr = node(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    &fr == first_hash && &sr == second_hash && s == 0
}

fn chain_next(prev: &H, leaf: &H) -> H {
    sha(&[&[2u8], prev, leaf])
}

// ------------------------------------------------------------------------------------------
// Entries and the log
// ------------------------------------------------------------------------------------------

/// What a holder appends.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendRequest {
    /// SHA-256 of the signed evidence pack (or of its signature file), 64 hex.
    pub pack_sha256: String,
    /// What the pack is (for example `kshana-dossier/1`, `kshana-pro-utm-attestation/1`,
    /// `meru-verdict`), 1 to 64 characters of `A-Z a-z 0-9 . _ - /`.
    pub kind: String,
    /// The key ID that signed the pack, when known.
    #[serde(default)]
    pub signer_key_id: Option<String>,
    /// `evidence_pack` (default) or `calibration_record` (the hash of a calibration record, for
    /// example a signed delay-calibration or receiver-scorecard result).
    #[serde(default)]
    pub class: Option<String>,
}

/// The entry classes.
pub const CLASSES: &[&str] = &["evidence_pack", "calibration_record"];

/// One entry as published (the leaf data is its canonical JSON).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub pack_sha256: String,
    pub kind: String,
    #[serde(default)]
    pub signer_key_id: Option<String>,
    pub logged_utc: String,
    /// The entry class, when given (absent in entries logged before classes existed, so their
    /// leaf data is unchanged).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
}

impl Entry {
    fn data(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// One line of the log file.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    index: usize,
    entry: Entry,
    leaf_hash: String,
    chain: String,
    /// The submitting licence, pseudonymised (`h:` and 16 hex of SHA-256 of the token ID).
    submitter: String,
}

fn ident_ok(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':'))
}

fn hex32(s: &str) -> Option<H> {
    hex::decode(s).ok().and_then(|b| <H>::try_from(b).ok())
}

/// An anchoring authority for tree heads.
pub trait Anchor: Send + Sync {
    /// The authority's name as configured.
    fn authority(&self) -> &str;
    /// Anchor a signed tree head; the receipt says whether it was anchored.
    fn anchor(&self, sth: &Value) -> Value;
}

/// A placeholder authority: anchors nothing, sends nothing, and says so.
pub struct PlaceholderAnchor {
    pub name: String,
}

impl Anchor for PlaceholderAnchor {
    fn authority(&self) -> &str {
        &self.name
    }
    fn anchor(&self, _sth: &Value) -> Value {
        json!({
            "authority": self.name,
            "status": "not_anchored",
            "note": "placeholder: the authority and its protocol are to confirm; nothing was sent",
        })
    }
}

/// Where the log lives and who anchors it.
#[derive(Clone, Debug, Default)]
pub struct TlogConfig {
    /// The append-only log file. `None`: no log is kept (the endpoints answer 404).
    pub path: Option<PathBuf>,
    /// Names of the two anchoring authorities (placeholders in this build).
    pub anchors: Vec<String>,
    /// Up to two RFC 3161 time-stamp authorities for the daily root: (name, https URL, PEM file
    /// of the trusted anchor). Empty: none configured.
    pub tsas: Vec<(String, String, PathBuf)>,
}

/// The log in memory.
pub struct Tlog {
    path: PathBuf,
    entries: Vec<Entry>,
    leaves: Vec<H>,
    chain: H,
    /// The chain value after each entry.
    chains: Vec<H>,
    anchors: Vec<Box<dyn Anchor>>,
    /// The daily root's time-stamp authorities.
    stampers: Vec<Box<dyn crate::tlog_tsa::TimeStamper>>,
}

impl Tlog {
    /// Open the log file, recomputing every leaf hash and chain value.
    pub fn open(path: &Path, anchors: Vec<Box<dyn Anchor>>) -> Result<Tlog, String> {
        let mut t = Tlog {
            path: path.to_path_buf(),
            entries: vec![],
            leaves: vec![],
            chain: [0u8; 32],
            chains: vec![],
            anchors,
            stampers: vec![],
        };
        if path.exists() {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            for (i, l) in text.lines().enumerate() {
                if l.trim().is_empty() {
                    continue;
                }
                let line: Line = serde_json::from_str(l)
                    .map_err(|e| format!("{} line {}: {e}", path.display(), i + 1))?;
                let lh = leaf_hash(&line.entry.data());
                let ch = chain_next(&t.chain, &lh);
                if line.index != t.entries.len()
                    || hex::encode(lh) != line.leaf_hash
                    || hex::encode(ch) != line.chain
                {
                    return Err(format!(
                        "{} line {}: the log does not recompute (index, leaf hash or chain): refusing it",
                        path.display(),
                        i + 1
                    ));
                }
                t.entries.push(line.entry);
                t.leaves.push(lh);
                t.chain = ch;
                t.chains.push(ch);
            }
        }
        Ok(t)
    }

    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    /// The index of a pack already logged.
    pub fn find(&self, pack_sha256: &str) -> Option<usize> {
        let p = pack_sha256.to_ascii_lowercase();
        self.entries.iter().position(|e| e.pack_sha256 == p)
    }

    /// Append a pack (or return the index it already has, and `false`).
    pub fn append(
        &mut self,
        r: &AppendRequest,
        token_id: &str,
        utc: &str,
    ) -> Result<(usize, bool), String> {
        if hex32(&r.pack_sha256).is_none() {
            return Err("pack_sha256 must be 64 hex".into());
        }
        if !ident_ok(&r.kind, 64) {
            return Err("kind: 1 to 64 characters of A-Z a-z 0-9 . _ - / :".into());
        }
        if r.class
            .as_ref()
            .is_some_and(|c| !CLASSES.contains(&c.as_str()))
        {
            return Err(format!("class: one of {}", CLASSES.join(", ")));
        }
        if r.signer_key_id.as_ref().is_some_and(|k| !ident_ok(k, 128)) {
            return Err("signer_key_id: 1 to 128 characters of A-Z a-z 0-9 . _ - / :".into());
        }
        if let Some(i) = self.find(&r.pack_sha256) {
            return Ok((i, false));
        }
        let entry = Entry {
            pack_sha256: r.pack_sha256.to_ascii_lowercase(),
            kind: r.kind.clone(),
            signer_key_id: r.signer_key_id.clone(),
            logged_utc: utc.into(),
            class: r.class.clone(),
        };
        let lh = leaf_hash(&entry.data());
        let ch = chain_next(&self.chain, &lh);
        let line = Line {
            index: self.entries.len(),
            entry: entry.clone(),
            leaf_hash: hex::encode(lh),
            chain: hex::encode(ch),
            submitter: format!(
                "h:{}",
                &hex::encode(Sha256::digest(token_id.as_bytes()))[..16]
            ),
        };
        let text = serde_json::to_string(&line).map_err(|e| e.to_string())?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("transparency log: {e}"))?;
        writeln!(f, "{text}")
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("transparency log: {e}"))?;
        self.entries.push(entry);
        self.leaves.push(lh);
        self.chain = ch;
        self.chains.push(ch);
        Ok((self.entries.len() - 1, true))
    }

    /// The entry and its leaf hash.
    pub fn entry(&self, i: usize) -> Option<Value> {
        let e = self.entries.get(i)?;
        Some(json!({"index": i, "entry": e, "leaf_hash": hex::encode(self.leaves[i])}))
    }

    /// The inclusion proof of `index` in the tree of the first `size` leaves.
    pub fn proof(&self, index: usize, size: usize) -> Result<Value, String> {
        if size == 0 || size > self.size() || index >= size {
            return Err(format!(
                "index must be below size, and size within 1 to {}",
                self.size()
            ));
        }
        let path = inclusion_path(index, &self.leaves[..size]);
        Ok(json!({
            "index": index,
            "size": size,
            "leaf_hash": hex::encode(self.leaves[index]),
            "root_hash": hex::encode(root(&self.leaves[..size])),
            "path": path.iter().map(hex::encode).collect::<Vec<_>>(),
        }))
    }

    /// The consistency proof between sizes `from` and `to`.
    pub fn consistency(&self, from: usize, to: usize) -> Result<Value, String> {
        if from == 0 || from > to || to > self.size() {
            return Err(format!("need 1 ≤ from ≤ to ≤ {}", self.size()));
        }
        let path = consistency_path(from, &self.leaves[..to]);
        Ok(json!({
            "from": from,
            "to": to,
            "from_root": hex::encode(root(&self.leaves[..from])),
            "to_root": hex::encode(root(&self.leaves[..to])),
            "path": path.iter().map(hex::encode).collect::<Vec<_>>(),
        }))
    }

    /// The signed tree head now.
    pub fn sth(
        &self,
        signer: &dyn LicenceSigner,
        key_id: &str,
        now: i64,
    ) -> Result<SignedVerdict, String> {
        let mut body = json!({
            "format": STH_FORMAT,
            "log_key_id": key_id,
            "size": self.size(),
            "root_hash": hex::encode(root(&self.leaves)),
            "chain_head": hex::encode(self.chain),
            "timestamp_utc": iso(now),
            "merkle": "RFC 6962 tree hash; leaf data is the entry's canonical JSON",
            "statement": "Each entry shows a hash was submitted at that time and has been in the log since; it says nothing about whether the pack is correct.",
        });
        let receipts: Vec<Value> = self.anchors.iter().map(|a| a.anchor(&body)).collect();
        body["anchors"] = json!(receipts);
        sign("tlog-sth", "RECORD", body, signer, key_id, &iso(now))
    }
}

impl Tlog {
    /// Set the daily root's time-stamp authorities.
    pub fn set_stampers(&mut self, s: Vec<Box<dyn crate::tlog_tsa::TimeStamper>>) {
        self.stampers = s;
    }

    /// The daily root of a completed UTC day (`YYYY-MM-DD`, before the day of `now`): the log as
    /// it stood at the end of that day. Its canonical JSON is what the authorities stamp.
    pub fn daily_root(&self, date: &str, key_id: &str, now: i64) -> Result<Value, String> {
        let start = crate::cause::parse_iso(&format!("{date}T00:00:00Z"))
            .map_err(|_| "date: YYYY-MM-DD".to_string())?;
        let end = start + 86_400.0;
        if end > now as f64 {
            return Err("the daily root is given only for a completed UTC day".into());
        }
        let size = self
            .entries
            .iter()
            .take_while(|e| crate::cause::parse_iso(&e.logged_utc).is_ok_and(|t| t < end))
            .count();
        Ok(json!({
            "format": DAILY_FORMAT,
            "log_key_id": key_id,
            "date": date,
            "size": size,
            "root_hash": hex::encode(root(&self.leaves[..size])),
            "chain_head": hex::encode(if size == 0 { [0u8; 32] } else { self.chains[size - 1] }),
        }))
    }

    /// The signed daily root, time-stamped by every configured authority (stamped once, then the
    /// kept token is reported).
    pub fn daily(
        &self,
        log: &Path,
        date: &str,
        signer: &dyn LicenceSigner,
        key_id: &str,
        now: i64,
    ) -> Result<SignedVerdict, String> {
        let body = self.daily_root(date, key_id, now)?;
        let canonical = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
        let receipts = crate::tlog_tsa::stamp_and_report(log, date, &canonical, &self.stampers);
        let out = json!({
            "daily_root": body,
            "daily_root_sha256": hex::encode(sha(&[&canonical])),
            "timestamps": receipts,
            "anchoring": if self.stampers.is_empty() { crate::tlog_tsa::NO_PROVIDER } else { "RFC 3161 time-stamps by the authorities listed; check each token against its authority's certificate" },
            "statement": "The log as it stood at the end of the day. A time-stamp shows the root existed by the stated time; it says nothing about whether any pack is correct.",
        });
        sign("tlog-daily-root", "RECORD", out, signer, key_id, &iso(now))
    }
}

/// Format of the daily root.
pub const DAILY_FORMAT: &str = "meru-tlog-daily-root/1";

/// Default anchor slots: two placeholders.
pub fn anchors_from(names: &[String]) -> Vec<Box<dyn Anchor>> {
    let mut v: Vec<String> = names.to_vec();
    let defaults = ["authority-a (to confirm)", "authority-b (to confirm)"];
    while v.len() < 2 {
        v.push(defaults[v.len()].to_string());
    }
    v.into_iter()
        .map(|name| Box::new(PlaceholderAnchor { name }) as Box<dyn Anchor>)
        .collect()
}

/// The log behind the endpoints, opened on first use.
#[derive(Default)]
pub struct SharedTlog {
    inner: Mutex<Option<Tlog>>,
}

impl SharedTlog {
    /// Run `f` on the log (opened from `cfg.path` on first use).
    pub fn with<T>(
        &self,
        cfg: &TlogConfig,
        f: impl FnOnce(&mut Tlog) -> Result<T, String>,
    ) -> Result<T, String> {
        let path = cfg
            .path
            .as_ref()
            .ok_or("no transparency log is kept by this service")?;
        let mut g = self
            .inner
            .lock()
            .map_err(|_| "transparency log lock poisoned")?;
        if g.is_none() {
            let mut t = Tlog::open(path, anchors_from(&cfg.anchors))?;
            let mut st: Vec<Box<dyn crate::tlog_tsa::TimeStamper>> = vec![];
            for (name, url, anchor) in cfg.tsas.iter().take(2) {
                st.push(Box::new(crate::tlog_tsa::HttpTsa::new(name, url, anchor)?));
            }
            t.set_stampers(st);
            *g = Some(t);
        }
        f(g.as_mut().expect("opened above"))
    }

    /// Replace the daily root's time-stamp authorities (the configured ones are set on first open).
    pub fn set_stampers(
        &self,
        cfg: &TlogConfig,
        st: Vec<Box<dyn crate::tlog_tsa::TimeStamper>>,
    ) -> Result<(), String> {
        self.with(cfg, |t| {
            t.set_stampers(st);
            Ok(())
        })
    }
}

/// Parse `a=1&b=2` into numbers by name.
pub fn query_num(query: &str, name: &str) -> Option<usize> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == name)
        .and_then(|(_, v)| v.parse().ok())
}

/// Parse `a=x` by name.
pub fn query_str<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// Decode hex hashes from a proof's `path`.
pub fn path_of(v: &Value) -> Option<Vec<H>> {
    v["path"]
        .as_array()?
        .iter()
        .map(|x| x.as_str().and_then(hex32))
        .collect()
}

/// Decode one hex hash field.
pub fn hash_of(v: &Value, k: &str) -> Option<H> {
    v[k].as_str().and_then(hex32)
}

#[cfg(test)]
#[path = "tlog_tests.rs"]
mod tests;
