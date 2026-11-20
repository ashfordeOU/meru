// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The `archive-seal` method: a signed, chained seal over a period of an evidence archive
//! (research backlog E26, archives; the item text is to confirm).
//!
//! A monitoring network or an evidence holder keeps an archive: observation batches, interference
//! maps, signed dossiers. Years later someone must be able to show that a file was in the archive
//! for a period and has not changed since. The holder sends the names and SHA-256 digests of the
//! period's files; the service returns a signed seal over their Merkle root, chained to the
//! previous seal of the same archive (whose signature the service checks against its own key).
//! The files themselves never leave the holder. Anyone can verify a file's inclusion offline with
//! the leaf and node rule below, the file's audit path and the seal.
//!
//! Merkle rule (`meru-archive-merkle/1`): entries sorted by name (names unique); leaf =
//! SHA-256(0x00 ‖ name ‖ 0x00 ‖ digest bytes); node = SHA-256(0x01 ‖ left ‖ right); a level with
//! an odd count carries its last node up unchanged; the root of one leaf is that leaf.
//!
//! What a seal shows: the service saw these digests under these names at the seal's time, after
//! the previous seal. It does not show the files are correct, and it is not a qualified
//! time-stamp or an archive service in any regulated sense. Evidence class MODELLED.

use crate::cause::Time;
use crate::server::iso;
use crate::verdict::{verify, SignedVerdict};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Method identifier written into every outcome.
pub const METHOD_VERSION: &str = "archive-seal/1";
/// The Merkle rule.
pub const MERKLE_RULE: &str = "meru-archive-merkle/1";

/// One archive entry.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The entry's name in the archive (1 to 512 characters, no control characters).
    pub name: String,
    /// SHA-256 of the file, 64 hex.
    pub sha256: String,
    #[serde(default)]
    pub bytes: Option<u64>,
}

/// Request for the `archive-seal` method.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealRequest {
    /// The archive's identifier (1 to 64 characters of `A-Z a-z 0-9 . _ -`).
    pub archive_id: String,
    pub period_start_utc: Time,
    pub period_end_utc: Time,
    pub entries: Vec<Entry>,
    /// The previous seal of this archive, as the service returned it; absent for the first.
    #[serde(default)]
    pub previous: Option<SignedVerdict>,
}

/// Request limits.
#[derive(Clone, Debug)]
pub struct SealLimits {
    pub max_entries: usize,
}

impl Default for SealLimits {
    fn default() -> Self {
        SealLimits {
            max_entries: 100_000,
        }
    }
}

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut s = Sha256::new();
    for p in parts {
        s.update(p);
    }
    s.finalize().into()
}

/// The leaf of an entry.
pub fn leaf(name: &str, digest: &[u8; 32]) -> [u8; 32] {
    h(&[&[0u8], name.as_bytes(), &[0u8], digest])
}

/// The Merkle root of leaves (in order).
pub fn merkle_root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    let mut level = leaves.to_vec();
    if level.is_empty() {
        return None;
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|c| match c {
                [a, b] => h(&[&[1u8], a, b]),
                [a] => *a,
                _ => unreachable!(),
            })
            .collect();
    }
    level.first().copied()
}

/// The audit path of leaf `index`: (sibling, sibling is on the left) per level where it has one.
pub fn audit_path(leaves: &[[u8; 32]], mut index: usize) -> Vec<([u8; 32], bool)> {
    let mut path = vec![];
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let sib = index ^ 1;
        if sib < level.len() {
            path.push((level[sib], sib < index));
        }
        level = level
            .chunks(2)
            .map(|c| match c {
                [a, b] => h(&[&[1u8], a, b]),
                [a] => *a,
                _ => unreachable!(),
            })
            .collect();
        index /= 2;
    }
    path
}

/// Recompute the root from a leaf and its audit path.
pub fn root_from_path(leaf: [u8; 32], path: &[([u8; 32], bool)]) -> [u8; 32] {
    path.iter().fold(leaf, |acc, (s, left)| {
        if *left {
            h(&[&[1u8], s, &acc])
        } else {
            h(&[&[1u8], &acc, s])
        }
    })
}

fn ident_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Run the method; the raw (unsigned) outcome. `service_key` (hex) is this service's verdict key.
pub fn analyse(r: &SealRequest, l: &SealLimits, service_key: &str) -> Result<Value, String> {
    if !ident_ok(&r.archive_id) {
        return Err("archive_id: 1 to 64 characters of A-Z a-z 0-9 . _ -".into());
    }
    let (p0, p1) = (r.period_start_utc.secs()?, r.period_end_utc.secs()?);
    if p1 <= p0 {
        return Err("the period must end after it starts".into());
    }
    if r.entries.is_empty() || r.entries.len() > l.max_entries {
        return Err(format!("1 to {} entries", l.max_entries));
    }
    let mut ents: Vec<(&str, [u8; 32], Option<u64>)> = Vec::with_capacity(r.entries.len());
    for e in &r.entries {
        if e.name.is_empty() || e.name.len() > 512 || e.name.chars().any(char::is_control) {
            return Err(format!(
                "entry name '{}': 1 to 512 characters, no control characters",
                e.name.chars().take(40).collect::<String>()
            ));
        }
        let d = hex::decode(&e.sha256)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| format!("entry '{}': sha256 must be 64 hex", e.name))?;
        ents.push((e.name.as_str(), d, e.bytes));
    }
    ents.sort_by(|a, b| a.0.cmp(b.0));
    if let Some(w) = ents.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(format!("entry '{}' listed twice", w[0].0));
    }
    let leaves: Vec<[u8; 32]> = ents.iter().map(|(n, d, _)| leaf(n, d)).collect();
    let root = merkle_root(&leaves).ok_or("no entries")?;
    // The chain.
    let (seq, prev) = match &r.previous {
        None => (1u64, Value::Null),
        Some(p) => {
            let problems = verify(p, service_key);
            if !problems.is_empty() {
                return Err(format!(
                    "previous: not a seal of this service: {}",
                    problems.join("; ")
                ));
            }
            if p.method != "archive-seal" {
                return Err("previous: not an archive-seal verdict".into());
            }
            let o = &p.verdict;
            if o["archive_id"] != json!(r.archive_id) {
                return Err("previous: a seal of another archive".into());
            }
            let pend = o["period"][1]
                .as_str()
                .ok_or("previous: no period")
                .and_then(|s| crate::cause::parse_iso(s).map_err(|_| "previous: bad period"))?;
            if p0 < pend {
                return Err(format!(
                    "the period starts before the previous seal's period ends ({})",
                    o["period"][1]
                ));
            }
            let seq = o["seq"].as_u64().ok_or("previous: no sequence number")? + 1;
            (
                seq,
                json!({"verdict_sha256": p.verdict_sha256, "merkle_root": o["merkle_root"], "seq": o["seq"]}),
            )
        }
    };
    let bytes: Option<u64> = ents
        .iter()
        .map(|e| e.2)
        .try_fold(0u64, |a, b| b.map(|b| a.saturating_add(b)));
    Ok(json!({
        "method_version": METHOD_VERSION,
        "archive_id": r.archive_id,
        "seq": seq,
        "period": [iso(p0.floor() as i64), iso(p1.ceil() as i64)],
        "entries": ents.len(),
        "total_bytes": bytes,
        "merkle_rule": MERKLE_RULE,
        "merkle_root": hex::encode(root),
        "first_entry": ents.first().map(|e| e.0),
        "last_entry": ents.last().map(|e| e.0),
        "previous": prev,
        "statement": "The service saw these digests under these names at the seal's time, after the previous seal. A seal does not show that the files are correct; it is not a qualified time-stamp.",
    }))
}

/// Run the `archive-seal` method and return a signed verdict. Not rounded in any way that
/// matters: the outcome holds digests, counts and names.
pub fn seal_verdict(
    req: &SealRequest,
    s: &crate::methods::Signing,
    limits: &SealLimits,
    utc: &str,
) -> Result<SignedVerdict, String> {
    let pk = s
        .signer
        .public_key()
        .map_err(|e| format!("service key unavailable: {e}"))?;
    let v = analyse(req, limits, &hex::encode(pk))?;
    crate::methods::finish("archive-seal", v, s, utc)
}

#[cfg(test)]
#[path = "archive_seal_tests.rs"]
mod tests;
