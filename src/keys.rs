// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! Publication of the service's verification key, with an auditable key history (B2502).
//!
//! `GET /keys` answers every verdict-signing key the service has used: its key ID, the Ed25519
//! public key and its validity period, plus the key history it came from. An offline verifier
//! checks signed verdicts (tree heads, daily roots, any method) against these keys.
//!
//! The key history (`MERU_KEY_HISTORY`, JSON Lines, append-only) has one record per key, in
//! order (`meru-key-history/1`): sequence number, key ID, public key, `not_before`, and the
//! SHA-256 of the previous record. Each record is signed by the key it introduces (showing the
//! service held that key) and, when the operator supplies it at rotation, endorsed by the
//! previous key (`meru key-endorse`, run with the outgoing key, prints the endorsement; the new
//! deployment receives it as `MERU_KEY_ENDORSEMENT`). A key's validity ends where the next
//! record's begins. At start the service appends a record when its key is not the last one in
//! the history, and refuses to start on a history that does not verify. A rotation without an
//! endorsement is recorded as such (`previous_key_endorsement: null`), so it stays visible.

use crate::verdict::{sign, SignedVerdict};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use kshana_pro::license::signer::{sign_checked, LicenceSigner};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

/// Format of a key-history record.
pub const HISTORY_FORMAT: &str = "meru-key-history/1";
/// Format of the statement the previous key signs at a rotation.
pub const ENDORSEMENT_FORMAT: &str = "meru-key-endorsement/1";
/// Format of the published key set.
pub const KEYS_FORMAT: &str = "meru-service-keys/1";

/// One line of the key history.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryLine {
    /// The record (`meru-key-history/1`); its canonical JSON (sorted keys, no whitespace) is
    /// what is hashed and signed.
    pub record: Value,
    /// SHA-256 of the record's canonical JSON.
    pub record_sha256: String,
    /// Ed25519 signature (hex) over the canonical record by the key it introduces.
    pub signature: String,
    /// Ed25519 signature (hex) by the previous key over the endorsement statement, or null.
    pub previous_key_endorsement: Option<String>,
}

fn canonical(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

fn verify_sig(public_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (hex::decode(public_hex), hex::decode(sig_hex)) else {
        return false;
    };
    let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(pk), <[u8; 64]>::try_from(sig)) else {
        return false;
    };
    VerifyingKey::from_bytes(&pk)
        .map(|k| k.verify(msg, &Signature::from_bytes(&sig)).is_ok())
        .unwrap_or(false)
}

/// The statement the previous key signs to endorse the next one (canonical JSON).
pub fn endorsement_statement(
    previous_key_id: &str,
    next_key_id: &str,
    next_public: &str,
) -> Vec<u8> {
    canonical(&json!({
        "format": ENDORSEMENT_FORMAT,
        "previous_key_id": previous_key_id,
        "next_key_id": next_key_id,
        "next_public_key": next_public.to_ascii_lowercase(),
    }))
}

/// Endorse the next key with this (outgoing) signer: the hex signature over the statement.
pub fn endorse(
    signer: &dyn LicenceSigner,
    own_key_id: &str,
    next_key_id: &str,
    next_public: &str,
) -> Result<String, String> {
    let next = hex::decode(next_public).map_err(|_| "next public key: 64 hex")?;
    if next.len() != 32 {
        return Err("next public key: 64 hex".into());
    }
    let sig = sign_checked(
        signer,
        &endorsement_statement(own_key_id, next_key_id, next_public),
    )
    .map_err(|e| format!("signing failed: {e}"))?;
    Ok(hex::encode(sig))
}

/// Read and verify a key history: record hashes, sequence, the hash chain, each record's own
/// signature and each endorsement present. An absent file is an empty history.
pub fn read(path: &Path) -> Result<Vec<HistoryLine>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(format!("key history: {e}")),
    };
    let mut out: Vec<HistoryLine> = vec![];
    for (n, l) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let bad = |what: &str| format!("key history line {}: {what}", n + 1);
        let line: HistoryLine = serde_json::from_str(l).map_err(|e| bad(&e.to_string()))?;
        let r = &line.record;
        let c = canonical(r);
        if hex::encode(Sha256::digest(&c)) != line.record_sha256 {
            return Err(bad("record_sha256 does not match the record"));
        }
        let prev_sha = out
            .last()
            .map(|p| p.record_sha256.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let s = |k: &str| r[k].as_str().unwrap_or("").to_string();
        if r["format"] != HISTORY_FORMAT
            || r["seq"].as_u64() != Some(n as u64)
            || s("algorithm") != "Ed25519"
            || s("previous_record_sha256") != prev_sha
        {
            return Err(bad("format, sequence or previous_record_sha256 is wrong"));
        }
        let pk = s("public_key");
        if !verify_sig(&pk, &c, &line.signature) {
            return Err(bad("the record is not signed by the key it introduces"));
        }
        if let Some(prev) = out.last() {
            let pr = &prev.record;
            if r["previous_key_id"] != pr["key_id"]
                || s("not_before").as_str() <= pr["not_before"].as_str().unwrap_or("")
            {
                return Err(bad(
                    "previous_key_id or not_before does not follow the previous record",
                ));
            }
            if let Some(e) = &line.previous_key_endorsement {
                let st =
                    endorsement_statement(pr["key_id"].as_str().unwrap_or(""), &s("key_id"), &pk);
                if !verify_sig(pr["public_key"].as_str().unwrap_or(""), &st, e) {
                    return Err(bad(
                        "the endorsement does not verify against the previous key",
                    ));
                }
            }
        } else if !r["previous_key_id"].is_null() || line.previous_key_endorsement.is_some() {
            return Err(bad("the first record has no previous key"));
        }
        out.push(line);
    }
    Ok(out)
}

/// Make sure the history ends with this signer's key: append a record when it does not. The
/// endorsement (hex, by the previous key) is checked before anything is written. Answers the
/// verified history.
pub fn ensure_current(
    path: &Path,
    signer: &dyn LicenceSigner,
    key_id: &str,
    utc: &str,
    endorsement: Option<&str>,
) -> Result<Vec<HistoryLine>, String> {
    let mut h = read(path)?;
    let pk = hex::encode(
        signer
            .public_key()
            .map_err(|e| format!("service key unavailable: {e}"))?,
    );
    if let Some(last) = h.last() {
        if last.record["public_key"] == pk.as_str() {
            if last.record["key_id"] != key_id {
                return Err(format!(
                    "key history: this key is recorded as key ID {}, not {key_id}",
                    last.record["key_id"]
                ));
            }
            return Ok(h);
        }
        if h.iter()
            .any(|l| l.record["public_key"] == pk.as_str() || l.record["key_id"] == key_id)
        {
            return Err("key history: a retired key or key ID may not come back".into());
        }
    }
    let prev = h.last().map(|l| l.record.clone());
    if let (Some(e), Some(p)) = (endorsement, &prev) {
        let st = endorsement_statement(p["key_id"].as_str().unwrap_or(""), key_id, &pk);
        if !verify_sig(p["public_key"].as_str().unwrap_or(""), &st, e) {
            return Err("MERU_KEY_ENDORSEMENT does not verify against the previous key".into());
        }
    }
    let record = json!({
        "format": HISTORY_FORMAT,
        "seq": h.len(),
        "key_id": key_id,
        "algorithm": "Ed25519",
        "public_key": pk,
        "not_before": utc,
        "previous_key_id": prev.as_ref().map(|p| p["key_id"].clone()),
        "previous_record_sha256": h.last().map(|l| l.record_sha256.clone()).unwrap_or_else(|| "0".repeat(64)),
    });
    let c = canonical(&record);
    let sig = sign_checked(signer, &c).map_err(|e| format!("signing failed: {e}"))?;
    let line = HistoryLine {
        record,
        record_sha256: hex::encode(Sha256::digest(&c)),
        signature: hex::encode(sig),
        previous_key_endorsement: if prev.is_some() {
            endorsement.map(str::to_string)
        } else {
            None
        },
    };
    let text = serde_json::to_string(&line).map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("key history: {e}"))?;
    writeln!(f, "{text}")
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("key history: {e}"))?;
    h.push(line);
    Ok(h)
}

/// The published key set, signed with the current key (method `service-keys`, evidence
/// `RECORD`). Without a history file only the current key is given, with no validity period.
pub fn published(
    history: Option<&Path>,
    signer: &dyn LicenceSigner,
    key_id: &str,
    utc: &str,
) -> Result<SignedVerdict, String> {
    let pk = hex::encode(
        signer
            .public_key()
            .map_err(|e| format!("service key unavailable: {e}"))?,
    );
    let body = match history {
        Some(p) => {
            let h = read(p)?;
            let keys: Vec<Value> = h
                .iter()
                .enumerate()
                .map(|(i, l)| {
                    let next = h.get(i + 1).map(|n| n.record["not_before"].clone());
                    json!({
                        "key_id": l.record["key_id"],
                        "algorithm": "Ed25519",
                        "public_key": l.record["public_key"],
                        "not_before": l.record["not_before"],
                        "not_after": next.unwrap_or(Value::Null),
                        "status": if i + 1 == h.len() { "current" } else { "retired" },
                        "endorsed_by_previous_key": i > 0 && l.previous_key_endorsement.is_some(),
                    })
                })
                .collect();
            if h.last()
                .map(|l| l.record["public_key"] != pk.as_str())
                .unwrap_or(true)
            {
                return Err("key history does not end with the key in use".into());
            }
            json!({
                "format": KEYS_FORMAT,
                "current_key_id": key_id,
                "keys": keys,
                "history": h,
                "history_head_sha256": h.last().map(|l| l.record_sha256.clone()),
            })
        }
        None => json!({
            "format": KEYS_FORMAT,
            "current_key_id": key_id,
            "keys": [{"key_id": key_id, "algorithm": "Ed25519", "public_key": pk,
                      "not_before": null, "not_after": null, "status": "current",
                      "endorsed_by_previous_key": false}],
            "history": [],
            "history_head_sha256": null,
            "note": "no key history is kept by this instance (MERU_KEY_HISTORY unset): validity period not recorded",
        }),
    };
    sign("service-keys", "RECORD", body, signer, key_id, utc)
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
