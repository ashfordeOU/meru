// PROPRIETARY — Kshana Core (meru). Trade secret. Never shipped to customers; runs only in
// Ashforde's hosted Kshana service and vetted Sovereign deployments. See NOTICE.
//
//! The signed verdict: the only thing a Core call returns. The outcome and its evidence
//! class, with an Ed25519 signature over the canonical body, and nothing else. Intermediate
//! values, per-iteration traces, tuning and model internals never leave the service.

use kshana_pro::license::signer::{sign_checked, LicenceSigner};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Service identifier placed in every verdict (codename, versioned).
pub const SERVICE: &str = "meru/1";

/// A signed Core verdict.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedVerdict {
    pub service: String,
    pub method: String,
    /// Evidence class of the outcome (MODELLED, VALIDATED, ...).
    pub evidence_class: String,
    pub utc: String,
    pub key_id: String,
    /// The outcome. Outcomes only: no internals, traces or tuning.
    pub verdict: Value,
    /// SHA-256 over the canonical signed body (every field above `signature`).
    pub verdict_sha256: String,
    /// Ed25519 signature (hex) over the same canonical body.
    pub signature: String,
}

fn canonical(
    service: &str,
    method: &str,
    evidence: &str,
    utc: &str,
    key_id: &str,
    verdict: &Value,
) -> Vec<u8> {
    // Field order fixed here, not by map iteration, so the bytes are stable.
    let body = json!({
        "service": service,
        "method": method,
        "evidence_class": evidence,
        "utc": utc,
        "key_id": key_id,
        "verdict": verdict,
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

/// Sign an outcome into a [`SignedVerdict`] with the service signer (a raw seed or a key held
/// in a cloud key vault, [`crate::signer`]). Every signature is checked against the signer's
/// own public key before it leaves, so a misbehaving remote signer is caught here.
pub(crate) fn sign(
    method: &str,
    evidence: &str,
    verdict: Value,
    signer: &dyn LicenceSigner,
    key_id: &str,
    utc: &str,
) -> Result<SignedVerdict, String> {
    let body = canonical(SERVICE, method, evidence, utc, key_id, &verdict);
    let sig = sign_checked(signer, &body).map_err(|e| format!("signing failed: {e}"))?;
    Ok(SignedVerdict {
        service: SERVICE.into(),
        method: method.into(),
        evidence_class: evidence.into(),
        utc: utc.into(),
        key_id: key_id.into(),
        verdict,
        verdict_sha256: hex::encode(Sha256::digest(&body)),
        signature: hex::encode(sig),
    })
}

/// Verify a signed verdict against a public key (hex). Returns the problems (empty = valid).
/// The customer runs this to trust a verdict without ever seeing how it was produced.
pub fn verify(v: &SignedVerdict, public_key_hex: &str) -> Vec<String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let mut problems = vec![];
    let body = canonical(
        &v.service,
        &v.method,
        &v.evidence_class,
        &v.utc,
        &v.key_id,
        &v.verdict,
    );
    if hex::encode(Sha256::digest(&body)) != v.verdict_sha256 {
        problems.push("verdict hash does not match the signed body".into());
    }
    let pk = match hex::decode(public_key_hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
    {
        Some(k) => k,
        None => {
            problems.push("public key is not 32 valid Ed25519 bytes".into());
            return problems;
        }
    };
    let sig = match hex::decode(&v.signature)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .map(|b| Signature::from_bytes(&b))
    {
        Some(s) => s,
        None => {
            problems.push("signature is not 64 hex bytes".into());
            return problems;
        }
    };
    if pk.verify(&body, &sig).is_err() {
        problems.push("signature does not verify".into());
    }
    problems
}
