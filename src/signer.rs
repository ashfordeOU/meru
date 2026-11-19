// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The verdict signer, from the environment.
//!
//! * `MERU_SIGNER=kms` (production): the signing key lives in AWS KMS and never leaves it.
//!   `MERU_KMS_KEY_ID` (key ID, ARN or `alias/...`), `MERU_KMS_REGION` (or `AWS_REGION`),
//!   optional `MERU_KMS_ENDPOINT`; credentials from the standard AWS environment (an
//!   instance or task role in production). A stolen server disk holds no key.
//! * `MERU_SIGNER=seed` or unset (development, tests): the raw 64-hex seed in `MERU_KEY`.
//!
//! The F1 lineage register signs with a raw seed inside the method. In KMS mode that seed is
//! `MERU_LINEAGE_KEY` (required); in seed mode it defaults to `MERU_KEY`. It signs only an
//! internal record, not customer verdicts.

use kshana_pro::license::kms::{CredentialSource, KmsSigner};
use kshana_pro::license::signer::{sign_checked, SharedSigner};
use kshana_pro::license::{key_id, parse_key_hex, KEY_LEN};
use std::sync::Arc;

/// The signers meru runs with.
pub struct Signers {
    pub verdict: SharedSigner,
    pub lineage_seed: [u8; KEY_LEN],
    pub lineage_key_id: String,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty())
}

fn seed(var: &str) -> Result<[u8; KEY_LEN], String> {
    let h = env(var).ok_or_else(|| format!("{var} (64-hex Ed25519 seed) is required"))?;
    parse_key_hex(&h).map_err(|e| format!("{var}: {e}"))
}

/// Build the signers from the environment and prove the verdict signer works (one signature
/// checked against its own public key) before the service accepts a call.
pub fn from_env() -> Result<Signers, String> {
    let mode = env("MERU_SIGNER").unwrap_or_default().to_ascii_lowercase();
    let (verdict, lineage_seed): (SharedSigner, [u8; KEY_LEN]) = match mode.as_str() {
        "" | "seed" => {
            let s = seed("MERU_KEY")?;
            let lineage = match env("MERU_LINEAGE_KEY") {
                Some(_) => seed("MERU_LINEAGE_KEY")?,
                None => s,
            };
            (Arc::new(s), lineage)
        }
        "kms" => {
            let key =
                env("MERU_KMS_KEY_ID").ok_or("MERU_KMS_KEY_ID is required with MERU_SIGNER=kms")?;
            let region = env("MERU_KMS_REGION")
                .or_else(|| env("AWS_REGION"))
                .ok_or("MERU_KMS_REGION (or AWS_REGION) is required with MERU_SIGNER=kms")?;
            let endpoint = env("MERU_KMS_ENDPOINT");
            let k = KmsSigner::new(
                &key,
                &region,
                endpoint.as_deref(),
                CredentialSource::Environment,
            )
            .map_err(|e| format!("KMS signer: {e}"))?;
            (Arc::new(k), seed("MERU_LINEAGE_KEY")?)
        }
        other => {
            return Err(format!(
                "unknown MERU_SIGNER '{other}' (expected seed or kms)"
            ))
        }
    };
    sign_checked(verdict.as_ref(), b"meru signer self-test").map_err(|e| {
        format!(
            "verdict signer self-test failed ({}): {e}",
            verdict.describe()
        )
    })?;
    let lineage_key_id = key_id(
        &ed25519_dalek::SigningKey::from_bytes(&lineage_seed)
            .verifying_key()
            .to_bytes(),
    );
    Ok(Signers {
        verdict,
        lineage_seed,
        lineage_key_id,
    })
}
