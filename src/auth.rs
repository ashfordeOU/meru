// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! Caller authorisation. A hosted call is authorised by the caller's Kshana licence: the
//! Bearer token must be a valid, unexpired licence signed by the vendor key and must carry
//! the `pro-eloran` entitlement. The method then runs on our server and only a signed
//! verdict is returned — this is how a Pro customer "buys a licence and calls the server"
//! without ever holding the method.
//!
//! v1 scope: signature + entitlement + expiry. Revocation-list checking is a follow-up
//! (wire the keyring + revocation store from kshana-pro's lifecycle service).

use kshana_pro::license::{check, verify, Entitlement};

/// The entitlement a caller must hold to use the hosted methods.
pub const REQUIRED_FEATURE: &str = "pro-eloran";

/// Verify a Bearer licence `token` against the vendor public key (hex) at `now` (unix s) and
/// confirm it grants [`REQUIRED_FEATURE`]. Returns the entitlement, or a reason it is refused.
pub fn authorize(token: &str, vendor_pubkey_hex: &str, now: i64) -> Result<Entitlement, String> {
    let pk: [u8; 32] = hex::decode(vendor_pubkey_hex.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or("vendor public key must be 64 hex characters")?;
    let ent = verify(&pk, token.trim(), now).map_err(|e| format!("licence invalid: {e}"))?;
    check(&ent, REQUIRED_FEATURE, now).map_err(|e| format!("licence not entitled: {e}"))?;
    Ok(ent)
}
