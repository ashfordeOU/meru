// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! Caller authorisation. A hosted call is authorised by the caller's Kshana licence: the
//! Bearer token must be a valid, unexpired licence signed by the vendor key, at the Pro tier
//! or above (owner decision, 19 November 2026: Pro customers get the hosted methods), or one
//! that explicitly grants `pro-eloran`. Evaluation licences are refused. This does not change
//! the on-device `pro-eloran` gate in Pro builds, which stays Enterprise-only. The method then runs on our server and only a signed
//! verdict is returned — this is how a Pro customer "buys a licence and calls the server"
//! without ever holding the method.
//!
//! v1 scope: signature + entitlement + expiry. Revocation-list checking is a follow-up
//! (wire the keyring + revocation store from kshana-pro's lifecycle service).

use kshana_pro::license::{verify, Entitlement, Tier};

/// The lowest licence tier that may use the hosted methods.
pub const MIN_TIER: Tier = Tier::Pro;
/// A feature that also admits a caller below [`MIN_TIER`] when granted explicitly.
pub const GRANT_FEATURE: &str = "pro-eloran";

/// Whether a verified entitlement may use the hosted methods at `now`.
pub fn admit(ent: &Entitlement, now: i64) -> Result<(), String> {
    if ent.is_expired(now) {
        return Err("licence not entitled: it has expired".into());
    }
    if ent.tier >= MIN_TIER || ent.allows(GRANT_FEATURE, now) {
        return Ok(());
    }
    Err(format!(
        "licence not entitled: hosted verdicts need the '{}' tier or above; this licence is '{}'",
        MIN_TIER.as_str(),
        ent.tier.as_str()
    ))
}

/// Verify a Bearer licence `token` against the vendor public key (hex) at `now` (unix s) and
/// confirm it may use the hosted methods ([`admit`]). Returns the entitlement, or a reason it is refused.
pub fn authorize(token: &str, vendor_pubkey_hex: &str, now: i64) -> Result<Entitlement, String> {
    let pk: [u8; 32] = hex::decode(vendor_pubkey_hex.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or("vendor public key must be 64 hex characters")?;
    let ent = verify(&pk, token.trim(), now).map_err(|e| format!("licence invalid: {e}"))?;
    admit(&ent, now)?;
    Ok(ent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ent(tier: Tier, expires: i64, features: &[&str]) -> Entitlement {
        Entitlement {
            licensee: "t".into(),
            tier,
            expires_unix: expires,
            features: features.iter().map(|f| f.to_string()).collect(),
            arksa: false,
        }
    }

    #[test]
    fn pro_and_enterprise_admitted_evaluation_and_expired_refused() {
        assert!(admit(&ent(Tier::Pro, 0, &[]), 100).is_ok());
        assert!(admit(&ent(Tier::Enterprise, 0, &[]), 100).is_ok());
        assert!(admit(&ent(Tier::Evaluation, 0, &[]), 100)
            .unwrap_err()
            .contains("'pro' tier"));
        assert!(admit(&ent(Tier::Pro, 50, &[]), 100)
            .unwrap_err()
            .contains("expired"));
    }

    #[test]
    fn explicit_grant_admits_below_pro() {
        assert!(admit(&ent(Tier::Evaluation, 0, &["pro-eloran"]), 100).is_ok());
        assert!(admit(&ent(Tier::Evaluation, 50, &["pro-eloran"]), 100).is_err());
    }
}
