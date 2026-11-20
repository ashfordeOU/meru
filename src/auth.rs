// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! Caller authorisation. A hosted call is authorised by the caller's Kshana licence: the
//! Bearer token must be a valid, unexpired licence signed by a current vendor key, not on the
//! signed revocation list, and at the Pro tier or above (owner decision, 19 November 2026:
//! Pro customers get the hosted methods) or one that explicitly grants `pro-eloran`.
//! Evaluation licences are refused. This does not change the on-device `pro-eloran` gate in
//! Pro builds, which stays Enterprise-only.
//!
//! Revocation: the vendor publishes a signed list (`kshana-pro license revocations build`).
//! meru reads it from `MERU_REVOCATIONS` at start and re-reads it whenever the file changes,
//! so a stolen or cancelled licence stops working within [`REFRESH_S`] seconds, and a key
//! the list retires stops being trusted. A list older than the one in force is refused, so
//! an old list cannot be replayed to un-revoke a token.
//!
//! Service credential (owner decision, 20 November 2026, roadmap 0.42 §1i): an instance in
//! the `arksa-internal` or `sovereign-contracted` profile ([`crate::profile`]) is called by
//! Arksa with ONE credential, not per-customer licences. It is an ordinary vendor-signed v2
//! licence token, issued with the existing vendor tools and verified by the same code, whose
//! `features` hold exactly one `meru-service:<client>` entry ([`SERVICE_FEATURE_PREFIX`]),
//! whose `products` include `service`, which has a token ID (so the revocation list can name
//! it) and an expiry (so it is rotated). The server decides per profile whether it is
//! accepted ([`Caller::service`]); a token that carries the marker but breaks these rules is
//! refused everywhere.

use kshana_pro::license::revocation::{self, RevocationList};
use kshana_pro::license::{verify_with, Entitlement, Keyring, LicenseClaims, Tier, VerifyOptions};
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Instant, SystemTime};

/// The lowest licence tier that may use the hosted methods.
pub const MIN_TIER: Tier = Tier::Pro;
/// A feature that also admits a caller below [`MIN_TIER`] when granted explicitly.
pub const GRANT_FEATURE: &str = "pro-eloran";
/// How often (seconds) the revocation file is checked for changes.
pub const REFRESH_S: u64 = 30;
/// A `features` entry `meru-service:<client>` marks a token as a service credential.
pub const SERVICE_FEATURE_PREFIX: &str = "meru-service:";
/// The service clients accepted when `MERU_SERVICE_CLIENTS` is not set.
pub const DEFAULT_SERVICE_CLIENTS: &[&str] = &["arksa"];

/// The service client a verified token names, `Ok(None)` for an ordinary licence, or why a
/// token carrying the service marker is not a valid service credential.
pub fn service_client(
    claims: &LicenseClaims,
    clients: &[String],
) -> Result<Option<String>, String> {
    let marks: Vec<&str> = claims
        .features
        .iter()
        .filter_map(|f| f.strip_prefix(SERVICE_FEATURE_PREFIX))
        .collect();
    let client = match marks.as_slice() {
        [] => return Ok(None),
        [one] => one.to_string(),
        _ => return Err("service credential invalid: more than one service marker".into()),
    };
    if !clients.contains(&client) {
        return Err(format!(
            "service credential invalid: client '{client}' is not accepted by this instance"
        ));
    }
    if claims.v != 2 || claims.id.is_empty() {
        return Err("service credential invalid: it must be a v2 token with a token ID".into());
    }
    if !claims.products.iter().any(|p| p == "service") {
        return Err("service credential invalid: its products must include 'service'".into());
    }
    if claims.expires_unix == 0 {
        return Err("service credential invalid: it must carry an expiry (rotate it)".into());
    }
    Ok(Some(client))
}

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

/// An authorised caller.
#[derive(Clone, Debug)]
pub struct Caller {
    pub licensee: String,
    pub tier: Tier,
    /// The token's ID: what quotas, the meter log and revocation name.
    pub token_id: String,
    /// Enterprise licences may ask for the full survey grid.
    pub allow_grid: bool,
    /// The service client (`arksa`) when the token is a service credential
    /// ([`service_client`]); `None` for a customer licence.
    pub service: Option<String>,
}

struct Current {
    ring: Keyring,
    list: Option<RevocationList>,
    mtime: Option<SystemTime>,
    checked: Instant,
}

/// Licence verification with key rotation and revocation.
pub struct Authority {
    base: Keyring,
    rev_path: Option<PathBuf>,
    cur: RwLock<Current>,
    service_clients: Vec<String>,
}

fn load(base: &Keyring, path: &PathBuf) -> Result<(RevocationList, Option<SystemTime>), String> {
    let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let list = revocation::verify(base, &text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((list, mtime))
}

impl Authority {
    /// `pubkeys`: the vendor licence public keys (64 hex, comma separated, for rotation).
    /// `root_kids`: root key IDs allowed to retire keys. `rev_path`: the signed revocation
    /// list, or `None` to run without one (development only).
    pub fn new(
        pubkeys: &str,
        root_kids: Option<&str>,
        rev_path: Option<PathBuf>,
    ) -> Result<Authority, String> {
        let mut base =
            Keyring::parse_keys(pubkeys).map_err(|e| format!("vendor public keys: {e}"))?;
        for r in root_kids
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            base.add_root(r);
        }
        let mut ring = base.clone();
        let (list, mtime) = match &rev_path {
            Some(p) => {
                let (l, m) = load(&base, p)?;
                l.apply_to(&mut ring);
                (Some(l), m)
            }
            None => (None, None),
        };
        Ok(Authority {
            base,
            rev_path,
            cur: RwLock::new(Current {
                ring,
                list,
                mtime,
                checked: Instant::now(),
            }),
            service_clients: DEFAULT_SERVICE_CLIENTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        })
    }

    /// Set the service clients a service credential may name (`MERU_SERVICE_CLIENTS`).
    pub fn with_service_clients(mut self, clients: Vec<String>) -> Authority {
        self.service_clients = clients;
        self
    }

    /// The revocation list's sequence number in force, if any.
    pub fn revocation_sequence(&self) -> Option<u64> {
        self.cur.read().ok()?.list.as_ref().map(|l| l.sequence)
    }

    /// Re-read the revocation list if the file changed. A list that fails to verify, or is
    /// older than the one in force, is refused and the current one kept (with an alert).
    pub fn refresh(&self, force: bool) {
        let Some(path) = &self.rev_path else { return };
        {
            let c = self.cur.read().unwrap_or_else(|e| e.into_inner());
            if !force && c.checked.elapsed().as_secs() < REFRESH_S {
                return;
            }
        }
        let mut c = self.cur.write().unwrap_or_else(|e| e.into_inner());
        c.checked = Instant::now();
        let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        if !force && mtime == c.mtime {
            return;
        }
        match load(&self.base, path) {
            Ok((l, m)) => {
                let held = c.list.as_ref().map(|x| x.sequence).unwrap_or(0);
                if l.sequence < held {
                    eprintln!(
                        "[meru][ALERT] revocation list sequence {} is older than {held} in force; kept the current list",
                        l.sequence
                    );
                    c.mtime = m;
                    return;
                }
                let mut ring = self.base.clone();
                l.apply_to(&mut ring);
                eprintln!(
                    "[meru] revocation list {} loaded ({} revoked)",
                    l.sequence,
                    l.revoked.len()
                );
                c.ring = ring;
                c.list = Some(l);
                c.mtime = m;
            }
            Err(e) => {
                eprintln!("[meru][ALERT] revocation list not reloaded: {e}; kept the current list");
                c.mtime = mtime;
            }
        }
    }

    /// Verify a Bearer licence `token` at `now` (unix s) and confirm it may use the hosted
    /// methods. Returns the caller, or a reason it is refused.
    pub fn authorize(&self, token: &str, now: i64) -> Result<Caller, String> {
        self.refresh(false);
        let c = self.cur.read().unwrap_or_else(|e| e.into_inner());
        let lic = verify_with(&c.ring, token.trim(), &VerifyOptions::at(now))
            .map_err(|e| format!("licence invalid: {e}"))?;
        if c.list.as_ref().is_some_and(|l| l.is_revoked(&lic.token_id)) {
            return Err("licence revoked".into());
        }
        let service = service_client(&lic.claims, &self.service_clients)?;
        if service.is_none() {
            admit(&lic.entitlement, now)?;
        }
        Ok(Caller {
            licensee: lic.entitlement.licensee.clone(),
            tier: lic.entitlement.tier,
            token_id: lic.token_id,
            allow_grid: service.is_none() && lic.entitlement.tier >= Tier::Enterprise,
            service,
        })
    }
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

    fn svc_claims() -> LicenseClaims {
        LicenseClaims {
            licensee: "Arksa cloud".into(),
            tier: "enterprise".into(),
            expires_unix: 1_000,
            features: vec!["meru-service:arksa".into()],
            v: 2,
            id: "kt_x".into(),
            products: vec!["service".into()],
            ..Default::default()
        }
    }

    #[test]
    fn service_credential_rules() {
        let arksa = vec!["arksa".to_string()];
        assert_eq!(
            service_client(&svc_claims(), &arksa).unwrap().as_deref(),
            Some("arksa")
        );
        // An ordinary licence is not a service credential.
        let mut c = svc_claims();
        c.features = vec!["pro-eloran".into()];
        assert_eq!(service_client(&c, &arksa).unwrap(), None);
        // A client this instance does not accept.
        assert!(service_client(&svc_claims(), &["other".to_string()])
            .unwrap_err()
            .contains("not accepted"));
        let mut c = svc_claims();
        c.features.push("meru-service:other".into());
        assert!(service_client(&c, &arksa)
            .unwrap_err()
            .contains("more than one"));
        let mut c = svc_claims();
        c.products = vec!["cli".into()];
        assert!(service_client(&c, &arksa)
            .unwrap_err()
            .contains("'service'"));
        let mut c = svc_claims();
        c.expires_unix = 0;
        assert!(service_client(&c, &arksa).unwrap_err().contains("expiry"));
        let mut c = svc_claims();
        c.v = 0;
        c.id.clear();
        assert!(service_client(&c, &arksa).unwrap_err().contains("v2"));
    }

    #[test]
    fn explicit_grant_admits_below_pro() {
        assert!(admit(&ent(Tier::Evaluation, 0, &["pro-eloran"]), 100).is_ok());
        assert!(admit(&ent(Tier::Evaluation, 50, &["pro-eloran"]), 100).is_err());
    }
}
