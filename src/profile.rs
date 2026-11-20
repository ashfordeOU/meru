// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! Deployment profiles (owner decision, 20 November 2026: meru runs as an internal service
//! next to Arksa; roadmap 0.42 §1i). One codebase and one binary, three ways to run it:
//!
//! * [`Profile::Public`] (the default): the internet-facing service for Kshana Pro customers.
//!   Per-customer licences only; a service credential is refused. Unchanged behaviour.
//! * [`Profile::ArksaInternal`]: inside Arksa's cloud, on the private network only, with no
//!   public endpoint. Arksa authenticates with one service credential
//!   ([`crate::auth::SERVICE_FEATURE_PREFIX`]); customer licences are refused. Metering stays
//!   on, with the caller's tenant/mission tag in plain text (Arksa's own cost data).
//! * [`Profile::SovereignContracted`]: a contracted instance that runs alongside a Sovereign
//!   Arksa install, provisioned with its own keys, revocation list and service credential.
//!   Same rules as `arksa-internal`; the tenant tag is recorded as a hash unless the contract
//!   says otherwise (`MERU_TENANT_TAG`).
//!
//! meru is never compiled into Arksa: each profile is this same service, reached over the
//! network.

use std::net::{IpAddr, SocketAddr};

/// How this instance is deployed (`MERU_PROFILE`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Profile {
    #[default]
    Public,
    ArksaInternal,
    SovereignContracted,
}

impl Profile {
    /// Parse `MERU_PROFILE`; unset or empty is `public`; an unknown value is refused.
    pub fn parse(v: Option<&str>) -> Result<Profile, String> {
        match v.map(str::trim).unwrap_or("") {
            "" | "public" => Ok(Profile::Public),
            "arksa-internal" => Ok(Profile::ArksaInternal),
            "sovereign-contracted" => Ok(Profile::SovereignContracted),
            other => Err(format!(
                "MERU_PROFILE '{other}' is not a profile (public, arksa-internal, sovereign-contracted)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Public => "public",
            Profile::ArksaInternal => "arksa-internal",
            Profile::SovereignContracted => "sovereign-contracted",
        }
    }

    /// Whether a service credential is accepted (and customer licences refused).
    pub fn internal(self) -> bool {
        self != Profile::Public
    }

    /// How the tenant tag is recorded when `MERU_TENANT_TAG` is not set.
    pub fn default_tenant_tag(self) -> TenantTag {
        match self {
            Profile::Public => TenantTag::Off,
            Profile::ArksaInternal => TenantTag::Plain,
            Profile::SovereignContracted => TenantTag::Hashed,
        }
    }

    /// Calls a minute from one client address when `MERU_RATE_PER_IP_PER_MIN` is not set:
    /// an internal instance has one caller (Arksa) from a few addresses, so no per-address
    /// limit; the service credential has its own rate.
    pub fn default_per_ip_per_minute(self) -> u32 {
        if self.internal() {
            0
        } else {
            60
        }
    }

    /// Check the listen address for this profile. An internal profile refuses a public
    /// (globally routable) address; `0.0.0.0` / `::` is allowed with a warning (a container
    /// whose network the orchestrator keeps private). Returns warnings.
    pub fn check_bind(self, addr: &str) -> Result<Vec<String>, String> {
        if !self.internal() {
            return Ok(vec![]);
        }
        let sa: SocketAddr = addr.parse().map_err(|_| {
            format!(
                "MERU_ADDR '{addr}': give an IP address and port (profile {})",
                self.as_str()
            )
        })?;
        let ip = sa.ip();
        if ip.is_unspecified() {
            return Ok(vec![format!(
                "MERU_ADDR {addr} listens on every interface: the {} profile relies on the network keeping it private (no public route, no public load balancer)",
                self.as_str()
            )]);
        }
        if !is_private(ip) {
            return Err(format!(
                "MERU_ADDR {addr} is a public address; the {} profile listens on loopback or a private network only",
                self.as_str()
            ));
        }
        Ok(vec![])
    }
}

/// Loopback, private (RFC 1918, RFC 6598 shared, unique-local), or link-local.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_loopback() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// How the caller's tenant/mission tag (`X-Meru-Tenant`) is written to the meter log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantTag {
    /// Not read and not recorded (the public profile).
    Off,
    /// Recorded as given.
    Plain,
    /// Recorded as `h:` and the first 16 hex characters of its SHA-256 (pseudonymous: a
    /// guessable tag can be recovered by trying candidates).
    Hashed,
}

impl TenantTag {
    /// Parse `MERU_TENANT_TAG` (`off`, `plain`, `hashed`); unset gives `default`.
    pub fn parse(v: Option<&str>, default: TenantTag) -> Result<TenantTag, String> {
        match v.map(str::trim).unwrap_or("") {
            "" => Ok(default),
            "off" => Ok(TenantTag::Off),
            "plain" => Ok(TenantTag::Plain),
            "hashed" => Ok(TenantTag::Hashed),
            other => Err(format!(
                "MERU_TENANT_TAG '{other}' is not one of off, plain, hashed"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TenantTag::Off => "off",
            TenantTag::Plain => "plain",
            TenantTag::Hashed => "hashed",
        }
    }

    /// The value written to the meter log for a validated tag.
    pub fn record(self, tag: &str) -> Option<String> {
        use sha2::{Digest, Sha256};
        match self {
            TenantTag::Off => None,
            TenantTag::Plain => Some(tag.to_string()),
            TenantTag::Hashed => Some(format!(
                "h:{}",
                &hex::encode(Sha256::digest(tag.as_bytes()))[..16]
            )),
        }
    }
}

/// The longest tenant tag accepted.
pub const TENANT_MAX: usize = 64;

/// Validate a tenant/mission tag: 1 to [`TENANT_MAX`] characters of `[A-Za-z0-9._-]`.
pub fn validate_tenant(tag: &str) -> Result<(), String> {
    if tag.is_empty() || tag.len() > TENANT_MAX {
        return Err(format!(
            "X-Meru-Tenant must be 1 to {TENANT_MAX} characters"
        ));
    }
    if !tag
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("X-Meru-Tenant may hold only A-Z, a-z, 0-9, '.', '_' and '-'".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_profiles_and_refuses_unknown() {
        assert_eq!(Profile::parse(None).unwrap(), Profile::Public);
        assert_eq!(Profile::parse(Some("  ")).unwrap(), Profile::Public);
        assert_eq!(Profile::parse(Some("public")).unwrap(), Profile::Public);
        assert_eq!(
            Profile::parse(Some("arksa-internal")).unwrap(),
            Profile::ArksaInternal
        );
        assert_eq!(
            Profile::parse(Some("sovereign-contracted")).unwrap(),
            Profile::SovereignContracted
        );
        for bad in ["internal", "Public", "arksa", "sovereign"] {
            assert!(Profile::parse(Some(bad))
                .unwrap_err()
                .contains("not a profile"));
        }
        for p in [
            Profile::Public,
            Profile::ArksaInternal,
            Profile::SovereignContracted,
        ] {
            assert_eq!(Profile::parse(Some(p.as_str())).unwrap(), p);
        }
    }

    #[test]
    fn profile_defaults() {
        assert!(!Profile::Public.internal());
        assert!(Profile::ArksaInternal.internal() && Profile::SovereignContracted.internal());
        assert_eq!(Profile::Public.default_tenant_tag(), TenantTag::Off);
        assert_eq!(
            Profile::ArksaInternal.default_tenant_tag(),
            TenantTag::Plain
        );
        assert_eq!(
            Profile::SovereignContracted.default_tenant_tag(),
            TenantTag::Hashed
        );
        assert_eq!(Profile::Public.default_per_ip_per_minute(), 60);
        assert_eq!(Profile::ArksaInternal.default_per_ip_per_minute(), 0);
    }

    #[test]
    fn internal_profiles_refuse_public_bind_addresses() {
        let p = Profile::ArksaInternal;
        for ok in [
            "127.0.0.1:8099",
            "10.1.2.3:8099",
            "172.16.0.9:8099",
            "192.168.1.5:8099",
            "100.64.0.1:8099",
            "[::1]:8099",
            "[fd00::5]:8099",
        ] {
            assert!(p.check_bind(ok).unwrap().is_empty(), "{ok}");
        }
        assert_eq!(p.check_bind("0.0.0.0:8099").unwrap().len(), 1);
        for bad in ["8.8.8.8:8099", "[2001:db8::1]:8099", "203.0.113.4:443"] {
            assert!(
                p.check_bind(bad).unwrap_err().contains("public address"),
                "{bad}"
            );
        }
        assert!(p.check_bind("meru.internal:8099").is_err());
        assert!(Profile::SovereignContracted
            .check_bind("8.8.8.8:1")
            .is_err());
        // The public profile does not restrict the address (nginx is in front).
        assert!(Profile::Public
            .check_bind("0.0.0.0:8099")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn tenant_tags_validated_and_recorded() {
        for ok in ["mission-42", "tenant_a.prod", "A", &"x".repeat(64)] {
            assert!(validate_tenant(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a b", "a/b", "ä", "x\r\ny", &"x".repeat(65), "a\"b"] {
            assert!(validate_tenant(bad).is_err(), "{bad:?}");
        }
        assert_eq!(TenantTag::Plain.record("m1").as_deref(), Some("m1"));
        assert_eq!(TenantTag::Off.record("m1"), None);
        let h = TenantTag::Hashed.record("m1").unwrap();
        assert!(h.starts_with("h:") && h.len() == 18 && !h.contains("m1"));
        assert_eq!(TenantTag::Hashed.record("m1").unwrap(), h, "stable");
        assert_eq!(
            TenantTag::parse(None, TenantTag::Plain).unwrap(),
            TenantTag::Plain
        );
        assert_eq!(
            TenantTag::parse(Some("hashed"), TenantTag::Plain).unwrap(),
            TenantTag::Hashed
        );
        assert!(TenantTag::parse(Some("yes"), TenantTag::Plain).is_err());
    }
}
