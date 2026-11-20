// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The lunar time-scale registry the `lunar-assist` method references.
//!
//! A lunar GNSS assistance package can carry a lunar time reference: which registry definition
//! the user maps GNSS time to lunar time with, `lunar − GPST` at the start of validity with its
//! uncertainty, and the secular rate. The registry (a versioned, explicitly provisional list of
//! candidate definitions: TCL, TL on several `W0_L` surfaces, and LTC as an envelope) is
//! published by Arksa; this module reads the same files and evaluates the named definition with
//! the same physics, Kshana Pro's lunar time model ([`kshana_pro::lunar_pro::time`]). The
//! types and their field order match the published registry format, so the SHA-256 a package
//! carries is the one the registry's owner computes.
//!
//! Version 1 is built in ([`Registry::builtin`]); further versions are loaded from files
//! (`MERU_LUNAR_REGISTRIES`). There is no default definition: a request names one.
//!
//! Evidence class: MODELLED (as the underlying lunar time model).

use kshana_pro::kshana::timescales::TwoPartJd;
use kshana_pro::lunar_pro::budget::{Budget, Term, TermKind};
use kshana_pro::lunar_pro::time::{self as lt, Model, RateSource, Scale, W0Candidate};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The built-in registry file (version 1, provisional).
pub const BUILTIN_V1_TOML: &str = include_str!("data/lunar_registry_v1.toml");

/// GPS time runs 19 s behind TAI (constant by definition).
pub const TAI_MINUS_GPST_S: f64 = 19.0;

/// Registry status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistryStatus {
    Provisional,
    Adopted,
}

/// The definition family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Tcl,
    Tl,
    Ltc,
}

/// A definition's status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefStatus {
    Candidate,
    Placeholder,
    Adopted,
    Withdrawn,
}

/// One lunar time-scale definition (field order as the published format).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Definition {
    pub id: String,
    pub family: Family,
    pub status: DefStatus,
    pub name: String,
    #[serde(default)]
    pub rate_source: Option<String>,
    #[serde(default)]
    pub w0: Option<String>,
    #[serde(default)]
    pub envelope_of: Vec<String>,
    #[serde(default)]
    pub stated_preferences: Vec<String>,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

/// A versioned registry of lunar time-scale definitions (field order as the published format).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Registry {
    pub registry_id: String,
    pub version: u32,
    pub issued: String,
    pub status: RegistryStatus,
    #[serde(default)]
    pub decision: Option<String>,
    pub notice: String,
    #[serde(default)]
    pub basis: Vec<String>,
    pub definitions: Vec<Definition>,
}

/// What a package's lunar time reference names.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegistryRef {
    pub registry_id: String,
    pub registry_version: u32,
    pub registry_sha256: String,
    pub registry_status: RegistryStatus,
    pub definition_id: String,
}

/// `lunar − GPST` (s) with its combined standard uncertainty, and the secular rate.
#[derive(Clone, Debug, PartialEq)]
pub struct GpstOffset {
    pub offset_s: f64,
    pub u_c_s: f64,
    /// `d(lunar)/d(TT) − 1`.
    pub rate: f64,
}

impl Registry {
    /// The built-in registry (version 1, provisional).
    pub fn builtin() -> Registry {
        Self::from_toml_str(BUILTIN_V1_TOML).expect("the built-in registry is valid")
    }

    /// Parse and validate a registry file.
    pub fn from_toml_str(text: &str) -> Result<Registry, String> {
        let r: Registry = toml::from_str(text).map_err(|e| format!("registry: {e}"))?;
        r.validate()?;
        Ok(r)
    }

    /// SHA-256 (hex) over the registry's canonical JSON (field order fixed by the type).
    pub fn sha256(&self) -> String {
        hex::encode(Sha256::digest(serde_json::to_vec(self).unwrap_or_default()))
    }

    /// The reference a package carries.
    pub fn reference(&self, definition_id: &str) -> RegistryRef {
        RegistryRef {
            registry_id: self.registry_id.clone(),
            registry_version: self.version,
            registry_sha256: self.sha256(),
            registry_status: self.status,
            definition_id: definition_id.to_string(),
        }
    }

    /// The definition named `id` (there is no default).
    pub fn get(&self, id: &str) -> Result<&Definition, String> {
        self.definitions.iter().find(|d| d.id == id).ok_or_else(|| {
            let ids: Vec<&str> = self.definitions.iter().map(|d| d.id.as_str()).collect();
            format!(
                "registry {} v{} has no definition '{id}' (there is no default; name one of: {})",
                self.registry_id,
                self.version,
                ids.join(", ")
            )
        })
    }

    /// The registry's rules: a provisional registry carries both the TCL and the TL families,
    /// marks nothing adopted and says PROVISIONAL; an adopted one cites its decision; TCL takes
    /// no `W0_L`, TL needs one; LTC members exist and are not withdrawn.
    pub fn validate(&self) -> Result<(), String> {
        if self.registry_id.trim().is_empty() || self.version == 0 {
            return Err("registry_id is empty or version is 0".into());
        }
        if self.notice.trim().is_empty() {
            return Err("a registry must carry a notice stating its status".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for d in &self.definitions {
            if d.id.trim().is_empty() || !seen.insert(d.id.as_str()) {
                return Err(format!("definition id '{}' is empty or repeated", d.id));
            }
        }
        match self.status {
            RegistryStatus::Provisional => {
                if self.decision.is_some() {
                    return Err("a provisional registry cites no decision".into());
                }
                if self
                    .definitions
                    .iter()
                    .any(|d| d.status == DefStatus::Adopted)
                {
                    return Err("a provisional registry marks no definition adopted".into());
                }
                let live = |f: Family| {
                    self.definitions
                        .iter()
                        .any(|d| d.family == f && d.status != DefStatus::Withdrawn)
                };
                if !(live(Family::Tcl) && live(Family::Tl)) {
                    return Err(
                        "a provisional registry must carry both the TCL and the TL families".into(),
                    );
                }
                if !self.notice.to_ascii_uppercase().contains("PROVISIONAL") {
                    return Err("a provisional registry's notice must say PROVISIONAL".into());
                }
            }
            RegistryStatus::Adopted => {
                if self
                    .decision
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
                {
                    return Err("an adopted registry must cite the decision it rests on".into());
                }
            }
        }
        for d in &self.definitions {
            let ctx = |m: &str| format!("definition '{}': {m}", d.id);
            match d.family {
                Family::Tcl | Family::Tl => {
                    if !d.envelope_of.is_empty() {
                        return Err(ctx("only an LTC definition has envelope_of"));
                    }
                    RateSource::parse(d.rate_source.as_deref().unwrap_or(""))
                        .map_err(|e| ctx(&e))?;
                    match (d.family, &d.w0) {
                        (Family::Tcl, Some(_)) => return Err(ctx("TCL takes no w0")),
                        (Family::Tl, None) => return Err(ctx("TL needs a w0")),
                        (Family::Tl, Some(w)) => {
                            W0Candidate::parse(w).map_err(|e| ctx(&e))?;
                        }
                        _ => {}
                    }
                }
                Family::Ltc => {
                    if d.rate_source.is_some() || d.w0.is_some() || d.envelope_of.is_empty() {
                        return Err(ctx("an LTC definition is realised by envelope_of only"));
                    }
                    for m in &d.envelope_of {
                        let md = self.get(m).map_err(|e| ctx(&e))?;
                        if md.family == Family::Ltc || md.status == DefStatus::Withdrawn {
                            return Err(ctx(&format!("envelope member '{m}' is LTC or withdrawn")));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn model_of(&self, d: &Definition) -> Result<(Model, Scale), String> {
        let rs = RateSource::parse(d.rate_source.as_deref().unwrap_or(""))?;
        match d.family {
            Family::Tcl => Ok((Model::new(rs, W0Candidate::kshana_equatorial()), Scale::Tcl)),
            Family::Tl => {
                let w0 = W0Candidate::parse(d.w0.as_deref().unwrap_or(""))?;
                Ok((Model::new(rs, w0), Scale::Tl))
            }
            Family::Ltc => Err(format!("'{}' is LTC (an envelope)", d.id)),
        }
    }

    /// `lunar − GPST` at the GPST instant `at` (ISO) and the secular rate, under definition
    /// `id`. LTC is the equal-weight envelope of its members (midpoint, with the half-spread
    /// as a rectangular "definition undecided" term and the largest member uncertainty).
    pub fn gpst_offset(&self, id: &str, at: &str) -> Result<GpstOffset, String> {
        let jd = lt::parse_iso(at)?;
        let mut models = BTreeMap::new();
        let b = self.offset_budget(id, jd, &mut models)?;
        let (rate, _) = self.rate(id, &mut models)?;
        Ok(GpstOffset {
            offset_s: b.value(),
            u_c_s: b.u_c(),
            rate,
        })
    }

    fn model(
        &self,
        d: &Definition,
        models: &mut BTreeMap<String, (Model, Scale)>,
    ) -> Result<(Model, Scale), String> {
        if let Some(m) = models.get(&d.id) {
            return Ok(m.clone());
        }
        let m = self.model_of(d)?;
        models.insert(d.id.clone(), m.clone());
        Ok(m)
    }

    fn offset_budget(
        &self,
        id: &str,
        jd_gpst: TwoPartJd,
        models: &mut BTreeMap<String, (Model, Scale)>,
    ) -> Result<Budget, String> {
        let d = self.get(id)?.clone();
        if d.status == DefStatus::Withdrawn {
            return Err(format!("definition '{id}' is withdrawn"));
        }
        match d.family {
            Family::Tcl | Family::Tl => {
                let (model, scale) = self.model(&d, models)?;
                // The instant read in GPST is the TAI instant 19 s later.
                let conv = model.convert(Scale::Tai, jd_gpst.add_seconds(TAI_MINUS_GPST_S), scale);
                let mut b = conv.offset;
                b.push(Term::exact(
                    "TAI - GPST",
                    TAI_MINUS_GPST_S,
                    "19 s, constant by definition (IS-GPS-200)",
                ));
                Ok(b)
            }
            Family::Ltc => {
                let mut vals = Vec::new();
                let mut max_u: f64 = 0.0;
                for m in &d.envelope_of {
                    let b = self.offset_budget(m, jd_gpst, models)?;
                    vals.push(b.value());
                    max_u = max_u.max(b.u_c());
                }
                let lo = vals.iter().copied().fold(f64::INFINITY, f64::min);
                let hi = vals.iter().copied().fold(f64::NEG_INFINITY, f64::max);
                Ok(Budget::new(vec![
                    Term::exact(
                        "LTC envelope midpoint",
                        0.5 * (lo + hi),
                        "equal-weight midpoint of the candidate realisations",
                    ),
                    Term::rectangular(
                        "LTC definition undecided (half-spread of candidates)",
                        0.0,
                        0.5 * (hi - lo),
                        "spread of the candidate realisations",
                    ),
                    Term::normal(
                        "LTC largest candidate model uncertainty",
                        0.0,
                        max_u,
                        TermKind::B,
                        "the largest combined uncertainty among the candidates",
                    ),
                ]))
            }
        }
    }

    fn rate(
        &self,
        id: &str,
        models: &mut BTreeMap<String, (Model, Scale)>,
    ) -> Result<(f64, f64), String> {
        let d = self.get(id)?.clone();
        match d.family {
            Family::Tcl | Family::Tl => {
                let (model, scale) = self.model(&d, models)?;
                let b = model.rate_vs_tt(scale);
                Ok((b.value(), b.u_c()))
            }
            Family::Ltc => {
                let mut rs = Vec::new();
                let mut max_u: f64 = 0.0;
                for m in &d.envelope_of {
                    let (r, u) = self.rate(m, models)?;
                    rs.push(r);
                    max_u = max_u.max(u);
                }
                let lo = rs.iter().copied().fold(f64::INFINITY, f64::min);
                let hi = rs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
                let half = 0.5 * (hi - lo);
                Ok((
                    0.5 * (lo + hi),
                    ((half / 3f64.sqrt()).powi(2) + max_u * max_u).sqrt(),
                ))
            }
        }
    }
}

/// The registries the service can reference: the built-in version 1 and any loaded files.
#[derive(Clone, Debug)]
pub struct Registries(pub Vec<Registry>);

impl Default for Registries {
    fn default() -> Self {
        Registries(vec![Registry::builtin()])
    }
}

impl Registries {
    /// The built-in registry plus the files at `paths`.
    pub fn load(paths: &[std::path::PathBuf]) -> Result<Self, String> {
        let mut v = vec![Registry::builtin()];
        for p in paths {
            let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let r = Registry::from_toml_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
            if v.iter()
                .any(|x| x.registry_id == r.registry_id && x.version == r.version)
            {
                return Err(format!(
                    "{}: registry {} v{} is loaded twice",
                    p.display(),
                    r.registry_id,
                    r.version
                ));
            }
            v.push(r);
        }
        Ok(Registries(v))
    }

    /// The registry `id` at `version`.
    pub fn find(&self, id: &str, version: u32) -> Result<&Registry, String> {
        self.0
            .iter()
            .find(|r| r.registry_id == id && r.version == version)
            .ok_or_else(|| {
                let have: Vec<String> = self
                    .0
                    .iter()
                    .map(|r| format!("{} v{}", r.registry_id, r.version))
                    .collect();
                format!(
                    "lunar time registry {id} v{version} is not available (available: {})",
                    have.join(", ")
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_is_provisional_and_has_no_default() {
        let r = Registry::builtin();
        assert_eq!(r.status, RegistryStatus::Provisional);
        assert_eq!(r.version, 1);
        // The registry hash over the published format's field order (cross-checked with an
        // independent serialisation of the same TOML).
        assert_eq!(
            r.sha256(),
            "ac8b45f7e408ddc305f6de7da48784d52cd3cfb11ffb3ac8a56bd11062e1125f"
        );
        assert!(r.get("nope").unwrap_err().contains("no default"));
        // A single-family provisional registry is refused.
        let mut one = r.clone();
        one.definitions.retain(|d| d.family != Family::Tl);
        one.definitions.retain(|d| d.family != Family::Ltc);
        assert!(one
            .validate()
            .unwrap_err()
            .contains("both the TCL and the TL"));
    }

    #[test]
    fn gpst_offset_is_tai_offset_plus_19_s_and_ltc_lies_inside_its_members() {
        let r = Registry::builtin();
        let at = "2027-01-01T00:00:00";
        let tcl = r.gpst_offset("tcl-iau2024-lte440", at).unwrap();
        // lunar − GPST = (lunar − TAI at the same instant) + 19 s.
        let model = Model::new(
            RateSource::parse("lte440").unwrap(),
            W0Candidate::kshana_equatorial(),
        );
        let jd = lt::parse_iso(at).unwrap().add_seconds(19.0);
        let lunar_tai = model.convert(Scale::Tai, jd, Scale::Tcl).offset.value();
        assert!((tcl.offset_s - (lunar_tai + 19.0)).abs() < 1e-12);
        assert!(tcl.u_c_s > 0.0 && tcl.rate > 0.0);
        let ltc = r.gpst_offset("ltc-placeholder", at).unwrap();
        let members: Vec<f64> = r
            .get("ltc-placeholder")
            .unwrap()
            .envelope_of
            .iter()
            .map(|m| r.gpst_offset(m, at).unwrap().offset_s)
            .collect();
        let lo = members.iter().copied().fold(f64::INFINITY, f64::min);
        let hi = members.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        assert!(lo <= ltc.offset_s && ltc.offset_s <= hi);
    }
}
