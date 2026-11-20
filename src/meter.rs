// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The meter log: one JSON line per call, for billing, audit and abuse review. It records
//! who called what and the hashes of the request and verdict, never the request itself, so
//! the log holds no customer data and nothing about the method. Extraction alerts
//! ([`crate::audit`]) are written here too, as lines with outcome `extraction_alert` or
//! `honeypot`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// One call.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub utc: String,
    pub unix: i64,
    pub licensee: String,
    pub token_id: String,
    pub tier: String,
    pub path: String,
    /// HTTP status returned.
    pub status: u16,
    /// `ok`, `refused`, `rate_limited`, `probe_alert`, `invalid`.
    pub outcome: String,
    pub request_sha256: String,
    #[serde(default)]
    pub verdict_sha256: String,
    pub ms: u64,
    /// The call fell in a fingerprint canary cell ([`crate::fingerprint`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub canary: bool,
    /// An extraction alert ([`crate::audit::Alert`]): shape hash, statistics and token IDs,
    /// never request contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert: Option<serde_json::Value>,
    /// The service client (`arksa`) when the call came with a service credential
    /// ([`crate::auth::Caller::service`]); absent for a customer licence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// The caller's tenant/mission tag (`X-Meru-Tenant`), as given or hashed per
    /// [`crate::profile::TenantTag`]; absent when none was sent or the profile records none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Appends entries to a JSON-lines file.
pub struct Meter {
    path: PathBuf,
    file: Mutex<std::fs::File>,
}

impl Meter {
    pub fn open(path: &Path) -> Result<Meter, String> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("meter log {}: {e}", path.display()))?;
        Ok(Meter {
            path: path.to_path_buf(),
            file: Mutex::new(file),
        })
    }

    pub fn record(&self, e: &Entry) {
        let line = serde_json::to_string(e).unwrap_or_default();
        let mut f = self.file.lock().unwrap_or_else(|p| p.into_inner());
        if writeln!(f, "{line}").and_then(|_| f.flush()).is_err() {
            eprintln!(
                "[meru][ALERT] could not write the meter log {}",
                self.path.display()
            );
        }
    }

    /// Successful calls per token today (UTC), to restore the daily quotas after a restart.
    pub fn today_counts(&self, now: i64) -> HashMap<String, u32> {
        today_counts(&self.path, now)
    }
}

/// Successful calls per token on the UTC day of `now`, read from the log at `path`.
pub fn today_counts(path: &Path, now: i64) -> HashMap<String, u32> {
    let day = now.div_euclid(86_400);
    let mut m = HashMap::new();
    if let Ok(f) = std::fs::File::open(path) {
        for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
            if let Ok(e) = serde_json::from_str::<Entry>(&line) {
                if e.outcome == "ok" && e.unix.div_euclid(86_400) == day {
                    *m.entry(e.token_id).or_insert(0) += 1;
                }
            }
        }
    }
    m
}

/// Every token ID that appears in the log at `path` (candidates for an ownership test).
pub fn token_ids(path: &Path) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    if let Ok(f) = std::fs::File::open(path) {
        for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
            if let Ok(e) = serde_json::from_str::<Entry>(&line) {
                if e.token_id != "-" {
                    out.insert(e.token_id);
                }
            }
        }
    }
    out.into_iter().collect()
}

/// One row of [`summary`]: a tenant's calls of one method.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct SummaryRow {
    /// The tenant tag as recorded, or `-` when the call carried none.
    pub tenant: String,
    /// The request path (`/verdict/calibrate`).
    pub path: String,
    /// Calls answered with a verdict.
    pub ok: u64,
    /// Calls refused, rate limited, invalid or busy.
    pub not_ok: u64,
    /// Compute time of the answered calls, milliseconds.
    pub ok_ms: u64,
    /// Time of every call, milliseconds.
    pub total_ms: u64,
}

/// Per-tenant, per-method call counts and time from the meter log at `path`, for calls with
/// `from <= unix < to`. Alert lines are not calls and are left out.
pub fn summary(path: &Path, from: i64, to: i64) -> Result<Vec<SummaryRow>, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut m: std::collections::BTreeMap<(String, String), SummaryRow> = Default::default();
    for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
        let Ok(e) = serde_json::from_str::<Entry>(&line) else {
            continue;
        };
        if e.unix < from || e.unix >= to || e.alert.is_some() || e.status == 0 {
            continue;
        }
        let tenant = e.tenant.clone().unwrap_or_else(|| "-".into());
        let r = m
            .entry((tenant.clone(), e.path.clone()))
            .or_insert_with(|| SummaryRow {
                tenant,
                path: e.path.clone(),
                ..Default::default()
            });
        if e.outcome == "ok" {
            r.ok += 1;
            r.ok_ms += e.ms;
        } else {
            r.not_ok += 1;
        }
        r.total_ms += e.ms;
    }
    Ok(m.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_counts_today_only() {
        let dir = std::env::temp_dir().join(format!("meru-meter-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("m.jsonl");
        let _ = std::fs::remove_file(&p);
        let m = Meter::open(&p).unwrap();
        let mk = |unix: i64, tok: &str, outcome: &str| Entry {
            utc: String::new(),
            unix,
            licensee: "L".into(),
            token_id: tok.into(),
            tier: "pro".into(),
            path: "/verdict/survey".into(),
            status: 200,
            outcome: outcome.into(),
            request_sha256: "r".into(),
            verdict_sha256: "v".into(),
            ms: 1,
            canary: false,
            alert: None,
            service: None,
            tenant: None,
        };
        m.record(&mk(86_400 * 10 + 5, "a", "ok"));
        m.record(&mk(86_400 * 10 + 6, "a", "ok"));
        m.record(&mk(86_400 * 10 + 7, "a", "rate_limited"));
        m.record(&mk(86_400 * 9, "a", "ok"));
        m.record(&mk(86_400 * 10 + 8, "b", "ok"));
        let c = m.today_counts(86_400 * 10 + 100);
        assert_eq!(c.get("a"), Some(&2));
        assert_eq!(c.get("b"), Some(&1));
        assert_eq!(token_ids(&p), vec!["a".to_string(), "b".to_string()]);
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.contains("scenario") && !text.contains("config"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn summary_per_tenant_and_method() {
        let dir = std::env::temp_dir().join(format!("meru-meter-sum-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("m.jsonl");
        let _ = std::fs::remove_file(&p);
        let m = Meter::open(&p).unwrap();
        let mk = |unix: i64, tenant: Option<&str>, path: &str, outcome: &str, ms: u64| Entry {
            utc: String::new(),
            unix,
            licensee: "Arksa".into(),
            token_id: "kt_s".into(),
            tier: "enterprise".into(),
            path: path.into(),
            status: if outcome == "ok" { 200 } else { 422 },
            outcome: outcome.into(),
            request_sha256: "r".into(),
            verdict_sha256: String::new(),
            ms,
            canary: false,
            alert: None,
            service: Some("arksa".into()),
            tenant: tenant.map(str::to_string),
        };
        m.record(&mk(100, Some("m1"), "/verdict/calibrate", "ok", 40));
        m.record(&mk(101, Some("m1"), "/verdict/calibrate", "ok", 60));
        m.record(&mk(102, Some("m1"), "/verdict/calibrate", "invalid", 1));
        m.record(&mk(103, Some("m2"), "/verdict/selfcal", "ok", 500));
        m.record(&mk(104, None, "/verdict/selfcal", "ok", 7));
        m.record(&mk(5_000, Some("m1"), "/verdict/calibrate", "ok", 9)); // outside
        let mut al = mk(105, Some("m1"), "/verdict/calibrate", "extraction_alert", 0);
        al.status = 0;
        al.alert = Some(serde_json::json!({"kind": "single_licence"}));
        m.record(&al);
        let rows = summary(&p, 0, 1_000).unwrap();
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert_eq!(
            rows[0],
            SummaryRow {
                tenant: "-".into(),
                path: "/verdict/selfcal".into(),
                ok: 1,
                not_ok: 0,
                ok_ms: 7,
                total_ms: 7
            }
        );
        assert_eq!(
            (rows[1].tenant.as_str(), rows[1].ok, rows[1].not_ok),
            ("m1", 2, 1)
        );
        assert_eq!((rows[1].ok_ms, rows[1].total_ms), (100, 101));
        assert_eq!((rows[2].tenant.as_str(), rows[2].ok_ms), ("m2", 500));
        // Old lines without the new fields still read.
        std::fs::write(
            &p,
            r#"{"utc":"","unix":5,"licensee":"L","token_id":"t","tier":"pro","path":"/verdict/survey","status":200,"outcome":"ok","request_sha256":"r","ms":3}"#,
        )
        .unwrap();
        assert_eq!(summary(&p, 0, 10).unwrap()[0].tenant, "-");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
