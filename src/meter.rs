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
}
