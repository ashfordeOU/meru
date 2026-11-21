// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! RFC 3161 time-stamping of the transparency log's daily root, pluggable for two independent
//! time-stamp authorities (TSAs) (research backlog E25, B2502).
//!
//! Each completed UTC day the log has a **daily root** (`meru-tlog-daily-root/1`: the size, root
//! hash and chain head of the log at the end of the day). Its canonical JSON is hashed (SHA-256)
//! and sent to each configured TSA as an RFC 3161 `TimeStampReq`; the token that comes back is
//! verified with the open engine's RFC 3161 verifier (CMS signature, ESS signing certificate,
//! time-stamping key usage, chain to the configured anchor, message imprint) and kept next to the
//! log. Anyone can check a token offline against the authority's certificate.
//!
//! **QTSP anchoring: interface built, no provider configured.** Which authorities (for example a
//! qualified trust service provider under eIDAS) is a contract for the owner; until one is
//! configured (`MERU_TLOG_TSA_1_URL` and `MERU_TLOG_TSA_1_ANCHOR`, likewise `_2_`) every daily root
//! says `not_configured`. Tests use a local synthetic TSA only (OpenSSL's `ts` command acting as a
//! test authority); no real authority is contacted.

pub use kshana_pro::kshana::evidence::tsa::{pem_certificates, verify_token};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// The statement every daily root carries while no authority is configured.
pub const NO_PROVIDER: &str = "QTSP anchoring: interface built, no provider configured";

/// A time-stamp authority.
pub trait TimeStamper: Send + Sync {
    /// The authority's name, as configured (used in file names: letters, digits, `-`, `_`).
    fn name(&self) -> &str;
    /// Send a DER `TimeStampReq`; the DER `TimeStampResp` (or bare token).
    fn stamp(&self, request_der: &[u8]) -> Result<Vec<u8>, String>;
    /// The trusted anchors (DER certificates) its tokens are verified against.
    fn anchors(&self) -> &[Vec<u8>];
}

/// An authority reached over HTTPS (RFC 3161 section 3.4, `application/timestamp-query`), with the
/// system `curl` as the transport. Not exercised by the tests, which contact no authority.
pub struct HttpTsa {
    pub name: String,
    pub url: String,
    pub anchors: Vec<Vec<u8>>,
}

impl HttpTsa {
    /// From a URL and the PEM file of the authority's root certificate(s).
    pub fn new(name: &str, url: &str, anchor_pem: &Path) -> Result<HttpTsa, String> {
        if !url.starts_with("https://") {
            return Err(format!("{name}: the authority's URL must be https://"));
        }
        let pem = std::fs::read_to_string(anchor_pem)
            .map_err(|e| format!("{name}: {}: {e}", anchor_pem.display()))?;
        let anchors = pem_certificates(&pem).map_err(|e| format!("{name}: {e}"))?;
        if anchors.is_empty() {
            return Err(format!(
                "{name}: no certificate in {}",
                anchor_pem.display()
            ));
        }
        Ok(HttpTsa {
            name: name.into(),
            url: url.into(),
            anchors,
        })
    }
}

impl TimeStamper for HttpTsa {
    fn name(&self) -> &str {
        &self.name
    }
    fn stamp(&self, request_der: &[u8]) -> Result<Vec<u8>, String> {
        let dir = std::env::temp_dir().join(format!(
            "meru-tsq-{}-{}",
            std::process::id(),
            hex::encode(&Sha256::digest(request_der)[..8])
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let q = dir.join("req.tsq");
        std::fs::write(&q, request_der).map_err(|e| e.to_string())?;
        let out = std::process::Command::new("curl")
            .args(["-sS", "--fail", "--max-time", "30", "-H"])
            .arg("Content-Type: application/timestamp-query")
            .arg("--data-binary")
            .arg(format!("@{}", q.display()))
            .arg(&self.url)
            .output()
            .map_err(|e| format!("{}: curl: {e}", self.name));
        let _ = std::fs::remove_dir_all(&dir);
        let out = out?;
        if !out.status.success() {
            return Err(format!(
                "{}: the authority did not answer: {}",
                self.name,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(out.stdout)
    }
    fn anchors(&self) -> &[Vec<u8>] {
        &self.anchors
    }
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut o = vec![tag];
    let n = content.len();
    if n < 0x80 {
        o.push(n as u8);
    } else if n < 0x100 {
        o.extend([0x81, n as u8]);
    } else {
        o.extend([0x82, (n >> 8) as u8, n as u8]);
    }
    o.extend(content);
    o
}

/// A DER `TimeStampReq` (RFC 3161 section 2.4.1) for a SHA-256 digest: version 1, the message
/// imprint, a nonce, and `certReq` TRUE so the token carries the authority's certificate.
pub fn timestamp_request(digest: &[u8; 32], nonce: u64) -> Vec<u8> {
    // id-sha256 2.16.840.1.101.3.4.2.1
    let oid = der(
        0x06,
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
    );
    let alg = der(0x30, &[oid, vec![0x05, 0x00]].concat());
    let imprint = der(0x30, &[alg, der(0x04, digest)].concat());
    let mut n = nonce.to_be_bytes().to_vec();
    while n.len() > 1 && n[0] == 0 && n[1] < 0x80 {
        n.remove(0);
    }
    if n[0] >= 0x80 {
        n.insert(0, 0);
    }
    der(
        0x30,
        &[
            der(0x02, &[1]),
            imprint,
            der(0x02, &n),
            vec![0x01, 0x01, 0xff],
        ]
        .concat(),
    )
}

/// Standard base64 with padding.
pub fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let v = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(A[(v >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// Where a day's token from an authority is kept.
pub fn token_path(log: &Path, date: &str, authority: &str) -> PathBuf {
    let mut p = log.as_os_str().to_owned();
    p.push(format!(".daily/{date}.{authority}.tsr"));
    PathBuf::from(p)
}

/// Stamp a daily root's canonical bytes with every authority that has not stamped it yet, and
/// report each authority's receipt. Tokens are verified before they are kept.
pub fn stamp_and_report(
    log: &Path,
    date: &str,
    canonical: &[u8],
    stampers: &[Box<dyn TimeStamper>],
) -> Vec<Value> {
    let digest: [u8; 32] = Sha256::digest(canonical).into();
    stampers
        .iter()
        .map(|t| {
            let path = token_path(log, date, t.name());
            let token = match std::fs::read(&path) {
                Ok(tok) => Ok(tok),
                Err(_) => {
                    let nonce = u64::from_be_bytes(digest[..8].try_into().unwrap_or_default());
                    t.stamp(&timestamp_request(&digest, nonce)).and_then(|tok| {
                        let v = verify_token(&tok, canonical, t.anchors(), &[]);
                        if !v.pass {
                            return Err(format!("the token does not verify: {}", v.reason));
                        }
                        if let Some(dir) = path.parent() {
                            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
                        }
                        std::fs::write(&path, &tok).map_err(|e| e.to_string())?;
                        Ok(tok)
                    })
                }
            };
            match token {
                Ok(tok) => {
                    let v = verify_token(&tok, canonical, t.anchors(), &[]);
                    json!({
                        "authority": t.name(),
                        "status": if v.pass { "stamped" } else { "token_invalid" },
                        "gen_time_utc": v.gen_time_unix.map(crate::server::iso),
                        "token_sha256": hex::encode(Sha256::digest(&tok)),
                        "token_der_base64": b64(&tok),
                        "verified_against_configured_anchor": v.pass,
                        "reason": if v.pass { Value::Null } else { json!(v.reason) },
                    })
                }
                Err(e) => json!({"authority": t.name(), "status": "failed", "reason": e}),
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "tlog_tsa_tests.rs"]
mod tests;
