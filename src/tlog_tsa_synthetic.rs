// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! A local synthetic time-stamp authority, for tests only (unit tests and the end-to-end suite
//! include this file by path; it is not part of the service). OpenSSL's `ts -reply` signs with a
//! test CA and test TSA certificate generated in a temporary directory; no real authority is
//! contacted and no key is kept.

use super::{pem_certificates, TimeStamper};
use std::path::{Path, PathBuf};
use std::process::Command;

/// OpenSSL's `ts -reply` with a test CA
/// and a test TSA certificate generated in a temporary directory. No real authority is contacted.
pub struct SyntheticTsa {
    pub name: String,
    pub dir: PathBuf,
    pub anchors: Vec<Vec<u8>>,
}

fn run(dir: &Path, args: &[&str]) {
    let out = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("openssl");
    assert!(
        out.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

impl SyntheticTsa {
    /// Generate a fresh test CA and TSA certificate (keys generated here, never stored in the repo).
    pub fn new(name: &str) -> SyntheticTsa {
        let dir = std::env::temp_dir().join(format!(
            "meru-synthetic-tsa-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("ts.cnf"),
            "[ tsa ]\ndefault_tsa = tsa_config1\n[ tsa_config1 ]\ndir = .\nserial = ./serial\n\
             signer_cert = ./tsa.pem\ncerts = ./ca.pem\nsigner_key = ./tsa.key\n\
             signer_digest = sha256\ndefault_policy = 1.2.3.4.1\nother_policies = 1.2.3.4.5\n\
             digests = sha256\naccuracy = secs:1\nordering = no\ntsa_name = no\n\
             ess_cert_id_chain = no\ness_cert_id_alg = sha256\n\
             [ v3_tsa ]\nbasicConstraints = CA:FALSE\nkeyUsage = critical, digitalSignature\n\
             extendedKeyUsage = critical, timeStamping\n\
             [ v3_ca ]\nbasicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign\n",
        )
        .unwrap();
        std::fs::write(dir.join("serial"), "01\n").unwrap();
        run(
            &dir,
            &[
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                "ca.key",
            ],
        );
        run(
            &dir,
            &[
                "req",
                "-new",
                "-x509",
                "-key",
                "ca.key",
                "-out",
                "ca.pem",
                "-days",
                "3650",
                "-subj",
                "/CN=synthetic test CA (not a real authority)",
                "-config",
                "ts.cnf",
                "-extensions",
                "v3_ca",
            ],
        );
        run(
            &dir,
            &[
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                "tsa.key",
            ],
        );
        run(
            &dir,
            &[
                "req",
                "-new",
                "-key",
                "tsa.key",
                "-out",
                "tsa.csr",
                "-subj",
                &format!("/CN=synthetic test TSA {name} (not a real authority)"),
            ],
        );
        run(
            &dir,
            &[
                "x509",
                "-req",
                "-in",
                "tsa.csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                "tsa.pem",
                "-days",
                "3650",
                "-extfile",
                "ts.cnf",
                "-extensions",
                "v3_tsa",
            ],
        );
        let anchors =
            pem_certificates(&std::fs::read_to_string(dir.join("ca.pem")).unwrap()).unwrap();
        SyntheticTsa {
            name: name.into(),
            dir,
            anchors,
        }
    }
}

impl TimeStamper for SyntheticTsa {
    fn name(&self) -> &str {
        &self.name
    }
    fn stamp(&self, request_der: &[u8]) -> Result<Vec<u8>, String> {
        std::fs::write(self.dir.join("req.tsq"), request_der).map_err(|e| e.to_string())?;
        let out = Command::new("openssl")
            .current_dir(&self.dir)
            .args([
                "ts",
                "-reply",
                "-config",
                "ts.cnf",
                "-queryfile",
                "req.tsq",
                "-out",
                "resp.tsr",
            ])
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).into());
        }
        std::fs::read(self.dir.join("resp.tsr")).map_err(|e| e.to_string())
    }
    fn anchors(&self) -> &[Vec<u8>] {
        &self.anchors
    }
}

impl Drop for SyntheticTsa {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
