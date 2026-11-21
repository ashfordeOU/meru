// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;
use std::process::Command;

#[path = "tlog_tsa_synthetic.rs"]
mod synthetic;
use synthetic::SyntheticTsa;

#[test]
fn base64_matches_rfc_4648_vectors() {
    for (i, o) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(b64(i.as_bytes()), o);
    }
}

#[test]
fn the_request_is_der_that_openssl_reads() {
    let d: [u8; 32] = Sha256::digest(b"daily root").into();
    let q = timestamp_request(&d, 0x8000_0000_0000_0001);
    assert_eq!(q[0], 0x30);
    assert_eq!(q[1] as usize, q.len() - 2);
    let dir = std::env::temp_dir().join(format!("meru-tsq-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("q.tsq"), &q).unwrap();
    let out = Command::new("openssl")
        .args(["ts", "-query", "-in"])
        .arg(dir.join("q.tsq"))
        .arg("-text")
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("sha256"), "{text}");
    assert!(text.contains("0x8000000000000001"), "{text}");
    assert!(text.contains("Certificate required: yes"), "{text}");
}

#[test]
fn two_synthetic_authorities_stamp_and_their_tokens_verify() {
    let log = std::env::temp_dir().join(format!("meru-tsa-log-{}.jsonl", std::process::id()));
    let a: Vec<Box<dyn TimeStamper>> = vec![
        Box::new(SyntheticTsa::new("synthetic-a")),
        Box::new(SyntheticTsa::new("synthetic-b")),
    ];
    let canonical = br#"{"format":"meru-tlog-daily-root/1","size":3}"#;
    let r = stamp_and_report(&log, "2026-11-20", canonical, &a);
    assert_eq!(r.len(), 2);
    for (x, name) in r.iter().zip(["synthetic-a", "synthetic-b"]) {
        assert_eq!(x["authority"], name);
        assert_eq!(x["status"], "stamped", "{x}");
        assert_eq!(x["verified_against_configured_anchor"], true);
        assert!(x["gen_time_utc"].as_str().unwrap().ends_with('Z'));
        assert!(token_path(&log, "2026-11-20", name).exists());
    }
    // The kept token is reported again, not re-stamped.
    let again = stamp_and_report(&log, "2026-11-20", canonical, &a);
    assert_eq!(again[0]["token_sha256"], r[0]["token_sha256"]);
    // A token does not verify over different bytes, nor against the other authority's anchor.
    let tok = std::fs::read(token_path(&log, "2026-11-20", "synthetic-a")).unwrap();
    assert!(!verify_token(&tok, b"other bytes", a[0].anchors(), &[]).pass);
    assert!(!verify_token(&tok, canonical, a[1].anchors(), &[]).pass);
    let mut d = log.as_os_str().to_owned();
    d.push(".daily");
    let _ = std::fs::remove_dir_all(PathBuf::from(d));
}

#[test]
fn an_authority_that_fails_is_reported_not_hidden() {
    struct Down;
    impl TimeStamper for Down {
        fn name(&self) -> &str {
            "down"
        }
        fn stamp(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            Err("unreachable".into())
        }
        fn anchors(&self) -> &[Vec<u8>] {
            &[]
        }
    }
    let log = std::env::temp_dir().join(format!("meru-tsa-down-{}.jsonl", std::process::id()));
    let r = stamp_and_report(
        &log,
        "2026-11-20",
        b"x",
        &[Box::new(Down) as Box<dyn TimeStamper>],
    );
    assert_eq!(r[0]["status"], "failed");
    assert!(!token_path(&log, "2026-11-20", "down").exists());
}

#[test]
fn http_authority_needs_https_and_an_anchor() {
    assert!(HttpTsa::new("x", "http://tsa.invalid", Path::new("/nonexistent")).is_err());
    assert!(HttpTsa::new("x", "https://tsa.invalid", Path::new("/nonexistent")).is_err());
}
