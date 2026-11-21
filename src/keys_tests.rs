// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;
use kshana_pro::license::key_id as kid_of;

fn seed(tag: &str) -> [u8; 32] {
    Sha256::digest(format!("meru keys test {tag}")).into()
}
fn kid(s: &[u8; 32]) -> String {
    kid_of(&s.public_key().unwrap())
}
fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("meru-keys-{tag}-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn rotation_with_endorsement_is_recorded_and_verifies() {
    let p = tmp("rotate");
    let (a, b, c) = (seed("a"), seed("b"), seed("c"));
    let h = ensure_current(&p, &a, &kid(&a), "2026-01-01T00:00:00Z", None).unwrap();
    assert_eq!(h.len(), 1);
    // Restarting with the same key appends nothing.
    assert_eq!(
        ensure_current(&p, &a, &kid(&a), "2026-02-01T00:00:00Z", None)
            .unwrap()
            .len(),
        1
    );
    // Rotation to b, endorsed by a.
    let bpk = hex::encode(b.public_key().unwrap());
    let e = endorse(&a, &kid(&a), &kid(&b), &bpk).unwrap();
    let h = ensure_current(&p, &b, &kid(&b), "2026-06-01T00:00:00Z", Some(&e)).unwrap();
    assert_eq!(h.len(), 2);
    assert_eq!(h[1].previous_key_endorsement.as_deref(), Some(e.as_str()));
    // Rotation to c without an endorsement: recorded as such.
    let h = ensure_current(&p, &c, &kid(&c), "2026-09-01T00:00:00Z", None).unwrap();
    assert!(h[2].previous_key_endorsement.is_none());
    assert_eq!(read(&p).unwrap(), h);
    let v = published(Some(&p), &c, &kid(&c), "2026-11-21T00:00:00Z").unwrap();
    assert!(crate::verdict::verify(&v, &hex::encode(c.public_key().unwrap())).is_empty());
    let k = &v.verdict["keys"];
    assert_eq!(k[0]["not_after"], "2026-06-01T00:00:00Z");
    assert_eq!(k[0]["status"], "retired");
    assert_eq!(k[1]["endorsed_by_previous_key"], true);
    assert_eq!(k[2]["endorsed_by_previous_key"], false);
    assert_eq!(k[2]["status"], "current");
    assert_eq!(k[2]["not_after"], Value::Null);
    assert_eq!(v.verdict["history_head_sha256"], json!(h[2].record_sha256));
    // A retired key may not come back.
    assert!(ensure_current(&p, &a, &kid(&a), "2026-10-01T00:00:00Z", None).is_err());
    let _ = std::fs::remove_file(&p);
}

#[test]
fn a_wrong_endorsement_is_refused_before_anything_is_written() {
    let p = tmp("bad-endorse");
    let (a, b, x) = (seed("a"), seed("b"), seed("x"));
    ensure_current(&p, &a, &kid(&a), "2026-01-01T00:00:00Z", None).unwrap();
    let bpk = hex::encode(b.public_key().unwrap());
    let forged = endorse(&x, &kid(&a), &kid(&b), &bpk).unwrap();
    assert!(ensure_current(&p, &b, &kid(&b), "2026-06-01T00:00:00Z", Some(&forged)).is_err());
    assert_eq!(read(&p).unwrap().len(), 1);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn a_tampered_history_is_refused() {
    let p = tmp("tamper");
    let (a, b) = (seed("a"), seed("b"));
    ensure_current(&p, &a, &kid(&a), "2026-01-01T00:00:00Z", None).unwrap();
    ensure_current(&p, &b, &kid(&b), "2026-06-01T00:00:00Z", None).unwrap();
    let good = std::fs::read_to_string(&p).unwrap();
    for (from, to) in [
        ("2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z"),
        ("\"seq\":1", "\"seq\":2"),
    ] {
        std::fs::write(&p, good.replace(from, to)).unwrap();
        assert!(read(&p).is_err(), "{from}");
    }
    // Dropping the first record breaks the chain.
    std::fs::write(&p, good.lines().nth(1).unwrap()).unwrap();
    assert!(read(&p).is_err());
    let _ = std::fs::remove_file(&p);
}

#[test]
fn without_a_history_only_the_current_key_is_published() {
    let a = seed("a");
    let v = published(None, &a, &kid(&a), "2026-11-21T00:00:00Z").unwrap();
    assert_eq!(
        v.verdict["keys"][0]["public_key"],
        hex::encode(a.public_key().unwrap())
    );
    assert_eq!(v.verdict["history"], json!([]));
    assert!(v.verdict["note"]
        .as_str()
        .unwrap()
        .contains("MERU_KEY_HISTORY"));
}

/// Pinned key-history vectors (docs/key-history-vectors.jsonl): key A then key B endorsed by A,
/// seeds SHA-256("meru keys test a") and SHA-256("meru keys test b"). Ed25519 is deterministic,
/// so the file is reproduced byte for byte.
#[test]
fn key_history_vectors() {
    let p = tmp("vectors");
    let (a, b) = (seed("a"), seed("b"));
    ensure_current(&p, &a, &kid(&a), "2026-01-01T00:00:00Z", None).unwrap();
    let e = endorse(
        &a,
        &kid(&a),
        &kid(&b),
        &hex::encode(b.public_key().unwrap()),
    )
    .unwrap();
    ensure_current(&p, &b, &kid(&b), "2026-06-01T00:00:00Z", Some(&e)).unwrap();
    let got = std::fs::read_to_string(&p).unwrap();
    if std::env::var("MERU_PRINT_VECTORS").is_ok() {
        print!("{got}");
    }
    assert_eq!(got, include_str!("../docs/key-history-vectors.jsonl"));
    let _ = std::fs::remove_file(&p);
}
