// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;

const SEED: [u8; 32] = *b"meru-service-test-key-32-bytes!!";
const T: i64 = 1_795_132_800; // 2026-11-20T00:00:00Z

fn pk() -> String {
    hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&SEED)
            .verifying_key()
            .to_bytes(),
    )
}

fn req(product: &str, method: &str, reason: Reason) -> RevokeRequest {
    RevokeRequest {
        product_id: product.into(),
        scored_under: ScoredUnder {
            method: method.into(),
            version: "1".into(),
        },
        verdict_sha256: Some("ab".repeat(32)),
        reason,
        note: Some("private: firmware 4.2 regression found in bench re-run".into()),
    }
}

fn tmp(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("meru-crl-{tag}-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn revocations_persist_and_the_list_verifies_offline() {
    let p = tmp("persist");
    let mut s = CrlStore::open(&p).unwrap();
    let rx = ScoredUnder {
        method: "receiver-scorecard".into(),
        version: "1".into(),
    };
    s.revoke(
        &req("RX-100", "receiver-scorecard", Reason::ProductChanged),
        "kt_admin",
        "2026-11-20T00:00:00Z",
    )
    .unwrap();
    s.revoke(
        &req("RX-007", "receiver-scorecard", Reason::EvidenceError),
        "kt_admin",
        "2026-11-20T00:01:00Z",
    )
    .unwrap();
    // A second revocation of the same entry is refused; another method for it is not.
    assert!(s
        .revoke(
            &req("RX-100", "receiver-scorecard", Reason::HolderRequest),
            "kt_admin",
            "t"
        )
        .unwrap_err()
        .starts_with("already revoked"));
    s.revoke(
        &req("RX-100", "timing-scorecard", Reason::MethodSuperseded),
        "kt_admin",
        "t",
    )
    .unwrap();
    let list = s.signed(&SEED, "k1", T).unwrap();
    assert_eq!(list.method, "crl");
    assert_eq!(list.evidence_class, "RECORD");
    assert_eq!(list.verdict["seq"], 3);
    assert_eq!(list.verdict["format"], FORMAT);
    // Entries are sorted, the private note and the revoker are not published.
    let ids: Vec<&str> = list.verdict["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["product_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["RX-007", "RX-100", "RX-100"]);
    let text = serde_json::to_string(&list).unwrap();
    assert!(!text.contains("firmware 4.2") && !text.contains("kt_admin"));
    // Never "validated" or "certified".
    for w in ["validated", "certified", "approved"] {
        assert!(!text.to_lowercase().contains(w), "{w}");
    }
    // The client-side check.
    assert!(is_revoked(&list, &pk(), "RX-100", &rx, T + 60).unwrap());
    assert!(!is_revoked(&list, &pk(), "RX-200", &rx, T + 60).unwrap());
    assert!(is_revoked(&list, &pk(), "RX-100", &rx, T + VALIDITY_S + 1)
        .unwrap_err()
        .contains("stale"));
    let mut t = list.clone();
    t.verdict["entries"] = json!([]);
    assert!(is_revoked(&t, &pk(), "RX-100", &rx, T).is_err());
    // Read back from the log after a restart: same entries, same signed body at the same time.
    let mut s2 = CrlStore::open(&p).unwrap();
    assert_eq!(s2.entries(), s.entries());
    assert_eq!(s2.signed(&SEED, "k1", T).unwrap().verdict, list.verdict);
    // The log keeps the private note.
    assert!(std::fs::read_to_string(&p)
        .unwrap()
        .contains("firmware 4.2"));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn resigned_daily_and_after_each_revocation() {
    let p = tmp("resign");
    let mut s = CrlStore::open(&p).unwrap();
    let a = s.signed(&SEED, "k1", T).unwrap();
    assert_eq!(a.verdict["seq"], 0);
    assert_eq!(s.signed(&SEED, "k1", T + 3600).unwrap(), a);
    let b = s.signed(&SEED, "k1", T + RESIGN_AFTER_S + 1).unwrap();
    assert_ne!(b.verdict["this_update"], a.verdict["this_update"]);
    s.revoke(
        &req("P-1", "perception-eval", Reason::ScoreWithdrawn),
        "kt_admin",
        "t",
    )
    .unwrap();
    assert_eq!(
        s.signed(&SEED, "k1", T + RESIGN_AFTER_S + 2)
            .unwrap()
            .verdict["seq"],
        1
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn requests_are_checked() {
    let mut r = req("P 1", "m", Reason::ScoreWithdrawn);
    assert!(check(&r).is_err());
    r.product_id = "P-1".into();
    assert!(check(&r).is_ok());
    r.verdict_sha256 = Some("xyz".into());
    assert!(check(&r).is_err());
    r.verdict_sha256 = None;
    r.note = Some("x".repeat(501));
    assert!(check(&r).is_err());
    assert!(serde_json::from_value::<RevokeRequest>(json!({
        "product_id": "P", "scored_under": {"method": "m", "version": "1"}, "reason": "certified_elsewhere"
    }))
    .is_err());
}

#[test]
fn entry_ids_and_the_record_hash_follow_the_documented_rule() {
    let su = ScoredUnder {
        method: "receiver-scorecard".into(),
        version: "1".into(),
    };
    let canonical = r#"{"method":"receiver-scorecard","product_id":"RX-100","version":"1"}"#;
    assert_eq!(
        entry_id("RX-100", &su),
        hex::encode(Sha256::digest(canonical))
    );
    let p = tmp("ids");
    let mut s = CrlStore::open(&p).unwrap();
    let r = s
        .revoke(
            &req("RX-100", "receiver-scorecard", Reason::ProductChanged),
            "kt_admin",
            "2026-11-20T00:00:00Z",
        )
        .unwrap();
    assert_eq!(r.entry_id, entry_id("RX-100", &su));
    let rec = format!(
        r#"{{"entry_id":"{}","product_id":"RX-100","reason":"product_changed","revoked_utc":"2026-11-20T00:00:00Z","scored_under":{{"method":"receiver-scorecard","version":"1"}},"verdict_sha256":"{}"}}"#,
        r.entry_id,
        "ab".repeat(32)
    );
    assert_eq!(record_sha256(&r), hex::encode(Sha256::digest(&rec)));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn logs_and_lists_from_before_entry_ids_are_still_read() {
    let p = tmp("legacy");
    std::fs::write(
        &p,
        r#"{"revoked":{"product_id":"RX-1","scored_under":{"method":"m","version":"1"},"verdict_sha256":null,"reason":"holder_request","revoked_utc":"2026-11-01T00:00:00Z"},"by_token_id":"kt","note":null}
"#,
    )
    .unwrap();
    let s = CrlStore::open(&p).unwrap();
    let su = ScoredUnder {
        method: "m".into(),
        version: "1".into(),
    };
    assert_eq!(s.entries()[0].entry_id, entry_id("RX-1", &su));
    // A list in the earlier format (no entry_id, old format name) is still checked.
    let mut b = body(s.entries(), "k1", T);
    b["format"] = json!(LEGACY_FORMAT);
    b["entries"][0].as_object_mut().unwrap().remove("entry_id");
    let l = sign("crl", "RECORD", b, &SEED, "k1", &crate::server::iso(T)).unwrap();
    assert!(is_revoked_id(&l, &pk(), &entry_id("RX-1", &su), T).unwrap());
    let _ = std::fs::remove_file(&p);
}

/// The pinned list vector in docs/crl-vector.json: two revocations signed with the public test
/// seed of this file at 2026-11-20T00:00:00Z. Ed25519 is deterministic, so it is reproduced.
#[test]
fn crl_vector() {
    let p = tmp("vector");
    let mut s = CrlStore::open(&p).unwrap();
    s.revoke(
        &req("RX-100", "receiver-scorecard", Reason::ProductChanged),
        "kt",
        "2026-11-19T10:00:00Z",
    )
    .unwrap();
    s.revoke(
        &req("RX-007", "receiver-scorecard", Reason::EvidenceError),
        "kt",
        "2026-11-19T11:00:00Z",
    )
    .unwrap();
    let l = build(s.entries(), &SEED, "k1", T).unwrap();
    let got = serde_json::to_string_pretty(&json!({
        "public_key": pk(),
        "list": l,
    }))
    .unwrap()
        + "\n";
    if std::env::var("MERU_PRINT_VECTORS").is_ok() {
        print!("{got}");
    }
    assert_eq!(got, include_str!("../docs/crl-vector.json"));
    // The list's entries digest is over the entries' canonical JSON (sorted keys).
    let ev = serde_json::to_vec(&l.verdict["entries"]).unwrap();
    assert_eq!(
        l.verdict["entries_sha256"],
        hex::encode(Sha256::digest(&ev))
    );
    let _ = std::fs::remove_file(&p);
}
