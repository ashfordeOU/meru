// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;

const SEED: [u8; 32] = *b"meru-service-test-key-32-bytes!!";
const OTHER: [u8; 32] = *b"some-other-service-key-32-bytes!";

fn signing(seed: &[u8; 32]) -> crate::methods::Signing<'_> {
    crate::methods::Signing {
        signer: seed,
        key_id: "k1",
        lineage_seed: seed,
        lineage_key_id: "k1",
        sigfigs: 3,
        bind: None,
    }
}

fn entries(n: usize, tag: &str) -> Vec<Value> {
    (0..n)
        .map(|i| {
            json!({"name": format!("obs/{tag}/b{i:04}.jsonl"),
                "sha256": hex::encode(Sha256::digest(format!("{tag}-{i}"))), "bytes": 1000 + i})
        })
        .collect()
}

fn req(start: &str, end: &str, n: usize, tag: &str, prev: Option<&SignedVerdict>) -> SealRequest {
    let mut v = json!({"archive_id": "net-archive", "period_start_utc": start, "period_end_utc": end,
        "entries": entries(n, tag)});
    if let Some(p) = prev {
        v["previous"] = serde_json::to_value(p).unwrap();
    }
    serde_json::from_value(v).unwrap()
}

#[test]
fn audit_paths_reach_the_root_for_every_size() {
    for n in 1..=17usize {
        let leaves: Vec<[u8; 32]> = (0..n)
            .map(|i| leaf(&format!("f{i}"), &[i as u8; 32]))
            .collect();
        let root = merkle_root(&leaves).unwrap();
        for i in 0..n {
            assert_eq!(
                root_from_path(leaves[i], &audit_path(&leaves, i)),
                root,
                "n {n} i {i}"
            );
        }
        // A changed leaf does not reach it.
        let bad = leaf("f0", &[99; 32]);
        if n > 1 {
            assert_ne!(root_from_path(bad, &audit_path(&leaves, 0)), root);
        }
    }
}

#[test]
fn seals_chain_and_the_order_of_entries_does_not_matter() {
    let s = signing(&SEED);
    let a = seal_verdict(
        &req(
            "2026-11-01T00:00:00Z",
            "2026-11-02T00:00:00Z",
            10,
            "d1",
            None,
        ),
        &s,
        &SealLimits::default(),
        "2026-11-02T00:05:00Z",
    )
    .unwrap();
    assert_eq!(a.method, "archive-seal");
    assert_eq!(a.verdict["seq"], 1);
    assert_eq!(a.verdict["entries"], 10);
    assert_eq!(a.verdict["total_bytes"], 10 * 1000 + 45);
    // Same entries in another order: same root.
    let mut r = req(
        "2026-11-01T00:00:00Z",
        "2026-11-02T00:00:00Z",
        10,
        "d1",
        None,
    );
    r.entries.reverse();
    let a2 = analyse(&r, &SealLimits::default(), &hex::encode(SEED_PK())).unwrap();
    assert_eq!(a2["merkle_root"], a.verdict["merkle_root"]);
    // The next seal chains to it.
    let b = seal_verdict(
        &req(
            "2026-11-02T00:00:00Z",
            "2026-11-03T00:00:00Z",
            7,
            "d2",
            Some(&a),
        ),
        &s,
        &SealLimits::default(),
        "2026-11-03T00:05:00Z",
    )
    .unwrap();
    assert_eq!(b.verdict["seq"], 2);
    assert_eq!(b.verdict["previous"]["verdict_sha256"], a.verdict_sha256);
    assert!(crate::verdict::verify(&b, &hex::encode(SEED_PK())).is_empty());
}

#[allow(non_snake_case)]
fn SEED_PK() -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&SEED)
        .verifying_key()
        .to_bytes()
}

#[test]
fn a_broken_chain_is_refused() {
    let s = signing(&SEED);
    let a = seal_verdict(
        &req(
            "2026-11-01T00:00:00Z",
            "2026-11-02T00:00:00Z",
            3,
            "d1",
            None,
        ),
        &s,
        &SealLimits::default(),
        "t",
    )
    .unwrap();
    let l = SealLimits::default();
    // Overlapping period.
    let e = seal_verdict(
        &req(
            "2026-11-01T12:00:00Z",
            "2026-11-03T00:00:00Z",
            3,
            "d2",
            Some(&a),
        ),
        &s,
        &l,
        "t",
    )
    .unwrap_err();
    assert!(e.contains("before the previous seal"), "{e}");
    // A tampered previous seal.
    let mut t = a.clone();
    t.verdict["seq"] = json!(41);
    assert!(seal_verdict(
        &req(
            "2026-11-02T00:00:00Z",
            "2026-11-03T00:00:00Z",
            3,
            "d2",
            Some(&t)
        ),
        &s,
        &l,
        "t"
    )
    .unwrap_err()
    .contains("not a seal of this service"));
    // A seal from another key.
    let o = seal_verdict(
        &req(
            "2026-11-01T00:00:00Z",
            "2026-11-02T00:00:00Z",
            3,
            "d1",
            None,
        ),
        &signing(&OTHER),
        &l,
        "t",
    )
    .unwrap();
    assert!(seal_verdict(
        &req(
            "2026-11-02T00:00:00Z",
            "2026-11-03T00:00:00Z",
            3,
            "d2",
            Some(&o)
        ),
        &s,
        &l,
        "t"
    )
    .is_err());
    // Another archive's seal.
    let mut r = req(
        "2026-11-02T00:00:00Z",
        "2026-11-03T00:00:00Z",
        3,
        "d2",
        Some(&a),
    );
    r.archive_id = "other".into();
    assert!(seal_verdict(&r, &s, &l, "t")
        .unwrap_err()
        .contains("another archive"));
    // Duplicate names, bad digests.
    let mut r = req(
        "2026-11-01T00:00:00Z",
        "2026-11-02T00:00:00Z",
        3,
        "d1",
        None,
    );
    r.entries[1].name = r.entries[0].name.clone();
    assert!(seal_verdict(&r, &s, &l, "t").unwrap_err().contains("twice"));
    let mut r = req(
        "2026-11-01T00:00:00Z",
        "2026-11-02T00:00:00Z",
        3,
        "d1",
        None,
    );
    r.entries[0].sha256 = "abc".into();
    assert!(seal_verdict(&r, &s, &l, "t")
        .unwrap_err()
        .contains("64 hex"));
}
