// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;

const SEED: [u8; 32] = *b"meru-service-test-key-32-bytes!!";

fn leaves(n: usize) -> Vec<H> {
    (0..n)
        .map(|i| leaf_hash(format!("leaf {i}").as_bytes()))
        .collect()
}

/// RFC 6962's own example shape: the root of 7 leaves splits 4 + 3.
#[test]
fn tree_hash_follows_the_rfc_split() {
    let l = leaves(7);
    let a = node(&node(&l[0], &l[1]), &node(&l[2], &l[3]));
    let b = node(&node(&l[4], &l[5]), &l[6]);
    assert_eq!(root(&l), node(&a, &b));
    assert_eq!(root(&[]), sha(&[]));
    assert_eq!(root(&l[..1]), l[0]);
}

#[test]
fn inclusion_proofs_verify_for_every_leaf_and_size() {
    for n in 1..=33usize {
        let l = leaves(n);
        let r = root(&l);
        for m in 0..n {
            let p = inclusion_path(m, &l);
            assert!(verify_inclusion(m, n, &l[m], &p, &r), "n {n} m {m}");
            // The wrong leaf or index does not verify.
            let other = leaf_hash(b"not in the log");
            assert!(!verify_inclusion(m, n, &other, &p, &r));
            if n > 1 {
                assert!(!verify_inclusion((m + 1) % n, n, &l[m], &p, &r) || l[m] == l[(m + 1) % n]);
            }
        }
    }
}

#[test]
fn consistency_proofs_verify_between_every_pair_of_sizes() {
    let all = leaves(33);
    for n in 1..=33usize {
        for m in 1..=n {
            let p = consistency_path(m, &all[..n]);
            let (a, b) = (root(&all[..m]), root(&all[..n]));
            assert!(verify_consistency(m, n, &a, &b, &p), "m {m} n {n}");
            if m < n {
                // A rewritten history does not verify.
                let mut forged = all[..n].to_vec();
                forged[0] = leaf_hash(b"rewritten");
                let fb = root(&forged);
                assert!(!verify_consistency(m, n, &a, &fb, &p), "m {m} n {n}");
            }
        }
    }
}

fn tmp(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("meru-tlog-{tag}-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

fn req(i: usize) -> AppendRequest {
    AppendRequest {
        pack_sha256: hex::encode(Sha256::digest(format!("pack {i}"))),
        kind: "kshana-dossier/1".into(),
        signer_key_id: Some("kid-test".into()),
    }
}

#[test]
fn the_log_appends_proves_and_survives_a_restart() {
    let p = tmp("append");
    let mut t = Tlog::open(&p, anchors_from(&[])).unwrap();
    for i in 0..10 {
        let (idx, new) = t
            .append(&req(i), "kt_holder", "2026-11-20T00:00:00Z")
            .unwrap();
        assert_eq!((idx, new), (i, true));
    }
    // Idempotent for a pack already logged.
    assert_eq!(t.append(&req(3), "kt_other", "t").unwrap(), (3, false));
    let sth = t.sth(&SEED, "k1", 1_795_132_800).unwrap();
    assert_eq!(sth.method, "tlog-sth");
    assert_eq!(sth.verdict["size"], 10);
    // Two anchor slots, both honest placeholders.
    let anchors = sth.verdict["anchors"].as_array().unwrap();
    assert_eq!(anchors.len(), 2);
    assert!(anchors.iter().all(|a| a["status"] == "not_anchored"));
    // An inclusion proof from the API verifies against the signed head.
    let pr = t.proof(7, 10).unwrap();
    let r = hash_of(&sth.verdict, "root_hash").unwrap();
    assert!(verify_inclusion(
        7,
        10,
        &hash_of(&pr, "leaf_hash").unwrap(),
        &path_of(&pr).unwrap(),
        &r
    ));
    // Consistency from an earlier head.
    let c = t.consistency(4, 10).unwrap();
    assert!(verify_consistency(
        4,
        10,
        &hash_of(&c, "from_root").unwrap(),
        &r,
        &path_of(&c).unwrap()
    ));
    // No pack contents and no submitter in what is published.
    let e = t.entry(2).unwrap();
    assert!(!e.to_string().contains("kt_holder") && !e.to_string().contains("h:"));
    // Restart: same head.
    let t2 = Tlog::open(&p, anchors_from(&[])).unwrap();
    assert_eq!(
        t2.sth(&SEED, "k1", 1_795_132_800).unwrap().verdict,
        sth.verdict
    );
    // Tampering with the file is caught at start.
    let text = std::fs::read_to_string(&p).unwrap();
    std::fs::write(&p, text.replacen("kshana-dossier/1", "kshana-dossier/2", 1)).unwrap();
    assert!(Tlog::open(&p, anchors_from(&[]))
        .err()
        .unwrap()
        .contains("does not recompute"));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn refusals_and_queries() {
    let p = tmp("refuse");
    let mut t = Tlog::open(&p, anchors_from(&["tsa-a".into(), "ledger-b".into()])).unwrap();
    let mut r = req(0);
    r.pack_sha256 = "xyz".into();
    assert!(t.append(&r, "k", "t").is_err());
    let mut r = req(0);
    r.kind = "bad kind with spaces".into();
    assert!(t.append(&r, "k", "t").is_err());
    t.append(&req(0), "k", "t").unwrap();
    assert!(t.proof(1, 1).is_err());
    assert!(t.consistency(0, 1).is_err());
    let sth = t.sth(&SEED, "k1", 0).unwrap();
    assert_eq!(sth.verdict["anchors"][0]["authority"], "tsa-a");
    assert_eq!(query_num("index=4&size=9", "size"), Some(9));
    assert_eq!(query_str("pack_sha256=ab", "pack_sha256"), Some("ab"));
    let _ = std::fs::remove_file(&p);
}
