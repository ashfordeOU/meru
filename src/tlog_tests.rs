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
        class: None,
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

/// The RFC 6962 reference vectors (the eight leaves of the Certificate Transparency test suite);
/// an open verifier can check its tree hash against these.
pub const RFC6962_LEAVES: [&str; 8] = [
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
];
pub const RFC6962_ROOTS: [&str; 8] = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];

#[test]
fn rfc_6962_reference_vectors() {
    let l: Vec<H> = RFC6962_LEAVES
        .iter()
        .map(|h| leaf_hash(&hex::decode(h).unwrap()))
        .collect();
    assert_eq!(
        hex::encode(root(&[])),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    for n in 1..=8 {
        assert_eq!(hex::encode(root(&l[..n])), RFC6962_ROOTS[n - 1], "size {n}");
    }
    // Inclusion of leaf 0 in 8, and consistency 1 → 8, 6 → 8, 2 → 5 (the CT suite's cases).
    let p = inclusion_path(0, &l);
    assert_eq!(
        p.iter().map(hex::encode).collect::<Vec<_>>(),
        [
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ]
    );
    for (m, n) in [(1, 8), (6, 8), (2, 5)] {
        let c = consistency_path(m, &l[..n]);
        assert!(verify_consistency(m, n, &root(&l[..m]), &root(&l[..n]), &c));
    }
    assert_eq!(
        consistency_path(6, &l)
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>(),
        [
            "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ]
    );
}

fn entry_req(i: usize, class: Option<&str>) -> AppendRequest {
    AppendRequest {
        pack_sha256: hex::encode(Sha256::digest(format!("vector {i}"))),
        kind: if class == Some("calibration_record") {
            "delay-calibration/1".into()
        } else {
            "kshana-dossier/1".into()
        },
        signer_key_id: Some("kid-vector".into()),
        class: class.map(String::from),
    }
}

/// The log's own test vectors (written into docs/TLOG-PROOFS.md): five entries, their leaf data,
/// leaf hashes, the root, one inclusion proof and one consistency proof.
#[test]
fn meru_entry_vectors() {
    let p = tmp("vectors");
    let mut t = Tlog::open(&p, anchors_from(&[])).unwrap();
    let classes = [
        None,
        Some("evidence_pack"),
        Some("calibration_record"),
        Some("evidence_pack"),
        Some("calibration_record"),
    ];
    for (i, c) in classes.iter().enumerate() {
        t.append(&entry_req(i, *c), "tok", &format!("2026-11-20T0{i}:00:00Z"))
            .unwrap();
    }
    // Leaf data is the entry's JSON with the fields in this order, no whitespace; `class` is
    // absent when it was not given.
    let d0 = String::from_utf8(t.entries[0].data()).unwrap();
    assert_eq!(
        d0,
        format!(
            r#"{{"pack_sha256":"{}","kind":"kshana-dossier/1","signer_key_id":"kid-vector","logged_utc":"2026-11-20T00:00:00Z"}}"#,
            hex::encode(Sha256::digest("vector 0"))
        )
    );
    let d2 = String::from_utf8(t.entries[2].data()).unwrap();
    assert!(d2.ends_with(r#","logged_utc":"2026-11-20T02:00:00Z","class":"calibration_record"}"#));
    let out = json!({
        "leaf_data": t.entries.iter().map(|e| String::from_utf8(e.data()).unwrap()).collect::<Vec<_>>(),
        "leaf_hashes": t.leaves.iter().map(hex::encode).collect::<Vec<_>>(),
        "root_5": hex::encode(root(&t.leaves)),
        "root_3": hex::encode(root(&t.leaves[..3])),
        "chain_head_5": hex::encode(t.chain),
        "inclusion_2_in_5": t.proof(2, 5).unwrap(),
        "consistency_3_to_5": t.consistency(3, 5).unwrap(),
    });
    if std::env::var("MERU_PRINT_VECTORS").is_ok() {
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    }
    // Pinned: any change to leaf data or hashing breaks this test (and the published vectors).
    let pinned: Value =
        serde_json::from_str(include_str!("../docs/tlog-vectors.json")).expect("vectors file");
    assert_eq!(out, pinned);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn an_unknown_class_is_refused() {
    let p = tmp("class");
    let mut t = Tlog::open(&p, anchors_from(&[])).unwrap();
    assert!(t
        .append(
            &entry_req(0, Some("anything")),
            "tok",
            "2026-11-20T00:00:00Z"
        )
        .unwrap_err()
        .contains("class"));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn the_daily_root_is_the_log_at_the_end_of_a_completed_day() {
    let p = tmp("daily");
    let mut t = Tlog::open(&p, anchors_from(&[])).unwrap();
    let times = [
        "2026-11-19T23:59:59Z",
        "2026-11-20T00:00:00Z",
        "2026-11-20T12:00:00Z",
        "2026-11-21T00:00:00Z",
    ];
    for (i, u) in times.iter().enumerate() {
        t.append(&entry_req(i, Some("evidence_pack")), "tok", u)
            .unwrap();
    }
    let now = crate::cause::parse_iso("2026-11-21T06:00:00Z").unwrap() as i64;
    let d = t.daily_root("2026-11-20", "kid", now).unwrap();
    assert_eq!(d["size"], 3);
    assert_eq!(d["root_hash"], hex::encode(root(&t.leaves[..3])));
    assert_eq!(d["chain_head"], hex::encode(t.chains[2]));
    assert_eq!(t.daily_root("2026-11-18", "kid", now).unwrap()["size"], 0);
    // Today is not complete; a bad date is refused.
    assert!(t.daily_root("2026-11-21", "kid", now).is_err());
    assert!(t.daily_root("20-11-2026", "kid", now).is_err());
    // With no authority configured the signed daily root says so.
    let s = t.daily(&p, "2026-11-20", &SEED, "kid", now).unwrap();
    assert_eq!(s.verdict["anchoring"], crate::tlog_tsa::NO_PROVIDER);
    assert_eq!(s.verdict["timestamps"], json!([]));
    let canonical = serde_json::to_vec(&s.verdict["daily_root"]).unwrap();
    assert_eq!(
        s.verdict["daily_root_sha256"],
        hex::encode(Sha256::digest(&canonical))
    );
    // After a restart the chain heads are rebuilt.
    let t2 = Tlog::open(&p, anchors_from(&[])).unwrap();
    assert_eq!(t2.daily_root("2026-11-20", "kid", now).unwrap(), d);
    let _ = std::fs::remove_file(&p);
}
