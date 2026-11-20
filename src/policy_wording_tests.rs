// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.

use super::*;
use crate::verdict::sign;

const SEED: [u8; 32] = *b"meru-service-test-key-32-bytes!!";
const OTHER: [u8; 32] = *b"some-other-service-key-32-bytes!";

fn pk(seed: &[u8; 32]) -> String {
    hex::encode(
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes(),
    )
}

fn verdict(seed: &[u8; 32], method: &str, outcome: Value) -> SignedVerdict {
    sign(
        method,
        "MODELLED",
        outcome,
        seed,
        "k1",
        "2026-11-20T00:00:00Z",
    )
    .unwrap()
}

fn spoofing() -> SignedVerdict {
    verdict(
        &SEED,
        "cause",
        json!({"classification": "external_spoofing", "confidence": 0.85}),
    )
}

/// The labelled synthetic wording: a malicious-electronic-means exclusion, a war exclusion, a
/// cyber buy-back and a parametric cover, each as identifiers and the facts they name.
fn wording() -> Wording {
    serde_json::from_value(json!({
        "id": "SYNTH-HULL-2026",
        "synthetic": true,
        "clauses": [
            {"id": "MEM-EXCL", "kind": "exclusion", "facts": ["gnss_interference_occurred", "intent_or_actor_identity"]},
            {"id": "WAR-EXCL", "kind": "exclusion", "facts": ["intent_or_actor_identity"]},
            {"id": "CYBER-BUYBACK", "kind": "buyback", "facts": ["cyber_intrusion", "gnss_spoofing_indicated"]},
            {"id": "SPOOF-COVER", "kind": "cover", "facts": ["gnss_spoofing_indicated", "gnss_interference_occurred"]},
            {"id": "FALSIFIED-COND", "kind": "condition", "facts": ["own_track_falsified"]},
            {"id": "PARAM", "kind": "cover", "facts": ["parametric_trigger_fired"]},
        ]
    }))
    .unwrap()
}

fn clause<'a>(v: &'a Value, id: &str) -> &'a Value {
    v["clauses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()
}

#[test]
fn labelled_fixtures() {
    let r = WordingRequest {
        wording: wording(),
        evidence: vec![
            spoofing(),
            verdict(&SEED, "parametric-trigger", json!({"state": "fired"})),
        ],
    };
    let v = analyse(&r, &WordingLimits::default(), &pk(&SEED)).unwrap();
    // Interference supported, intent never determinable: the MEM and war exclusions cannot be
    // answered from PNT evidence.
    assert_eq!(
        v["facts"]["gnss_interference_occurred"]["answer"],
        "supported"
    );
    assert_eq!(
        v["facts"]["intent_or_actor_identity"]["answer"],
        "not_determinable"
    );
    assert_eq!(clause(&v, "MEM-EXCL")["not_determinable"], 1);
    assert!(clause(&v, "MEM-EXCL")["evidence_reading"]
        .as_str()
        .unwrap()
        .contains("cannot be determined"));
    assert_eq!(clause(&v, "WAR-EXCL")["supported"], 0);
    assert_eq!(v["facts"]["cyber_intrusion"]["answer"], "not_determinable");
    // Every fact of the spoofing cover is supported; falsification is not.
    assert_eq!(clause(&v, "SPOOF-COVER")["supported"], 2);
    assert!(clause(&v, "SPOOF-COVER")["evidence_reading"]
        .as_str()
        .unwrap()
        .starts_with("every fact"));
    assert_eq!(clause(&v, "FALSIFIED-COND")["not_supported"], 1);
    assert_eq!(clause(&v, "PARAM")["supported"], 1);
    // The basis names the verdict.
    assert_eq!(
        v["facts"]["gnss_spoofing_indicated"]["verdict_sha256"],
        spoofing().verdict_sha256
    );
    // Never a coverage position (outside the fixed statement that says so).
    let mut w = v.clone();
    w.as_object_mut().unwrap().remove("statement");
    let s = w.to_string();
    for w in ["applies", "covered\"", "excluded\"", "pay"] {
        assert!(!s.contains(w), "{w} in {s}");
    }
    assert_eq!(v["statement"], STATEMENT);
}

#[test]
fn disagreeing_or_weak_evidence_is_not_determinable() {
    let actor = verdict(
        &SEED,
        "victim-actor",
        json!({"classification": "actor", "confidence": 0.8, "questions": {"regional_interference": "not_reported"}}),
    );
    let r = WordingRequest {
        wording: wording(),
        evidence: vec![spoofing(), actor],
    };
    let v = analyse(&r, &WordingLimits::default(), &pk(&SEED)).unwrap();
    assert_eq!(
        v["facts"]["gnss_interference_occurred"]["answer"],
        "not_determinable"
    );
    assert!(v["facts"]["gnss_interference_occurred"]["basis"]
        .as_str()
        .unwrap()
        .contains("disagree"));
    assert_eq!(
        v["facts"]["own_track_falsified"]["answer"],
        "not_determinable"
    );
    let weak = verdict(
        &SEED,
        "cause",
        json!({"classification": "insufficient_evidence", "leading_confidence": 0.5}),
    );
    let r = WordingRequest {
        wording: wording(),
        evidence: vec![weak],
    };
    let v = analyse(&r, &WordingLimits::default(), &pk(&SEED)).unwrap();
    assert_eq!(
        v["facts"]["gnss_spoofing_indicated"]["answer"],
        "not_determinable"
    );
}

#[test]
fn refusals() {
    let mut w = wording();
    w.synthetic = false;
    let e = analyse(
        &WordingRequest {
            wording: w,
            evidence: vec![],
        },
        &WordingLimits::default(),
        &pk(&SEED),
    )
    .unwrap_err();
    assert!(e.contains("only synthetic wordings"), "{e}");
    // A verdict from another key, a tampered verdict, a method that is not evidence.
    for ev in [
        verdict(
            &OTHER,
            "cause",
            json!({"classification": "external_spoofing", "confidence": 0.9}),
        ),
        {
            let mut v = spoofing();
            v.verdict["confidence"] = json!(0.95);
            v
        },
        verdict(&SEED, "calibrate", json!({})),
    ] {
        assert!(analyse(
            &WordingRequest {
                wording: wording(),
                evidence: vec![ev],
            },
            &WordingLimits::default(),
            &pk(&SEED),
        )
        .unwrap_err()
        .contains("evidence[0]"));
    }
    let mut w = wording();
    w.clauses[0].facts.push("vessel_was_seaworthy".into());
    assert!(analyse(
        &WordingRequest {
            wording: w,
            evidence: vec![]
        },
        &WordingLimits::default(),
        &pk(&SEED)
    )
    .unwrap_err()
    .contains("unknown fact"));
    let mut w = wording();
    w.clauses[1].id = "Clause 4.2 of the real policy".into();
    assert!(analyse(
        &WordingRequest {
            wording: w,
            evidence: vec![]
        },
        &WordingLimits::default(),
        &pk(&SEED)
    )
    .is_err());
    // Free text is not a field.
    assert!(serde_json::from_value::<Wording>(json!({
        "id": "X", "synthetic": true, "text": "...", "clauses": []
    }))
    .is_err());
}

#[test]
fn verdict_is_signed_and_checks_evidence_against_its_own_key() {
    let s = crate::methods::Signing {
        signer: &SEED,
        key_id: "k1",
        lineage_seed: &SEED,
        lineage_key_id: "k1",
        sigfigs: 3,
        bind: None,
    };
    let r = WordingRequest {
        wording: wording(),
        evidence: vec![spoofing()],
    };
    let v = wording_verdict(&r, &s, &WordingLimits::default(), "2026-11-20T00:00:00Z").unwrap();
    assert_eq!(v.method, "policy-wording");
    assert!(crate::verdict::verify(&v, &pk(&SEED)).is_empty());
    let s2 = crate::methods::Signing {
        signer: &OTHER,
        ..s
    };
    assert!(wording_verdict(&r, &s2, &WordingLimits::default(), "t").is_err());
}

/// B2804's four named questions as labelled fixtures: each synthetic clause stands for a public
/// model clause (name and number only) and takes its facts from the registry. Evidence: a
/// spoofing `cause` verdict and a `victim-actor` verdict whose regional monitoring reported
/// interference.
#[test]
fn the_four_named_questions() {
    let w: Wording = serde_json::from_value(json!({
        "id": "SYNTH-MODEL-1",
        "synthetic": true,
        "clauses": [
            {"id": "MEM", "kind": "exclusion", "model": "LMA5403"},
            {"id": "CL380", "kind": "exclusion", "model": "CL380"},
            {"id": "BUYBACK", "kind": "buyback", "model": "cyber-buy-back"},
            {"id": "WAR-CYBER", "kind": "exclusion", "model": "LMA5564-LMA5567"},
        ]
    }))
    .unwrap();
    let victim = verdict(
        &SEED,
        "victim-actor",
        json!({"classification": "victim", "confidence": 0.85,
            "questions": {"regional_interference": "reported"}}),
    );
    let r = WordingRequest {
        wording: w,
        evidence: vec![spoofing(), victim],
    };
    let v = analyse(&r, &WordingLimits::default(), &pk(&SEED)).unwrap();
    // Labels: (clause, supported, not supported, not determinable).
    for (id, s, ns, nd) in [
        ("MEM", 2, 0, 2),
        ("CL380", 1, 0, 2),
        ("BUYBACK", 0, 1, 2),
        ("WAR-CYBER", 2, 0, 1),
    ] {
        let c = clause(&v, id);
        assert_eq!(
            (
                c["supported"].as_u64(),
                c["not_supported"].as_u64(),
                c["not_determinable"].as_u64()
            ),
            (Some(s), Some(ns), Some(nd)),
            "{id}: {c:#}"
        );
        // The reference is by name and number only, and says the mapping is ours.
        assert!(c["model"]["status"]
            .as_str()
            .unwrap()
            .contains("not reproduced"));
    }
    assert_eq!(
        clause(&v, "MEM")["model"]["question"],
        "malicious electronic means"
    );
    assert_eq!(
        clause(&v, "WAR-CYBER")["model"]["number"],
        "LMA5564, LMA5565, LMA5566, LMA5567"
    );
    // Who acted and why is never determinable from PNT evidence: the war/cyber boundary and the
    // malicious element stay open whatever the evidence.
    assert_eq!(
        v["facts"]["intent_or_actor_identity"]["answer"],
        "not_determinable"
    );
    assert_eq!(
        v["facts"]["regional_interference_reported"]["answer"],
        "supported"
    );
    // Unknown model clause.
    let w2: Wording = serde_json::from_value(json!({"id": "X", "synthetic": true,
        "clauses": [{"id": "A", "kind": "exclusion", "model": "LMA9999"}]}))
    .unwrap();
    assert!(analyse(
        &WordingRequest {
            wording: w2,
            evidence: vec![]
        },
        &WordingLimits::default(),
        &pk(&SEED)
    )
    .unwrap_err()
    .contains("unknown model clause"));
}
