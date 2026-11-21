// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! Fuzz-style hardening test of every hosted verdict endpoint (audit-1): for each endpoint a
//! valid example body (`src/data/fuzz-corpus.json`, recorded from the end-to-end suite and with
//! arrays trimmed) is mutated field by field (extreme and non-finite-looking numbers, wrong types,
//! empty and oversized arrays and strings, removed and unknown keys) and run through the same
//! dispatch the server uses. No mutation may panic, and no accepted answer may carry a
//! non-finite number.

use super::*;
use serde_json::{json, Value};
use std::panic::{catch_unwind, AssertUnwindSafe};

const SEED: [u8; 32] = *b"meru-fuzz-service-test-seed-32b!";

fn service() -> Service {
    let dir = std::env::temp_dir().join(format!("meru-fuzz-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Service::new(
        {
            // Production limits, except the survey's work bound, lowered so the slowest legal
            // survey stays short in a debug build (the bound itself is tested in `methods`).
            let mut c = Config {
                key_id: "fuzz".into(),
                ..Config::default()
            };
            c.limits.max_survey_work = 2.0e5;
            c
        },
        crate::signer::Signers {
            verdict: std::sync::Arc::new(SEED),
            lineage_seed: SEED,
            lineage_key_id: "lineage".into(),
        },
        Authz::Open,
        crate::limits::Limiter::new(crate::limits::LimitConfig::default()),
        crate::meter::Meter::open(&dir.join("meter.jsonl")).unwrap(),
    )
}

fn caller() -> Caller {
    Caller {
        licensee: "fuzz".into(),
        tier: Tier::Evaluation,
        token_id: "fuzz".into(),
        allow_grid: false,
        service: None,
    }
}

/// One leaf or container per schema path (array indices folded), with its JSON pointer.
fn schema_paths(v: &Value, ptr: String, schema: String, out: &mut Vec<(String, String)>) {
    if !out.iter().any(|(s, _)| *s == schema) {
        out.push((schema.clone(), ptr.clone()));
    }
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                let k2 = k.replace('~', "~0").replace('/', "~1");
                schema_paths(x, format!("{ptr}/{k2}"), format!("{schema}/{k2}"), out);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate().take(3) {
                schema_paths(x, format!("{ptr}/{i}"), format!("{schema}/*"), out);
            }
        }
        _ => {}
    }
}

fn replacements(v: &Value) -> Vec<Value> {
    let mut r: Vec<Value> = vec![Value::Null, json!(true), json!({})];
    match v {
        Value::Number(_) => r.extend([
            json!(0),
            json!(-1),
            json!(-0.0),
            json!(1e308),
            json!(-1e308),
            json!(1e-320),
            json!(u64::MAX),
            json!(i64::MIN),
            json!(0.5),
            json!("1"),
        ]),
        Value::String(_) => r.extend([
            json!(""),
            json!("x".repeat(20_000)),
            json!("\u{0}\u{7f}Ω"),
            json!("NaN"),
            json!("1970-01-01T00:00:00Z"),
            json!("9999-12-31T23:59:59Z"),
            json!(1),
        ]),
        Value::Array(a) => {
            r.push(json!([]));
            if let Some(f) = a.first() {
                r.push(json!([f]));
                r.push(json!(vec![
                    f.clone();
                    2000.min(200_000 / f.to_string().len().max(1))
                ]));
                r.push(json!([null]));
            }
        }
        Value::Object(_) => r.push(json!([])),
        _ => r.push(json!(1)),
    }
    r
}

fn has_non_finite(v: &Value) -> bool {
    match v {
        Value::Number(n) => n.as_f64().is_some_and(|f| !f.is_finite()),
        Value::Array(a) => a.iter().any(has_non_finite),
        Value::Object(m) => m.values().any(has_non_finite),
        _ => false,
    }
}

#[test]
fn every_endpoint_survives_malformed_and_extreme_json() {
    let corpus: serde_json::Map<String, Value> =
        serde_json::from_str(include_str!("data/fuzz-corpus.json")).unwrap();
    let svc = service();
    let who = caller();
    let now = 1_795_132_800;
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut panics: Vec<String> = vec![];
    let mut nonfinite: Vec<String> = vec![];
    let mut runs = 0usize;
    let mut base_ok: Vec<String> = vec![];
    let mut slow: Vec<String> = vec![];
    let mut try_one = |path: &str, label: &str, body: &[u8]| {
        let method = method_of(path).unwrap_or("survey-plan");
        let j: Option<Value> = serde_json::from_slice(body).ok();
        runs += 1;
        let started = std::time::Instant::now();
        if std::env::var("MERU_FUZZ_TRACE").is_ok() {
            eprintln!("> {path} {label}");
        }
        let res = match catch_unwind(AssertUnwindSafe(|| {
            svc.run(path, method, body, j.as_ref(), &who, now)
        })) {
            Err(p) => {
                let m = p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                eprintln!("PANIC {path} {label}: {m}");
                panics.push(format!("{path} {label}: {m}"));
                None
            }
            Ok((Ok(v), _)) => {
                let val = serde_json::to_value(&v).unwrap();
                if has_non_finite(&val) || v.verdict.to_string().contains("NaN") {
                    nonfinite.push(format!("{path} {label}"));
                }
                Some(true)
            }
            Ok((Err(_), _)) => Some(false),
        };
        let took = started.elapsed().as_secs_f64();
        if took > 2.0 {
            eprintln!("SLOW {path} {label}: {took:.1} s");
            slow.push(format!("{path} {label}: {took:.1} s"));
        }
        res
    };
    // Whole-body malformations, every endpoint.
    let raw: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"{".to_vec(),
        b"null".to_vec(),
        b"[]".to_vec(),
        b"\"x\"".to_vec(),
        b"1e400".to_vec(),
        br#"{"a":1e400}"#.to_vec(),
        br#"{"a":NaN}"#.to_vec(),
        "[".repeat(100_000).into_bytes(),
        vec![0xff, 0xfe, 0x00],
    ];
    let mut paths: Vec<&str> = corpus.keys().map(String::as_str).collect();
    paths.push("/verdict/selfcal");
    for p in &paths {
        for (i, b) in raw.iter().enumerate() {
            try_one(p, &format!("raw#{i}"), b);
        }
    }
    // Field-by-field mutations of a valid example.
    for (path, base) in &corpus {
        if try_one(path, "base", base.to_string().as_bytes()) == Some(true) {
            base_ok.push(path.clone());
        }
        let mut sp = vec![];
        schema_paths(base, String::new(), String::new(), &mut sp);
        for (schema, ptr) in sp.iter().filter(|(s, _)| !s.is_empty()) {
            let orig = base.pointer(ptr).cloned().unwrap_or(Value::Null);
            for (k, r) in replacements(&orig).into_iter().enumerate() {
                let mut b = base.clone();
                *b.pointer_mut(ptr).unwrap() = r;
                try_one(path, &format!("{schema}#{k}"), b.to_string().as_bytes());
            }
            // The key removed, and an unknown key added beside it.
            let (parent, key) = ptr.rsplit_once('/').unwrap();
            let mut b = base.clone();
            let k = key.replace("~1", "/").replace("~0", "~");
            if let Some(Value::Object(m)) = b.pointer_mut(parent) {
                m.remove(&k);
            } else {
                continue;
            }
            try_one(path, &format!("{schema}#removed"), b.to_string().as_bytes());
            if let Some(Value::Object(m)) = b.pointer_mut(parent) {
                m.insert("zz_unknown".into(), json!(1));
            }
            try_one(path, &format!("{schema}#unknown"), b.to_string().as_bytes());
        }
    }
    std::panic::set_hook(prev);
    eprintln!(
        "fuzz: {runs} runs; valid example accepted for {}/{} endpoints: {base_ok:?}",
        base_ok.len(),
        corpus.len()
    );
    assert!(
        panics.is_empty(),
        "{} panics:\n{}",
        panics.len(),
        panics.join("\n")
    );
    assert!(
        nonfinite.is_empty(),
        "non-finite numbers in accepted answers:\n{}",
        nonfinite.join("\n")
    );
}
