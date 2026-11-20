// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
// End to end over a real socket: licences issued and revoked with the vendor tools, the
// service started on a loopback port, and every protection exercised.

use kshana_pro::license::register::Register;
use kshana_pro::license::LicenseClaims;
use meru::auth::Authority;
use meru::limits::{LimitConfig, Limiter};
use meru::meter::Meter;
use meru::server::{Authz, Config, Service};
use meru::signer::Signers;
use meru::SignedVerdict;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;

const VENDOR: [u8; 32] = *b"meru-e2e-vendor-licence-seed-32b";
const SERVICE: [u8; 32] = *b"meru-e2e-service-verdict-seed-32";

fn pubhex(seed: &[u8; 32]) -> String {
    hex::encode(
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes(),
    )
}

fn tmp() -> PathBuf {
    let d = std::env::temp_dir().join(format!("meru-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn now() -> i64 {
    meru::server::now_unix()
}

fn issue(reg: &Register, tier: &str, who: &str) -> (String, String) {
    let claims = LicenseClaims {
        licensee: who.into(),
        tier: tier.into(),
        expires_unix: now() + 30 * 86_400,
        products: vec!["cli".into()],
        ..Default::default()
    };
    let (tok, e) = reg
        .issue(&VENDOR, &claims, "manual", "", now() - 10)
        .unwrap();
    (tok, e.token_id)
}

fn raw(addr: SocketAddr, req: &[u8]) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(req).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let code = out
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = out
        .split_once("\r\n\r\n")
        .map(|x| x.1)
        .unwrap_or("")
        .to_string();
    (code, body)
}

fn post(addr: SocketAddr, path: &str, token: &str, body: &str) -> (u16, String) {
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    raw(addr, req.as_bytes())
}

fn survey(budget: usize, grid: bool) -> String {
    format!(
        r#"{{"config":{{"area":[54.0,56.0,10.0,13.0],"step_deg":0.5,"budget":{budget},"stations":[["A",57.5,10.0],["B",52.5,8.5],["C",54.5,16.0]],"candidates":[],"sigma_floor_m":0.0,"sigma_scale_m":0.0,"corr_km":0.0,"survey_noise_m":0.0,"toa_noise_m":0.0,"k_pl":5.33,"target_pl_m":0.0}},"include_grid":{grid}}}"#
    )
}

/// A vessel episode for the `cause` method: the AIS track is moved 40 km east for 40 minutes
/// while VTS radar and the ship's own GNSS receiver (normal signals) keep the true track, and
/// regional monitoring reports nothing. Unix-second times.
fn cause_episode() -> String {
    let t0 = 1_795_000_000.0f64;
    let truth = |t: f64| (59.5 + 0.0018 * t / 60.0, 24.0 + 0.0063 * t / 60.0);
    let mut rep = vec![];
    let mut t = 0.0;
    while t <= 7200.0 {
        let (la, lo) = truth(t);
        let lo = if (2400.0..=4800.0).contains(&t) {
            lo + 0.705
        } else {
            lo
        };
        rep.push(serde_json::json!({"t": t0 + t, "lat_deg": la, "lon_deg": lo, "sog_kn": 12.0}));
        t += 60.0;
    }
    let mut radar = vec![];
    let mut t = 30.0;
    while t <= 7200.0 {
        let (la, lo) = truth(t);
        radar.push(serde_json::json!({"t": t0 + t, "lat_deg": la, "lon_deg": lo}));
        t += 300.0;
    }
    let mut eps = vec![];
    let mut t = -600.0;
    while t <= 7200.0 {
        let (la, lo) = truth(t);
        eps.push(serde_json::json!({"t": t0 + t, "fix": true, "cn0_mean_dbhz": 42.0 + (t / 97.0).sin() * 0.4,
            "n_sats": 10, "agc_db": 40.0, "lat_deg": la, "lon_deg": lo}));
        t += 60.0;
    }
    serde_json::json!({
        "platform": "vessel",
        "subject_id": "IMO 9000001",
        "reported": rep,
        "independent": [{"source": "coastal_radar", "id": "VTS", "positions": radar}],
        "receiver": {"epochs": eps},
        "regional": [],
    })
    .to_string()
}

#[test]
fn end_to_end_protections() {
    let dir = tmp();
    let reg = Register::open(dir.join("register.jsonl"));
    let (pro, _) = issue(&reg, "pro", "Pro Customer");
    let (ent, _) = issue(&reg, "enterprise", "Enterprise Customer");
    let (eval, _) = issue(&reg, "evaluation", "Trial User");
    let (stolen, stolen_id) = issue(&reg, "pro", "Stolen Licence");
    let (prober, _) = issue(&reg, "pro", "Prober");
    let (later, later_id) = issue(&reg, "pro", "Cancelled Later");
    let (causer, _) = issue(&reg, "pro", "Cause Customer");
    reg.revoke(&stolen_id, "stolen", "manual", now()).unwrap();
    let rev = dir.join("revocations.txt");
    let old_list = reg.revocation_list(&VENDOR, &[], now()).unwrap();
    std::fs::write(&rev, &old_list).unwrap();

    let authority = Authority::new(&pubhex(&VENDOR), None, Some(rev.clone())).unwrap();
    let signers = Signers {
        verdict: Arc::new(SERVICE),
        lineage_seed: SERVICE,
        lineage_key_id: "lineage".into(),
    };
    let limiter = Limiter::new(LimitConfig {
        per_minute: 1000,
        per_day: 1000,
        probe_distinct_per_hour: 4,
        probe_block_s: 600,
    });
    let meter_path = dir.join("meter.jsonl");
    let meter = Meter::open(&meter_path).unwrap();
    let cfg = Config {
        key_id: "svc-key".into(),
        max_body: 64 * 1024,
        ..Config::default()
    };
    let mut cfg = cfg;
    cfg.limits.cause.max_track_points = 500;
    let svc = Arc::new(Service::new(
        cfg,
        signers,
        Authz::Licence(Box::new(authority)),
        limiter,
        meter,
    ));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let s2 = Arc::clone(&svc);
    std::thread::spawn(move || s2.serve(listener));

    // Health.
    assert_eq!(raw(addr, b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n").0, 200);

    // 1. A Pro licence gets a signed, coarsened verdict with no grid.
    let (code, body) = post(addr, "/verdict/survey", &pro, &survey(2, false));
    assert_eq!(code, 200, "{body}");
    let v: SignedVerdict = serde_json::from_str(&body).unwrap();
    assert!(meru::verify(&v, &pubhex(&SERVICE)).is_empty());
    assert_eq!(v.key_id, "svc-key");
    assert!(v.verdict.get("grid").is_none());
    let pl = v.verdict["mean_pl_after_m"].as_f64().unwrap();
    assert_eq!(pl, meru::outputs::round_sig(pl, 3), "outputs are coarsened");

    // 2. The full grid: refused for Pro, available for Enterprise.
    assert_eq!(post(addr, "/verdict/survey", &pro, &survey(2, true)).0, 403);
    let (code, body) = post(addr, "/verdict/survey", &ent, &survey(2, true));
    assert_eq!(code, 200, "{body}");
    assert!(serde_json::from_str::<SignedVerdict>(&body)
        .unwrap()
        .verdict
        .get("grid")
        .is_some());

    // 3. Evaluation, revoked, malformed and missing licences are refused.
    let (code, body) = post(addr, "/verdict/survey", &eval, &survey(2, false));
    assert_eq!(code, 401);
    assert!(body.contains("'pro' tier"), "{body}");
    let (code, body) = post(addr, "/verdict/survey", &stolen, &survey(2, false));
    assert_eq!(code, 401);
    assert!(body.contains("revoked"), "{body}");
    assert_eq!(
        post(addr, "/verdict/survey", "garbage", &survey(2, false)).0,
        401
    );
    assert_eq!(post(addr, "/verdict/survey", "", &survey(2, false)).0, 401);

    // 4. Oversized surveys are refused before any work.
    let big = survey(2, false).replace("\"step_deg\":0.5", "\"step_deg\":0.0001");
    let (code, body) = post(addr, "/verdict/survey", &pro, &big);
    assert_eq!(code, 422);
    assert!(body.contains("survey too large"), "{body}");

    // 4b. The `cause` method: signed, coarsened, outcome only; its own size limits.
    let (code, body) = post(addr, "/verdict/cause", &causer, &cause_episode());
    assert_eq!(code, 200, "{body}");
    let v: SignedVerdict = serde_json::from_str(&body).unwrap();
    assert!(meru::verify(&v, &pubhex(&SERVICE)).is_empty());
    assert_eq!(v.method, "cause");
    assert_eq!(v.evidence_class, "MODELLED");
    assert_eq!(
        v.verdict["classification"], "self_reported_track_falsification",
        "{body}"
    );
    assert_eq!(v.verdict["questions"]["origin"], "own_ship");
    let c = v.verdict["confidence"].as_f64().unwrap();
    assert!(
        c >= 0.6 && ((c * 20.0) - (c * 20.0).round()).abs() < 1e-9,
        "{c}"
    );
    assert!(v.verdict["window"]["start_utc"].is_string());
    for k in ["\"score", "\"weight", "\"threshold", "\"posterior"] {
        assert!(!body.contains(k), "{k} leaked: {body}");
    }
    // Unauthenticated calls are refused here as on every method.
    assert_eq!(post(addr, "/verdict/cause", "", &cause_episode()).0, 401);
    let many: Vec<String> = (0..600)
        .map(|i| {
            format!(
                r#"{{"t":{},"lat_deg":59.5,"lon_deg":24.0}}"#,
                1_795_000_000 + i * 10
            )
        })
        .collect();
    let big = format!(r#"{{"platform":"vessel","reported":[{}]}}"#, many.join(","));
    let (code, body) = post(addr, "/verdict/cause", &causer, &big);
    assert_eq!(code, 422);
    assert!(body.contains("too many reported positions"), "{body}");
    let (code, body) = post(
        addr,
        "/verdict/cause",
        &causer,
        r#"{"platform":"boat","reported":[]}"#,
    );
    assert_eq!(code, 422);
    assert!(body.contains("request:"), "{body}");

    // 5. HTTP hardening.
    let chunked = format!(
        "POST /verdict/survey HTTP/1.1\r\nAuthorization: Bearer {pro}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    );
    assert_eq!(raw(addr, chunked.as_bytes()).0, 501);
    let no_len = format!("POST /verdict/survey HTTP/1.1\r\nAuthorization: Bearer {pro}\r\n\r\n");
    assert_eq!(raw(addr, no_len.as_bytes()).0, 411);
    let long = format!(
        "GET /health HTTP/1.1\r\nX-Pad: {}\r\n\r\n",
        "a".repeat(9000)
    );
    assert_eq!(raw(addr, long.as_bytes()).0, 431);
    let huge = format!(
        "POST /verdict/survey HTTP/1.1\r\nAuthorization: Bearer {pro}\r\nContent-Length: 999999\r\n\r\n"
    );
    assert_eq!(raw(addr, huge.as_bytes()).0, 413);
    let dup = format!(
        "POST /verdict/survey HTTP/1.1\r\nAuthorization: Bearer {pro}\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{{}}"
    );
    assert_eq!(raw(addr, dup.as_bytes()).0, 400);
    assert_eq!(post(addr, "/nope", &pro, "{}").0, 404);

    // 6. A sweep of distinct requests trips the probe detector and pauses the licence.
    let mut codes = vec![];
    for b in 1..=6 {
        codes.push(post(addr, "/verdict/survey", &prober, &survey(b, false)).0);
    }
    assert_eq!(&codes[..4], &[200, 200, 200, 200], "{codes:?}");
    assert_eq!(codes[4], 429, "{codes:?}");
    let (code, body) = post(addr, "/verdict/survey", &prober, &survey(1, false));
    assert_eq!(code, 429);
    assert!(body.contains("paused"), "{body}");
    // Other licences are unaffected.
    assert_eq!(
        post(addr, "/verdict/survey", &pro, &survey(2, false)).0,
        200
    );

    // 7. A licence revoked while the service runs stops working at the next refresh; an
    //    older list cannot be replayed to bring it back.
    assert_eq!(
        post(addr, "/verdict/survey", &later, &survey(2, false)).0,
        200
    );
    reg.revoke(&later_id, "cancelled", "manual", now()).unwrap();
    std::fs::write(&rev, reg.revocation_list(&VENDOR, &[], now()).unwrap()).unwrap();
    let Authz::Licence(a) = &svc.authz else {
        unreachable!()
    };
    a.refresh(true);
    let (code, body) = post(addr, "/verdict/survey", &later, &survey(2, false));
    assert_eq!(code, 401, "{body}");
    assert!(body.contains("revoked"));
    std::fs::write(&rev, &old_list).unwrap();
    a.refresh(true);
    assert_eq!(
        post(addr, "/verdict/survey", &later, &survey(2, false)).0,
        401,
        "replay refused"
    );

    // 8. The meter log records every call by hash, never the request contents.
    let log = std::fs::read_to_string(&meter_path).unwrap();
    assert!(log.contains("\"outcome\":\"ok\""));
    assert!(log.contains("\"outcome\":\"probe_alert\""));
    assert!(log.contains("\"outcome\":\"refused\""));
    assert!(log.contains("Pro Customer"));
    assert!(!log.contains("stations") && !log.contains("step_deg") && !log.contains(&pro));
    assert!(log.contains("/verdict/cause") && !log.contains("lat_deg") && !log.contains("IMO"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Synthetic SP3 products for `lunar-assist`: two GNSS satellites propagated with the open
/// engine's precise force model (a richer one than the service fits), with drifting clocks,
/// 900 s spacing, `hours` long, ending at `end` (GPST, `YYYY-MM-DDTHH:MM:SS`).
fn synthetic_sp3(end: &str, hours: usize) -> String {
    use kshana_pro::kshana::cio::gcrs_to_itrs_matrix;
    use kshana_pro::kshana::integrator::Tolerance;
    use kshana_pro::kshana::precession::mat_vec;
    use kshana_pro::kshana::precise_od::{propagate_samples, ForceModel, PreciseForceModel};
    use kshana_pro::kshana::sp3::{Sp3Epoch, Sp3File, Sp3Header, Sp3SatState};
    use meru::lunar_assist::{format_s, parse_iso_s};
    let t_end = parse_iso_s(end).unwrap();
    let n = hours * 4 + 1;
    let t0 = t_end - (n - 1) as f64 * 900.0;
    let jd_tt = |t: f64| 2_440_587.5 + (t + 51.184) / 86_400.0;
    let epoch = |t: f64| {
        let s = format_s(t.round() as i64);
        kshana_pro::kshana::rinex::EpochUtc {
            year: s[0..4].parse().unwrap(),
            month: s[5..7].parse().unwrap(),
            day: s[8..10].parse().unwrap(),
            hour: s[11..13].parse().unwrap(),
            minute: s[14..16].parse().unwrap(),
            second: s[17..19].parse().unwrap(),
        }
    };
    let times: Vec<f64> = (0..n).map(|i| i as f64 * 900.0).collect();
    let tol = Tolerance {
        rtol: 1e-11,
        atol: 1e-6,
        ..Tolerance::default()
    };
    let sats = ["G07", "E19"];
    let mut tracks = vec![];
    for k in 0..sats.len() {
        let a: f64 = if k == 0 { 26_560e3 } else { 29_600e3 };
        let (u, raan, inc) = (0.4 + k as f64, 1.1 * k as f64, 0.96f64);
        let v = (3.986_004_418e14 / a).sqrt();
        let r0 = [
            a * (raan.cos() * u.cos() - raan.sin() * u.sin() * inc.cos()),
            a * (raan.sin() * u.cos() + raan.cos() * u.sin() * inc.cos()),
            a * u.sin() * inc.sin(),
        ];
        let v0 = [
            v * (-raan.cos() * u.sin() - raan.sin() * u.cos() * inc.cos()),
            v * (-raan.sin() * u.sin() + raan.cos() * u.cos() * inc.cos()),
            v * u.cos() * inc.sin(),
        ];
        let mut fm = PreciseForceModel::egm2008(8, jd_tt(t0))
            .third_body(true, true)
            .solar_radiation(1.2, 0.02)
            .relativity();
        fm.set_cr(1.2);
        let gcrs = propagate_samples(&fm, r0, v0, &times, &tol);
        let pos: Vec<[f64; 3]> = gcrs
            .iter()
            .zip(&times)
            .map(|(r, t)| {
                let jd = jd_tt(t0 + t);
                // UT1 = UTC (GPST − 18 s in 2027), no polar motion: as the service without EOP.
                let m = gcrs_to_itrs_matrix(jd, jd - 69.184 / 86_400.0, 0.0, 0.0);
                mat_vec(&m, *r)
            })
            .collect();
        tracks.push(pos);
    }
    let f = Sp3File {
        header: Sp3Header {
            version: 'd',
            has_velocity: false,
            start: epoch(t0),
            num_epochs: n,
            sat_ids: sats.iter().map(|s| s.to_string()).collect(),
        },
        epochs: (0..n)
            .map(|i| Sp3Epoch {
                time: epoch(t0 + times[i]),
                sats: sats
                    .iter()
                    .enumerate()
                    .map(|(k, s)| Sp3SatState {
                        sat: s.to_string(),
                        pos_m: tracks[k][i],
                        clock_us: 50.0 * (k as f64 + 1.0)
                            + 2e-6 * times[i]
                            + 1e-12 * times[i].powi(2),
                        vel_m_s: None,
                    })
                    .collect(),
            })
            .collect(),
    };
    f.to_sp3_string()
}

#[test]
fn end_to_end_lunar_assist() {
    // Its own directory: the other end-to-end test runs in parallel and removes its own.
    let dir = std::env::temp_dir().join(format!("meru-e2e-lunar-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("products")).unwrap();
    let reg = Register::open(dir.join("register.jsonl"));
    let (pro, _) = issue(&reg, "pro", "Lunar Customer");
    let rev = dir.join("revocations.txt");
    std::fs::write(&rev, reg.revocation_list(&VENDOR, &[], now()).unwrap()).unwrap();
    std::fs::write(
        dir.join("products/igs_observed.sp3"),
        synthetic_sp3("2027-01-04T00:00:00", 42),
    )
    .unwrap();
    let mut cfg = Config {
        key_id: "svc-key".into(),
        max_body: 64 * 1024,
        ..Config::default()
    };
    cfg.assist.source_dir = Some(dir.join("products"));
    cfg.assist.fit_hours = 12.0;
    cfg.assist.geopotential_degree = 4;
    let svc = Arc::new(Service::new(
        cfg,
        Signers {
            verdict: Arc::new(SERVICE),
            lineage_seed: SERVICE,
            lineage_key_id: "lineage".into(),
        },
        Authz::Licence(Box::new(
            Authority::new(&pubhex(&VENDOR), None, Some(rev)).unwrap(),
        )),
        Limiter::new(LimitConfig::default()),
        Meter::open(&dir.join("meter.jsonl")).unwrap(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || svc.serve(listener));

    // The request exactly as the Arksa client serialises it.
    let req = r#"{"satellites":["G07","E19"],"validity_start":"2027-01-04T00:00:00","validity_hours":12.0,"step_s":300,"integrity_risk":1e-7,"lunar_time":{"registry_id":"ks-lunar-time-definitions","registry_version":1,"definition_id":"tcl-iau2024-lte440"}}"#;
    let (code, body) = post(addr, "/verdict/lunar-assist", &pro, req);
    assert_eq!(code, 200, "{body}");
    // The Pro verdict client accepts it (signature against the service key, method name).
    let pv: kshana_pro::remote_verdict::SignedVerdict = serde_json::from_str(&body).unwrap();
    assert!(kshana_pro::remote_verdict::verify(&pv, &pubhex(&SERVICE)).is_empty());
    assert_eq!(pv.method, "lunar-assist");
    assert_eq!(pv.evidence_class, "MODELLED");
    // The package parses, carries its own signature by the service key, and answers the request.
    let pkg: meru::lunar_assist::AssistPackage =
        serde_json::from_value(pv.verdict["package"].clone()).unwrap();
    assert!(pkg.verify_signature(&pubhex(&SERVICE)).is_empty());
    assert_eq!(pkg.format, "ks-lunar-gnss-assist/1");
    assert_eq!(pkg.satellites.len(), 2);
    assert_eq!(pkg.start, "2027-01-03T23:35:00");
    assert_eq!(pkg.validity_start_s, 1500);
    assert_eq!(pkg.validity_end_s, 1500 + 12 * 3600);
    assert_eq!(
        pkg.lunar_time.as_ref().unwrap().registry.definition_id,
        "tcl-iau2024-lte440"
    );
    assert!(pkg
        .satellites
        .iter()
        .all(|s| s.bound.integrity_risk <= 1e-7));
    assert_eq!(pv.verdict["source"]["age_at_validity_start_h"], 0.0);

    // Errors: unauthenticated, a satellite the source lacks, a malformed request.
    assert_eq!(post(addr, "/verdict/lunar-assist", "", req).0, 401);
    let (code, body) = post(
        addr,
        "/verdict/lunar-assist",
        &pro,
        &req.replace("\"E19\"", "\"E33\""),
    );
    assert_eq!(code, 422);
    assert!(body.contains("no source data for E33"), "{body}");
    let (code, body) = post(
        addr,
        "/verdict/lunar-assist",
        &pro,
        r#"{"satellites":"G07"}"#,
    );
    assert_eq!(code, 422);
    assert!(body.contains("request:"), "{body}");

    // The meter log records the call by hash, never the satellites or epochs asked for.
    let log = std::fs::read_to_string(dir.join("meter.jsonl")).unwrap();
    assert!(log.contains("/verdict/lunar-assist") && log.contains("\"outcome\":\"ok\""));
    assert!(!log.contains("G07") && !log.contains("2027-01-04"));
    let _ = std::fs::remove_dir_all(&dir);
}
