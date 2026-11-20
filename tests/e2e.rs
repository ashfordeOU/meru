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

/// A vessel episode for the `victim-actor` method: from minute 40 to 80 the subject and four
/// nearby vessels all report one position circling at 1 km radius (a spoofed position), with a
/// regional spoofing report. Unix-second times; about a metre of position wander.
fn victim_actor_episode() -> String {
    let t0 = 1_795_000_000.0f64;
    let wander = |t: f64, k: f64| (2e-5 * (t * 0.013 + k).sin(), 2e-5 * (t * 0.017 + k).cos());
    let spoof = |t: f64| {
        let th = ((t - 2400.0) / 60.0 * 30.0).to_radians();
        (59.7 + th.sin() / 111.2, 24.3 + th.cos() / (111.2 * 0.507))
    };
    let track = |k: f64| {
        let mut v = vec![];
        let mut t = 0.0;
        while t <= 7200.0 {
            let (la, lo) = if (2400.0..4800.0).contains(&t) {
                spoof(t)
            } else {
                let (a, b) = wander(t, k);
                (
                    59.5 + 0.05 * k + 0.0018 * t / 60.0 + a,
                    24.0 - 0.1 * k + 0.0063 * t / 60.0 + b,
                )
            };
            v.push(serde_json::json!({"t": t0 + t, "lat_deg": la, "lon_deg": lo}));
            t += 60.0;
        }
        v
    };
    let neighbours: Vec<_> = (1..=4)
        .map(|k| serde_json::json!({"id": format!("n{k}"), "reported": track(k as f64)}))
        .collect();
    serde_json::json!({
        "subject_id": "MMSI 230000001",
        "reported": track(0.0),
        "neighbours": neighbours,
        "regional": [{
            "format": "kshana-pnt-interference-event/1", "id": "r1",
            "start_utc": "2026-11-18T11:40:00Z", "end_utc": "2026-11-18T12:35:00Z",
            "systems": [{"system": "gnss", "band": "L1"}], "kind": "spoofing",
            "location": {"lat_deg": 59.6, "lon_deg": 24.2, "radius_m": 30000.0},
            "observers": ["m1", "m2"], "confidence": 0.8, "basis": "monitoring network",
            "corroborated": true
        }],
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
    let (va, va_id) = issue(&reg, "pro", "Victim Actor Customer");
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

    // 4c. The `victim-actor` method: signed, bound to the licence, outcome only.
    let (code, body) = post(addr, "/verdict/victim-actor", &va, &victim_actor_episode());
    assert_eq!(code, 200, "{body}");
    let v: SignedVerdict = serde_json::from_str(&body).unwrap();
    assert!(meru::verify(&v, &pubhex(&SERVICE)).is_empty());
    assert_eq!(v.method, "victim-actor");
    assert_eq!(v.evidence_class, "MODELLED");
    assert_eq!(v.verdict["classification"], "victim", "{body}");
    assert_eq!(v.verdict["licence"]["token_id"], va_id.as_str());
    assert!(v.verdict["confidence"].as_f64().unwrap() >= 0.85, "{body}");
    assert!(v.verdict["confidence_interval"]["low"].is_number());
    for k in [
        "\"score",
        "\"weight",
        "\"threshold",
        "\"posterior",
        "\"n1\"",
    ] {
        assert!(!body.contains(k), "{k} leaked: {body}");
    }
    let (code, body) = post(
        addr,
        "/verdict/victim-actor",
        &va,
        r#"{"reported":[],"unknown_field":1}"#,
    );
    assert_eq!(code, 422);
    assert!(body.contains("unknown field"), "{body}");
    assert_eq!(
        post(addr, "/verdict/victim-actor", "", &victim_actor_episode()).0,
        401
    );

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

/// A power model recalibrated from telemetry: a bus voltage that sags and a battery
/// temperature that relaxes towards its radiator, with a deterministic wobble as noise.
fn calibrate_request() -> String {
    let mut obs = vec![];
    for i in 0..90 {
        let t = i as f64 * 60.0;
        let wob = ((i * 37 % 11) as f64 - 5.0) / 5.0;
        obs.push(serde_json::json!({"observable": "eps.bus_v", "t_s": t,
            "value": 28.3 - 1.7e-4 * t + 0.01 * wob, "sigma": 0.01}));
        obs.push(serde_json::json!({"observable": "thermal.batt_c", "t_s": t,
            "value": 5.0 + 15.0 * (-t / 2400.0).exp() + 0.1 * wob, "sigma": 0.1}));
    }
    serde_json::json!({
        "subject": "TOY-1/eps",
        "parameters": [
            {"name": "v0", "prior": 28.0, "prior_sigma": 1.0},
            {"name": "sag", "prior": 1e-4, "lower": 0.0},
            {"name": "sink", "prior": 0.0, "prior_sigma": 20.0},
            {"name": "tau", "prior": 1000.0, "lower": 10.0, "upper": 1e5}
        ],
        "model": {"kind": "expression", "observables": {
            "eps.bus_v": "v0 - sag * t",
            "thermal.batt_c": "sink + 15 * exp(-t / tau)"
        }},
        "observations": obs
    })
    .to_string()
}

#[test]
fn end_to_end_calibrate() {
    // Its own directory: the other end-to-end tests run in parallel.
    let dir = std::env::temp_dir().join(format!("meru-e2e-cal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let reg = Register::open(dir.join("register.jsonl"));
    let (pro, _) = issue(&reg, "pro", "Mission Customer");
    let rev = dir.join("revocations.txt");
    std::fs::write(&rev, reg.revocation_list(&VENDOR, &[], now()).unwrap()).unwrap();
    let svc = Arc::new(Service::new(
        Config {
            key_id: "svc-key".into(),
            max_body: 256 * 1024,
            ..Config::default()
        },
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

    let req = calibrate_request();
    let (code, body) = post(addr, "/verdict/calibrate", &pro, &req);
    assert_eq!(code, 200, "{body}");
    // The Pro verdict client accepts it.
    let pv: kshana_pro::remote_verdict::SignedVerdict = serde_json::from_str(&body).unwrap();
    assert!(kshana_pro::remote_verdict::verify(&pv, &pubhex(&SERVICE)).is_empty());
    assert_eq!(pv.method, "calibrate");
    assert_eq!(pv.evidence_class, "MODELLED");
    // The outcome the simulator-recalibration client reads.
    let o = &pv.verdict;
    assert_eq!(o["converged"], true, "{body}");
    assert!(o["lineage"]["head"].as_str().is_some_and(|h| h.len() == 64));
    let tau = o["posterior"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "tau")
        .unwrap();
    let (v, s) = (
        tau["value"].as_f64().unwrap(),
        tau["std_err"].as_f64().unwrap(),
    );
    assert!((v - 2400.0).abs() < 4.0 * s && s > 0.0, "{v} ± {s}");
    assert!(o["fidelity_last"].as_f64().unwrap() > o["fidelity_first"].as_f64().unwrap());

    // Errors: unauthenticated, an expression naming an unknown parameter, a malformed request.
    assert_eq!(post(addr, "/verdict/calibrate", "", &req).0, 401);
    let (code, body) = post(
        addr,
        "/verdict/calibrate",
        &pro,
        &req.replace("v0 - sag * t", "v0 - leak * t"),
    );
    assert_eq!(code, 422);
    assert!(body.contains("unknown name 'leak'"), "{body}");
    let (code, body) = post(addr, "/verdict/calibrate", &pro, r#"{"parameters":[]}"#);
    assert_eq!(code, 422);
    assert!(body.contains("request:"), "{body}");
    // The meter log records the call by hash, never the telemetry or the model.
    let log = std::fs::read_to_string(dir.join("meter.jsonl")).unwrap();
    assert!(log.contains("/verdict/calibrate") && log.contains("\"outcome\":\"ok\""));
    assert!(!log.contains("eps.bus_v") && !log.contains("TOY-1") && !log.contains("exp("));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Anti-extraction over a real socket: licence-bound and fingerprinted verdicts (accepted by
/// the Pro client), the ownership test on them, honeypots, the query-pattern audit with
/// delayed verdicts, and the per-address limit.
#[test]
fn end_to_end_anti_extraction() {
    use meru::audit::{sobol, AuditConfig};
    use meru::fingerprint::{ownership, FpKeys, Suspect};
    use sha2::Digest;
    let dir = std::env::temp_dir().join(format!("meru-e2e-fp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let reg = Register::open(dir.join("register.jsonl"));
    let (alice, alice_id) = issue(&reg, "pro", "Alice Ltd");
    let (bob, bob_id) = issue(&reg, "pro", "Bob GmbH");
    let (copier, copier_id) = issue(&reg, "pro", "Copier");
    let rev = dir.join("revocations.txt");
    std::fs::write(&rev, reg.revocation_list(&VENDOR, &[], now()).unwrap()).unwrap();
    // A fixed fingerprint epoch key, not a rotated random one. Which input cells are canary cells
    // (1 in 64) depends only on the epoch key, and a canary cell's bits do not count towards a
    // licence. Alice's 25 survey requests fall in 11 coarse input cells with two quantity families
    // each: 22 informative bits, just enough for the ownership threshold (all 22 matching: chance
    // 2^-22, times 3 candidates, below 1e-6). With a random key, a canary among her 11 cells
    // (1 - (63/64)^11, about 16 % of keys) left 20 bits and the attribution failed: the flake.
    // This key has no canary among those cells (checked: the "epoch 1" and "epoch 2" keys each
    // have one), so the result is the same on every run; the bit count is asserted below, so a
    // change to the method shows up as a clear failure rather than a flake.
    let keys = FpKeys::parse(
        &serde_json::json!({
            "format": meru::fingerprint::KEYS_FORMAT,
            "epochs": [{"id": "e1-test", "from_unix": now() - 10,
                "key_hex": hex::encode(sha2::Sha256::digest(b"meru e2e fingerprint epoch 3"))}],
        })
        .to_string(),
    )
    .unwrap();
    let meter_path = dir.join("meter.jsonl");
    let svc = Arc::new(Service::new(
        Config {
            key_id: "svc-key".into(),
            fingerprint_keys: Some(keys.clone()),
            per_ip_per_minute: 200,
            audit: AuditConfig {
                delay_ms: 300,
                ..AuditConfig::default()
            },
            ..Config::default()
        },
        Signers {
            verdict: Arc::new(SERVICE),
            lineage_seed: SERVICE,
            lineage_key_id: "lineage".into(),
        },
        Authz::Licence(Box::new(
            Authority::new(&pubhex(&VENDOR), None, Some(rev)).unwrap(),
        )),
        Limiter::new(LimitConfig {
            per_minute: 1000,
            per_day: 1000,
            probe_distinct_per_hour: 1000,
            probe_block_s: 600,
        }),
        Meter::open(&meter_path).unwrap(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let s2 = Arc::clone(&svc);
    std::thread::spawn(move || s2.serve(listener));

    let req = |lat: f64, lon: f64, scale: f64| {
        serde_json::json!({"config": {"area": [54.0, 56.0, 10.0, 13.0], "step_deg": 0.5, "budget": 3,
            "stations": [["A", 57.5, 10.0], ["B", 52.5, 8.5], ["C", lat, lon]], "candidates": [],
            "sigma_floor_m": 15.0, "sigma_scale_m": scale, "corr_km": 80.0, "survey_noise_m": 5.0,
            "toa_noise_m": 10.0, "k_pl": 5.33, "target_pl_m": 300.0}, "include_grid": false})
    };

    // 1. Verdicts are bound to the licence (inside the signed body) and the Pro client accepts them.
    let mut alice_held = vec![];
    for i in 0..25 {
        let q = req(52.0 + 0.23 * i as f64, 14.0 + 0.19 * i as f64, 60.0);
        let (code, body) = post(addr, "/verdict/survey", &alice, &q.to_string());
        assert_eq!(code, 200, "{body}");
        let v: SignedVerdict = serde_json::from_str(&body).unwrap();
        assert!(meru::verify(&v, &pubhex(&SERVICE)).is_empty());
        assert_eq!(v.verdict["licence"]["token_id"], alice_id.as_str());
        let pv: kshana_pro::remote_verdict::SignedVerdict = serde_json::from_str(&body).unwrap();
        assert!(kshana_pro::remote_verdict::verify(&pv, &pubhex(&SERVICE)).is_empty());
        // Rebinding to another licence breaks the signature.
        let mut forged = v.clone();
        forged.verdict["licence"]["token_id"] = serde_json::json!(bob_id);
        assert!(!meru::verify(&forged, &pubhex(&SERVICE)).is_empty());
        alice_held.push(Suspect {
            method: "survey-plan".into(),
            request: q,
            verdict: v.verdict,
        });
    }
    // 2. The ownership test names Alice from the numbers alone (binding stripped).
    for s in &mut alice_held {
        s.verdict.as_object_mut().unwrap().remove("licence");
    }
    let limits = meru::Limits::default();
    let cands = meru::meter::token_ids(&meter_path);
    assert!(cands.contains(&alice_id));
    // Two bystander licences with fixed IDs (Bob and the copier have not called yet, and their
    // IDs are random, which made the runner-up's chance matches vary from run to run).
    let cands: Vec<String> = cands
        .into_iter()
        .chain([
            "kt_000000000000000000bystander1".to_string(),
            "kt_000000000000000000bystander2".to_string(),
        ])
        .collect();
    let rep = ownership(&alice_held, &keys, &cands, 3, &|m, q| {
        meru::methods::raw_outcome(m, q, &limits)
    });
    let best = &rep.scores[0];
    assert_eq!(best.token_id, alice_id, "{rep:#?}");
    assert!(
        best.bits >= 22 && best.matches == best.bits,
        "Alice's own verdicts must give at least 22 informative bits, all matching: {rep:#?}"
    );
    assert_eq!(
        rep.attributed.as_deref(),
        Some(alice_id.as_str()),
        "{rep:#?}"
    );

    // 3. A honeypot answers like an unknown path and marks the licence suspect.
    let (code, body) = post(addr, "/verdict/survey/grid", &bob, "{}");
    assert_eq!((code, body.as_str()), (404, r#"{"error":"unknown path"}"#));
    assert_eq!(post(addr, "/verdict/nope", &bob, "{}").1, body);
    assert!(svc.audit.is_suspect(&bob_id, now()));
    // A suspect licence's verdicts are delayed.
    let t = std::time::Instant::now();
    assert_eq!(
        post(
            addr,
            "/verdict/survey",
            &bob,
            &req(54.5, 16.0, 60.0).to_string()
        )
        .0,
        200
    );
    assert!(t.elapsed() >= std::time::Duration::from_millis(300));

    // 4. A Sobol sweep raises an extraction alert in the meter log.
    for u in sobol(40, 3) {
        let q = req(52.0 + 6.0 * u[0], 14.0 + 5.0 * u[1], 30.0 + 60.0 * u[2]);
        assert_eq!(
            post(addr, "/verdict/survey", &copier, &q.to_string()).0,
            200
        );
    }
    assert!(svc.audit.is_suspect(&copier_id, now()));
    assert!(!svc.audit.is_suspect(&alice_id, now()));
    let log = std::fs::read_to_string(&meter_path).unwrap();
    let alerts: Vec<serde_json::Value> = log
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|e| e["outcome"] == "extraction_alert")
        .collect();
    assert!(
        alerts.iter().any(|a| a["alert"]["kind"] == "single_licence"
            && a["alert"]["licences"][0] == copier_id.as_str()),
        "{alerts:?}"
    );
    assert!(log.contains("\"outcome\":\"honeypot\""));
    assert!(!log.contains("stations") && !log.contains("sigma_scale") && !log.contains(&copier));
    // The quotas still count only the calls.
    let counts = meru::meter::today_counts(&meter_path, now());
    assert_eq!(counts.get(&copier_id), Some(&40));

    // 5. The per-address limit.
    let svc2 = Arc::new(Service::new(
        Config {
            per_ip_per_minute: 2,
            ..Config::default()
        },
        Signers {
            verdict: Arc::new(SERVICE),
            lineage_seed: SERVICE,
            lineage_key_id: "lineage".into(),
        },
        Authz::Open,
        Limiter::new(LimitConfig::default()),
        Meter::open(&dir.join("meter2.jsonl")).unwrap(),
    ));
    let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let a2 = l2.local_addr().unwrap();
    std::thread::spawn(move || svc2.serve(l2));
    let codes: Vec<u16> = (0..3)
        .map(|_| post(a2, "/verdict/survey", "", &survey(2, false)).0)
        .collect();
    assert_eq!(codes, [200, 200, 429]);
    let _ = std::fs::remove_dir_all(&dir);
}

fn post_tenant(
    addr: SocketAddr,
    path: &str,
    token: &str,
    tenant: &str,
    body: &str,
) -> (u16, String) {
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nX-Meru-Tenant: {tenant}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    raw(addr, req.as_bytes())
}

/// A service credential issued with the vendor tools: an ordinary v2 licence whose features
/// name the service client.
fn service_credential(reg: &Register, client: &str) -> (String, String) {
    let claims = LicenseClaims {
        licensee: "Arksa cloud (service)".into(),
        tier: "enterprise".into(),
        expires_unix: now() + 30 * 86_400,
        products: vec!["service".into()],
        features: vec![format!("meru-service:{client}")],
        ..Default::default()
    };
    let (tok, e) = reg
        .issue(&VENDOR, &claims, "manual", "", now() - 10)
        .unwrap();
    (tok, e.token_id)
}

/// The deployment profiles over a real socket: the service credential is accepted on an
/// `arksa-internal` instance and refused on the public one, customer licences the other way
/// round; service calls carry no daily quota, no probe pause, a record-only audit and no
/// fingerprint, stay licence-bound and signed, and are metered with the tenant tag; the
/// batch route answers each request with its own signed verdict.
#[test]
fn end_to_end_profiles_and_service_credential() {
    use meru::audit::{sobol, AuditConfig};
    use meru::fingerprint::FpKeys;
    use meru::profile::{Profile, TenantTag};
    let dir = std::env::temp_dir().join(format!("meru-e2e-svc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let reg = Register::open(dir.join("register.jsonl"));
    let (svc_tok, svc_id) = service_credential(&reg, "arksa");
    let (other_client, _) = service_credential(&reg, "someone-else");
    let (old_svc, old_svc_id) = service_credential(&reg, "arksa");
    let (pro, pro_id) = issue(&reg, "pro", "Pro Customer");
    reg.revoke(&old_svc_id, "rotated", "manual", now()).unwrap();
    let rev = dir.join("revocations.txt");
    std::fs::write(&rev, reg.revocation_list(&VENDOR, &[], now()).unwrap()).unwrap();
    let fp = dir.join("fp-keys.json");
    FpKeys::rotate(&fp, now() - 10).unwrap();
    let keys = FpKeys::load(&fp).unwrap();

    let start = |profile: Profile, tag: TenantTag, meter: &str| {
        let svc = Arc::new(Service::new(
            Config {
                key_id: "svc-key".into(),
                max_body: 512 * 1024,
                profile,
                tenant_tag: tag,
                fingerprint_keys: Some(keys.clone()),
                per_ip_per_minute: profile.default_per_ip_per_minute(),
                audit: AuditConfig {
                    delay_ms: 2000,
                    pause: true,
                    ..AuditConfig::default()
                },
                batch_max: 3,
                ..Config::default()
            },
            Signers {
                verdict: Arc::new(SERVICE),
                lineage_seed: SERVICE,
                lineage_key_id: "lineage".into(),
            },
            Authz::Licence(Box::new(
                Authority::new(&pubhex(&VENDOR), None, Some(rev.clone())).unwrap(),
            )),
            // Customer limits so tight a sweep would trip them at once.
            Limiter::new(LimitConfig {
                per_minute: 1000,
                per_day: 3,
                probe_distinct_per_hour: 3,
                probe_block_s: 600,
            }),
            Meter::open(&dir.join(meter)).unwrap(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let s2 = Arc::clone(&svc);
        std::thread::spawn(move || s2.serve(listener));
        (svc, addr)
    };
    let (_public, pub_addr) = start(Profile::Public, TenantTag::Off, "public.jsonl");
    let (internal, int_addr) = start(Profile::ArksaInternal, TenantTag::Plain, "internal.jsonl");
    let cal = calibrate_request();

    // 1. Public: the service credential is refused; a customer licence works as before, and a
    //    tenant header (even a malformed one) is ignored.
    let (code, body) = post(pub_addr, "/verdict/calibrate", &svc_tok, &cal);
    assert_eq!(code, 403, "{body}");
    assert!(body.contains("not accepted on this instance"), "{body}");
    let (code, body) = post_tenant(pub_addr, "/verdict/calibrate", &pro, "bad tag/x", &cal);
    assert_eq!(code, 200, "{body}");
    let v: SignedVerdict = serde_json::from_str(&body).unwrap();
    assert_eq!(v.verdict["licence"]["token_id"], pro_id.as_str());
    assert_eq!(post(pub_addr, "/verdict/batch", &pro, "{}").0, 404);
    let plog = std::fs::read_to_string(dir.join("public.jsonl")).unwrap();
    assert!(!plog.contains("tenant") && !plog.contains("bad tag"));

    // 2. Internal: customer licences, revoked or foreign service credentials are refused.
    let (code, body) = post(int_addr, "/verdict/calibrate", &pro, &cal);
    assert_eq!(code, 403, "{body}");
    assert!(
        body.contains("accepts only its service credential"),
        "{body}"
    );
    let (code, body) = post(int_addr, "/verdict/calibrate", &old_svc, &cal);
    assert_eq!(code, 401);
    assert!(body.contains("revoked"), "{body}");
    let (code, body) = post(int_addr, "/verdict/calibrate", &other_client, &cal);
    assert_eq!(code, 401);
    assert!(body.contains("not accepted by this instance"), "{body}");

    // 3. The service credential: a signed verdict, bound to the credential, not fingerprinted
    //    (every number is plain nearest rounding of the method's own outcome).
    let (code, body) = post_tenant(int_addr, "/verdict/calibrate", &svc_tok, "mission-7", &cal);
    assert_eq!(code, 200, "{body}");
    let pv: kshana_pro::remote_verdict::SignedVerdict = serde_json::from_str(&body).unwrap();
    assert!(kshana_pro::remote_verdict::verify(&pv, &pubhex(&SERVICE)).is_empty());
    assert_eq!(pv.verdict["licence"]["token_id"], svc_id.as_str());
    let raw_out = meru::methods::raw_outcome(
        "calibrate",
        &serde_json::from_str(&cal).unwrap(),
        &meru::Limits::default(),
    )
    .unwrap();
    for (got, want) in pv.verdict["posterior"]
        .as_array()
        .unwrap()
        .iter()
        .zip(raw_out["posterior"].as_array().unwrap())
    {
        assert_eq!(
            got["value"].as_f64().unwrap(),
            meru::outputs::round_sig(want["value"].as_f64().unwrap(), 3),
            "service verdicts are not fingerprinted"
        );
    }
    // A malformed tenant tag is refused.
    let (code, body) = post_tenant(int_addr, "/verdict/calibrate", &svc_tok, "a/b", &cal);
    assert_eq!(code, 400);
    assert!(body.contains("X-Meru-Tenant"), "{body}");

    // 4. A Sobol design sweep: far past the customer daily quota (3) and probe detector (3
    //    distinct an hour); the audit records it but never delays or pauses (pause is on).
    let survey_q = |lat: f64, lon: f64, scale: f64| {
        serde_json::json!({"config": {"area": [54.0, 56.0, 10.0, 13.0], "step_deg": 0.5, "budget": 3,
            "stations": [["A", 57.5, 10.0], ["B", 52.5, 8.5], ["C", lat, lon]], "candidates": [],
            "sigma_floor_m": 15.0, "sigma_scale_m": scale, "corr_km": 80.0, "survey_noise_m": 5.0,
            "toa_noise_m": 10.0, "k_pl": 5.33, "target_pl_m": 300.0}, "include_grid": false})
        .to_string()
    };
    let mut late = std::time::Duration::ZERO;
    for (i, u) in sobol(40, 3).into_iter().enumerate() {
        let q = survey_q(52.0 + 6.0 * u[0], 14.0 + 5.0 * u[1], 30.0 + 60.0 * u[2]);
        let t = std::time::Instant::now();
        let (code, body) = post_tenant(int_addr, "/verdict/survey", &svc_tok, "design.sweep", &q);
        assert_eq!(code, 200, "call {i}: {body}");
        if i >= 32 {
            late += t.elapsed();
        }
    }
    assert!(
        late < std::time::Duration::from_millis(2000),
        "no audit delay for the service credential ({late:?})"
    );
    let log = std::fs::read_to_string(dir.join("internal.jsonl")).unwrap();
    let lines: Vec<serde_json::Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(
        lines.iter().any(|e| e["outcome"] == "extraction_alert"
            && e["service"] == "arksa"
            && e["alert"]["licences"][0] == svc_id.as_str()),
        "the audit records the sweep"
    );
    assert!(!lines.iter().any(|e| e["outcome"] == "audit_refused"
        || e["outcome"] == "probe_alert"
        || e["outcome"] == "rate_limited"));
    assert!(!lines.iter().any(|e| e["canary"] == true));

    // 5. The batch route: each request answered with its own signed verdict, in order.
    let bad = cal.replace("v0 - sag * t", "v0 - leak * t");
    let batch = format!(
        r#"{{"requests":[{{"method":"calibrate","request":{cal}}},{{"method":"calibrate","request":{bad}}}]}}"#
    );
    let (code, body) = post_tenant(int_addr, "/verdict/batch", &svc_tok, "mission-7", &batch);
    assert_eq!(code, 200, "{body}");
    let r: serde_json::Value = serde_json::from_str(&body).unwrap();
    let res = r["results"].as_array().unwrap();
    assert_eq!(res.len(), 2);
    let v0: kshana_pro::remote_verdict::SignedVerdict =
        serde_json::from_value(res[0]["verdict"].clone()).unwrap();
    assert!(kshana_pro::remote_verdict::verify(&v0, &pubhex(&SERVICE)).is_empty());
    assert_eq!(v0.method, "calibrate");
    assert_eq!(v0.verdict["licence"]["token_id"], svc_id.as_str());
    assert_eq!(res[1]["status"], 422);
    assert!(res[1]["error"].as_str().unwrap().contains("leak"));
    // Only recalibration methods, at most `batch_max` requests, and only the service.
    let (code, body) = post(
        int_addr,
        "/verdict/batch",
        &svc_tok,
        r#"{"requests":[{"method":"cause","request":{}}]}"#,
    );
    assert_eq!(code, 422);
    assert!(body.contains("not batched"), "{body}");
    let four = format!(
        r#"{{"requests":[{0},{0},{0},{0}]}}"#,
        r#"{"method":"selfcal","request":{}}"#
    );
    assert!(post(int_addr, "/verdict/batch", &svc_tok, &four)
        .1
        .contains("1 to 3"));
    assert_eq!(post(int_addr, "/verdict/batch", &pro, &batch).0, 403);

    // 6. Metering: every call with the service client and the tenant tag, by hash only; the
    //    summary counts per tenant and method.
    let log = std::fs::read_to_string(dir.join("internal.jsonl")).unwrap();
    assert!(!log.contains("eps.bus_v") && !log.contains("stations"));
    let rows = meru::meter::summary(&dir.join("internal.jsonl"), 0, i64::MAX).unwrap();
    let row = |t: &str, p: &str| {
        rows.iter()
            .find(|r| r.tenant == t && r.path == p)
            .cloned()
            .unwrap_or_else(|| panic!("{t} {p}: {rows:?}"))
    };
    let m7 = row("mission-7", "/verdict/calibrate");
    assert_eq!(
        (m7.ok, m7.not_ok),
        (2, 1),
        "single call + batch item ok; batch item invalid"
    );
    assert_eq!(row("design.sweep", "/verdict/survey").ok, 40);
    assert!(
        internal.audit.is_suspect(&svc_id, now()),
        "recorded, not acted on"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn end_to_end_sovereign_hashes_the_tenant() {
    use meru::profile::{Profile, TenantTag};
    let dir = std::env::temp_dir().join(format!("meru-e2e-sov-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let reg = Register::open(dir.join("register.jsonl"));
    let (svc_tok, _) = service_credential(&reg, "arksa");
    let rev = dir.join("revocations.txt");
    std::fs::write(&rev, reg.revocation_list(&VENDOR, &[], now()).unwrap()).unwrap();
    let profile = Profile::SovereignContracted;
    let svc = Arc::new(Service::new(
        Config {
            max_body: 512 * 1024,
            profile,
            tenant_tag: profile.default_tenant_tag(),
            per_ip_per_minute: 0,
            ..Config::default()
        },
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
    let (code, body) = post_tenant(
        addr,
        "/verdict/calibrate",
        &svc_tok,
        "ministry-mission-3",
        &calibrate_request(),
    );
    assert_eq!(code, 200, "{body}");
    let log = std::fs::read_to_string(dir.join("meter.jsonl")).unwrap();
    assert!(!log.contains("ministry-mission-3"));
    let want = TenantTag::Hashed.record("ministry-mission-3").unwrap();
    assert!(log.contains(&format!("\"tenant\":\"{want}\"")), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}
