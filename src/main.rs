// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! `meru`: the Kshana Core hosted service binary. Serves the crown-jewel methods over HTTP,
//! each returning a signed verdict and nothing else:
//!   * `POST /verdict/selfcal` — F1, the self-calibrating simulator loop.
//!   * `POST /verdict/survey`  — F2, the integrity-driven ASF survey planner.
//!   * `GET  /health`          — liveness.
//!
//! Run it behind the TLS reverse proxy in `deploy/`. Configuration is the environment; see
//! README.md for the full list. It refuses to start without a working signer, a licence
//! configuration and an explicit revocation choice.

use meru::auth::Authority;
use meru::limits::{LimitConfig, Limiter};
use meru::meter::Meter;
use meru::server::{now_unix, Authz, Config, Service};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty())
}

fn num<T: std::str::FromStr>(k: &str, default: T) -> T {
    match env(k) {
        Some(v) => v.trim().parse().unwrap_or_else(|_| {
            eprintln!("{k}: not a number: {v}");
            std::process::exit(2)
        }),
        None => default,
    }
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("meru: {msg}");
    std::process::exit(2)
}

fn main() {
    let addr = env("MERU_ADDR").unwrap_or_else(|| "127.0.0.1:8099".into());
    let signers = meru::signer::from_env().unwrap_or_else(|e| die(e));
    let key_id = env("MERU_KEY_ID").unwrap_or_else(|| {
        signers
            .verdict
            .kid()
            .unwrap_or_else(|e| die(format!("signer key ID: {e}")))
    });
    let authz = match env("MERU_LICENCE_PUBKEY") {
        Some(pk) => {
            let rev = match env("MERU_REVOCATIONS").as_deref() {
                Some("none") => {
                    eprintln!("[meru][WARNING] MERU_REVOCATIONS=none: revoked licences are NOT refused (development only)");
                    None
                }
                Some(p) => Some(PathBuf::from(p)),
                None => die(
                    "set MERU_REVOCATIONS to the signed revocation list (kshana-pro license revocations build), \
                     or MERU_REVOCATIONS=none for development",
                ),
            };
            let a = Authority::new(&pk, env("MERU_LICENCE_ROOT_KID").as_deref(), rev)
                .unwrap_or_else(|e| die(e));
            Authz::Licence(Box::new(a))
        }
        None if env("MERU_ALLOW_UNAUTHENTICATED").as_deref() == Some("1") => Authz::Open,
        None => die(
            "refusing to start without caller authorisation: set MERU_LICENCE_PUBKEY \
             (the vendor public key(s)) or MERU_ALLOW_UNAUTHENTICATED=1 for development",
        ),
    };
    let meter_path =
        PathBuf::from(env("MERU_METER_LOG").unwrap_or_else(|| "meru-meter.jsonl".into()));
    let meter = Meter::open(&meter_path).unwrap_or_else(|e| die(e));
    let limiter = Limiter::new(LimitConfig {
        per_minute: num("MERU_RATE_PER_MIN", 10),
        per_day: num("MERU_DAILY_QUOTA", 200),
        probe_distinct_per_hour: num("MERU_PROBE_DISTINCT_PER_HOUR", 60),
        probe_block_s: num("MERU_PROBE_BLOCK_S", 3600),
    });
    let now = now_unix();
    for (tok, n) in meter.today_counts(now) {
        limiter.seed_daily(&tok, now, n);
    }
    let jobs_default = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    let mut cfg = Config {
        key_id: key_id.clone(),
        sigfigs: num("MERU_OUTPUT_SIGFIGS", 3),
        max_conn: num("MERU_MAX_CONN", 64),
        max_jobs: num("MERU_MAX_JOBS", jobs_default),
        max_body: num("MERU_MAX_BODY", 2 * 1024 * 1024),
        read_timeout: Duration::from_secs(num("MERU_READ_TIMEOUT_S", 15)),
        write_timeout: Duration::from_secs(num("MERU_WRITE_TIMEOUT_S", 30)),
        ..Config::default()
    };
    cfg.limits.max_cells = num("MERU_MAX_CELLS", cfg.limits.max_cells);
    if !(1..=15).contains(&cfg.sigfigs) {
        die("MERU_OUTPUT_SIGFIGS must be 1..15");
    }
    let mode = match &authz {
        Authz::Licence(a) => format!(
            "licence required, revocation list {}",
            a.revocation_sequence()
                .map(|s| format!("#{s}"))
                .unwrap_or_else(|| "OFF".into())
        ),
        Authz::Open => "UNAUTHENTICATED (development)".into(),
    };
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| die(format!("bind {addr}: {e}")));
    eprintln!(
        "meru (Kshana Core) listening on {addr}: signer {} key {key_id}, {mode}, {} sig. figs, meter {}",
        signers.verdict.describe(),
        cfg.sigfigs,
        meter_path.display()
    );
    let svc = Arc::new(Service::new(cfg, signers, authz, limiter, meter));
    svc.serve(listener);
}
