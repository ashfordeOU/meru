// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! `meru`: the Kshana Core hosted service binary. Serves the crown-jewel methods over HTTP,
//! each returning a signed verdict and nothing else:
//!   * `POST /verdict/selfcal` — F1, the self-calibrating simulator loop.
//!   * `POST /verdict/survey`  — F2, the integrity-driven ASF survey planner.
//!   * `POST /verdict/cause`   — what caused a position episode.
//!   * `POST /verdict/calibrate` — general parametric calibration against telemetry.
//!   * `POST /verdict/lunar-assist` — long-validity lunar GNSS assistance packages.
//!   * `POST /verdict/victim-actor` — was a vessel's AIS position interfered with, or its own
//!     reports manipulated.
//!   * `GET  /health`          — liveness.
//!
//! Run it behind the TLS reverse proxy in `deploy/`. Configuration is the environment; see
//! README.md for the full list. It refuses to start without a working signer, a licence
//! configuration and an explicit revocation choice.
//!
//! Operator commands (not served):
//!   * `meru fingerprint-keys rotate <file> [--from <unix>]` — add a fingerprint key epoch.
//!   * `meru ownership --keys <file> --suspects <jsonl> (--licences <file> | --meter <log>)`
//!     — which licence suspect numbers came from.
//!   * `meru redteam [--budgets 16,32,64,128,256] [--out report.json]` — the extraction
//!     exercise against F2.
//!   * `meru meter summary [--log <meter log>] [--from <unix>] [--to <unix>] [--json]` —
//!     per-tenant, per-method calls and compute time (Arksa cost tracking).
//!
//! Deployment profile: `MERU_PROFILE` = `public` (default), `arksa-internal` or
//! `sovereign-contracted` (see `meru::profile` and README "Deployment profiles").

use meru::audit::AuditConfig;
use meru::auth::Authority;
use meru::fingerprint::{FpKeys, Suspect};
use meru::limits::{LimitConfig, Limiter};
use meru::meter::Meter;
use meru::profile::{Profile, TenantTag};
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

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// Operator commands. Returns `true` when one ran.
fn command(args: &[String]) -> bool {
    match args.first().map(String::as_str) {
        Some("fingerprint-keys") => {
            let (Some("rotate"), Some(path)) = (args.get(1).map(String::as_str), args.get(2))
            else {
                die("usage: meru fingerprint-keys rotate <file> [--from <unix>]")
            };
            let from = flag(args, "--from")
                .map(|v| v.parse().unwrap_or_else(|_| die("--from: not a number")))
                .unwrap_or_else(now_unix);
            let id = FpKeys::rotate(std::path::Path::new(path), from).unwrap_or_else(|e| die(e));
            eprintln!("added fingerprint epoch {id} (in force from {from}); keep every epoch: later ownership tests need them");
            true
        }
        Some("ownership") => {
            let keys = flag(args, "--keys")
                .or_else(|| env("MERU_FINGERPRINT_KEYS"))
                .unwrap_or_else(|| die("--keys <file> (or MERU_FINGERPRINT_KEYS) is required"));
            let keys = FpKeys::load(std::path::Path::new(&keys)).unwrap_or_else(|e| die(e));
            let sp =
                flag(args, "--suspects").unwrap_or_else(|| die("--suspects <jsonl> is required"));
            let text = std::fs::read_to_string(&sp).unwrap_or_else(|e| die(format!("{sp}: {e}")));
            let suspects: Vec<Suspect> = text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str(l).unwrap_or_else(|e| die(format!("{sp}: {e}"))))
                .collect();
            let mut cands: Vec<String> = match (flag(args, "--licences"), flag(args, "--meter")) {
                (Some(p), _) => std::fs::read_to_string(&p)
                    .unwrap_or_else(|e| die(format!("{p}: {e}")))
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect(),
                (None, Some(p)) => meru::meter::token_ids(std::path::Path::new(&p)),
                _ => die("--licences <file> or --meter <meter log> is required"),
            };
            cands.sort();
            cands.dedup();
            let sig = flag(args, "--sigfigs")
                .map(|v| v.parse().unwrap_or(3))
                .unwrap_or(3);
            let limits = meru::Limits::default();
            let rep = meru::fingerprint::ownership(&suspects, &keys, &cands, sig, &|m, q| {
                meru::methods::raw_outcome(m, q, &limits)
            });
            println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
            true
        }
        Some("redteam") => {
            let mut cfg = meru::redteam::RedTeamConfig::default();
            if let Some(b) = flag(args, "--budgets") {
                cfg.budgets = b
                    .split(',')
                    .map(|x| {
                        x.trim()
                            .parse()
                            .unwrap_or_else(|_| die("--budgets: numbers"))
                    })
                    .collect();
            }
            let r = meru::redteam::run(&cfg).unwrap_or_else(|e| die(e));
            eprint!("{}", meru::redteam::summary(&r));
            let json = serde_json::to_string_pretty(&r).unwrap_or_default();
            match flag(args, "--out") {
                Some(p) => std::fs::write(&p, json).unwrap_or_else(|e| die(format!("{p}: {e}"))),
                None => println!("{json}"),
            }
            true
        }
        Some("meter") => {
            if args.get(1).map(String::as_str) != Some("summary") {
                die("usage: meru meter summary [--log <meter log>] [--from <unix>] [--to <unix>] [--json]")
            }
            let log = flag(args, "--log")
                .or_else(|| env("MERU_METER_LOG"))
                .unwrap_or_else(|| "meru-meter.jsonl".into());
            let unix = |name: &str, default: i64| {
                flag(args, name)
                    .map(|v| {
                        v.parse::<i64>()
                            .unwrap_or_else(|_| die(format!("{name}: Unix seconds")))
                    })
                    .unwrap_or(default)
            };
            let (from, to) = (unix("--from", i64::MIN), unix("--to", i64::MAX));
            let rows = meru::meter::summary(std::path::Path::new(&log), from, to)
                .unwrap_or_else(|e| die(e));
            if args.iter().any(|a| a == "--json") {
                println!("{}", serde_json::to_string_pretty(&rows).unwrap_or_default());
            } else {
                println!(
                    "{:<24} {:<24} {:>8} {:>8} {:>12} {:>12}",
                    "tenant", "method", "ok", "not_ok", "ok_ms", "total_ms"
                );
                for r in &rows {
                    println!(
                        "{:<24} {:<24} {:>8} {:>8} {:>12} {:>12}",
                        r.tenant,
                        r.path.trim_start_matches("/verdict/"),
                        r.ok,
                        r.not_ok,
                        r.ok_ms,
                        r.total_ms
                    );
                }
            }
            true
        }
        Some(other) => die(format!(
            "unknown command '{other}' (fingerprint-keys, ownership, redteam, meter; no command serves)"
        )),
        None => false,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if command(&args) {
        return;
    }
    let profile = Profile::parse(env("MERU_PROFILE").as_deref()).unwrap_or_else(|e| die(e));
    let addr = env("MERU_ADDR").unwrap_or_else(|| "127.0.0.1:8099".into());
    for w in profile.check_bind(&addr).unwrap_or_else(|e| die(e)) {
        eprintln!("[meru][WARNING] {w}");
    }
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
            let mut a = Authority::new(&pk, env("MERU_LICENCE_ROOT_KID").as_deref(), rev)
                .unwrap_or_else(|e| die(e));
            if let Some(c) = env("MERU_SERVICE_CLIENTS") {
                a = a.with_service_clients(
                    c.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
            }
            Authz::Licence(Box::new(a))
        }
        None if profile.internal() => die(format!(
            "the {} profile needs MERU_LICENCE_PUBKEY (the service credential is a vendor-signed token); \
             unauthenticated mode is for the public profile in development only",
            profile.as_str()
        )),
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
    cfg.limits.cause.max_track_points =
        num("MERU_MAX_TRACK_POINTS", cfg.limits.cause.max_track_points);
    cfg.limits.cause.max_epochs = num("MERU_MAX_EPOCHS", cfg.limits.cause.max_epochs);
    cfg.limits.victim_actor.max_track_points = num(
        "MERU_MAX_TRACK_POINTS",
        cfg.limits.victim_actor.max_track_points,
    );
    cfg.limits.victim_actor.max_neighbour_points = num(
        "MERU_MAX_NEIGHBOUR_POINTS",
        cfg.limits.victim_actor.max_neighbour_points,
    );
    // `lunar-assist`: offered only when a directory of observed SP3 products is configured.
    if let Some(dir) = env("MERU_ASSIST_SOURCE") {
        cfg.assist.source_dir = Some(PathBuf::from(dir));
    }
    // `parametric-trigger`: the station archive (stations.toml and the station series).
    if let Some(dir) = env("MERU_ORACLE_STATIONS") {
        cfg.oracle.stations_dir = Some(PathBuf::from(dir));
    }
    // `spaceweather`: the live input directory and regional calibrations.
    if let Some(dir) = env("MERU_SPACEWX_SOURCE") {
        cfg.spaceweather.source_dir = Some(PathBuf::from(dir));
    }
    if let Some(p) = env("MERU_SPACEWX_REGIONS") {
        let body = std::fs::read_to_string(&p).unwrap_or_else(|e| die(format!("{p}: {e}")));
        cfg.spaceweather.regions =
            meru::spaceweather::parse_regions(&body).unwrap_or_else(|e| die(format!("{p}: {e}")));
    }
    // The observation archives and who may write to them.
    if let Some(d) = env("MERU_ARCHIVE_DIR") {
        cfg.archive.dir = Some(PathBuf::from(d));
        cfg.archive.writers = env("MERU_ARCHIVE_WRITERS")
            .map(|a| {
                a.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            })
            .unwrap_or_default();
    }
    if let Some(p) = env("MERU_ASSIST_EOP") {
        let body = std::fs::read_to_string(&p).unwrap_or_else(|e| die(format!("{p}: {e}")));
        let eop = meru::lunar_assist::eop_from_finals(&body);
        if eop.is_empty() {
            die(format!("{p}: no finals2000A record"));
        }
        cfg.assist.eop = Some(eop);
    }
    if let Some(list) = env("MERU_LUNAR_REGISTRIES") {
        let paths: Vec<PathBuf> = list.split(',').map(|p| PathBuf::from(p.trim())).collect();
        cfg.assist.registries =
            meru::lunar_registry::Registries::load(&paths).unwrap_or_else(|e| die(e));
    }
    cfg.assist.fit_hours = num("MERU_ASSIST_FIT_HOURS", cfg.assist.fit_hours);
    cfg.assist.backtests = num("MERU_ASSIST_BACKTESTS", cfg.assist.backtests);
    cfg.limits.assist.max_satellites =
        num("MERU_ASSIST_MAX_SATS", cfg.limits.assist.max_satellites);
    // Deployment profile: who is served, the service rate, batches, the tenant tag.
    cfg.profile = profile;
    cfg.tenant_tag = TenantTag::parse(
        env("MERU_TENANT_TAG").as_deref(),
        profile.default_tenant_tag(),
    )
    .unwrap_or_else(|e| die(e));
    if !profile.internal() && cfg.tenant_tag != TenantTag::Off {
        die("MERU_TENANT_TAG applies to the arksa-internal and sovereign-contracted profiles only");
    }
    cfg.service_per_minute = num("MERU_SERVICE_RATE_PER_MIN", cfg.service_per_minute);
    cfg.batch_max = num("MERU_BATCH_MAX", cfg.batch_max);
    if cfg.batch_max == 0 || cfg.batch_max > 256 {
        die("MERU_BATCH_MAX must be 1..256");
    }
    // Anti-extraction: per-address rate, the query-pattern audit, fingerprints, honeypots.
    cfg.per_ip_per_minute = num(
        "MERU_RATE_PER_IP_PER_MIN",
        profile.default_per_ip_per_minute(),
    );
    cfg.trust_proxy = env("MERU_TRUST_PROXY").as_deref() == Some("1");
    let d = AuditConfig::default();
    cfg.audit = AuditConfig {
        window_s: num("MERU_AUDIT_WINDOW_S", d.window_s),
        min_points: num("MERU_AUDIT_MIN_POINTS", d.min_points),
        suspect_s: num("MERU_AUDIT_SUSPECT_S", d.suspect_s),
        delay_ms: num("MERU_AUDIT_DELAY_MS", d.delay_ms),
        pause: env("MERU_AUDIT_PAUSE").as_deref() == Some("1"),
        max_new_cells_per_day: num("MERU_REGION_CELLS_PER_DAY", d.max_new_cells_per_day),
        ..d
    };
    if let Some(h) = env("MERU_HONEYPOTS") {
        cfg.honeypots = if h.trim() == "none" {
            vec![]
        } else {
            h.split(',').map(|p| p.trim().to_string()).collect()
        };
    }
    match env("MERU_FINGERPRINT_KEYS") {
        Some(p) => {
            let k = FpKeys::load(std::path::Path::new(&p)).unwrap_or_else(|e| die(e));
            if k.active(now_unix()).is_none() {
                die(format!("{p}: no fingerprint epoch in force yet"));
            }
            cfg.fingerprint_keys = Some(k);
        }
        None if profile.internal() => {}
        None => {
            eprintln!("[meru][WARNING] MERU_FINGERPRINT_KEYS unset: verdicts are not fingerprinted")
        }
    }
    if !(1..=15).contains(&cfg.sigfigs) {
        die("MERU_OUTPUT_SIGFIGS must be 1..15");
    }
    let mode = match &authz {
        Authz::Licence(a) if profile.internal() => format!(
            "profile {}: service credential only (clients via MERU_SERVICE_CLIENTS, {} calls/min), tenant tag {}, revocation list {}",
            profile.as_str(),
            cfg.service_per_minute,
            cfg.tenant_tag.as_str(),
            a.revocation_sequence()
                .map(|s| format!("#{s}"))
                .unwrap_or_else(|| "OFF".into())
        ),
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
        "meru (Kshana Core) listening on {addr}: signer {} key {key_id}, {mode}, {} sig. figs, meter {}, fingerprints {}, audit window {} s",
        signers.verdict.describe(),
        cfg.sigfigs,
        meter_path.display(),
        cfg.fingerprint_keys
            .as_ref()
            .and_then(|k| k.active(now))
            .map(|e| format!("epoch {}", e.id))
            .unwrap_or_else(|| "OFF".into()),
        cfg.audit.window_s
    );
    let svc = Arc::new(Service::new(cfg, signers, authz, limiter, meter));
    svc.serve(listener);
}
