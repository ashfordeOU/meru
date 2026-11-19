// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! `meru`: the Kshana Core hosted service binary. Serves the crown-jewel methods over HTTP,
//! each returning a signed verdict and nothing else:
//!   * `POST /verdict/selfcal` — F1, the self-calibrating simulator loop.
//!   * `POST /verdict/survey`  — F2, the integrity-driven ASF survey planner.
//!   * `GET  /health`          — liveness.
//!
//! One request per connection, `Content-Length` framed; put it behind a reverse proxy for
//! TLS and rate limiting.
//!
//! Configuration (environment):
//! - `MERU_ADDR` — listen address (default `127.0.0.1:8099`).
//! - `MERU_KEY` — 64-hex Ed25519 seed that signs verdicts (required).
//! - `MERU_KEY_ID` — key identifier placed in the verdict (default `meru`).
//! - `MERU_LICENCE_PUBKEY` — 64-hex vendor public key. When set, every `/verdict/*` call must
//!   carry `Authorization: Bearer <licence-token>` and the licence must be valid, unexpired
//!   at the Pro tier or above (or explicitly granted `pro-eloran`).
//! - `MERU_ALLOW_UNAUTHENTICATED=1` — start without licence checking (development only).

use meru::auth::authorize;
use meru::{selfcal_verdict, survey_verdict, SelfCalRequest, SurveyRequest};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

const MAX_BODY: usize = 8 * 1024 * 1024;

fn env_var(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_iso() -> String {
    let secs = now_unix();
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60
    )
}

fn respond(stream: &mut TcpStream, status: u16, reason: &str, body: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn err(stream: &mut TcpStream, status: u16, reason: &str, msg: &str) {
    respond(
        stream,
        status,
        reason,
        &serde_json::json!({ "error": msg }).to_string(),
    );
}

/// How a caller is authorised: a vendor public key (licence mode) or open (development).
#[derive(Clone)]
enum Authz {
    Licence(String),
    Open,
}

fn handle(mut stream: TcpStream, seed: &[u8; 32], key_id: &str, authz: &Authz) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let (mut content_length, mut auth) = (0usize, String::new());
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).is_err() || h == "\r\n" || h == "\n" || h.is_empty() {
            break;
        }
        let lower = h.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        } else if lower.starts_with("authorization:") {
            auth = h["authorization:".len()..].trim().to_string();
        }
    }
    if content_length > MAX_BODY {
        return err(&mut stream, 413, "Payload Too Large", "body above the cap");
    }
    let mut body = vec![0u8; content_length];
    if reader.read_exact(&mut body).is_err() {
        return err(&mut stream, 400, "Bad Request", "short body");
    }
    if path == "/health" {
        return respond(&mut stream, 200, "OK", "{\"ok\":true}");
    }
    if method != "POST" {
        return err(&mut stream, 405, "Method Not Allowed", "use POST");
    }
    // Authorise the caller by their Kshana licence before running any method.
    match authz {
        Authz::Licence(pubkey) => {
            let token = auth.strip_prefix("Bearer ").unwrap_or("");
            match authorize(token, pubkey, now_unix()) {
                Ok(ent) => eprintln!(
                    "[meru] {} -> {} ({})",
                    ent.licensee,
                    path,
                    ent.tier.as_str()
                ),
                Err(e) => return err(&mut stream, 401, "Unauthorized", &e),
            }
        }
        Authz::Open => eprintln!("[meru] (unauthenticated) -> {path}"),
    }
    let utc = now_iso();
    let out = match path.as_str() {
        "/verdict/selfcal" => serde_json::from_slice::<SelfCalRequest>(&body)
            .map_err(|e| format!("request: {e}"))
            .and_then(|r| selfcal_verdict(&r, seed, key_id, &utc)),
        "/verdict/survey" => serde_json::from_slice::<SurveyRequest>(&body)
            .map_err(|e| format!("request: {e}"))
            .and_then(|r| survey_verdict(&r, seed, key_id, &utc)),
        _ => return err(&mut stream, 404, "Not Found", "unknown path"),
    };
    match out {
        Ok(v) => respond(
            &mut stream,
            200,
            "OK",
            &serde_json::to_string(&v).unwrap_or_default(),
        ),
        Err(e) => err(&mut stream, 422, "Unprocessable Entity", &e),
    }
}

fn main() {
    let addr = env_var("MERU_ADDR").unwrap_or_else(|| "127.0.0.1:8099".into());
    let seed: [u8; 32] = match env_var("MERU_KEY")
        .and_then(|k| hex::decode(k.trim()).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        Some(s) => s,
        None => {
            eprintln!("MERU_KEY (64-hex Ed25519 seed) is required");
            std::process::exit(2);
        }
    };
    let key_id = env_var("MERU_KEY_ID").unwrap_or_else(|| "meru".into());
    let authz = match env_var("MERU_LICENCE_PUBKEY") {
        Some(pk) => Authz::Licence(pk),
        None if env_var("MERU_ALLOW_UNAUTHENTICATED").as_deref() == Some("1") => Authz::Open,
        None => {
            eprintln!(
                "refusing to start without caller authorisation: set MERU_LICENCE_PUBKEY \
                 (the vendor public key) or MERU_ALLOW_UNAUTHENTICATED=1 for development"
            );
            std::process::exit(2);
        }
    };
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "meru (Kshana Core) listening on {addr} (signing key {key_id}){}",
        match authz {
            Authz::Licence(_) => ", licence required",
            Authz::Open => ", UNAUTHENTICATED (development)",
        }
    );
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let (s, k, a) = (seed, key_id.clone(), authz.clone());
                std::thread::spawn(move || handle(stream, &s, &k, &a));
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
}
