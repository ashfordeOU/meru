// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The HTTP front of the service: one request per connection, `Content-Length` framed, meant
//! to sit behind a TLS reverse proxy (deploy/). Hardened for the open internet:
//!
//! * read and write timeouts on every connection (a slow client cannot hold a thread);
//! * a cap on open connections and a separate cap on methods running at once (503 when
//!   full, so a burst cannot exhaust the machine);
//! * bounded request line, header count and header size; a body cap; chunked bodies and
//!   duplicate `Content-Length` refused (no request smuggling through the proxy);
//! * licence check, then per-licence limits ([`crate::limits`]), then the method, then
//!   output coarsening and signing; every call written to the meter log.

use crate::auth::{Authority, Caller};
use crate::limits::Limiter;
use crate::lunar_assist::AssistConfig;
use crate::meter::{Entry, Meter};
use crate::methods::{Limits, Signing};
use crate::signer::Signers;
use crate::{
    cause_verdict, lunar_assist_verdict, selfcal_verdict, survey_verdict, AssistRequest,
    CauseRequest, SelfCalRequest, SurveyRequest,
};
use kshana_pro::license::Tier;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_LINE: usize = 8 * 1024;
const MAX_HEADERS: usize = 64;

/// How callers are authorised.
pub enum Authz {
    Licence(Box<Authority>),
    /// Development only: no licence check.
    Open,
}

/// Service settings.
pub struct Config {
    pub key_id: String,
    pub sigfigs: u32,
    pub max_conn: usize,
    pub max_jobs: usize,
    pub max_body: usize,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub limits: Limits,
    /// The `lunar-assist` source products and method settings.
    pub assist: AssistConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            key_id: "meru".into(),
            sigfigs: 3,
            max_conn: 64,
            max_jobs: 4,
            max_body: 2 * 1024 * 1024,
            read_timeout: Duration::from_secs(15),
            write_timeout: Duration::from_secs(30),
            limits: Limits::default(),
            assist: AssistConfig::default(),
        }
    }
}

/// Everything a request handler needs.
pub struct Service {
    pub cfg: Config,
    pub signers: Signers,
    pub authz: Authz,
    pub limiter: Limiter,
    pub meter: Meter,
    conns: AtomicUsize,
    jobs: AtomicUsize,
}

/// Decrements a counter when dropped.
struct Slot<'a>(&'a AtomicUsize);
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn take_slot(c: &AtomicUsize, max: usize) -> Option<Slot<'_>> {
    if c.fetch_add(1, Ordering::SeqCst) >= max {
        c.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    Some(Slot(c))
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// ISO-8601 UTC for a Unix time.
pub fn iso(secs: i64) -> String {
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
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.flush();
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn err(stream: &mut TcpStream, status: u16, msg: &str) {
    respond(
        stream,
        status,
        reason(status),
        &serde_json::json!({ "error": msg }).to_string(),
    );
}

/// Read one line of at most `max` bytes. `Ok(None)` if the line is too long.
fn read_line_limited<R: BufRead>(r: &mut R, max: usize) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    loop {
        let avail = r.fill_buf()?;
        if avail.is_empty() {
            break;
        }
        let (n, done) = match avail.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (avail.len(), false),
        };
        if buf.len() + n > max {
            return Ok(None);
        }
        buf.extend_from_slice(&avail[..n]);
        r.consume(n);
        if done {
            break;
        }
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// SHA-256 of the request in canonical form (keys sorted, no whitespace), so the same request
/// written differently counts as the same request for the probe detector.
fn request_hash(body: &[u8]) -> String {
    let canon = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| serde_json::to_vec(&v).ok())
        .unwrap_or_else(|| body.to_vec());
    hex::encode(Sha256::digest(&canon))
}

struct Parsed {
    method: String,
    path: String,
    auth: String,
    body: Vec<u8>,
}

/// Parse a request, or answer the error and return `None`.
fn parse(stream: &mut TcpStream, max_body: usize) -> Option<Parsed> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let line = match read_line_limited(&mut reader, MAX_LINE) {
        Ok(Some(l)) if !l.trim().is_empty() => l,
        Ok(None) => {
            err(stream, 431, "request line too long");
            return None;
        }
        _ => return None,
    };
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let (mut content_length, mut auth, mut n) = (None::<usize>, String::new(), 0usize);
    loop {
        let h = match read_line_limited(&mut reader, MAX_LINE) {
            Ok(Some(h)) => h,
            Ok(None) => {
                err(stream, 431, "header line too long");
                return None;
            }
            Err(_) => return None,
        };
        if h == "\r\n" || h == "\n" || h.is_empty() {
            break;
        }
        n += 1;
        if n > MAX_HEADERS {
            err(stream, 431, "too many headers");
            return None;
        }
        let lower = h.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            let Ok(v) = v.trim().parse::<usize>() else {
                err(stream, 400, "bad Content-Length");
                return None;
            };
            if content_length.is_some_and(|c| c != v) {
                err(stream, 400, "conflicting Content-Length headers");
                return None;
            }
            content_length = Some(v);
        } else if lower.starts_with("transfer-encoding:") {
            err(
                stream,
                501,
                "chunked bodies are not accepted; send Content-Length",
            );
            return None;
        } else if lower.starts_with("authorization:") {
            auth = h["authorization:".len()..].trim().to_string();
        }
    }
    let len = content_length.unwrap_or(0);
    if len > max_body {
        err(stream, 413, "request body above the cap");
        return None;
    }
    if method == "POST" && content_length.is_none() {
        err(stream, 411, "Content-Length required");
        return None;
    }
    let mut body = vec![0u8; len];
    if reader.read_exact(&mut body).is_err() {
        err(stream, 400, "short or slow body");
        return None;
    }
    Some(Parsed {
        method,
        path,
        auth,
        body,
    })
}

impl Service {
    pub fn new(
        cfg: Config,
        signers: Signers,
        authz: Authz,
        limiter: Limiter,
        meter: Meter,
    ) -> Self {
        Service {
            cfg,
            signers,
            authz,
            limiter,
            meter,
            conns: AtomicUsize::new(0),
            jobs: AtomicUsize::new(0),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn meter_entry(
        &self,
        caller: Option<&Caller>,
        path: &str,
        status: u16,
        outcome: &str,
        req: &str,
        verdict: &str,
        t0: Instant,
    ) {
        let now = now_unix();
        self.meter.record(&Entry {
            utc: iso(now),
            unix: now,
            licensee: caller
                .map(|c| c.licensee.clone())
                .unwrap_or_else(|| "-".into()),
            token_id: caller
                .map(|c| c.token_id.clone())
                .unwrap_or_else(|| "-".into()),
            tier: caller
                .map(|c| c.tier.as_str().to_string())
                .unwrap_or_else(|| "-".into()),
            path: path.into(),
            status,
            outcome: outcome.into(),
            request_sha256: req.into(),
            verdict_sha256: verdict.into(),
            ms: t0.elapsed().as_millis() as u64,
        });
    }

    /// Handle one connection.
    pub fn handle(&self, mut stream: TcpStream) {
        let Some(_conn) = take_slot(&self.conns, self.cfg.max_conn) else {
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            return err(&mut stream, 503, "too many connections; retry shortly");
        };
        let _ = stream.set_read_timeout(Some(self.cfg.read_timeout));
        let _ = stream.set_write_timeout(Some(self.cfg.write_timeout));
        let t0 = Instant::now();
        let Some(req) = parse(&mut stream, self.cfg.max_body) else {
            return;
        };
        if req.path == "/health" && req.method == "GET" {
            return respond(&mut stream, 200, "OK", "{\"ok\":true}");
        }
        if !matches!(
            req.path.as_str(),
            "/verdict/selfcal" | "/verdict/survey" | "/verdict/cause" | "/verdict/lunar-assist"
        ) {
            return err(&mut stream, 404, "unknown path");
        }
        if req.method != "POST" {
            return err(&mut stream, 405, "use POST");
        }
        let rhash = request_hash(&req.body);
        // 1. The licence.
        let now = now_unix();
        let caller = match &self.authz {
            Authz::Licence(a) => {
                let token = req.auth.strip_prefix("Bearer ").unwrap_or("");
                match a.authorize(token, now) {
                    Ok(c) => c,
                    Err(e) => {
                        self.meter_entry(None, &req.path, 401, "refused", &rhash, "", t0);
                        return err(&mut stream, 401, &e);
                    }
                }
            }
            Authz::Open => Caller {
                licensee: "(unauthenticated development)".into(),
                tier: Tier::Evaluation,
                token_id: "unauthenticated".into(),
                allow_grid: false,
            },
        };
        // 2. Per-licence limits and probe detection.
        if let Err(r) = self.limiter.admit(&caller.token_id, &rhash, now) {
            let outcome = if r.probe_alert {
                "probe_alert"
            } else {
                "rate_limited"
            };
            if r.probe_alert {
                eprintln!(
                    "[meru][ALERT] probe pattern from {} (token {}): licence paused",
                    caller.licensee, caller.token_id
                );
            }
            self.meter_entry(Some(&caller), &req.path, 429, outcome, &rhash, "", t0);
            return err(&mut stream, 429, &r.message);
        }
        // 3. Capacity.
        let Some(_job) = take_slot(&self.jobs, self.cfg.max_jobs) else {
            self.meter_entry(Some(&caller), &req.path, 503, "busy", &rhash, "", t0);
            return err(&mut stream, 503, "the service is busy; retry shortly");
        };
        // 4. The method, coarsened and signed.
        let utc = iso(now);
        let s = Signing {
            signer: self.signers.verdict.as_ref(),
            key_id: &self.cfg.key_id,
            lineage_seed: &self.signers.lineage_seed,
            lineage_key_id: &self.signers.lineage_key_id,
            sigfigs: self.cfg.sigfigs,
        };
        let out = match req.path.as_str() {
            "/verdict/selfcal" => serde_json::from_slice::<SelfCalRequest>(&req.body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| selfcal_verdict(&r, &s, &self.cfg.limits, &utc)),
            "/verdict/cause" => serde_json::from_slice::<CauseRequest>(&req.body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| cause_verdict(&r, &s, &self.cfg.limits, &utc)),
            "/verdict/lunar-assist" => serde_json::from_slice::<AssistRequest>(&req.body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| {
                    lunar_assist_verdict(&r, &s, &self.cfg.limits.assist, &self.cfg.assist, &utc)
                }),
            _ => serde_json::from_slice::<SurveyRequest>(&req.body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| survey_verdict(&r, &s, &self.cfg.limits, caller.allow_grid, &utc)),
        };
        match out {
            Ok(v) => {
                self.meter_entry(
                    Some(&caller),
                    &req.path,
                    200,
                    "ok",
                    &rhash,
                    &v.verdict_sha256,
                    t0,
                );
                respond(
                    &mut stream,
                    200,
                    "OK",
                    &serde_json::to_string(&v).unwrap_or_default(),
                );
            }
            Err(e) => {
                let status = if e.contains("not available on this licence") {
                    403
                } else {
                    422
                };
                self.meter_entry(Some(&caller), &req.path, status, "invalid", &rhash, "", t0);
                err(&mut stream, status, &e);
            }
        }
    }

    /// Serve forever on `listener`, one thread per connection (bounded by the connection cap).
    pub fn serve(self: Arc<Self>, listener: TcpListener) {
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let me = Arc::clone(&self);
                    std::thread::spawn(move || me.handle(stream));
                }
                Err(e) => eprintln!("accept: {e}"),
            }
        }
    }
}
