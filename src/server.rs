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
//! * a per-address rate, the licence check, per-licence limits ([`crate::limits`]), the
//!   query-pattern audit ([`crate::audit`]: alerts, delayed verdicts for suspect licences,
//!   optional pause and per-region cap), then the method, then output rounding with the
//!   licence's keyed fingerprint ([`crate::fingerprint`]), the licence binding and signing;
//!   every call written to the meter log;
//! * honeypot paths that look like internals: a call to one marks the licence suspect and is
//!   answered exactly like any unknown path.
//!
//! The deployment profile ([`crate::profile`]) decides who is served. `public` serves
//! customer licences and refuses a service credential. `arksa-internal` and
//! `sovereign-contracted` serve only the service credential, and for it: the service rate
//! instead of the per-licence quota and probe detector, the audit in record-only mode, no
//! fingerprint (verdicts still licence-bound and signed), the `X-Meru-Tenant` tag in the
//! meter log, and `POST /verdict/batch` for recalibration.

use crate::audit::{AuditConfig, Auditor};
use crate::auth::{Authority, Caller};
use crate::crl::{Crl, CrlConfig, RevokeRequest};
use crate::fingerprint::{plan, FpKeys, Mark};
use crate::limits::{IpLimiter, Limiter};
use crate::lunar_assist::AssistConfig;
use crate::meter::{Entry, Meter};
use crate::methods::{Binding, Limits, Signing};
use crate::parametric_oracle::OracleConfig;
use crate::profile::{validate_tenant, Profile, TenantTag};
use crate::signer::Signers;
use crate::spaceweather::SpaceWxConfig;
use crate::{
    calibrate_verdict, cause_verdict, feeder_verdict, flight_verdict, lunar_assist_verdict,
    perception_verdict, rtk_quality_verdict, seal_verdict, selfcal_verdict, spaceweather_verdict,
    survey_verdict, trigger_verdict, victim_actor_verdict, wording_verdict, AssistRequest,
    CalibrateRequest, CauseRequest, FeederRequest, FlightRequest, PerceptionRequest,
    RtkQualityRequest, SealRequest, SelfCalRequest, SpaceWxRequest, SurveyRequest, TriggerRequest,
    VictimActorRequest, WordingRequest,
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
    /// The `parametric-trigger` station archive.
    pub oracle: OracleConfig,
    /// The `spaceweather` live inputs and regional calibrations.
    pub spaceweather: SpaceWxConfig,
    /// Query-pattern audit settings.
    pub audit: AuditConfig,
    /// Fingerprint key epochs; `None`: verdicts are not fingerprinted.
    pub fingerprint_keys: Option<FpKeys>,
    /// Calls a minute from one client address (0 = no limit).
    pub per_ip_per_minute: u32,
    /// Take the client address from `X-Real-IP` when the connection comes from loopback (the
    /// reverse proxy in front).
    pub trust_proxy: bool,
    /// Paths that look like internals; a call marks the licence suspect.
    pub honeypots: Vec<String>,
    /// The deployment profile ([`crate::profile`]).
    pub profile: Profile,
    /// How the tenant/mission tag is recorded in the meter log.
    pub tenant_tag: TenantTag,
    /// Calls a minute from the service credential (internal profiles; 0 = no limit).
    pub service_per_minute: u32,
    /// Most requests in one `POST /verdict/batch`.
    pub batch_max: usize,
    /// The product register's revocation list (`GET /crl`, `POST /verdict/crl/revoke`).
    pub crl: CrlConfig,
}

/// The revocation endpoint of the product register (operator licences in `MERU_CRL_ADMINS`).
pub const CRL_REVOKE_PATH: &str = "/verdict/crl/revoke";
/// The revocation list fetch (no licence needed).
pub const CRL_PATH: &str = "/crl";

/// The batch route (internal profiles only).
pub const BATCH_PATH: &str = "/verdict/batch";
/// The methods a batch may hold: simulator recalibration.
pub const BATCH_METHODS: &[&str] = &["calibrate", "selfcal"];

/// What the meter log needs to know about one call.
struct Call<'a> {
    caller: Option<&'a Caller>,
    tenant: Option<&'a str>,
    path: &'a str,
    rhash: &'a str,
    t0: Instant,
}

/// Default honeypot paths.
/// Under `/verdict/`, so the reverse proxy passes them on like the real methods.
pub const HONEYPOTS: &[&str] = &[
    "/verdict/survey/grid",
    "/verdict/selfcal/trace",
    "/verdict/cause/scores",
    "/verdict/victim-actor/scores",
    "/verdict/calibrate/residuals",
    "/verdict/rtk-quality/monitors",
    "/verdict/flight-integrity/scores",
    "/verdict/parametric-trigger/stations",
    "/verdict/policy-wording/rules",
    "/verdict/spaceweather/thresholds",
    "/verdict/perception-eval/raw",
    "/verdict/feeder-trust/weights",
    "/verdict/internal/params",
    "/verdict/debug/model",
];

/// The verdict `method` name served at a path.
pub fn method_of(path: &str) -> Option<&'static str> {
    Some(match path {
        "/verdict/selfcal" => "selfcal",
        "/verdict/survey" => "survey-plan",
        "/verdict/cause" => "cause",
        "/verdict/calibrate" => "calibrate",
        "/verdict/lunar-assist" => "lunar-assist",
        "/verdict/victim-actor" => "victim-actor",
        "/verdict/rtk-quality" => "rtk-quality",
        "/verdict/flight-integrity" => "flight-integrity",
        "/verdict/parametric-trigger" => "parametric-trigger",
        "/verdict/policy-wording" => "policy-wording",
        "/verdict/spaceweather" => "spaceweather",
        "/verdict/perception-eval" => "perception-eval",
        "/verdict/feeder-trust" => "feeder-trust",
        "/verdict/archive-seal" => "archive-seal",
        _ => return None,
    })
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
            oracle: OracleConfig::default(),
            spaceweather: SpaceWxConfig::default(),
            audit: AuditConfig::default(),
            fingerprint_keys: None,
            per_ip_per_minute: 60,
            trust_proxy: false,
            honeypots: HONEYPOTS.iter().map(|s| s.to_string()).collect(),
            profile: Profile::Public,
            tenant_tag: TenantTag::Off,
            service_per_minute: 600,
            batch_max: 16,
            crl: CrlConfig::default(),
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
    pub audit: Auditor,
    /// The product register's revocation list.
    pub crl: Crl,
    ip_limiter: IpLimiter,
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
        409 => "Conflict",
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
    real_ip: String,
    /// `X-Meru-Tenant`, as sent (validated later, per profile).
    tenant: Option<String>,
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
    let mut real_ip = String::new();
    let mut tenant = None;
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
        } else if let Some(v) = lower.strip_prefix("x-real-ip:") {
            real_ip = v.trim().to_string();
        } else if lower.starts_with("x-meru-tenant:") {
            tenant = Some(h["x-meru-tenant:".len()..].trim().to_string());
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
        real_ip,
        tenant,
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
        let audit = Auditor::new(cfg.audit.clone());
        let ip_limiter = IpLimiter::new(cfg.per_ip_per_minute);
        Service {
            cfg,
            signers,
            authz,
            limiter,
            meter,
            audit,
            crl: Crl::default(),
            ip_limiter,
            conns: AtomicUsize::new(0),
            jobs: AtomicUsize::new(0),
        }
    }

    /// Write an alert to the meter log and stderr. For a service credential the audit is
    /// record-only: the line is written, nothing is delayed or refused, and stderr says so
    /// instead of raising an alert.
    fn alert_entry(
        &self,
        caller: Option<&Caller>,
        path: &str,
        outcome: &str,
        a: &crate::audit::Alert,
    ) {
        let tag = if caller.is_some_and(|c| c.service.is_some()) {
            "[meru] audit (record only, service credential)"
        } else {
            "[meru][ALERT]"
        };
        eprintln!(
            "{tag} {outcome}: {} on {} ({}), licences {:?}, signatures {:?}",
            a.kind, a.method, a.shape, a.licences, a.rules
        );
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
            status: 0,
            outcome: outcome.into(),
            request_sha256: String::new(),
            verdict_sha256: String::new(),
            ms: 0,
            canary: false,
            alert: serde_json::to_value(a).ok(),
            service: caller.and_then(|c| c.service.clone()),
            tenant: None,
        });
    }

    /// Write one call to the meter log.
    fn meter_entry(&self, m: &Call<'_>, status: u16, outcome: &str, verdict: &str, canary: bool) {
        let now = now_unix();
        let caller = m.caller;
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
            path: m.path.into(),
            status,
            outcome: outcome.into(),
            request_sha256: m.rhash.into(),
            verdict_sha256: verdict.into(),
            ms: m.t0.elapsed().as_millis() as u64,
            canary,
            alert: None,
            service: caller.and_then(|c| c.service.clone()),
            tenant: m.tenant.map(str::to_string),
        });
    }

    /// Whether this instance's profile accepts the caller: the public profile serves
    /// customer licences only; an internal profile serves the service credential only.
    fn profile_gate(&self, caller: &Caller) -> Result<(), String> {
        match (self.cfg.profile.internal(), caller.service.is_some()) {
            (false, true) => Err("service credentials are not accepted on this instance".into()),
            (true, false) => Err(format!(
                "this instance ({} profile) accepts only its service credential",
                self.cfg.profile.as_str()
            )),
            _ => Ok(()),
        }
    }

    /// The tenant tag to record: `Ok(None)` when none was sent or the profile records none;
    /// an `Err` for a malformed tag on a profile that reads it.
    fn tenant_of(&self, raw: Option<&str>) -> Result<Option<String>, String> {
        if self.cfg.tenant_tag == TenantTag::Off {
            return Ok(None);
        }
        let Some(t) = raw else { return Ok(None) };
        validate_tenant(t)?;
        Ok(self.cfg.tenant_tag.record(t))
    }

    /// Per-caller limits: the per-licence limits and probe detector for a customer licence,
    /// the service rate for a service credential.
    fn limit(&self, caller: &Caller, rhash: &str, now: i64) -> Result<(), crate::limits::Refusal> {
        if caller.service.is_some() {
            self.limiter
                .admit_service(&caller.token_id, self.cfg.service_per_minute, now)
        } else {
            self.limiter.admit(&caller.token_id, rhash, now)
        }
    }

    /// The query-pattern audit for one call. Returns a refusal message when the call must be
    /// refused. A service credential is audited in record-only mode: alerts are written,
    /// nothing is delayed or refused.
    fn audit_call(
        &self,
        caller: &Caller,
        path: &str,
        method: &str,
        body: Option<&serde_json::Value>,
        now: i64,
    ) -> Option<String> {
        let v = body?;
        let a = self.audit.observe(&caller.token_id, method, v, now);
        for al in &a.alerts {
            self.alert_entry(Some(caller), path, "extraction_alert", al);
        }
        if caller.service.is_some() {
            return None;
        }
        if let Some(m) = a.refuse {
            return Some(m);
        }
        if a.suspect && self.cfg.audit.delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(self.cfg.audit.delay_ms));
        }
        None
    }

    /// Run the method at `path` on `body`: rounded with the licence's fingerprint (never for
    /// a service credential), bound to the licence, signed. Returns the verdict and whether
    /// the call fell in a canary cell.
    fn run(
        &self,
        path: &str,
        method: &str,
        body: &[u8],
        body_json: Option<&serde_json::Value>,
        caller: &Caller,
        now: i64,
    ) -> (Result<crate::SignedVerdict, String>, bool) {
        let utc = iso(now);
        let mark = match (&self.cfg.fingerprint_keys, body_json) {
            (Some(k), Some(v)) if caller.service.is_none() && !plan(method).is_empty() => k
                .active(now)
                .and_then(|e| Mark::new(e, &caller.token_id, method, v).ok()),
            _ => None,
        };
        let canary = mark.as_ref().is_some_and(Mark::is_canary);
        let binding = Binding {
            token_id: caller.token_id.clone(),
            mark,
        };
        let s = Signing {
            signer: self.signers.verdict.as_ref(),
            key_id: &self.cfg.key_id,
            lineage_seed: &self.signers.lineage_seed,
            lineage_key_id: &self.signers.lineage_key_id,
            sigfigs: self.cfg.sigfigs,
            bind: Some(&binding),
        };
        let out = match path {
            "/verdict/selfcal" => serde_json::from_slice::<SelfCalRequest>(body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| selfcal_verdict(&r, &s, &self.cfg.limits, &utc)),
            "/verdict/cause" => serde_json::from_slice::<CauseRequest>(body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| cause_verdict(&r, &s, &self.cfg.limits, &utc)),
            "/verdict/victim-actor" => serde_json::from_slice::<VictimActorRequest>(body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| victim_actor_verdict(&r, &s, &self.cfg.limits, &utc)),
            "/verdict/rtk-quality" => serde_json::from_slice::<RtkQualityRequest>(body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| rtk_quality_verdict(&r, &s, &self.cfg.limits.rtk_quality, &utc)),
            "/verdict/flight-integrity" => serde_json::from_slice::<FlightRequest>(body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| flight_verdict(&r, &s, &self.cfg.limits.flight, &utc)),
            "/verdict/parametric-trigger" => serde_json::from_slice::<TriggerRequest>(body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| {
                    trigger_verdict(&r, &s, &self.cfg.limits.trigger, &self.cfg.oracle, &utc)
                }),
            "/verdict/policy-wording" => serde_json::from_slice::<WordingRequest>(body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| wording_verdict(&r, &s, &self.cfg.limits.wording, &utc)),
            "/verdict/spaceweather" => serde_json::from_slice::<SpaceWxRequest>(body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| {
                    spaceweather_verdict(
                        &r,
                        &s,
                        &self.cfg.limits.spaceweather,
                        &self.cfg.spaceweather,
                        now as f64,
                        &utc,
                    )
                }),
            "/verdict/perception-eval" => serde_json::from_slice::<PerceptionRequest>(body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| perception_verdict(&r, &s, &self.cfg.limits.perception, &utc)),
            "/verdict/feeder-trust" => serde_json::from_slice::<FeederRequest>(body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| feeder_verdict(&r, &s, &self.cfg.limits.feeder, &utc)),
            "/verdict/archive-seal" => serde_json::from_slice::<SealRequest>(body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| seal_verdict(&r, &s, &self.cfg.limits.seal, &utc)),
            "/verdict/calibrate" => serde_json::from_slice::<CalibrateRequest>(body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| calibrate_verdict(&r, &s, &self.cfg.limits.calibrate, &utc)),
            "/verdict/lunar-assist" => serde_json::from_slice::<AssistRequest>(body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| {
                    lunar_assist_verdict(&r, &s, &self.cfg.limits.assist, &self.cfg.assist, &utc)
                }),
            _ => serde_json::from_slice::<SurveyRequest>(body)
                .map_err(|e| format!("request: {e}"))
                .and_then(|r| survey_verdict(&r, &s, &self.cfg.limits, caller.allow_grid, &utc)),
        };
        (out, canary)
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
        let now = now_unix();
        // 0. The client address (held in memory for a minute, never logged).
        let peer = stream.peer_addr().ok().map(|a| a.ip());
        let ip = match peer {
            Some(p) if self.cfg.trust_proxy && p.is_loopback() && !req.real_ip.is_empty() => {
                req.real_ip.clone()
            }
            Some(p) => p.to_string(),
            None => "-".into(),
        };
        if let Err(e) = self.ip_limiter.admit(&ip, now) {
            return err(&mut stream, 429, &e);
        }
        let caller_of = |token: &str| -> Result<Caller, String> {
            match &self.authz {
                Authz::Licence(a) => a.authorize(token, now),
                Authz::Open => Ok(Caller {
                    licensee: "(unauthenticated development)".into(),
                    tier: Tier::Evaluation,
                    token_id: "unauthenticated".into(),
                    allow_grid: false,
                    service: None,
                }),
            }
        };
        // The revocation list: public, rate limited per address like everything else.
        if req.path == CRL_PATH {
            if req.method != "GET" {
                return err(&mut stream, 405, "use GET");
            }
            let signer = self.signers.verdict.as_ref();
            return match self
                .crl
                .with(&self.cfg.crl, |c| c.signed(signer, &self.cfg.key_id, now))
            {
                Ok(v) => respond(
                    &mut stream,
                    200,
                    "OK",
                    &serde_json::to_string(&v).unwrap_or_default(),
                ),
                Err(e) if self.cfg.crl.log.is_none() => {
                    let _ = e;
                    err(&mut stream, 404, "unknown path")
                }
                Err(e) => err(&mut stream, 503, &e),
            };
        }
        let token = req.auth.strip_prefix("Bearer ").unwrap_or("");
        // Honeypots: answered like any unknown path; a licensed caller is marked suspect.
        if self.cfg.honeypots.contains(&req.path) {
            let c = caller_of(token).ok();
            let id = c.as_ref().map(|c| c.token_id.as_str()).unwrap_or("-");
            let a = self.audit.flag(id, "honeypot", &req.path, now);
            self.alert_entry(c.as_ref(), &req.path, "honeypot", &a);
            return err(&mut stream, 404, "unknown path");
        }
        if req.path == CRL_REVOKE_PATH && self.cfg.crl.log.is_some() {
            return self.revoke(&mut stream, &req, caller_of(token), now, t0);
        }
        let batch = self.cfg.profile.internal() && req.path == BATCH_PATH;
        let method = match method_of(&req.path) {
            Some(m) => m,
            None if batch => "batch",
            None => return err(&mut stream, 404, "unknown path"),
        };
        if req.method != "POST" {
            return err(&mut stream, 405, "use POST");
        }
        let rhash = request_hash(&req.body);
        let mut call = Call {
            caller: None,
            tenant: None,
            path: &req.path,
            rhash: &rhash,
            t0,
        };
        // 1. The licence (or the service credential), and whether this profile serves it.
        let caller = match caller_of(token) {
            Ok(c) => c,
            Err(e) => {
                self.meter_entry(&call, 401, "refused", "", false);
                return err(&mut stream, 401, &e);
            }
        };
        call.caller = Some(&caller);
        if let Err(e) = self.profile_gate(&caller) {
            self.meter_entry(&call, 403, "refused", "", false);
            return err(&mut stream, 403, &e);
        }
        // 1b. The tenant/mission tag (internal profiles), for cost tracking.
        let tenant = match self.tenant_of(req.tenant.as_deref()) {
            Ok(t) => t,
            Err(e) => {
                self.meter_entry(&call, 400, "invalid", "", false);
                return err(&mut stream, 400, &e);
            }
        };
        call.tenant = tenant.as_deref();
        if batch {
            return self.batch(&mut stream, &req.body, &caller, tenant.as_deref(), now, t0);
        }
        // 2. Per-licence limits and probe detection (the service rate for a service call).
        if let Err(r) = self.limit(&caller, &rhash, now) {
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
            self.meter_entry(&call, 429, outcome, "", false);
            return err(&mut stream, 429, &r.message);
        }
        // 2b. The query-pattern audit (slow sweeps, split sweeps, per-region cap).
        let body_json = serde_json::from_slice::<serde_json::Value>(&req.body).ok();
        if let Some(m) = self.audit_call(&caller, &req.path, method, body_json.as_ref(), now) {
            self.meter_entry(&call, 429, "audit_refused", "", false);
            return err(&mut stream, 429, &m);
        }
        // 3. Capacity.
        let Some(_job) = take_slot(&self.jobs, self.cfg.max_jobs) else {
            self.meter_entry(&call, 503, "busy", "", false);
            return err(&mut stream, 503, "the service is busy; retry shortly");
        };
        // 4. The method, rounded with the licence's fingerprint, bound to the licence, signed.
        let (out, canary) = self.run(
            &req.path,
            method,
            &req.body,
            body_json.as_ref(),
            &caller,
            now,
        );
        match out {
            Ok(v) => {
                self.meter_entry(&call, 200, "ok", &v.verdict_sha256, canary);
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
                self.meter_entry(&call, status, "invalid", "", false);
                err(&mut stream, status, &e);
            }
        }
    }

    /// `POST /verdict/crl/revoke`: an operator licence (`MERU_CRL_ADMINS`) revokes one register
    /// entry. Answers the revocation and the newly signed list; metered like any call.
    fn revoke(
        &self,
        stream: &mut TcpStream,
        req: &Parsed,
        caller: Result<Caller, String>,
        now: i64,
        t0: Instant,
    ) {
        let rhash = request_hash(&req.body);
        let mut call = Call {
            caller: None,
            tenant: None,
            path: CRL_REVOKE_PATH,
            rhash: &rhash,
            t0,
        };
        if req.method != "POST" {
            return err(stream, 405, "use POST");
        }
        let caller = match caller {
            Ok(c) => c,
            Err(e) => {
                self.meter_entry(&call, 401, "refused", "", false);
                return err(stream, 401, &e);
            }
        };
        call.caller = Some(&caller);
        if !self.cfg.crl.admins.contains(&caller.token_id) {
            self.meter_entry(&call, 403, "refused", "", false);
            return err(stream, 403, "this licence may not revoke register entries");
        }
        let r = match serde_json::from_slice::<RevokeRequest>(&req.body) {
            Ok(r) => r,
            Err(e) => {
                self.meter_entry(&call, 422, "invalid", "", false);
                return err(stream, 422, &format!("request: {e}"));
            }
        };
        let signer = self.signers.verdict.as_ref();
        let out = self.crl.with(&self.cfg.crl, |c| {
            let rev = c.revoke(&r, &caller.token_id, &iso(now))?;
            let list = c.signed(signer, &self.cfg.key_id, now)?;
            Ok((rev, list))
        });
        match out {
            Ok((rev, list)) => {
                self.meter_entry(&call, 200, "ok", &list.verdict_sha256, false);
                respond(
                    stream,
                    200,
                    "OK",
                    &serde_json::json!({"revoked": rev, "crl": list}).to_string(),
                );
            }
            Err(e) => {
                let status = if e.starts_with("already revoked") {
                    409
                } else {
                    422
                };
                self.meter_entry(&call, status, "invalid", "", false);
                err(stream, status, &e);
            }
        }
    }

    /// `POST /verdict/batch` (internal profiles, service credential only): several
    /// recalibration requests in one call, `{"requests": [{"method": "calibrate" | "selfcal",
    /// "request": {...}}]}`, at most [`Config::batch_max`]. Each item is limited, audited,
    /// metered and signed exactly as its own call would be; the answer is `{"results": [...]}`
    /// in order, each `{"verdict": <signed verdict>}` or `{"status": <code>, "error": "..."}`.
    /// The envelope is not signed; every verdict in it is.
    fn batch(
        &self,
        stream: &mut TcpStream,
        body: &[u8],
        caller: &Caller,
        tenant: Option<&str>,
        now: i64,
        t0: Instant,
    ) {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Item {
            method: String,
            request: serde_json::Value,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Batch {
            requests: Vec<Item>,
        }
        let rhash = request_hash(body);
        let whole = Call {
            caller: Some(caller),
            tenant,
            path: BATCH_PATH,
            rhash: &rhash,
            t0,
        };
        let b = match serde_json::from_slice::<Batch>(body) {
            Ok(b) => b,
            Err(e) => {
                self.meter_entry(&whole, 422, "invalid", "", false);
                return err(stream, 422, &format!("batch: {e}"));
            }
        };
        if b.requests.is_empty() || b.requests.len() > self.cfg.batch_max {
            self.meter_entry(&whole, 422, "invalid", "", false);
            return err(
                stream,
                422,
                &format!("batch: 1 to {} requests", self.cfg.batch_max),
            );
        }
        if let Some(bad) = b
            .requests
            .iter()
            .find(|i| !BATCH_METHODS.contains(&i.method.as_str()))
        {
            self.meter_entry(&whole, 422, "invalid", "", false);
            return err(
                stream,
                422,
                &format!(
                    "batch: method '{}' is not batched (only {})",
                    bad.method,
                    BATCH_METHODS.join(", ")
                ),
            );
        }
        // One running-job slot for the whole batch: its items run one after another.
        let Some(_job) = take_slot(&self.jobs, self.cfg.max_jobs) else {
            self.meter_entry(&whole, 503, "busy", "", false);
            return err(stream, 503, "the service is busy; retry shortly");
        };
        let mut results = Vec::with_capacity(b.requests.len());
        for item in &b.requests {
            let t_item = Instant::now();
            let path = format!("/verdict/{}", item.method);
            let bytes = serde_json::to_vec(&item.request).unwrap_or_default();
            let ih = request_hash(&bytes);
            let call = Call {
                caller: Some(caller),
                tenant,
                path: &path,
                rhash: &ih,
                t0: t_item,
            };
            let method = method_of(&path).unwrap_or("selfcal");
            if let Err(r) = self.limit(caller, &ih, now) {
                self.meter_entry(&call, 429, "rate_limited", "", false);
                results.push(serde_json::json!({"status": 429, "error": r.message}));
                continue;
            }
            if let Some(m) = self.audit_call(caller, &path, method, Some(&item.request), now) {
                self.meter_entry(&call, 429, "audit_refused", "", false);
                results.push(serde_json::json!({"status": 429, "error": m}));
                continue;
            }
            match self.run(&path, method, &bytes, Some(&item.request), caller, now) {
                (Ok(v), canary) => {
                    self.meter_entry(&call, 200, "ok", &v.verdict_sha256, canary);
                    results.push(serde_json::json!({ "verdict": v }));
                }
                (Err(e), _) => {
                    self.meter_entry(&call, 422, "invalid", "", false);
                    results.push(serde_json::json!({"status": 422, "error": e}));
                }
            }
        }
        respond(
            stream,
            200,
            "OK",
            &serde_json::json!({ "results": results }).to_string(),
        );
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
