// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! Per-licence call limits and probe detection.
//!
//! Someone with a licence could try to rebuild a method from the outside by sending many
//! chosen inputs and studying the answers. Three limits make that slow and visible:
//!
//! * a per-minute rate and a daily quota for each licence token;
//! * a probe detector: more than `probe_distinct_per_hour` *different* requests from one
//!   licence within an hour raises an alert and blocks that licence for `probe_block_s`.
//!   Ordinary work repeats or varies a few inputs; a sweep of many distinct inputs is what
//!   model-copying looks like;
//! * every call (and every alert) is written to the meter log ([`crate::meter`]);
//! * a per-client-address rate ([`IpLimiter`]) in front of the licence check.
//!
//! Slower, patient sweeps are the job of the query-pattern audit ([`crate::audit`]).
//!
//! State is in memory. The daily counts are rebuilt from the meter log at start-up
//! ([`Limiter::seed_daily`]), so a restart does not reset a quota.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// Limit settings.
#[derive(Clone, Debug)]
pub struct LimitConfig {
    pub per_minute: u32,
    pub per_day: u32,
    pub probe_distinct_per_hour: usize,
    pub probe_block_s: i64,
}

impl Default for LimitConfig {
    fn default() -> Self {
        LimitConfig {
            per_minute: 10,
            per_day: 200,
            probe_distinct_per_hour: 60,
            probe_block_s: 3600,
        }
    }
}

#[derive(Default)]
struct State {
    minute: VecDeque<i64>,
    day: i64,
    day_count: u32,
    /// (time, request hash) within the last hour.
    recent: VecDeque<(i64, String)>,
    blocked_until: i64,
}

/// Why a call was refused (HTTP 429), and whether it is a probe alert.
#[derive(Debug, PartialEq)]
pub struct Refusal {
    pub message: String,
    pub probe_alert: bool,
}

/// The per-licence limiter.
pub struct Limiter {
    cfg: LimitConfig,
    state: Mutex<HashMap<String, State>>,
}

impl Limiter {
    pub fn new(cfg: LimitConfig) -> Self {
        Limiter {
            cfg,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Set today's call count for `token` (from the meter log at start-up).
    pub fn seed_daily(&self, token: &str, now: i64, count: u32) {
        let mut m = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let st = m.entry(token.to_string()).or_default();
        st.day = now.div_euclid(86_400);
        st.day_count = count;
    }

    /// Admit or refuse one call from licence `token` with request hash `req` at `now`.
    pub fn admit(&self, token: &str, req: &str, now: i64) -> Result<(), Refusal> {
        let mut m = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let st = m.entry(token.to_string()).or_default();
        if now < st.blocked_until {
            return Err(Refusal {
                message: format!(
                    "this licence is paused for {} s after unusual request patterns; contact Ashforde if this is unexpected",
                    st.blocked_until - now
                ),
                probe_alert: false,
            });
        }
        while st.minute.front().is_some_and(|t| *t <= now - 60) {
            st.minute.pop_front();
        }
        if st.minute.len() as u32 >= self.cfg.per_minute {
            return Err(Refusal {
                message: format!("rate limit: at most {} calls a minute", self.cfg.per_minute),
                probe_alert: false,
            });
        }
        let day = now.div_euclid(86_400);
        if st.day != day {
            st.day = day;
            st.day_count = 0;
        }
        if st.day_count >= self.cfg.per_day {
            return Err(Refusal {
                message: format!(
                    "daily quota of {} calls reached (resets 00:00 UTC)",
                    self.cfg.per_day
                ),
                probe_alert: false,
            });
        }
        while st.recent.front().is_some_and(|(t, _)| *t <= now - 3600) {
            st.recent.pop_front();
        }
        let is_new = !st.recent.iter().any(|(_, h)| h == req);
        if is_new {
            let distinct = {
                let mut v: Vec<&str> = st.recent.iter().map(|(_, h)| h.as_str()).collect();
                v.sort_unstable();
                v.dedup();
                v.len()
            };
            if distinct + 1 > self.cfg.probe_distinct_per_hour {
                st.blocked_until = now + self.cfg.probe_block_s;
                return Err(Refusal {
                    message: "this licence is paused after unusual request patterns; contact Ashforde if this is unexpected".into(),
                    probe_alert: true,
                });
            }
        }
        st.minute.push_back(now);
        st.day_count += 1;
        st.recent.push_back((now, req.to_string()));
        Ok(())
    }

    /// Admit or refuse one call from a service credential ([`crate::auth::Caller::service`])
    /// at `now`: a per-minute rate only (`per_minute`, 0 = no limit). No daily quota and no
    /// probe detector: Arksa's own design sweeps are many distinct requests by design; the
    /// rate and the running-job cap protect the service.
    pub fn admit_service(&self, token: &str, per_minute: u32, now: i64) -> Result<(), Refusal> {
        if per_minute == 0 {
            return Ok(());
        }
        let mut m = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let st = m.entry(token.to_string()).or_default();
        while st.minute.front().is_some_and(|t| *t <= now - 60) {
            st.minute.pop_front();
        }
        if st.minute.len() as u32 >= per_minute {
            return Err(Refusal {
                message: format!("service rate limit: at most {per_minute} calls a minute"),
                probe_alert: false,
            });
        }
        st.minute.push_back(now);
        Ok(())
    }
}

/// A per-client-address rate (calls a minute). Addresses are held in memory for a minute and
/// never written anywhere.
pub struct IpLimiter {
    per_minute: u32,
    state: Mutex<HashMap<String, VecDeque<i64>>>,
}

impl IpLimiter {
    /// `per_minute` 0 turns the limit off.
    pub fn new(per_minute: u32) -> Self {
        IpLimiter {
            per_minute,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Admit or refuse one call from `ip` at `now`.
    pub fn admit(&self, ip: &str, now: i64) -> Result<(), String> {
        if self.per_minute == 0 {
            return Ok(());
        }
        let mut m = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() > 50_000 {
            m.retain(|_, q| q.back().is_some_and(|t| *t > now - 60));
        }
        let q = m.entry(ip.to_string()).or_default();
        while q.front().is_some_and(|t| *t <= now - 60) {
            q.pop_front();
        }
        if q.len() as u32 >= self.per_minute {
            return Err(format!(
                "rate limit: at most {} calls a minute from one address",
                self.per_minute
            ));
        }
        q.push_back(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim(per_minute: u32, per_day: u32, probe: usize) -> Limiter {
        Limiter::new(LimitConfig {
            per_minute,
            per_day,
            probe_distinct_per_hour: probe,
            probe_block_s: 600,
        })
    }

    #[test]
    fn per_address_rate() {
        let l = IpLimiter::new(2);
        assert!(l.admit("1.2.3.4", 0).is_ok());
        assert!(l.admit("1.2.3.4", 1).is_ok());
        assert!(l.admit("1.2.3.4", 2).unwrap_err().contains("one address"));
        assert!(l.admit("5.6.7.8", 2).is_ok());
        assert!(l.admit("1.2.3.4", 61).is_ok());
        let off = IpLimiter::new(0);
        for t in 0..100 {
            assert!(off.admit("x", t).is_ok());
        }
    }

    #[test]
    fn per_minute_rate() {
        let l = lim(2, 100, 100);
        assert!(l.admit("t", "a", 0).is_ok());
        assert!(l.admit("t", "a", 1).is_ok());
        assert!(l
            .admit("t", "a", 2)
            .unwrap_err()
            .message
            .contains("a minute"));
        assert!(l.admit("other", "a", 2).is_ok(), "limits are per licence");
        assert!(l.admit("t", "a", 61).is_ok());
    }

    #[test]
    fn daily_quota_and_reset_and_seed() {
        let l = lim(100, 2, 100);
        assert!(l.admit("t", "a", 10).is_ok());
        assert!(l.admit("t", "a", 100).is_ok());
        assert!(l
            .admit("t", "a", 200)
            .unwrap_err()
            .message
            .contains("daily quota"));
        assert!(l.admit("t", "a", 86_400 + 5).is_ok(), "new UTC day");
        let l = lim(100, 2, 100);
        l.seed_daily("t", 50, 2);
        assert!(l.admit("t", "a", 60).is_err(), "quota survives a restart");
    }

    #[test]
    fn service_rate_only_no_quota_no_probe() {
        let l = lim(1, 1, 1);
        // Hundreds of distinct calls a day: no daily quota, no probe pause.
        for i in 0..500 {
            assert!(l.admit_service("svc", 1000, i * 10).is_ok());
        }
        // The service rate still applies.
        let l = lim(1, 1, 1);
        assert!(l.admit_service("svc", 2, 0).is_ok());
        assert!(l.admit_service("svc", 2, 1).is_ok());
        assert!(l
            .admit_service("svc", 2, 2)
            .unwrap_err()
            .message
            .contains("service rate"));
        assert!(l.admit_service("svc", 2, 61).is_ok());
        assert!(l.admit_service("svc", 0, 61).is_ok(), "0 = no limit");
    }

    #[test]
    fn probe_sweep_is_blocked_and_flagged() {
        let l = lim(1000, 1000, 3);
        for (i, h) in ["a", "b", "c"].iter().enumerate() {
            assert!(l.admit("t", h, i as i64).is_ok());
        }
        // Repeating a known request is fine.
        assert!(l.admit("t", "a", 4).is_ok());
        // A fourth distinct request trips the detector.
        let r = l.admit("t", "d", 5).unwrap_err();
        assert!(r.probe_alert);
        // Paused afterwards, even for a known request.
        let r = l.admit("t", "a", 6).unwrap_err();
        assert!(!r.probe_alert && r.message.contains("paused"));
        // After the pause and the hour window, work resumes.
        assert!(l.admit("t", "e", 5 + 3601).is_ok());
    }
}
