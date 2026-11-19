// PROPRIETARY — Kshana Core (meru). Trade secret. Never shipped to customers; runs only in
// Ashforde's hosted Kshana service and vetted Sovereign deployments. See NOTICE.
//
//! # meru — Kshana Core, the hosted verdict-only service
//!
//! The crown-jewel PNT methods run here, on Ashforde's servers, and never leave as code. A
//! caller sends inputs with a valid Kshana licence; the method runs server-side; only a
//! **signed verdict** (the outcome, with an Ed25519 signature) comes back. This is the
//! strongest protection in the Open / Pro / Core model: the method is a trade secret that
//! never reaches a customer binary, so it cannot be extracted or reverse-engineered.
//!
//! Hosted methods: F1 self-calibrating simulator loop, F2 integrity-driven ASF survey
//! planner ([`methods`]). Verdicts: [`verdict`]. Caller authorisation: [`auth`].
//!
//! X3 rule: this repository is the Core home. The `kshana-pro` overlay must never name or
//! contain Core code; a Pro client reaches these methods only over the network, against a
//! configurable endpoint, never by linking this crate.

pub mod auth;
pub mod limits;
pub mod meter;
pub mod methods;
pub mod outputs;
pub mod server;
pub mod signer;
pub mod verdict;

pub use methods::{
    selfcal_verdict, survey_verdict, Limits, SelfCalRequest, Signing, SurveyRequest,
};
pub use verdict::{verify, SignedVerdict, SERVICE};
