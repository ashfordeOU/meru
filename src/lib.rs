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
//! planner, `cause` (episode cause attribution, [`cause`]) ([`methods`]), `calibrate`
//! (general parametric calibration of a simulator against telemetry, [`calibrate`]) and
//! `lunar-assist` (long-validity lunar GNSS assistance packages, [`lunar_assist`]) and
//! `victim-actor` (was a vessel's AIS position interfered with, or its own reports manipulated,
//! [`victim_actor`]), `rtk-quality` (RTK correction-service quality across many monitors,
//! [`rtk_quality`]), `flight-integrity` (a signed per-flight positioning-integrity verdict for
//! a drone flight, [`flight_integrity`]), `parametric-trigger` (a neutral oracle for a
//! parametric GNSS-outage trigger, [`parametric_oracle`]), `policy-wording` (which facts of a
//! synthetic wording the signed PNT evidence answers, [`policy_wording`]), `spaceweather` (a
//! space-weather advisory per location and positioning service from live ionosphere inputs and
//! per-region thresholds, [`spaceweather`]), `perception-eval` (an evaluation of a
//! perception-aided positioning system's outputs, landmark identifications and integrity claims
//! against tester truth, [`perception_eval`]), `feeder-trust` (how far each feeder of a
//! crowd-sourced monitoring network can be trusted, [`feeder_trust`]) and `archive-seal` (a
//! signed, chained Merkle seal over a period of an evidence archive, [`archive_seal`]).
//! Verdicts: [`verdict`]. Caller authorisation: [`auth`]. Anti-extraction: query-pattern
//! audit ([`audit`]), keyed fingerprints, canaries and the ownership test ([`fingerprint`]),
//! the red-team harness ([`redteam`]). Deployment profiles (public, arksa-internal,
//! sovereign-contracted) and the service credential: [`profile`], [`auth`].
//!
//! X3 rule: this repository is the Core home. The `kshana-pro` overlay must never name or
//! contain Core code; a Pro client reaches these methods only over the network, against a
//! configurable endpoint, never by linking this crate.

pub mod archive_seal;
pub mod archives;
pub mod audit;
pub mod auth;
pub mod base_audit;
pub mod calibrate;
pub mod cause;
pub mod crl;
pub mod delay_cal;
pub mod feeder_trust;
pub mod fingerprint;
pub mod flight_integrity;
pub mod gnss_leo;
pub mod keys;
pub mod limits;
pub mod lunar_assist;
pub mod lunar_registry;
pub mod meter;
pub mod methods;
pub mod ntrip_qos;
pub mod outputs;
pub mod parametric_oracle;
pub mod perception_eval;
pub mod policy_wording;
pub mod portal;
pub mod profile;
pub mod redteam;
pub mod rtk_quality;
pub mod server;
pub mod signer;
pub mod spaceweather;
pub mod timing_correlation;
pub mod tlog;
pub mod tlog_tsa;
pub mod verdict;
pub mod victim_actor;
pub mod vision_claims;

pub use archive_seal::{seal_verdict, SealRequest};
pub use calibrate::{calibrate_verdict, CalibrateRequest};
pub use cause::CauseRequest;
pub use feeder_trust::{feeder_verdict, FeederRequest};
pub use flight_integrity::{flight_verdict, FlightRequest};
pub use lunar_assist::{lunar_assist_verdict, AssistRequest};
pub use methods::victim_actor_verdict;
pub use methods::{
    cause_verdict, selfcal_verdict, survey_verdict, Limits, SelfCalRequest, Signing, SurveyRequest,
};
pub use parametric_oracle::{trigger_verdict, TriggerRequest};
pub use perception_eval::{perception_verdict, PerceptionRequest};
pub use policy_wording::{wording_verdict, WordingRequest};
pub use rtk_quality::{rtk_quality_verdict, RtkQualityRequest};
pub use spaceweather::{spaceweather_verdict, SpaceWxRequest};
pub use verdict::{verify, SignedVerdict, SERVICE};
pub use victim_actor::VictimActorRequest;
