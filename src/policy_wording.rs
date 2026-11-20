// PROPRIETARY — Kshana Core (meru). Trade secret. See NOTICE.
//
//! The `policy-wording` method: which factual questions in a **synthetic** policy wording does
//! the PNT evidence answer, and how (research backlog E28, B2804)?
//!
//! Cover for GNSS disruption turns on clauses such as a malicious-electronic-means exclusion, a
//! war exclusion against cyber cover, or a cyber buy-back. Each clause rests on facts (was there
//! interference; was it spoofing; was the vessel's own track falsified; was there an intrusion;
//! who acted and why). Some of these the PNT evidence can answer; some it never can. This method
//! takes a wording **in structured, synthetic form only** (clause identifiers, a kind, and the
//! facts each clause names from a fixed vocabulary; never real policy text) and signed verdicts
//! this service issued (`cause`, `victim-actor`, `parametric-trigger`), checks each verdict's
//! signature, and answers every fact `supported`, `not_supported` or `not_determinable`, with the
//! verdict it rests on. Per clause it says whether all the facts it names are supported, whether
//! one is not supported, or whether one cannot be determined from PNT evidence.
//!
//! It never says whether a clause applies, whether cover responds, or what a wording means: not
//! insurance advice, not legal advice, not a coverage position. Requests whose wording is not
//! marked synthetic are refused. Ashforde has no insurer partners. Evidence class MODELLED.

use crate::verdict::{verify, SignedVerdict};
use serde::Deserialize;
use serde_json::{json, Value};

/// Method identifier written into every outcome. A change to any rule is a new version.
pub const METHOD_VERSION: &str = "policy-wording/1";

/// What every verdict says about itself.
pub const STATEMENT: &str = "Maps signed PNT evidence to the factual questions a synthetic \
wording names. Not insurance or legal advice, not an interpretation of any wording and not a \
coverage position: whether a clause applies is for the parties and their advisers.";

/// Lowest stated confidence of a `cause` or `victim-actor` verdict that supports a fact.
const MIN_CONFIDENCE: f64 = 0.6;

/// The fact vocabulary, version 1: identifier and what it asks.
pub const FACTS: &[(&str, &str)] = &[
    (
        "gnss_interference_occurred",
        "external GNSS interference (jamming or spoofing) affected the platform or the area",
    ),
    ("gnss_jamming_indicated", "the evidence indicates jamming"),
    ("gnss_spoofing_indicated", "the evidence indicates spoofing"),
    (
        "own_track_falsified",
        "the platform's own reported track was falsified",
    ),
    (
        "equipment_fault_indicated",
        "the evidence indicates an equipment fault rather than interference",
    ),
    (
        "regional_interference_reported",
        "regional monitoring reported interference in the area at the time",
    ),
    (
        "parametric_trigger_fired",
        "a parametric outage trigger fired under its stated definition",
    ),
    (
        "intent_or_actor_identity",
        "who caused the event and with what intent (malice, a state actor, an act of war)",
    ),
    (
        "cyber_intrusion",
        "a computer system was accessed or altered without authorisation",
    ),
];

// ------------------------------------------------------------------------------------------
// Request
// ------------------------------------------------------------------------------------------

/// What a clause is, for the caller's own bookkeeping (echoed).
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClauseKind {
    Cover,
    Exclusion,
    Buyback,
    Condition,
}

/// One clause of the synthetic wording: an identifier, its kind and the facts it names.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Clause {
    pub id: String,
    pub kind: ClauseKind,
    /// Facts from [`FACTS`]. May be left out when `model` names a model clause: its facts are used.
    #[serde(default)]
    pub facts: Vec<String>,
    /// A public model clause this synthetic clause stands for ([`MODEL_CLAUSES`] id).
    #[serde(default)]
    pub model: Option<String>,
}

/// A public model clause, referenced by name and number only (its text is not reproduced), with
/// the facts of [`FACTS`] that, on our reading, the clause's operative questions turn on. The
/// mapping is ours and is to confirm against the clause text; it is not an interpretation of the
/// clause and says nothing about whether it applies.
pub struct ModelClause {
    pub id: &'static str,
    pub name: &'static str,
    pub number: &'static str,
    pub publisher: &'static str,
    pub date: &'static str,
    /// The named question, as the backlog states it.
    pub question: &'static str,
    pub facts: &'static [&'static str],
}

/// The model clauses version 1 knows (B2804's four named questions).
pub const MODEL_CLAUSES: &[ModelClause] = &[
    ModelClause {
        id: "LMA5403",
        name: "Marine Cyber Endorsement",
        number: "LMA5403",
        publisher: "Lloyd's Market Association",
        date: "2019 (to confirm)",
        question: "malicious electronic means",
        facts: &[
            "gnss_interference_occurred",
            "gnss_spoofing_indicated",
            "cyber_intrusion",
            "intent_or_actor_identity",
        ],
    },
    ModelClause {
        id: "CL380",
        name: "Institute Cyber Attack Exclusion Clause",
        number: "CL380",
        publisher: "Institute clauses (publisher to confirm)",
        date: "10/11/2003 (to confirm)",
        question: "Clause 380: a computer system or software used as a means of inflicting harm",
        facts: &[
            "gnss_spoofing_indicated",
            "cyber_intrusion",
            "intent_or_actor_identity",
        ],
    },
    ModelClause {
        id: "cyber-buy-back",
        name: "Cyber buy-back (write-back of cover for non-malicious cyber events)",
        number: "none: a market practice, not one numbered clause (to confirm which endorsement)",
        publisher: "market practice (to confirm)",
        date: "to confirm",
        question: "cyber buy-back trigger",
        facts: &[
            "cyber_intrusion",
            "equipment_fault_indicated",
            "intent_or_actor_identity",
        ],
    },
    ModelClause {
        id: "LMA5564-LMA5567",
        name: "War, cyber war and cyber operation exclusion clauses",
        number: "LMA5564, LMA5565, LMA5566, LMA5567",
        publisher: "Lloyd's Market Association",
        date: "2021 (to confirm)",
        question: "war versus cyber boundary",
        facts: &[
            "gnss_interference_occurred",
            "regional_interference_reported",
            "intent_or_actor_identity",
        ],
    },
];

fn model(id: &str) -> Option<&'static ModelClause> {
    MODEL_CLAUSES.iter().find(|m| m.id == id)
}

impl Clause {
    /// The facts the clause names: its own, else its model clause's.
    fn effective_facts(&self) -> Vec<String> {
        if !self.facts.is_empty() {
            return self.facts.clone();
        }
        self.model
            .as_deref()
            .and_then(model)
            .map(|m| m.facts.iter().map(|f| f.to_string()).collect())
            .unwrap_or_default()
    }
}

/// A synthetic wording, in structured form only.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wording {
    pub id: String,
    /// Must be `true`: only synthetic (illustrative) wordings are accepted.
    pub synthetic: bool,
    pub clauses: Vec<Clause>,
}

/// Request for the `policy-wording` method.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WordingRequest {
    pub wording: Wording,
    /// Verdicts this service issued (`cause`, `victim-actor`, `parametric-trigger`).
    pub evidence: Vec<SignedVerdict>,
}

/// Request limits.
#[derive(Clone, Debug)]
pub struct WordingLimits {
    pub max_clauses: usize,
    pub max_facts_per_clause: usize,
    pub max_evidence: usize,
}

impl Default for WordingLimits {
    fn default() -> Self {
        WordingLimits {
            max_clauses: 64,
            max_facts_per_clause: 9,
            max_evidence: 16,
        }
    }
}

fn ident_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

// ------------------------------------------------------------------------------------------
// Facts from verdicts
// ------------------------------------------------------------------------------------------

/// One answer: `supported`, `not_supported` or `not_determinable`, and the basis.
#[derive(Clone, Debug)]
struct Answer {
    state: &'static str,
    basis: String,
    /// The SHA-256 of the verdict it rests on, when one.
    from: Option<String>,
}

fn nd(why: &str) -> Answer {
    Answer {
        state: "not_determinable",
        basis: why.into(),
        from: None,
    }
}

fn conf(v: &Value) -> f64 {
    v["confidence"].as_f64().unwrap_or(0.0)
}

/// What one verdict says about one fact (`None`: nothing).
fn from_verdict(fact: &str, v: &SignedVerdict) -> Option<Answer> {
    let o = &v.verdict;
    let at = |state: &'static str, basis: String| {
        Some(Answer {
            state,
            basis,
            from: Some(v.verdict_sha256.clone()),
        })
    };
    match v.method.as_str() {
        "cause" => {
            let class = o["classification"].as_str().unwrap_or("");
            let c = conf(o);
            if class == "insufficient_evidence" || c < MIN_CONFIDENCE {
                return None;
            }
            let yes = match fact {
                "gnss_interference_occurred" => {
                    matches!(class, "external_interference_jamming" | "external_spoofing")
                }
                "gnss_jamming_indicated" => class == "external_interference_jamming",
                "gnss_spoofing_indicated" => class == "external_spoofing",
                "own_track_falsified" => class == "self_reported_track_falsification",
                "equipment_fault_indicated" => class == "equipment_fault",
                _ => return None,
            };
            at(
                if yes { "supported" } else { "not_supported" },
                format!("cause verdict: {class} at confidence {c}"),
            )
        }
        "victim-actor" => {
            let class = o["classification"].as_str().unwrap_or("");
            let c = conf(o);
            let decided = class != "indeterminate" && c >= MIN_CONFIDENCE;
            match fact {
                "gnss_interference_occurred" if decided => at(
                    if class == "victim" { "supported" } else { "not_supported" },
                    format!("victim-actor verdict: {class} at confidence {c}"),
                ),
                "own_track_falsified" if decided => at(
                    if class == "actor" { "supported" } else { "not_supported" },
                    format!("victim-actor verdict: {class} at confidence {c}"),
                ),
                "regional_interference_reported" => {
                    match o["questions"]["regional_interference"].as_str() {
                        Some("reported") => at(
                            "supported",
                            "victim-actor verdict: regional monitoring reported interference".into(),
                        ),
                        Some("not_reported") => at(
                            "not_supported",
                            "victim-actor verdict: regional monitoring covered the window and reported none".into(),
                        ),
                        _ => None,
                    }
                }
                _ => None,
            }
        }
        "parametric-trigger" => match (fact, o["state"].as_str()) {
            ("parametric_trigger_fired", Some("fired")) => {
                at("supported", "parametric-trigger verdict: fired".into())
            }
            ("parametric_trigger_fired", Some("not_fired")) => {
                at("not_supported", "parametric-trigger verdict: not fired".into())
            }
            ("gnss_interference_occurred", Some("fired")) => at(
                "supported",
                "parametric-trigger verdict: stations in the area were degraded together (cause not separated)".into(),
            ),
            _ => None,
        },
        _ => None,
    }
}

/// Combine what every verdict says about one fact. Agreement keeps the state; disagreement is
/// `not_determinable`, with both bases.
fn answer(fact: &str, ev: &[SignedVerdict]) -> Answer {
    match fact {
        "intent_or_actor_identity" => {
            return nd("PNT evidence does not establish who acted or why; the methods do not assess intent or attribute an actor")
        }
        "cyber_intrusion" => {
            return nd("PNT evidence does not establish whether a computer system was accessed or altered")
        }
        _ => {}
    }
    let found: Vec<Answer> = ev.iter().filter_map(|v| from_verdict(fact, v)).collect();
    match found.as_slice() {
        [] => nd("no verdict supplied answers this fact"),
        [a, rest @ ..] if rest.iter().all(|b| b.state == a.state) => a.clone(),
        _ => Answer {
            state: "not_determinable",
            basis: format!(
                "the verdicts disagree: {}",
                found
                    .iter()
                    .map(|a| a.basis.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            from: None,
        },
    }
}

// ------------------------------------------------------------------------------------------
// The method
// ------------------------------------------------------------------------------------------

/// Run the method; the raw (unsigned) outcome. `service_key` is this service's verdict public
/// key (hex): every evidence verdict must verify against it.
pub fn analyse(r: &WordingRequest, l: &WordingLimits, service_key: &str) -> Result<Value, String> {
    let w = &r.wording;
    if !w.synthetic {
        return Err("only synthetic wordings are accepted (structured clause identifiers and facts, never real policy text): set wording.synthetic to true".into());
    }
    if !ident_ok(&w.id) {
        return Err("wording.id: 1 to 64 characters of A-Z a-z 0-9 . _ -".into());
    }
    if w.clauses.is_empty() || w.clauses.len() > l.max_clauses {
        return Err(format!("1 to {} clauses", l.max_clauses));
    }
    if r.evidence.len() > l.max_evidence {
        return Err(format!("at most {} evidence verdicts", l.max_evidence));
    }
    let mut ids = std::collections::BTreeSet::new();
    for c in &w.clauses {
        if !ident_ok(&c.id) || !ids.insert(c.id.as_str()) {
            return Err(format!(
                "clause '{}': identifiers are 1 to 64 characters of A-Z a-z 0-9 . _ - and unique",
                c.id
            ));
        }
        if let Some(m) = &c.model {
            if model(m).is_none() {
                return Err(format!(
                    "clause '{}': unknown model clause '{m}' (known: {})",
                    c.id,
                    MODEL_CLAUSES
                        .iter()
                        .map(|m| m.id)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        let facts = c.effective_facts();
        if facts.is_empty() || facts.len() > l.max_facts_per_clause {
            return Err(format!(
                "clause '{}': 1 to {} facts",
                c.id, l.max_facts_per_clause
            ));
        }
        for f in &facts {
            if !FACTS.iter().any(|(k, _)| k == f) {
                return Err(format!("clause '{}': unknown fact '{f}'", c.id));
            }
        }
    }
    for (i, v) in r.evidence.iter().enumerate() {
        let p = verify(v, service_key);
        if !p.is_empty() {
            return Err(format!(
                "evidence[{i}]: not a verdict of this service: {}",
                p.join("; ")
            ));
        }
        if !matches!(
            v.method.as_str(),
            "cause" | "victim-actor" | "parametric-trigger"
        ) {
            return Err(format!(
                "evidence[{i}]: a '{}' verdict is not evidence for this method (cause, victim-actor, parametric-trigger)",
                v.method
            ));
        }
    }
    let mut facts = serde_json::Map::new();
    let mut clauses = vec![];
    for c in &w.clauses {
        let mut n = (0usize, 0usize, 0usize);
        let cfacts = c.effective_facts();
        for f in &cfacts {
            let a = answer(f, &r.evidence);
            match a.state {
                "supported" => n.0 += 1,
                "not_supported" => n.1 += 1,
                _ => n.2 += 1,
            }
            facts.entry(f.clone()).or_insert_with(|| {
                json!({
                    "question": FACTS.iter().find(|(k, _)| k == f).map(|x| x.1),
                    "answer": a.state,
                    "basis": a.basis,
                    "verdict_sha256": a.from,
                })
            });
        }
        let reading = if n.1 > 0 {
            "at least one fact the clause names is not supported by the evidence"
        } else if n.2 > 0 {
            "at least one fact the clause names cannot be determined from the PNT evidence supplied"
        } else {
            "every fact the clause names is supported by the evidence"
        };
        clauses.push(json!({
            "id": c.id,
            "kind": c.kind_name(),
            "facts": cfacts,
            "model": c.model.as_deref().and_then(model).map(|m| json!({
                "id": m.id,
                "name": m.name,
                "number": m.number,
                "publisher": m.publisher,
                "date": m.date,
                "question": m.question,
                "status": "referenced by name and number only; the clause text is not reproduced; the mapping to facts is our reading, to confirm against the clause text",
            })),
            "supported": n.0,
            "not_supported": n.1,
            "not_determinable": n.2,
            "evidence_reading": reading,
        }));
    }
    Ok(json!({
        "method_version": METHOD_VERSION,
        "wording": {"id": w.id, "synthetic": true},
        "evidence": r.evidence.iter().map(|v| json!({"method": v.method, "verdict_sha256": v.verdict_sha256, "utc": v.utc})).collect::<Vec<_>>(),
        "facts": facts,
        "clauses": clauses,
        "statement": STATEMENT,
    }))
}

impl Clause {
    fn kind_name(&self) -> &'static str {
        match self.kind {
            ClauseKind::Cover => "cover",
            ClauseKind::Exclusion => "exclusion",
            ClauseKind::Buyback => "buyback",
            ClauseKind::Condition => "condition",
        }
    }
}

/// Run the `policy-wording` method and return a signed verdict. Not fingerprinted: answers in
/// three states and digests.
pub fn wording_verdict(
    req: &WordingRequest,
    s: &crate::methods::Signing,
    limits: &WordingLimits,
    utc: &str,
) -> Result<SignedVerdict, String> {
    let pk = s
        .signer
        .public_key()
        .map_err(|e| format!("service key unavailable: {e}"))?;
    let v = analyse(req, limits, &hex::encode(pk))?;
    crate::methods::finish("policy-wording", v, s, utc)
}

#[cfg(test)]
#[path = "policy_wording_tests.rs"]
mod tests;
