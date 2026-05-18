//! Phase 3: re-ID auditor.
//!
//! Phase 0 gave us pseudonymization + reverse-mapping, Phase 2 grew a
//! session entity graph. But nothing today inspects what the model
//! *actually wrote back*. Two soft leakage vectors survive:
//!
//! 1. **Unknown pseudonym.** The reply contains a pseudonym-shaped token
//!    (e.g. `EMAIL_99`) that this pipeline never minted. Either the model
//!    hallucinated it from thin air, or — worse — a prior turn's reply
//!    seeded its attention with a pseudonym from a different session and
//!    it's now attempting to reference it. Either way, `reverse_map`
//!    silently passes the token through, and the user sees a fake-looking
//!    `EMAIL_99` in their reply.
//! 2. **Likely leak.** The reply contains a raw entity (email, path, IP,
//!    URL, UUID) that the pipeline did not mint a pseudonym for. That's
//!    the model writing a real-looking entity directly into its output
//!    instead of the pseudonym we gave it — the textbook re-identification
//!    failure mode.
//!
//! This module keeps the two types (`AuditFinding`, `AuditReason`,
//! `VeilPolicy`) plain and synchronous. The audit itself is performed by
//! `crate::pipeline::VeilPipeline::audit_reply` so it has access to both
//! the detector and the session table.

use crate::entities::EntityKind;

/// Why a span in the reply was flagged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditReason {
    /// A pseudonym-shaped token (`<PREFIX>_<digits>`) appears in the reply
    /// but this pipeline never minted it. The `kind` is recovered from the
    /// prefix — useful for downstream routing / policy.
    UnknownPseudonym { kind: EntityKind },
    /// A raw entity (email / path / IP / URL / UUID) appears in the reply
    /// that was *not* produced by reverse-mapping — i.e. the model wrote
    /// the real entity back instead of the pseudonym we substituted.
    /// Person is excluded: regex cannot reliably find names, and we don't
    /// run a learned detector on replies yet. That's Phase 4 work.
    LikelyLeaked { kind: EntityKind },
}

/// A single auditor hit. `text` is the offending literal, `start`/`end`
/// are byte offsets into the audited reply (so policies like `Redact` can
/// splice without re-scanning).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFinding {
    pub text: String,
    pub start: usize,
    pub end: usize,
    pub reason: AuditReason,
}

/// What to do when the auditor fires.
///
/// `Log` is the Phase-3 default: observability only, reply passes through.
/// `Redact` rewrites the offending spans in-place before returning.
/// `Reject` surfaces as `AuditVerdict::Reject` so the caller can raise an
/// error rather than hand the user a response that leaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnknownPseudonymPolicy {
    #[default]
    Log,
    Redact,
    Reject,
}

/// Policy bundle threaded through `ProviderClient::Veil`. Phase 3 only
/// gates `UnknownPseudonym`; `LikelyLeaked` is always logged and redaction
/// / rejection for it is left to a later phase (we want to watch the
/// false-positive rate of raw-entity detection on real traffic first).
#[derive(Debug, Clone, Copy, Default)]
pub struct VeilPolicy {
    pub on_unknown_pseudonym: UnknownPseudonymPolicy,
}

/// Sentinel inserted by `Redact`. Intentionally chosen to be visible to a
/// human reader so nobody mistakes it for real content.
pub const REDACTION_SENTINEL: &str = "[REDACTED]";

/// What `ProviderClient::Veil` should do given a batch of findings and the
/// current policy. Pure derivation — no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerdict {
    /// No findings; pass the reply through untouched.
    Pass,
    /// Findings exist but policy says log only; caller should still emit
    /// observability for `findings` and then pass the reply through.
    LogOnly,
    /// Rewrite the reply text by replacing every finding's span with
    /// `REDACTION_SENTINEL`. Findings are returned so the caller can log
    /// what was redacted.
    Redact,
    /// Caller must surface an error. The attached findings are the reason.
    Reject,
}

impl VeilPolicy {
    /// Decide what to do given the findings. Only the `on_unknown_pseudonym`
    /// axis escalates beyond logging today; `LikelyLeaked` findings always
    /// log even when unknown-pseudonym policy is `Log`.
    #[must_use]
    pub fn verdict(self, findings: &[AuditFinding]) -> AuditVerdict {
        if findings.is_empty() {
            return AuditVerdict::Pass;
        }
        let has_unknown = findings
            .iter()
            .any(|f| matches!(f.reason, AuditReason::UnknownPseudonym { .. }));
        if has_unknown {
            match self.on_unknown_pseudonym {
                UnknownPseudonymPolicy::Log => AuditVerdict::LogOnly,
                UnknownPseudonymPolicy::Redact => AuditVerdict::Redact,
                UnknownPseudonymPolicy::Reject => AuditVerdict::Reject,
            }
        } else {
            // Only LikelyLeaked findings — log for now, no escalation.
            AuditVerdict::LogOnly
        }
    }
}

/// Splice `REDACTION_SENTINEL` over every finding's byte span. Assumes
/// findings are sorted by `start` and non-overlapping (which is how
/// `audit_reply` produces them). Does not allocate when `findings` is empty.
#[must_use]
pub fn apply_redaction(reply: &str, findings: &[AuditFinding]) -> String {
    if findings.is_empty() {
        return reply.to_string();
    }
    let mut out = String::with_capacity(reply.len());
    let mut cursor = 0usize;
    for f in findings {
        if f.start < cursor {
            // Overlap or out-of-order — skip defensively. audit_reply
            // guarantees this won't happen, but returning a broken string
            // is worse than silently dropping the redaction.
            continue;
        }
        out.push_str(&reply[cursor..f.start]);
        out.push_str(REDACTION_SENTINEL);
        cursor = f.end;
    }
    out.push_str(&reply[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::{
        apply_redaction, AuditFinding, AuditReason, AuditVerdict, UnknownPseudonymPolicy,
        VeilPolicy, REDACTION_SENTINEL,
    };
    use crate::entities::EntityKind;

    #[test]
    fn empty_findings_yield_pass_regardless_of_policy() {
        for p in [
            UnknownPseudonymPolicy::Log,
            UnknownPseudonymPolicy::Redact,
            UnknownPseudonymPolicy::Reject,
        ] {
            let policy = VeilPolicy {
                on_unknown_pseudonym: p,
            };
            assert_eq!(policy.verdict(&[]), AuditVerdict::Pass);
        }
    }

    #[test]
    fn unknown_pseudonym_escalates_per_policy() {
        let f = AuditFinding {
            text: "EMAIL_99".to_string(),
            start: 0,
            end: 8,
            reason: AuditReason::UnknownPseudonym {
                kind: EntityKind::Email,
            },
        };
        assert_eq!(
            VeilPolicy {
                on_unknown_pseudonym: UnknownPseudonymPolicy::Log,
            }
            .verdict(std::slice::from_ref(&f)),
            AuditVerdict::LogOnly
        );
        assert_eq!(
            VeilPolicy {
                on_unknown_pseudonym: UnknownPseudonymPolicy::Redact,
            }
            .verdict(std::slice::from_ref(&f)),
            AuditVerdict::Redact
        );
        assert_eq!(
            VeilPolicy {
                on_unknown_pseudonym: UnknownPseudonymPolicy::Reject,
            }
            .verdict(std::slice::from_ref(&f)),
            AuditVerdict::Reject
        );
    }

    #[test]
    fn likely_leaked_only_logs_regardless_of_unknown_policy() {
        // `on_unknown_pseudonym` should NOT gate LikelyLeaked findings —
        // they always log. That's intentional: we want to watch the
        // false-positive rate of raw-entity detection before escalating.
        let f = AuditFinding {
            text: "a@b.com".to_string(),
            start: 0,
            end: 7,
            reason: AuditReason::LikelyLeaked {
                kind: EntityKind::Email,
            },
        };
        for p in [
            UnknownPseudonymPolicy::Log,
            UnknownPseudonymPolicy::Redact,
            UnknownPseudonymPolicy::Reject,
        ] {
            assert_eq!(
                VeilPolicy {
                    on_unknown_pseudonym: p,
                }
                .verdict(std::slice::from_ref(&f)),
                AuditVerdict::LogOnly,
                "LikelyLeaked-only should always log-only, policy={p:?}"
            );
        }
    }

    #[test]
    fn redact_replaces_spans_with_sentinel() {
        let reply = "saw EMAIL_99 today";
        let findings = vec![AuditFinding {
            text: "EMAIL_99".to_string(),
            start: 4,
            end: 12,
            reason: AuditReason::UnknownPseudonym {
                kind: EntityKind::Email,
            },
        }];
        let out = apply_redaction(reply, &findings);
        assert_eq!(out, format!("saw {REDACTION_SENTINEL} today"));
    }

    #[test]
    fn redact_handles_multiple_non_overlapping_findings() {
        let reply = "EMAIL_99 then PATH_42";
        let findings = vec![
            AuditFinding {
                text: "EMAIL_99".to_string(),
                start: 0,
                end: 8,
                reason: AuditReason::UnknownPseudonym {
                    kind: EntityKind::Email,
                },
            },
            AuditFinding {
                text: "PATH_42".to_string(),
                start: 14,
                end: 21,
                reason: AuditReason::UnknownPseudonym {
                    kind: EntityKind::Path,
                },
            },
        ];
        assert_eq!(
            apply_redaction(reply, &findings),
            format!("{REDACTION_SENTINEL} then {REDACTION_SENTINEL}")
        );
    }

    #[test]
    fn redact_is_identity_when_no_findings() {
        assert_eq!(apply_redaction("nothing here", &[]), "nothing here");
    }
}
