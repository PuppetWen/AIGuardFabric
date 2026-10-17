//! Fixed semantic classification of actual verdicts; never persist raw provider errors.
use super::{records::*, store};
use agf_aigw::gateway::GatewayResponse;
use agf_core::error::{DomainError, DomainResult};

pub(super) fn safe_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id != "00000000-0000-0000-0000-000000000000"
        && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

pub(super) fn known(result: &DomainResult<GatewayResponse>, evidence: Evidence) -> DomainResult<Option<Rejection>> {
    let rejection = match result {
        Ok(response) => {
            let limit = response.screening.response_rules.iter().any(|id| id == "gateway-output-limit");
            if !limit && !response.screening.response_blocked {
                return Ok(None);
            }
            if response.screening.response_rules.len() > 32
                || response.screening.response_rules.iter().any(|id| !safe_rule_id(id))
            {
                return Err(store::missing());
            }
            Rejection {
                stage: Stage::ResponseScreen,
                reason: if limit { Reason::OutputLimit } else { Reason::Denied },
                rule_ids: response.screening.response_rules.clone(),
            }
        }
        Err(error) => from_error(error, evidence),
    };
    Ok(Some(rejection))
}

pub(super) fn from_error(error: &DomainError, evidence: Evidence) -> Rejection {
    let (stage, reason) = match error {
        DomainError::Forbidden(_) | DomainError::Unauthenticated(_) | DomainError::TenantViolation { .. } => (
            Stage::Authorization,
            if evidence == Evidence::NotSent { Reason::Permission } else { Reason::AuthorityChanged },
        ),
        DomainError::Conflict(_) | DomainError::PreconditionFailed(_) => (Stage::Execution, Reason::SourceChanged),
        DomainError::Timeout(_) => (Stage::Execution, Reason::Timeout),
        DomainError::QuotaExceeded { .. } | DomainError::RateLimited(_) => (Stage::Quota, Reason::Quota),
        DomainError::PolicyDenied { .. } => (Stage::RequestScreen, Reason::Denied),
        DomainError::Validation(_) | DomainError::Parse(_) => (Stage::Wire, Reason::InvalidInput),
        DomainError::Config(_) => (Stage::Execution, Reason::Configuration),
        DomainError::DependencyUnavailable { dependency, .. } if dependency == "model-provider" => {
            (Stage::Transport, Reason::Provider)
        }
        _ => (Stage::Execution, Reason::Unavailable),
    };
    let rule_ids = match error {
        DomainError::PolicyDenied { policy, .. } if safe_rule_id(policy) => vec![policy.clone()],
        _ => Vec::new(),
    };
    Rejection { stage, reason, rule_ids }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn authority_conflict_and_original_timeout_never_claim_provider_failure() {
        let cases = [
            (DomainError::Forbidden("private source".into()), "authorization", "permission"),
            (DomainError::Conflict("private source".into()), "execution", "source-changed"),
            (DomainError::Timeout("private source".into()), "execution", "timeout"),
        ];
        for (error, stage, reason) in cases {
            let value = json!(from_error(&error, Evidence::NotSent));
            assert_eq!(value["stage"], stage);
            assert_eq!(value["reason"], reason);
            assert!(!value.to_string().contains("private source"));
        }
    }
    #[test]
    fn revoked_authority_after_consumption_does_not_erase_actual_usage_evidence() {
        let value = json!(from_error(&DomainError::Forbidden("synthetic".into()), Evidence::SentUsageKnown));
        assert_eq!(value["stage"], "authorization");
        assert_eq!(value["reason"], "authority-changed");
    }
    #[test]
    fn real_keyword_rule_names_are_preserved_but_notes_are_never_rule_ids() {
        let value = json!(from_error(
            &DomainError::PolicyDenied {
                policy: "kw.jailbreak".into(),
                action: "deny".into(),
                reason: "private text".into()
            },
            Evidence::NotSent,
        ));
        assert_eq!(value["rule_ids"], json!(["kw.jailbreak"]));
        assert!(!value.to_string().contains("private text"));
        assert!(!safe_rule_id("raw source with spaces"));
        assert!(!safe_rule_id(""));
        assert!(!safe_rule_id(&"x".repeat(129)));
    }
}
