//! Fixed durable admission limits are refusals, never permissions to choose weaker accounting.
use super::source::{Bypass, Capture};
use agf_core::error::{DomainError, DomainResult};

pub(super) fn source(value: &Capture) -> DomainResult<()> {
    match value {
        Capture::Ready(_) => Ok(()),
        Capture::Bypass(Bypass::Cardinality) => Err(DomainError::PreconditionFailed(
            "Protected gateway configuration exceeds its complete source count; no model request was started".into(),
        )),
        Capture::Bypass(Bypass::EncodedBytes) => Err(DomainError::PreconditionFailed(
            "Protected gateway configuration exceeds its complete source byte bound; no model request was started"
                .into(),
        )),
    }
}

pub(super) fn request(session: &str, model: &str) -> DomainResult<()> {
    // wire::request maps the supported `auto` selector to an empty model before routing.
    if session.trim().is_empty() || session.len() > 256 || model.len() > 256 {
        return Err(DomainError::Validation(
            "Protected gateway session must contain 1 to 256 UTF-8 bytes and the model selector at most 256; no model request was started"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn components(count: usize) -> DomainResult<()> {
    if count == 0 || count > agf_aigw::gateway::MAX_CHAT_COMPONENTS {
        return Err(DomainError::Validation(
            "Protected gateway requires 1 to 8 eligible chat endpoints; no model request was started".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_complete_source_capacity_verdicts_refuse_dispatch() {
        for reason in [Bypass::Cardinality, Bypass::EncodedBytes] {
            assert!(matches!(source(&Capture::Bypass(reason)), Err(DomainError::PreconditionFailed(_))));
        }
    }

    #[test]
    fn request_bounds_count_utf8_bytes_and_reject_empty_scopes() -> DomainResult<()> {
        request(&"s".repeat(256), &"m".repeat(256))?;
        request(&"中".repeat(85), "owned-model")?;
        request("owned-session", "")?; // canonical auto selector remains supported.
        for session in [String::new(), " ".to_owned(), "s".repeat(257), "中".repeat(86)] {
            assert!(request(&session, "owned-model").is_err());
        }
        for model in ["m".repeat(257), "中".repeat(86)] {
            assert!(request("owned-session", &model).is_err());
        }
        Ok(())
    }

    #[test]
    fn component_limit_is_inclusive_and_never_selects_legacy() -> DomainResult<()> {
        components(1)?;
        components(8)?;
        assert!(components(0).is_err());
        assert!(components(9).is_err());
        Ok(())
    }
}
