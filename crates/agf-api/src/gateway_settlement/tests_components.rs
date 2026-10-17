use super::{components::*, records::*, tests_fixture::*};
use agf_core::{
    enums::{LlmProvider, QuotaDimension},
    error::DomainResult,
    ids::Id,
};
use serde_json::json;

fn with_embedding() -> DomainResult<Fixture> {
    let mut f = fixture(864_100)?;
    let anchor = EmbeddingAnchor {
        usage_id: embedding_id(f.fact.origin.tenant, f.fact.attempt),
        endpoint: Id::new(),
        version: 1,
        provider: LlmProvider::OpenAi,
        model: "owned-embedding".into(),
        model_revision: "v1".into(),
        tokens: 5,
        cost: 5,
        price_per_1k: 1000,
    };
    let mut usage = f.pending.outcome.usage.clone().ok_or_else(super::store::missing)?;
    usage.id = anchor.usage_id;
    usage.endpoint_id = anchor.endpoint;
    usage.model = anchor.model.clone();
    usage.prompt_tokens = 2;
    usage.completion_tokens = 0;
    usage.cost_micro = 2;
    f.pending.outcome.components =
        vec![ComponentOutcome { usage_id: anchor.usage_id, evidence: Evidence::SentUsageKnown, usage: Some(usage) }];
    f.fact.charge.as_mut().ok_or_else(super::store::missing)?.embedding = Some(anchor);
    Ok(f)
}

#[test]
fn local_chat_reply_cannot_erase_paid_embedding_and_request_counts_only_once() -> DomainResult<()> {
    let mut f = with_embedding()?;
    let chat = f.pending.outcome.usage.as_mut().ok_or_else(super::store::missing)?;
    chat.cache_hit = true;
    chat.cost_micro = 0;
    f.pending.outcome.evidence = Evidence::LocalReply;
    let next = write(&f.fact, &f.pending, f.gateway, f.runtime, 864_101)?;
    assert_eq!(next.gateway.as_ref().map(|row| &row["totals"]), Some(&json!({"tokens":9,"cost":2})));
    let ledger = next.runtime.ok_or_else(super::store::missing)?;
    assert_eq!(counter(&ledger, &next.fact, QuotaDimension::Requests)?, 1);
    assert_eq!(counter(&ledger, &next.fact, QuotaDimension::Concurrency)?, 0);
    assert_eq!(usage_rows(&f.pending.outcome).count(), 2);
    Ok(())
}

#[test]
fn consumed_embedding_changes_authorization_reason_even_without_chat_dispatch() -> DomainResult<()> {
    let mut f = with_embedding()?;
    f.pending.outcome.evidence = Evidence::NotSent;
    f.pending.outcome.usage = None;
    let evidence = dispatch_evidence(Evidence::NotSent, &f.pending.outcome.components);
    let error = Err(agf_core::error::DomainError::Forbidden("private reason".into()));
    f.pending.outcome.rejection = super::rejection::known(&error, evidence)?;
    assert_eq!(f.pending.outcome.rejection.as_ref().map(|row| row.reason), Some(Reason::AuthorityChanged));
    let next = write(&f.fact, &f.pending, f.gateway, f.runtime, 864_101)?;
    assert_eq!(next.gateway.as_ref().map(|row| &row["totals"]), Some(&json!({"tokens":2,"cost":2})));
    let mut dishonest = f.pending;
    dishonest.outcome.rejection.as_mut().ok_or_else(super::store::missing)?.reason = Reason::Permission;
    assert!(super::reducer::validate(&f.fact, &dishonest).is_err());
    Ok(())
}

#[test]
fn unknown_embedding_uses_its_own_estimate_and_rejects_another_component_identity() -> DomainResult<()> {
    let mut f = with_embedding()?;
    f.pending.outcome.components[0].evidence = Evidence::SentUsageUnknown;
    f.pending.outcome.components[0].usage = None;
    let next = write(&f.fact, &f.pending, f.gateway.clone(), f.runtime.clone(), 864_101)?;
    assert_eq!(next.gateway.as_ref().map(|row| &row["totals"]), Some(&json!({"tokens":12,"cost":16})));
    let before = super::codec::hash(&(&f.gateway, &f.runtime))?;
    f.pending.outcome.components[0].usage_id = Id::new();
    assert!(
        super::reducer::reduce(&f.fact, &f.pending, Some(f.gateway.clone()), Some(f.runtime.clone()), 864_101).is_err()
    );
    assert_eq!(super::codec::hash(&(&f.gateway, &f.runtime))?, before);
    Ok(())
}

#[test]
fn canonical_service_providers_bridge_to_the_persisted_enum_without_changing_serde() -> DomainResult<()> {
    for provider in LlmProvider::all() {
        assert_eq!(service_provider(provider.as_str())?, provider);
        let persisted = serde_json::to_value(provider)?;
        assert_eq!(serde_json::from_value::<LlmProvider>(persisted)?, provider);
    }
    assert_eq!(LlmProvider::OpenAi.as_str(), "openai");
    assert_eq!(serde_json::to_value(LlmProvider::OpenAi)?, json!("open-ai"));
    assert_eq!(LlmProvider::CustomOpenAiCompat.as_str(), "custom-openai-compat");
    assert_eq!(serde_json::to_value(LlmProvider::CustomOpenAiCompat)?, json!("custom-open-ai-compat"));
    Ok(())
}

#[test]
fn provider_bridge_rejects_unknown_and_noncanonical_text_without_echoing_it() -> DomainResult<()> {
    for value in [
        "",
        "OPENAI",
        "open_ai",
        "open-ai",
        "custom-open-ai-compat",
        "custom_openai_compat",
        " openai",
        "openai ",
        "azure-open-ai",
        "owned-sensitive-provider-marker",
    ] {
        let error = service_provider(value).err().ok_or_else(super::store::missing)?;
        assert!(matches!(error, agf_core::error::DomainError::PreconditionFailed(_)));
        assert_eq!(error.to_string(), super::store::missing().to_string());
    }
    Ok(())
}

fn inert_embedding(f: &Fixture, provider: LlmProvider) -> DomainResult<crate::gateway_semantic_profile::LiveEmbedding> {
    use agf_aigw::provider::embedding::{EmbeddingClient, EmbeddingConfiguration, EmbeddingProfile};
    let configuration = EmbeddingConfiguration {
        tenant_id: f.fact.origin.tenant,
        endpoint_id: Id::new(),
        configuration_version: 1,
        provider: provider.as_str().into(),
        origin: "https://embedding.example.test".into(),
        model: "owned-embedding".into(),
        model_revision: "owned-v1".into(),
        dimensions: 8,
        send_dimensions: false,
        max_input_tokens: 5,
        input_micro_per_1k: 1000,
    };
    let profile =
        EmbeddingProfile::from_server_configuration(configuration.clone()).map_err(|_| super::store::missing())?;
    let client = EmbeddingClient::from_service_profile(profile, "synthetic-owned-unit-only")
        .map_err(|_| super::store::missing())?;
    Ok(crate::gateway_semantic_profile::LiveEmbedding {
        configuration,
        client,
        input: "owned-unit-input".into(),
        input_tokens_bound: 5,
        estimated_cost_micro: 5,
    })
}

#[test]
fn captured_anchor_and_paid_invalid_vector_keep_the_same_usage_identity_after_serde() -> DomainResult<()> {
    use agf_aigw::provider::embedding::{
        EmbeddingAttempt, EmbeddingDispatch, EmbeddingFailure, EmbeddingOutcome, EmbeddingReservation, EmbeddingUsage,
    };
    for provider in [LlmProvider::OpenAi, LlmProvider::CustomOpenAiCompat] {
        let mut f = fixture(864_100)?;
        let authenticated = AuthenticatedAttempt {
            id: f.fact.attempt,
            origin: f.fact.origin.clone(),
            submitted_at: f.fact.submitted_at,
            execute_before: f.fact.execute_before,
        };
        let live = inert_embedding(&f, provider)?;
        let anchor = EmbeddingAnchor::capture(&authenticated, &live)?;
        let encoded = serde_json::to_value(&anchor)?;
        assert_eq!(encoded["provider"], serde_json::to_value(provider)?);
        let restored: EmbeddingAnchor = serde_json::from_value(encoded)?;
        assert_eq!(super::codec::hash(&restored)?, super::codec::hash(&anchor)?);
        assert_eq!(restored.usage_id, embedding_id(f.fact.origin.tenant, f.fact.attempt));
        assert_ne!(restored.usage_id, f.fact.usage_id);
        f.fact.charge.as_mut().ok_or_else(super::store::missing)?.embedding = Some(restored.clone());
        let mut attempt = EmbeddingAttempt {
            tenant_id: f.fact.origin.tenant,
            endpoint_id: restored.endpoint,
            configuration_version: restored.version,
            provider: provider.as_str().into(),
            model: restored.model.clone(),
            model_revision: restored.model_revision.clone(),
            dispatch: EmbeddingDispatch::ResponseReceived,
            outcome: EmbeddingOutcome::Failed(EmbeddingFailure::InvalidVector),
            usage: Some(EmbeddingUsage { prompt_tokens: 2, total_tokens: 2 }),
            configured_cost_micro: Some(2),
            reservation: EmbeddingReservation { reserved_tokens: 5, reserved_cost_micro: 5 },
        };
        let known = restored.known(&f.fact, &attempt, 1)?;
        assert!(matches!(known.evidence, Evidence::SentUsageKnown));
        let usage = known.usage.as_ref().ok_or_else(super::store::missing)?;
        assert_eq!((usage.id, usage.provider, usage.cost_micro), (restored.usage_id, provider, 2));
        let persisted_usage: agf_core::model::UsageRecord = serde_json::from_value(serde_json::to_value(usage)?)?;
        assert_eq!(super::codec::hash(&persisted_usage)?, super::codec::hash(usage)?);
        f.pending.outcome.components = vec![known];
        validate(&f.fact, &f.pending)?;
        let next = write(&f.fact, &f.pending, f.gateway.clone(), f.runtime.clone(), 864_101)?;
        assert_eq!(next.gateway.as_ref().map(|row| &row["totals"]), Some(&json!({"tokens":9,"cost":13})));
        assert_eq!(usage_rows(&f.pending.outcome).count(), 2);
        let before = super::codec::hash(&(&f.fact, &f.pending, &f.gateway, &f.runtime))?;
        for wrong in ["anthropic", "open-ai", "owned-sensitive-provider-marker"] {
            attempt.provider = wrong.into();
            assert!(restored.known(&f.fact, &attempt, 1).is_err());
            assert_eq!(super::codec::hash(&(&f.fact, &f.pending, &f.gateway, &f.runtime))?, before);
        }
    }
    Ok(())
}
