use super::*;
use agf_core::{rbac::SubjectKind, user::User};
use axum::http::{HeaderMap, HeaderValue, header};

async fn fixture() -> DomainResult<(AppState, Submission)> {
    let env = [
        ("AGF_ENV", "test"),
        ("AGF_MOCK_MODE", "1"),
        ("AGF_JWT_SECRET", "owned-rule-publication-secret-at-least-32-bytes"),
        ("AGF_MASTER_KEY_BASE64", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
        ("AGF_PROJECT_ROOT", "."),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    let mut config = agf_core::config::from_env_map(&env)?;
    config.data_dir = std::path::PathBuf::from("./target/test-data")
        .join(format!("owned-rule-publication-{}", Id::new()))
        .to_string_lossy()
        .into_owned();
    let state = AppState::offline(config)?;
    let tenant = TenantId::default_tenant();
    let mut user = User::new_local(tenant, "owned-rule-editor", "owned-rule@local.test");
    user.must_change_password = false;
    state.auth_backend.save_account(&user, None, &["tenant-admin".into()]).await?;
    let issued = state.auth.issue_for_user(&user, tenant, vec!["tenant-admin".into()])?;
    let principal = crate::Principal {
        subject_id: Some(user.id),
        subject_kind: SubjectKind::User,
        tenant,
        identity_tenant: tenant,
        agent_id: None,
        roles: vec!["tenant-admin".into()],
        scopes: Vec::new(),
        superadmin: false,
        must_change_password: false,
        must_setup_mfa: false,
        session_id: Some(issued.session_id),
        source_ip: None,
        user_agent: None,
        department: None,
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", issued.access_token))
            .map_err(|error| DomainError::Internal(error.to_string()))?,
    );
    let submission = Submission::capture(&state, &principal, &headers, Grant::Rules)?;
    Ok((state, submission))
}
fn definition() -> DomainResult<RuleDefinition> {
    serde_yaml::from_str("key: OWNED-ATOMIC\nname: Owned atomic\ndomain: prompt-attack\nseverity: high\nkind: keyword\ntarget: prompt\naction: deny\ndetection:\n  type: keyword\n  any: [ownedAtomicMarker]\nsamples:\n  positive: [ownedAtomicMarker]\n  negative: [clean]\n")
        .map_err(|error|DomainError::Validation(error.to_string()))
}
#[tokio::test]
async fn failed_audit_cannot_publish_a_rule_or_its_revision() -> DomainResult<()> {
    let (state, submission) = fixture().await?;
    let rule = definition()?;
    change(&state, &submission, &rule.key, |_| Ok(rule.clone())).await?;
    let tenant = submission.principal.tenant;
    let before = serde_json::to_value(registry(&state, tenant).await?)?;
    let mut last = audit(&submission, &rule);
    last.sequence = i64::MAX;
    last.seal();
    state.store.hydrate_audit(&last)?;
    let chain = serde_json::to_value(state.store.audit_chain_durable(tenant, 0, i64::MAX).await?)?;
    let failed = change(&state, &submission, &rule.key, |previous| {
        let mut current = previous.ok_or_else(|| DomainError::Internal("Rule missing".into()))?;
        current.enabled = false;
        Ok(current)
    })
    .await;
    assert!(failed.is_err());
    assert_eq!(serde_json::to_value(registry(&state, tenant).await?)?, before);
    assert_eq!(serde_json::to_value(state.store.audit_chain_durable(tenant, 0, i64::MAX).await?)?, chain);
    assert!(get(&state, tenant, &rule.key).await?.enabled);
    Ok(())
}
