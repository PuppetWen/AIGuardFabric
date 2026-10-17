use super::*;
use agf_core::{
    asset::ChangeKind,
    audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget},
    enums::AssetKind,
};

fn log(tenant: TenantId) -> AuditLog {
    crate::AppState::audit_entry(
        tenant,
        AuditAction::Update,
        AuditOutcome::Success,
        AuditActor::system("owned-skill-publication"),
        AuditTarget::new("asset", None, None),
        "test",
    )
}
fn fixture() -> DomainResult<(ApiStore, Asset, Identity)> {
    let store = ApiStore::offline();
    let asset = Asset::new(TenantId::default_tenant(), AssetKind::Skill, "Owned Skill", "owned-skill");
    store.lock()?.assets.insert((asset.tenant_id, asset.id), asset.clone());
    let identity = Identity { tenant: asset.tenant_id, key: None, agent: None };
    Ok((store, asset, identity))
}
fn changed(mut asset: Asset) -> (Asset, Option<AssetChange>) {
    asset.attributes.insert("whitelist".into(), serde_json::json!({"domains":["owned.test"],"paths":[]}));
    let change = AssetChange {
        id: Id::new(),
        tenant_id: asset.tenant_id,
        asset_id: asset.id,
        kind: AssetKind::Skill,
        change_kind: ChangeKind::Modified,
        field: Some("attributes.whitelist".into()),
        old_value: None,
        new_value: asset.attributes.get("whitelist").cloned(),
        risky: false,
        risk_note: None,
        domain: None,
        detected_at: Timestamp::now(),
    };
    (asset, Some(change))
}

#[test]
fn audit_overflow_preserves_skill_history_and_audit_chain() -> DomainResult<()> {
    let (store, asset, identity) = fixture()?;
    let mut last = log(asset.tenant_id);
    last.sequence = i64::MAX;
    last.seal();
    store.lock()?.audits.insert(asset.tenant_id, vec![last]);
    let before = serde_json::to_value(&store.lock()?.audits)?;
    let result = store.publish_skill_offline(
        asset.tenant_id,
        asset.id,
        &identity,
        |_| Ok(changed(asset.clone())),
        |_| log(asset.tenant_id),
        || Ok(()),
    );
    assert!(result.is_err());
    let memory = store.lock()?;
    assert_eq!(
        memory.assets.get(&(asset.tenant_id, asset.id)).map(serde_json::to_value).transpose()?,
        Some(serde_json::to_value(&asset)?)
    );
    assert!(memory.changes.is_empty());
    assert_eq!(serde_json::to_value(&memory.audits)?, before);
    Ok(())
}

#[test]
fn budget_refusal_precedes_every_skill_write() -> DomainResult<()> {
    let (store, asset, identity) = fixture()?;
    let result = store.publish_skill_offline(
        asset.tenant_id,
        asset.id,
        &identity,
        |_| Ok(changed(asset.clone())),
        |_| log(asset.tenant_id),
        || Err(DomainError::Forbidden("owned expired lease".into())),
    );
    assert!(result.is_err());
    let memory = store.lock()?;
    assert!(memory.changes.is_empty() && memory.audits.is_empty());
    assert_eq!(
        memory.assets.get(&(asset.tenant_id, asset.id)).map(serde_json::to_value).transpose()?,
        Some(serde_json::to_value(&asset)?)
    );
    Ok(())
}

#[test]
fn revoked_key_is_rechecked_inside_the_asset_and_audit_mutex() -> DomainResult<()> {
    let (store, asset, _) = fixture()?;
    let key = ApiKey {
        id: Id::new(),
        tenant_id: asset.tenant_id,
        name: "owned-key".into(),
        prefix: "owned".into(),
        key_fingerprint: "owned-fingerprint".into(),
        scopes: Vec::new(),
        bound_agent_id: None,
        expires_at: None,
        last_used_at: None,
        allowed_cidrs: Vec::new(),
        revoked: false,
        created_at: Timestamp::now(),
    };
    let identity = Identity { tenant: key.tenant_id, key: Some((key.id, serde_json::to_value(&key)?)), agent: None };
    let mut revoked = key;
    revoked.revoked = true;
    store.lock()?.api_keys.push(revoked);
    let result = store.publish_skill_offline(
        asset.tenant_id,
        asset.id,
        &identity,
        |_| Ok(changed(asset.clone())),
        |_| log(asset.tenant_id),
        || Ok(()),
    );
    assert!(matches!(result, Err(DomainError::Forbidden(_))));
    let memory = store.lock()?;
    assert!(memory.changes.is_empty() && memory.audits.is_empty());
    assert_eq!(
        memory.assets.get(&(asset.tenant_id, asset.id)).map(serde_json::to_value).transpose()?,
        Some(serde_json::to_value(&asset)?)
    );
    Ok(())
}

#[test]
fn legacy_audit_overflow_returns_error_without_poisoning_the_shared_store() -> DomainResult<()> {
    let (store, asset, _) = fixture()?;
    let mut last = log(asset.tenant_id);
    last.sequence = i64::MAX;
    last.seal();
    store.lock()?.audits.insert(asset.tenant_id, vec![last]);
    let before = serde_json::to_value(&store.lock()?.audits)?;
    assert!(matches!(store.audit_append(log(asset.tenant_id)), Err(DomainError::Validation(_))));
    assert_eq!(serde_json::to_value(&store.lock()?.audits)?, before);
    assert_eq!(store.lock()?.assets.len(), 1);
    Ok(())
}
