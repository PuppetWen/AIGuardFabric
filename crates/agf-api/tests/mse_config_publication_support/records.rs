//! Private state comparisons and actual persisted Mock content establish causal write evidence.
use super::*;
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome},
    credential::SecretMaterial,
    ids::deterministic_id,
};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};

const KINDS: [&str; 8] = [
    "mse-config-publication-state",
    "mse-config-publication-fact",
    "mse-config-publication-detail",
    "mse-config-publication-preview",
    "mse-config-publication-pending",
    "mse-config-publication-mock",
    "cloud-integration",
    "signed-policy-registry",
];

#[derive(Debug, PartialEq)]
pub(crate) struct Snapshot {
    configurations: BTreeMap<String, Vec<Value>>,
    audits: Value,
}

pub(crate) async fn snapshot(h: &Harness) -> DomainResult<Snapshot> {
    Ok(Snapshot {
        configurations: configurations(h).await?,
        audits: serde_json::to_value(h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await?)?,
    })
}

pub(crate) async fn configurations(h: &Harness) -> DomainResult<BTreeMap<String, Vec<Value>>> {
    let mut configurations = BTreeMap::new();
    for kind in KINDS {
        configurations.insert(kind.to_owned(), h.state.configurations.list::<Value>(h.tenant, kind).await?);
    }
    Ok(configurations)
}

pub(crate) async fn workflow_audits(h: &Harness, request: Id, action: AuditAction) -> DomainResult<Vec<AuditLog>> {
    let target =
        if action == AuditAction::Configure { "mse-config-publication-claim" } else { "mse-config-publication" };
    let request = request.to_string();
    Ok(h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await?
        .into_iter()
        .filter(|entry| {
            entry.target.kind == target
                && entry.target.id.as_deref() == Some(request.as_str())
                && entry.action == action
                && entry.outcome == AuditOutcome::Success
        })
        .collect())
}

pub(crate) struct Provider {
    pub(crate) revision: u64,
    pub(crate) plaintext: String,
    pub(crate) scope: Id,
    pub(crate) row: Value,
}
impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedMockProvider")
            .field("revision", &self.revision)
            .field("scope", &self.scope)
            .field("content_bytes", &self.plaintext.len())
            .finish_non_exhaustive()
    }
}

pub(crate) async fn provider(h: &Harness) -> DomainResult<Provider> {
    let rows = h.state.configurations.list::<Value>(h.tenant, "mse-config-publication-mock").await?;
    assert_eq!(rows.len(), 1, "fixture must have exactly one observed Mock target");
    let row = rows.into_iter().next().ok_or_else(|| DomainError::Internal("missing owned Mock provider row".into()))?;
    decode_provider(h, row)
}

pub(crate) async fn provider_at(h: &Harness, scope: Id) -> DomainResult<Provider> {
    let rows = h.state.configurations.list::<Value>(h.tenant, "mse-config-publication-mock").await?;
    let row = rows
        .into_iter()
        .find(|row| row["target_scope_id"] == json!(scope))
        .ok_or_else(|| DomainError::Internal("missing specific owned Mock provider scope".into()))?;
    decode_provider(h, row)
}

fn decode_provider(h: &Harness, row: Value) -> DomainResult<Provider> {
    let id = identifier(&row, "id")?;
    let scope = identifier(&row, "target_scope_id")?;
    assert_eq!(id, deterministic_id("agf.mse.config-publication.mock", &format!("{}:{scope}", h.tenant)));
    assert_eq!(row["tenant_id"], json!(h.tenant));
    let encrypted: SecretMaterial = serde_json::from_value(row["content"].clone())?;
    assert_eq!(encrypted.aad.as_deref(), Some(FieldCipher::make_aad(&h.tenant, &id).as_str()));
    let content = agf_api::model_gateway::cipher(&h.state)?.decrypt(&encrypted)?;
    let plaintext = content.expose_secret().to_owned();
    assert_eq!(row["content_md5"], agf_alicloud::mse::config_cas::content_md5(&plaintext));
    Ok(Provider { revision: number(&row, "revision")?, plaintext, scope, row })
}

fn hash(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

pub(crate) fn assert_bundle(h: &Harness, saved: &Provider, policy: &Value, receipt: &Value) -> DomainResult<()> {
    let bundle: Value = serde_json::from_str(&saved.plaintext)?;
    let payload = &bundle["payload"];
    assert_eq!(payload["schema"], "agf.policy-bundle.v1");
    assert_eq!(payload["tenantId"], json!(h.tenant));
    assert_eq!(payload["targetScopeId"], json!(saved.scope));
    assert_eq!(payload["target"]["namespaceId"], "");
    assert_eq!(payload["target"]["transportMode"], "mock");
    assert_eq!(payload["policies"], json!([policy]));
    assert_policy(h, &payload["policies"][0])?;
    let actual_hash = hash(&serde_json::to_vec(payload)?);
    assert_eq!(bundle["payloadHash"], actual_hash);
    let signer = agf_api::policy_store::signer(&h.state)?;
    assert_eq!(bundle["keyId"], signer.key_id());
    assert_eq!(bundle["signature"], signer.sign_hash(&format!("agf.mse-nacos-bundle.v1:{actual_hash}")));
    assert_eq!(receipt["readback"]["currentHash"], hash(saved.plaintext.as_bytes()));
    Ok(())
}
