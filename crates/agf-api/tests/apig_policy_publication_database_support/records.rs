//! Counts and raw provider effects come from authenticated persisted Mock state, never generic receipts.
use super::*;
use agf_alicloud::{
    AdapterMode,
    apig::policy_driver::{Binding, CurrentGuard, MockBridge, MockCodec, MockScope, MockSourceGuard, MockState},
};
use agf_core::{credential::SecretMaterial, ids::deterministic_id};
use agf_storage::crypto::FieldCipher;
use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

const MOCK: &str = "apig-policy-driver-mock";
const KINDS: [&str; 10] = [
    "apig-policy-publication-state",
    "apig-policy-publication-fact",
    "apig-policy-publication-detail",
    "apig-policy-publication-preview",
    "apig-policy-publication-pending",
    MOCK,
    "cloud-integration",
    "signed-policy-registry",
    "quota-definitions",
    "integration-operation",
];

#[derive(Debug, PartialEq)]
pub(crate) struct Snapshot {
    pub(super) configurations: BTreeMap<String, Vec<Value>>,
    audits: Value,
}
pub(crate) async fn snapshot(h: &Harness) -> DomainResult<Snapshot> {
    Ok(Snapshot {
        configurations: configurations(h).await?,
        audits: serde_json::to_value(h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await?)?,
    })
}
pub(crate) async fn configurations(h: &Harness) -> DomainResult<BTreeMap<String, Vec<Value>>> {
    let mut values = BTreeMap::new();
    for kind in KINDS {
        values.insert(kind.into(), h.state.configurations.list::<Value>(h.tenant, kind).await?);
    }
    Ok(values)
}
pub(crate) struct Provider {
    pub(crate) row: Value,
    pub(crate) state: MockState,
    decoded: Value,
}
impl Provider {
    pub(crate) fn response(&self, action: &str) -> DomainResult<&Value> {
        self.decoded["responses"]
            .get(action)
            .ok_or_else(|| DomainError::Internal(format!("missing owned provider action {action}")))
    }
    pub(crate) fn config(&self) -> DomainResult<Value> {
        let raw = text(&self.response("GetPolicy")?["data"], "config")?;
        serde_json::from_str(&raw).map_err(Into::into)
    }
    pub(crate) fn calls(&self, action: &str) -> u64 {
        self.state.call_count(action)
    }
}
pub(crate) async fn provider(h: &Harness) -> DomainResult<Provider> {
    let rows = h.state.configurations.list::<Value>(h.tenant, MOCK).await?;
    assert_eq!(rows.len(), 1, "exactly one owned Mock target must be present");
    let row = rows.into_iter().next().ok_or_else(|| DomainError::Internal("missing initialized Mock row".into()))?;
    let id = identifier(&row, "id")?;
    assert_eq!(row["tenant"], json!(h.tenant));
    let binding: Binding = serde_json::from_value(row["binding"].clone())?;
    let scope = MockScope::new(
        h.tenant,
        identifier(&row, "source_id")?,
        &text(&row, "region")?,
        &text(&row, "source_identity")?,
        binding,
        AdapterMode::Mocked,
    )?;
    assert_eq!(scope.record_id(), id);
    assert_eq!(row["scope"], scope.fingerprint());
    let cipher: SecretMaterial = serde_json::from_value(row["state"].clone())?;
    let aad = format!("{}|kind:{MOCK}:v1", FieldCipher::make_aad(&h.tenant, &id));
    assert_eq!(cipher.aad.as_deref(), Some(aad.as_str()));
    let plaintext = agf_api::model_gateway::cipher(&h.state)?.decrypt(&cipher)?;
    let state: MockState = serde_json::from_str(plaintext.expose_secret())?;
    let decoded = serde_json::to_value(&state)?;
    assert_eq!(decoded["scope"], row["scope"]);
    assert_eq!(decoded["binding"], row["binding"]);
    assert_eq!(decoded["revision"], state.call_count("UpdatePolicy"));
    Ok(Provider { row, state, decoded })
}

pub(crate) async fn assert_package(h: &Harness, preview: &Value, policy: &Value) -> DomainResult<()> {
    let request = identifier(preview, "id")?;
    let id = content_id(h.tenant, request, "preview");
    let row: Value = h
        .state
        .configurations
        .get(h.tenant, "apig-policy-publication-preview", id)
        .await?
        .ok_or_else(|| DomainError::Internal("missing authenticated preview body".into()))?;
    assert_eq!(row["tenant"], json!(h.tenant));
    assert_eq!(row["request_id"], json!(request));
    let material: SecretMaterial = serde_json::from_value(row["body"].clone())?;
    let aad = format!(
        "{}|kind:apig-policy-publication:v1",
        FieldCipher::make_aad(&h.tenant, &content_id(h.tenant, request, "intent"))
    );
    assert_eq!(material.aad.as_deref(), Some(aad.as_str()));
    let plaintext = agf_api::model_gateway::cipher(&h.state)?.decrypt(&material)?;
    assert_eq!(row["body_bytes"], plaintext.expose_secret().len());
    assert_eq!(row["body_hash"], hex::encode(Sha256::digest(plaintext.expose_secret().as_bytes())));
    let package: Value = serde_json::from_str(plaintext.expose_secret())?;
    assert_eq!(package["schema"], 1);
    assert_eq!(package["source_policies"], json!([policy]));
    assert_policy(h, &package["source_policies"][0])?;
    assert_eq!(package["proof"]["scope"], row["scope"]);
    assert_eq!(package["proof"]["fence"], row["fence"]);
    let binding: Binding = serde_json::from_value(row["scope"]["target"]["binding"].clone())?;
    let baseline = agf_alicloud::apig::policy_driver::restore_evidence(&binding, &package["baseline"])?;
    assert_eq!(baseline.fingerprint(), row["baseline_fingerprint"]);
    assert_eq!(baseline.config_hash(), row["baseline_config_hash"]);
    let mode = serde_json::from_value(row["managed_limit"].clone())?;
    let limit = u32::try_from(number(&row, "desired_limit")?)
        .map_err(|_| DomainError::Internal("invalid prepared limit".into()))?;
    let update = agf_alicloud::apig::policy_driver::prepare_limit(&baseline, mode, limit)?;
    assert_eq!(update.desired_hash(), row["desired_hash"]);
    assert_eq!(row["desired_bytes"], json!(update.desired_config_bytes()?));
    Ok(())
}
pub(crate) fn content_id(tenant: TenantId, request: Id, purpose: &str) -> Id {
    deterministic_id("agf.apig.policy-publication.content", &format!("{tenant}:{request}:{purpose}"))
}
pub(crate) fn fact_id(tenant: TenantId, request: Id) -> Id {
    deterministic_id("agf.apig.policy-publication.fact", &format!("{tenant}:{request}"))
}

struct Codec(FieldCipher);
impl MockCodec for Codec {
    fn seal(&self, plaintext: &str, aad: &str) -> DomainResult<SecretMaterial> {
        self.0.encrypt(&SecretString::from(plaintext.to_owned()), aad)
    }
    fn open(&self, material: &SecretMaterial, aad: &str) -> DomainResult<String> {
        if material.aad.as_deref() != Some(aad) {
            return Err(DomainError::Crypto("owned external provider AAD differs".into()));
        }
        Ok(self.0.decrypt(material)?.expose_secret().to_owned())
    }
}
struct SourceGuard<'a> {
    h: &'a Harness,
    version: u64,
    fingerprint: String,
}
#[async_trait]
impl CurrentGuard for SourceGuard<'_> {
    async fn validate(&self) -> DomainResult<()> {
        let row = agf_api::cloud_store::load(&self.h.state, self.h.tenant, "alicloud-apig")
            .await?
            .ok_or_else(|| DomainError::Internal("missing owned external source".into()))?;
        if !row.enabled
            || !row.mock
            || row.version != self.version
            || MockBridge::source_fingerprint(&serde_json::to_value(row)?) != self.fingerprint
        {
            return Err(DomainError::Conflict("owned external provider source changed".into()));
        }
        Ok(())
    }
}
/// A separate simulated provider writer changes real persistent Mock data; it never writes a platform policy or receipt.
pub(crate) async fn external_edit(h: &Harness) -> DomainResult<Value> {
    let current = provider(h).await?;
    let row = agf_api::cloud_store::load(&h.state, h.tenant, "alicloud-apig")
        .await?
        .ok_or_else(|| DomainError::Internal("missing source for external provider edit".into()))?;
    let fingerprint = MockBridge::source_fingerprint(&serde_json::to_value(&row)?);
    let guard = SourceGuard { h, version: row.version, fingerprint: fingerprint.clone() };
    let binding: Binding = serde_json::from_value(current.row["binding"].clone())?;
    let scope = MockScope::new(
        h.tenant,
        row.id,
        &text(&current.row, "region")?,
        &text(&current.row, "source_identity")?,
        binding.clone(),
        AdapterMode::Mocked,
    )?;
    let mut config = current.config()?;
    config["globalRules"][1]["limitValue"] = json!(44);
    config["rules"][0]["limitValue"] = json!(999);
    config["futurePreserved"]["note"] = json!("a later external edit must survive rollback");
    let policy = &current.response("GetPolicy")?["data"];
    let input = json!({"policyId":binding.policy_id,"body":{"name":policy["name"],
        "description":"a later external description","config":config.to_string()}});
    let codec = Codec(agf_api::model_gateway::cipher(&h.state)?);
    let bridge = MockBridge::new(h.state.configurations.as_ref(), &codec);
    bridge
        .execute(
            &scope,
            MockSourceGuard { version: row.version, payload_fingerprint: &fingerprint },
            "UpdatePolicy",
            &input,
            &guard,
            tokio::time::Instant::now() + std::time::Duration::from_secs(10),
        )
        .await?;
    Ok(config)
}
