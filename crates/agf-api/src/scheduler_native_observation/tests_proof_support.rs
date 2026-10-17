use super::{binding, eligibility, input::Assignment, proof, records::BindingRecord, safe::SafeSnapshot, scope, util};
use agf_core::{
    credential::KeyBackend,
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_storage::crypto::FieldCipher;
use base64::Engine;
use serde_json::{Value, json};

pub(super) fn target() -> DomainResult<scope::SourceTarget> {
    let tenant = TenantId::default_tenant();
    let mut target = scope::SourceTarget {
        tenant,
        configuration_id: util::main_id(tenant),
        configuration_version: 1,
        scope_id: Id::new(),
        fingerprint: "0".repeat(64),
        region: "cn-hangzhou".into(),
        rpc_origin: "https://schedulerx3.cn-hangzhou.aliyuncs.com/".into(),
        configured_account_id: None,
        account_identity_verified: false,
        cluster_id: "cluster-agf-demo".into(),
        app_name: "app-agf-demo".into(),
        mocked: true,
        transport_mode: "mock".into(),
    };
    target.scope_id = scope::identity(&target)?;
    Ok(target)
}
pub(super) fn parse(target: &scope::SourceTarget, mut value: Value) -> DomainResult<SafeSnapshot> {
    let length = value["jobs"].as_array().ok_or_else(util::corrupt)?.len();
    value["pagination"]["total"] = json!(length);
    value["pagination"]["pages"][0]["records"] = json!(length);
    value["fingerprint"] = json!(util::canonical_hash(
        &json!({"scope":value["scope"],"app":value["app"],"jobs":value["jobs"],"total":length})
    )?);
    SafeSnapshot::parse(target, value)
}
pub(super) fn fixture(target: &scope::SourceTarget) -> DomainResult<SafeSnapshot> {
    let mut mock = agf_alicloud::schedulerx3::native_observation::MockState::default();
    mock.seed_owned_fixture(&target.native())?;
    SafeSnapshot::parse(target, serde_json::to_value(mock.observe(&target.native())?)?)
}
pub(super) fn cipher() -> DomainResult<FieldCipher> {
    FieldCipher::from_base64(
        &base64::engine::general_purpose::STANDARD.encode([37_u8; 32]),
        "owned-adoption-proof",
        KeyBackend::LocalFile,
    )
}
pub(super) fn adopt(
    target: &scope::SourceTarget,
    data: &SafeSnapshot,
    items: Vec<Assignment>,
) -> DomainResult<BindingRecord> {
    let tenant = target.tenant;
    let at = Timestamp::now().offset_secs(-600);
    let request = Id::new();
    let mut row = BindingRecord {
        tenant: Some(tenant),
        version: 3,
        enabled: !items.is_empty(),
        target: Some(target.clone()),
        observation_id: Some(request),
        app_id: Some(data.app_id().into()),
        fingerprint: Some(data.fingerprint().into()),
        verified_at: Some(at),
        items,
        adoption_version: 3,
        ..BindingRecord::default()
    };
    row.eligibility = eligibility::adopt(&row, data, request, at)?;
    row.adopted_proofs = proof::seal_with_cipher(&cipher()?, &row, tenant)?;
    proof::seal_qualification_with_cipher(&cipher()?, &mut row, tenant)?;
    binding::validate(&row, tenant)?;
    Ok(row)
}
pub(super) fn setup() -> DomainResult<(scope::SourceTarget, SafeSnapshot, BindingRecord)> {
    let target = target()?;
    let data = fixture(&target)?;
    let row = adopt(&target, &data, vec![Assignment { kind: "report".into(), job_id: "9007199254741002".into() }])?;
    Ok((target, data, row))
}
pub(super) fn reseal(row: &mut BindingRecord) -> DomainResult<()> {
    let tenant = row.tenant.ok_or_else(util::corrupt)?;
    proof::seal_qualification_with_cipher(&cipher()?, row, tenant)
}
