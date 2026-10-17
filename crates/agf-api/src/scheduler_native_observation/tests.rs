use super::*;
use agf_core::{
    audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget},
    credential::KeyBackend,
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_storage::crypto::FieldCipher;
use base64::Engine;
use secrecy::SecretString;
use serde_json::{Value, json};

fn target() -> DomainResult<scope::SourceTarget> {
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
fn fixture(target: &scope::SourceTarget) -> DomainResult<Value> {
    let mut mock = agf_alicloud::schedulerx3::native_observation::MockState::default();
    mock.seed_owned_fixture(&target.native())?;
    Ok(serde_json::to_value(mock.observe(&target.native())?)?)
}
fn rehash(value: &mut Value) -> DomainResult<()> {
    value["fingerprint"] = json!(util::canonical_hash(
        &json!({"scope":value["scope"],"app":value["app"],"jobs":value["jobs"],"total":value["pagination"]["total"]})
    )?);
    Ok(())
}
#[test]
fn strict_safe_restore_accepts_complete_driver_data_and_never_exposes_opaque_bodies() -> DomainResult<()> {
    let target = target()?;
    let value = fixture(&target)?;
    let data = safe::SafeSnapshot::parse(&target, value)?;
    assert_eq!(data.total(), 6);
    assert_eq!(data.app_id(), "9007199254740993");
    let output = serde_json::to_string(data.value())?;
    for secret in ["AccessToken", "JobHandler", "Parameters", "Xattrs", "secret"] {
        assert!(!output.contains(secret));
    }
    assert!(data.jobs().iter().all(|job| job["http"]["verified"] == false));
    Ok(())
}
#[test]
fn safe_restore_rejects_extra_field_identity_truncation_and_recomputed_contradictions() -> DomainResult<()> {
    let target = target()?;
    let original = fixture(&target)?;
    let mut extra = original.clone();
    extra["app"]["AccessToken"] = json!("must-not-leak");
    rehash(&mut extra)?;
    assert!(safe::SafeSnapshot::parse(&target, extra).is_err());
    let mut foreign = original.clone();
    foreign["jobs"][0]["appId"] = json!("1");
    rehash(&mut foreign)?;
    assert!(safe::SafeSnapshot::parse(&target, foreign).is_err());
    let mut unknown = original.clone();
    unknown["jobs"][0]["status"] = Value::Null;
    unknown["jobs"][0]["enabled"] = json!(true);
    rehash(&mut unknown)?;
    assert!(safe::SafeSnapshot::parse(&target, unknown).is_err());
    let mut incomplete = original;
    incomplete["jobs"].as_array_mut().ok_or_else(util::corrupt)?.pop();
    rehash(&mut incomplete)?;
    assert!(safe::SafeSnapshot::parse(&target, incomplete).is_err());
    Ok(())
}
#[test]
fn unknown_and_non_utc_evidence_remain_unknown_or_explicit_false() -> DomainResult<()> {
    let target = target()?;
    let mut value = fixture(&target)?;
    value["jobs"][0]["status"] = Value::Null;
    value["jobs"][0]["enabled"] = Value::Null;
    value["jobs"][0]["schedule"]["zone"] = Value::Null;
    value["jobs"][0]["schedule"]["utc"] = Value::Null;
    value["jobs"][1]["schedule"]["zone"] = json!("America/New_York");
    value["jobs"][1]["schedule"]["utc"] = json!(false);
    rehash(&mut value)?;
    let data = safe::SafeSnapshot::parse(&target, value)?;
    assert!(data.jobs()[0]["enabled"].is_null());
    assert!(data.jobs()[0]["schedule"]["utc"].is_null());
    assert_eq!(data.jobs()[1]["schedule"]["utc"], false);
    Ok(())
}
#[test]
fn encrypted_two_mib_plaintext_requires_main_record_and_fits_full_four_mib_envelope() -> DomainResult<()> {
    let target = target()?;
    let request = Id::new();
    let id = util::body_key(target.tenant, request).1;
    let key = base64::engine::general_purpose::STANDARD.encode([23_u8; 32]);
    let cipher = FieldCipher::from_base64(&key, "owned-scheduler-size-test", KeyBackend::LocalFile)?;
    let clear = "x".repeat(MAX_BODY_BYTES);
    let secret = cipher.encrypt(&SecretString::from(clear), &FieldCipher::make_aad(&target.tenant, &id))?;
    assert!(cipher.decrypt(&secret).is_ok());
    let envelope = records::BodyRecord::Content(Box::new(records::StoredBody {
        tenant: target.tenant,
        request_id: request,
        target,
        app_id: "1".into(),
        hash: "0".repeat(64),
        secret,
    }));
    let encoded = util::bound(&envelope, 4 * 1024 * 1024)?;
    assert!(encoded > 1024 * 1024);
    assert!(encoded < 4 * 1024 * 1024);
    assert!(util::bound(&envelope, 1024 * 1024).is_err());
    Ok(())
}
#[test]
fn hundred_archive_markers_fit_declared_batch_and_do_not_erase_permanent_facts() -> DomainResult<()> {
    let tenant = TenantId::default_tenant();
    let mut writes = records::Values::new();
    let mut journal = records::Journal { tenant: Some(tenant), archived_count: 100, ..Default::default() };
    for _ in 0..100 {
        let id = Id::new();
        util::put(
            &mut writes,
            util::body_key(tenant, id),
            &records::BodyRecord::Archived {
                tenant,
                request_id: id,
                archived_at: Timestamp::now(),
                original_status: "observed".into(),
            },
        )?;
    }
    store::bump(&mut journal, tenant)?;
    util::put(&mut writes, util::state_key(tenant), &journal)?;
    assert_eq!(writes.len(), 101);
    assert!(writes.keys().all(|(kind, _)| kind != records::FACT));
    let audit = crate::state::AppState::audit_entry(
        tenant,
        AuditAction::Configure,
        AuditOutcome::Success,
        AuditActor::system("owned-scheduler-archive-test"),
        AuditTarget::new("scheduler-native-archive", None, None),
        "owned size assertion",
    );
    util::batch_bound(tenant, &writes, &audit)?;
    Ok(())
}
#[test]
fn strict_binding_union_preserves_disable_and_rejects_duplicate_alias_unknowns() -> DomainResult<()> {
    let id = Id::new();
    let mut disable: input::BindingInput =
        serde_json::from_value(json!({"action":"disable","request_id":id,"expected_version":1}))?;
    disable.validate()?;
    assert!(
        serde_json::from_value::<input::BindingInput>(
            json!({"action":"disable","request_id":id,"expected_version":1,"bindings":[]})
        )
        .is_err()
    );
    let mut duplicate: input::BindingInput = serde_json::from_value(
        json!({"action":"replace","request_id":id,"expected_version":0,"configuration_version":1,
        "observation_id":Id::new(),"confirm_local_only":true,"bindings":[{"kind":"report","job_id":"1"},{"kind":"archive","job_id":"1"}]}),
    )?;
    assert!(duplicate.validate().is_err());
    assert!(!util::positive_id("01"));
    assert!(!util::positive_id("9223372036854775808"));
    Ok(())
}
#[test]
fn journal_capacity_preserves_archived_latest_summary_and_detects_duplicates() -> DomainResult<()> {
    let tenant = TenantId::default_tenant();
    let id = Id::new();
    let mut journal =
        records::Journal { tenant: Some(tenant), latest: Some(id), archived_count: 1, ..Default::default() };
    store::validate_journal(&journal, tenant)?;
    journal.observations = vec![id, id];
    assert!(store::validate_journal(&journal, tenant).is_err());
    journal.observations.clear();
    journal.stored_bytes = MAX_STORED_BYTES + 1;
    assert!(store::validate_journal(&journal, tenant).is_err());
    Ok(())
}
#[test]
fn durable_cipher_identity_is_bound_to_tenant_record_and_exact_safe_content() -> DomainResult<()> {
    let target = target()?;
    let request = Id::new();
    let id = util::body_key(target.tenant, request).1;
    let key = base64::engine::general_purpose::STANDARD.encode([31_u8; 32]);
    let cipher = FieldCipher::from_base64(&key, "owned-scheduler-aad-test", KeyBackend::LocalFile)?;
    let value = fixture(&target)?;
    let clear = serde_json::to_string(&value)?;
    let hash = util::hash(clear.as_bytes());
    let secret = cipher.encrypt(&SecretString::from(clear), &FieldCipher::make_aad(&target.tenant, &id))?;
    assert_eq!(util::decode_secret(&cipher, target.tenant, id, &secret, &hash)?, value);
    assert!(util::decode_secret(&cipher, TenantId::new(), id, &secret, &hash).is_err());
    assert!(util::decode_secret(&cipher, target.tenant, Id::new(), &secret, &hash).is_err());
    assert!(util::decode_secret(&cipher, target.tenant, id, &secret, &"0".repeat(64)).is_err());
    assert_ne!(util::fact_key(target.tenant, request), util::fact_key(TenantId::new(), request));
    Ok(())
}
#[test]
fn canonical_kinds_match_real_platform_defaults_and_name_the_existing_consumers() {
    let actual = agf_alicloud::schedulerx3::SchedulerX3Job::platform_defaults(TenantId::default_tenant())
        .into_iter()
        .map(|job| job.job_kind)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = KINDS.into_iter().map(str::to_owned).collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected);
    assert_eq!(util::runtime_kind("report"), "report-generate");
    assert_eq!(util::runtime_kind("archive"), "cold-archive");
}

#[test]
fn complete_source_fingerprint_is_order_independent_and_account_text_changes_scope() -> DomainResult<()> {
    let ordered = json!({"z":{"b":1,"a":2},"a":[{"y":true,"x":null}]});
    let reordered = json!({"a":[{"x":null,"y":true}],"z":{"a":2,"b":1}});
    assert_eq!(source_fingerprint(&ordered)?, source_fingerprint(&reordered)?);
    assert_eq!(source_fingerprint(&ordered)?, util::canonical_hash(&ordered)?);
    let original = target()?;
    let mut changed = original.clone();
    changed.configured_account_id = Some("unverified-configured-account".into());
    assert_ne!(scope::identity(&original)?, scope::identity(&changed)?);
    changed = original.clone();
    changed.configuration_version += 1;
    changed.fingerprint = "1".repeat(64);
    assert_eq!(scope::identity(&original)?, scope::identity(&changed)?);
    assert!(!changed.account_identity_verified);
    let dto = serde_json::to_value(changed)?;
    assert_eq!(dto["accountIdentityVerified"], false);
    assert!(dto["configuredAccountId"].is_null());
    for forbidden in ["http://localhost:31901/", "http://192.168.1.2:31901/", "https://example.com/callback"] {
        assert!(scope::normalized_origin(forbidden).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn the_original_deadline_cancels_pending_work_and_is_not_renewed() {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(20);
    let pending = std::future::pending::<DomainResult<()>>();
    let result = authority::bounded(deadline, pending).await;
    assert!(matches!(result, Err(agf_core::error::DomainError::Timeout(_))));
    let dispatched = std::sync::atomic::AtomicBool::new(false);
    let result = authority::bounded(deadline, async {
        dispatched.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    })
    .await;
    assert!(matches!(result, Err(agf_core::error::DomainError::Timeout(_))));
    assert!(!dispatched.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn an_actual_full_safe_observation_fits_the_large_encrypted_main_record() -> DomainResult<()> {
    let target = target()?;
    let mut value = fixture(&target)?;
    let template = value["jobs"][0].clone();
    let mut jobs = (1..=2000)
        .map(|id| {
            let mut job = template.clone();
            job["id"] = json!(id.to_string());
            job["name"] = json!("x".repeat(260));
            job
        })
        .collect::<Vec<_>>();
    jobs.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    value["jobs"] = json!(jobs);
    value["pagination"]["total"] = json!(2000);
    value["pagination"]["pages"] = json!(
        (1..=20)
            .map(|number| json!({
                "number":number,"size":100,"records":100,"requestId":format!("owned-page-{number}")
            }))
            .collect::<Vec<_>>()
    );
    rehash(&mut value)?;
    let data = safe::SafeSnapshot::parse(&target, value)?;
    assert_eq!(data.total(), 2000);
    let clear = serde_json::to_string(data.value())?;
    assert!(clear.len() > 1024 * 1024 && clear.len() <= MAX_BODY_BYTES);
    let id = Id::new();
    let key = base64::engine::general_purpose::STANDARD.encode([43_u8; 32]);
    let cipher = FieldCipher::from_base64(&key, "owned-scheduler-full-test", KeyBackend::LocalFile)?;
    let hash = util::hash(clear.as_bytes());
    let secret = cipher.encrypt(&SecretString::from(clear), &FieldCipher::make_aad(&target.tenant, &id))?;
    let restored = util::decode_secret(&cipher, target.tenant, id, &secret, &hash)?;
    assert_eq!(safe::SafeSnapshot::parse(&target, restored)?.total(), 2000);
    let envelope = records::BodyRecord::Content(Box::new(records::StoredBody {
        tenant: target.tenant,
        request_id: Id::new(),
        target,
        app_id: data.app_id().into(),
        hash,
        secret,
    }));
    assert!(util::bound(&envelope, 4 * 1024 * 1024)? > 1024 * 1024);
    Ok(())
}
