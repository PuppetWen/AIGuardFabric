use super::{
    Registry, input,
    model::{Attempt, Delivery, Item, Journal, Outcome, Owner, Phase},
    records,
    source::Source,
    util,
};
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId},
    rbac::SubjectKind,
    time::Timestamp,
};
use std::collections::BTreeMap;

fn item() -> Item {
    let tenant = TenantId::new();
    let now = Timestamp::now();
    Item {
        tenant,
        id: Id::new(),
        enqueue_id: Id::new(),
        owner: Owner {
            tenant,
            identity_tenant: tenant,
            kind: SubjectKind::User,
            subject: Some(Id::new()),
            agent: None,
        },
        source: Source {
            tenant,
            id: crate::integration_store::id(tenant, super::NAME),
            version: 1,
            fingerprint: "a".repeat(64),
            group: "agf-cms-demo".into(),
            region: "cn-hangzhou".into(),
            mode: "mock".into(),
        },
        name: "owned-event".into(),
        action: "PutCustomEvent".into(),
        payload_hash: "b".repeat(64),
        payload_bytes: 32,
        queued_at: now,
        attempts: Vec::new(),
        archived_at: None,
    }
}
fn attempt(item: &mut Item, delivery: Delivery) -> Attempt {
    let id = Id::new();
    item.attempts.push(id);
    let now = Timestamp::now();
    Attempt {
        tenant: item.tenant,
        id,
        item_id: item.id,
        request_id: Id::new(),
        owner: item.owner.clone(),
        source: item.source.clone(),
        admitted_at: now,
        lease_expires_at: now.offset_secs(110),
        phase: Phase::Complete,
        started_at: Some(now),
        outcome: Some(Outcome { delivery, provider_request_id: Some("owned-ack".into()), finished_at: now }),
    }
}
#[test]
fn accepted_unknown_and_archived_never_become_retryable() -> DomainResult<()> {
    for delivery in [Delivery::Accepted, Delivery::Unknown] {
        let mut row = item();
        let last = attempt(&mut row, delivery);
        records::attempt(&last, &row)?;
        assert!(!records::retryable(&row, Some(&last)));
    }
    let mut row = item();
    let last = attempt(&mut row, Delivery::NotSent);
    assert!(records::retryable(&row, Some(&last)));
    row.archived_at = Some(Timestamp::now());
    assert!(!records::retryable(&row, Some(&last)));
    Ok(())
}
#[test]
fn five_explicit_attempts_exhaust_capacity_without_evicting_identity() {
    let mut row = item();
    let mut last = None;
    for _ in 0..5 {
        last = Some(attempt(&mut row, Delivery::Rejected));
    }
    assert_eq!(row.attempts.len(), 5);
    assert!(!records::retryable(&row, last.as_ref()));
}
#[test]
fn only_canonical_owned_loopback_capability_permits_http() -> DomainResult<()> {
    let tenant = TenantId::new();
    let registry =
        Registry::literal_loopback_for_test(tenant, "127.0.0.1:19099".parse().map_err(|_| util::invalid())?)?;
    assert_eq!(registry.mode(tenant, "http://127.0.0.1:19099/")?, "loopback_test");
    assert!(registry.mode(TenantId::new(), "http://127.0.0.1:19099/").is_err());
    assert!(Registry::default().mode(tenant, "http://127.0.0.1:19099/").is_err());
    assert!(registry.mode(tenant, "http://127.0.0.1:19099/?credential=secret").is_err());
    Ok(())
}
#[test]
fn canonical_hash_ignores_object_order_but_keeps_payload_identity() -> DomainResult<()> {
    let a = serde_json::json!({"a":1,"b":{"d":2,"c":3}});
    let b = serde_json::json!({"b":{"c":3,"d":2},"a":1});
    assert_eq!(util::fingerprint(&a)?, util::fingerprint(&b)?);
    assert_ne!(util::fingerprint(&a)?, util::fingerprint(&serde_json::json!({"a":2,"b":{"c":3,"d":2}}))?);
    Ok(())
}
#[test]
fn payload_shape_finite_values_and_actual_encoded_bound_are_enforced() -> DomainResult<()> {
    assert!(
        serde_json::from_value::<input::Payload>(
            serde_json::json!({"kind":"event","name":"x","content":"y","at":Timestamp::now(),"url":"https://invalid"})
        )
        .is_err()
    );
    let metric =
        input::Payload::Metric { name: "x".into(), value: f64::NAN, dimensions: BTreeMap::new(), at: Timestamp::now() };
    assert!(metric.validate().is_err());
    let event = input::Payload::Event { name: "x".into(), content: "\u{0001}".repeat(4096), at: Timestamp::now() };
    assert!(event.validate().is_err());
    let ids = [Id::new()];
    input::ids(Id::new(), &ids, 20)?;
    assert!(input::ids(Id::new(), &[ids[0], ids[0]], 20).is_err());
    Ok(())
}
#[test]
fn unowned_or_corrupt_journal_cannot_supply_capacity_or_generation() -> DomainResult<()> {
    let tenant = TenantId::new();
    util::validate_journal(&Journal::default(), tenant)?;
    let mut row = Journal { facts: 1, ..Journal::default() };
    assert!(util::validate_journal(&row, tenant).is_err());
    row.tenant = Some(tenant);
    row.items = vec![Id::new(); 2];
    assert!(util::validate_journal(&row, tenant).is_err());
    Ok(())
}

#[tokio::test]
async fn expired_original_budget_does_not_poll_a_new_permission_or_renew_it() {
    let polled = std::sync::atomic::AtomicBool::new(false);
    let future = async {
        polled.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok::<_, agf_core::error::DomainError>(())
    };
    let deadline = tokio::time::Instant::now() - std::time::Duration::from_millis(1);
    assert!(super::authority::bounded(deadline, future).await.is_err());
    assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn authenticated_item_shape_never_accepts_empty_names_foreign_owner_or_invalid_hash() -> DomainResult<()> {
    let original = item();
    records::item(&original, original.tenant, original.id)?;
    for change in 0..4 {
        let mut row = original.clone();
        match change {
            0 => row.name.clear(),
            1 => row.owner.subject = Some(Id::nil()),
            2 => row.payload_hash = "z".repeat(64),
            _ => row.source.group = "bad\nsource".into(),
        }
        assert!(records::item(&row, row.tenant, row.id).is_err());
    }
    Ok(())
}
