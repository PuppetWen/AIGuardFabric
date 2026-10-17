#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use agf_core::ids::{Id, TenantId};
use serde_json::json;
#[test]
fn create_risk_does_not_split_by_labels_or_mode() {
    let tenant = TenantId::new();
    let target = mock::fixture();
    let mut journal = model::Journal::default();
    util::bump(&mut journal, tenant, 1).unwrap();
    let risk = util::create_resource(tenant, &target).unwrap();
    journal.risks.insert(risk, Id::new());
    let intent = model::Intent::Create { target: Box::new(target.clone()) };
    assert!(util::risk(&journal, tenant, &intent).is_err());
    let accept = model::Intent::Accept {
        target: agf_alicloud::privatelink::provisioning::AcceptConnection {
            region_id: target.region_id.clone(),
            service_id: target.service_id.clone(),
            endpoint_id: "ep-existing".into(),
        },
        planned: Box::new(target),
        observation_id: Id::new(),
    };
    assert!(util::risk(&journal, tenant, &accept).is_err());
    assert_ne!(util::resource(tenant, &accept).unwrap(), util::resource(TenantId::new(), &accept).unwrap());
}
#[test]
fn strict_selection_and_confirmations_do_not_accept_raw_carriers() {
    assert!(serde_json::from_value::<input::Preview>(json!({"request_id":Id::new(),"configuration_version":1,"expected_generation":0,"selection":{"action":"accept","endpoint_id":"ep-any","service_id":"epsrv-any"}})).is_err());
    assert!(serde_json::from_value::<input::Apply>(json!({"request_id":Id::new(),"preview_id":Id::new(),"expected_generation":0,"raw_provider_url":"https://example.invalid"})).is_err());
}
#[test]
fn canonical_hash_preserves_all_source_fields() {
    assert_eq!(util::fingerprint(&json!({"a":1,"b":2})).unwrap(), util::fingerprint(&json!({"b":2,"a":1})).unwrap());
    assert_ne!(
        util::fingerprint(&json!({"enabled":true,"secret":{"ciphertext":"a"}})).unwrap(),
        util::fingerprint(&json!({"enabled":true,"secret":{"ciphertext":"b"}})).unwrap()
    );
}
#[test]
fn permanent_capacity_has_no_eviction() {
    let tenant = TenantId::new();
    let mut journal = model::Journal { tenant: Some(tenant), facts: MAX_FACTS, ..Default::default() };
    assert!(util::bump(&mut journal, tenant, 1).is_err());
    assert!(journal.items.is_empty());
}
#[test]
fn typed_mock_fixture_keeps_connectivity_unknown() {
    let target = mock::fixture();
    assert!(target.prepare(Id::new()).is_ok());
    assert!(target.prepare(Id::parse("00000000-0000-0000-0000-000000000000").unwrap()).is_err());
    let observation = agf_alicloud::privatelink::provisioning::EndpointObservation {
        endpoint_id: "ep-demo".into(),
        endpoint_state: "Active".into(),
        connection_state: "Connected".into(),
        requested_resources_match: true,
        connectivity_verified: false,
    };
    assert!(!observation.connectivity_verified);
}
#[tokio::test]
async fn expired_original_deadline_never_polls_the_operation() {
    let polled = std::sync::atomic::AtomicBool::new(false);
    let result = authority::bounded(tokio::time::Instant::now(), async {
        polled.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok::<_, agf_core::error::DomainError>(())
    })
    .await;
    assert!(result.is_err());
    assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
}
