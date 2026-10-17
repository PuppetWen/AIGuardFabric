use super::{
    codec,
    model::{Delivery, Evidence, Fact, Intent, MockEndpoint, MockRecord, Values, Write},
    util,
};
use crate::state::AppState;
use agf_alicloud::privatelink::provisioning::EndpointObservation;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{TenantId, deterministic_id},
    time::Timestamp,
};
pub(super) fn fixture() -> agf_alicloud::privatelink::provisioning::CreateEndpoint {
    agf_alicloud::privatelink::provisioning::CreateEndpoint {
        region_id: "cn-hangzhou".into(),
        service_region_id: "cn-hangzhou".into(),
        service_id: "epsrv-agf-demo".into(),
        vpc_id: "vpc-agf-demo".into(),
        name: "AgfDemoEndpoint".into(),
        zones: vec![agf_alicloud::privatelink::provisioning::Zone {
            zone_id: "cn-hangzhou-a".into(),
            vswitch_id: "vsw-agf-demo".into(),
        }],
        security_group_ids: vec!["sg-agf-demo".into()],
        cross_region_bandwidth: None,
    }
}
fn record(state: &AppState, tenant: TenantId, values: &Values) -> DomainResult<Option<MockRecord>> {
    let row = codec::read::<MockRecord>(state, tenant, values, &util::mock_key(tenant))?;
    if row.as_ref().is_some_and(|r| {
        r.tenant != Some(tenant)
            || r.endpoints.len() > 256
            || r.endpoints.iter().any(|(id, e)| {
                !id.starts_with("ep-")
                    || id.len() > 67
                    || agf_alicloud::privatelink::provisioning::validate_reference(&e.plan, id).is_err()
                    || !["Connecting", "Connected"].contains(&e.connection.as_str())
            })
    }) {
        return Err(util::corrupt());
    }
    Ok(row)
}
pub(super) fn apply(
    state: &AppState,
    tenant: TenantId,
    values: &Values,
    writes: &mut Values,
    fact: &Fact,
    seed: bool,
) -> DomainResult<Write> {
    let intent = fact.intent.as_ref().ok_or_else(util::corrupt)?;
    let mut row = match record(state, tenant, values)? {
        Some(row) => row,
        None if seed && intent.planned() == &fixture() => MockRecord { tenant: Some(tenant), ..MockRecord::default() },
        None if seed
            && matches!(intent,Intent::Accept{target,planned,..} if target.endpoint_id=="ep-agf-demo" && is_existing_fixture(planned)) =>
        {
            let mut record = MockRecord { tenant: Some(tenant), ..MockRecord::default() };
            record.endpoints.insert(
                "ep-agf-demo".into(),
                MockEndpoint { plan: Box::new(intent.planned().clone()), connection: "Connected".into() },
            );
            record
        }
        None => {
            return Err(DomainError::PreconditionFailed(
                "Mock has no owned fixture; explicitly initialize the exact demo tuple".into(),
            ));
        }
    };
    if matches!(intent, Intent::Create { .. }) && row.endpoints.len() >= 256 {
        return Err(util::capacity());
    }
    let endpoint = match intent {
        Intent::Create { target } => {
            let id = format!("ep-{}", &fact.id.to_string().replace('-', "")[..24]);
            if row.endpoints.contains_key(&id) {
                return Err(util::conflict());
            }
            row.endpoints.insert(id.clone(), MockEndpoint { plan: target.clone(), connection: "Connecting".into() });
            id
        }
        Intent::Accept { target, planned, .. } => {
            let existing = row.endpoints.get_mut(&target.endpoint_id).ok_or_else(|| {
                DomainError::PreconditionFailed("Mock does not invent an existing external endpoint".into())
            })?;
            if existing.plan.as_ref() != planned.as_ref() {
                return Err(util::conflict());
            }
            existing.connection = "Connected".into();
            target.endpoint_id.clone()
        }
    };
    row.writes = row.writes.checked_add(1).ok_or_else(util::capacity)?;
    codec::put(state, tenant, writes, util::mock_key(tenant), &row)?;
    Ok(Write {
        delivery: Delivery::Acknowledged,
        provider_request_id: Some(deterministic_id("agf.privatelink.mock.ack.v1", &format!("{tenant}:{}", fact.id))),
        endpoint_id: Some(endpoint),
        finished_at: Timestamp::now(),
    })
}
pub(super) fn observe(
    state: &AppState,
    tenant: TenantId,
    values: &Values,
    writes: &mut Values,
    original: &Fact,
) -> DomainResult<Evidence> {
    let Some(super::model::ResultData::Write { outcome }) = &original.result else { return Err(util::conflict()) };
    if outcome.delivery != Delivery::Acknowledged {
        return Err(util::conflict());
    }
    let endpoint = outcome.endpoint_id.as_ref().ok_or_else(util::corrupt)?;
    let mut row = record(state, tenant, values)?.ok_or_else(util::corrupt)?;
    let existing = row.endpoints.get(endpoint).ok_or_else(util::corrupt)?;
    let evidence = Evidence {
        plan: existing.plan.clone(),
        observation: EndpointObservation {
            endpoint_id: endpoint.clone(),
            endpoint_state: "Active".into(),
            connection_state: existing.connection.clone(),
            requested_resources_match: true,
            connectivity_verified: false,
        },
        checked_at: Timestamp::now(),
        original_create_id: Some(original.id),
        inventory_scope_id: None,
        inventory_payload_hash: None,
    };
    if original.intent.as_ref().ok_or_else(util::corrupt)?.planned() != existing.plan.as_ref() {
        return Err(util::conflict());
    }
    row.reads = row.reads.checked_add(1).ok_or_else(util::capacity)?;
    codec::put(state, tenant, writes, util::mock_key(tenant), &row)?;
    Ok(evidence)
}

fn is_existing_fixture(plan: &agf_alicloud::privatelink::provisioning::CreateEndpoint) -> bool {
    let mut expected = fixture();
    expected.service_region_id = "cn-beijing".into();
    expected.name = "ObservedExistingEndpoint".into();
    plan == &expected
}
