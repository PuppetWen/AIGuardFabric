#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Actual signed loopback POSTs; no cloud credentials or recording-transport responses.
mod privatelink_provisioning_transport_support;

use agf_alicloud::privatelink::provisioning::{AcceptConnection, CreateEndpoint, WriteStatus, Zone, dispatch_once};
use agf_core::{error::DomainResult, ids::Id};
use privatelink_provisioning_transport_support::{
    Authority, Gate, Server, client, fixture_error, query, verify_signature,
};
use serde_json::json;
use std::sync::Arc;
use tokio::time::{Duration, Instant};

fn target() -> CreateEndpoint {
    CreateEndpoint {
        region_id: "cn-hangzhou".into(),
        service_region_id: "cn-hangzhou".into(),
        service_id: "epsrv-ownedservice".into(),
        vpc_id: "vpc-ownedvpc".into(),
        name: "AGF-private".into(),
        zones: vec![Zone { zone_id: "cn-hangzhou-b".into(), vswitch_id: "vsw-ownedswitch".into() }],
        security_group_ids: vec!["sg-ownedgroup".into()],
        cross_region_bandwidth: None,
    }
}

fn ack() -> privatelink_provisioning_transport_support::Reply {
    privatelink_provisioning_transport_support::Reply::json(&json!({
        "RequestId":"0ed8d006-f706-4d23-88ed-e11ed28dcac0", "EndpointId":"ep-ownedendpoint"
    }))
}

#[tokio::test]
async fn create_is_one_signed_official_post_with_original_token_and_exact_selected_resources() -> DomainResult<()> {
    let original = Id::new();
    let server = Server::start(move |request| {
        let values = query(request)?;
        let expected = [
            ("ClientToken", original.to_string()),
            ("RegionId", "cn-hangzhou".into()),
            ("ServiceRegionId", "cn-hangzhou".into()),
            ("ServiceId", "epsrv-ownedservice".into()),
            ("VpcId", "vpc-ownedvpc".into()),
            ("EndpointName", "AGF-private".into()),
            ("EndpointType", "Interface".into()),
            ("DryRun", "false".into()),
            ("ProtectedEnabled", "true".into()),
            ("AddressIpVersion", "IPv4".into()),
            ("ZonePrivateIpAddressCount", "1".into()),
            ("Zone.1.ZoneId", "cn-hangzhou-b".into()),
            ("Zone.1.VSwitchId", "vsw-ownedswitch".into()),
            ("SecurityGroupId.1", "sg-ownedgroup".into()),
        ];
        if request.method != "POST"
            || !request.body.is_empty()
            || values.len() != expected.len()
            || expected.iter().any(|(key, value)| values.get(*key) != Some(value))
            || request.headers.get("x-acs-action").map(String::as_str) != Some("CreateVpcEndpoint")
        {
            return Err(fixture_error("create wire parameters differ"));
        }
        Ok(ack())
    })
    .await?;
    let evidence = dispatch_once(
        &client(&server)?,
        &target().prepare(original)?,
        &Authority::default(),
        Instant::now() + Duration::from_secs(3),
    )
    .await?;
    server.settled(1).await?;
    verify_signature(&server.requests()?[0], &server.origin)?;
    assert_eq!(evidence.status, WriteStatus::Acknowledged);
    assert_eq!(evidence.endpoint_id.as_deref(), Some("ep-ownedendpoint"));
    assert!(evidence.authority_current && evidence.original_deadline_current);
    Ok(())
}

#[tokio::test]
async fn provider_acceptance_is_its_own_single_post_and_never_implicitly_creates_an_endpoint() -> DomainResult<()> {
    let original = Id::new();
    let server = Server::start(move |request| {
        let values = query(request)?;
        if request.headers.get("x-acs-action").map(String::as_str) != Some("EnableVpcEndpointConnection")
            || values.len() != 5
            || values.get("ClientToken") != Some(&original.to_string())
            || values.get("EndpointId").map(String::as_str) != Some("ep-ownedendpoint")
            || values.get("ServiceId").map(String::as_str) != Some("epsrv-ownedservice")
            || values.get("RegionId").map(String::as_str) != Some("cn-hangzhou")
            || values.get("DryRun").map(String::as_str) != Some("false")
        {
            return Err(fixture_error("accept wire parameters differ"));
        }
        Ok(privatelink_provisioning_transport_support::Reply::json(&json!({
            "RequestId":"0ed8d006-f706-4d23-88ed-e11ed28dcac0"
        })))
    })
    .await?;
    let planned = AcceptConnection {
        region_id: "cn-hangzhou".into(),
        service_id: "epsrv-ownedservice".into(),
        endpoint_id: "ep-ownedendpoint".into(),
    }
    .prepare(original)?;
    let evidence =
        dispatch_once(&client(&server)?, &planned, &Authority::default(), Instant::now() + Duration::from_secs(3))
            .await?;
    server.settled(1).await?;
    verify_signature(&server.requests()?[0], &server.origin)?;
    assert_eq!(evidence.status, WriteStatus::Acknowledged);
    Ok(())
}

#[tokio::test]
async fn revoked_authority_and_expired_original_deadline_each_send_zero_requests() -> DomainResult<()> {
    let server = Server::start(|_| Ok(ack())).await?;
    let authority = Authority::default();
    authority.revoke();
    let planned = target().prepare(Id::new())?;
    assert!(
        dispatch_once(&client(&server)?, &planned, &authority, Instant::now() + Duration::from_secs(2)).await.is_err()
    );
    assert!(dispatch_once(&client(&server)?, &planned, &Authority::default(), Instant::now()).await.is_err());
    assert!(server.requests()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn revocation_after_the_provider_received_one_post_preserves_the_known_ack() -> DomainResult<()> {
    let gate = Arc::new(Gate::default());
    let release = gate.release_on_drop();
    let held = gate.clone();
    let server = Server::start(move |_| Ok(ack().held(&held))).await?;
    let authority = Authority::default();
    let rpc = client(&server)?;
    let planned = target().prepare(Id::new())?;
    let change = dispatch_once(&rpc, &planned, &authority, Instant::now() + Duration::from_secs(3));
    let revoke = async {
        gate.wait_entered().await?;
        authority.revoke();
        gate.release();
        Ok::<(), agf_core::error::DomainError>(())
    };
    let (result, revoked) = tokio::join!(change, revoke);
    revoked?;
    drop(release);
    let evidence = result?;
    server.settled(1).await?;
    assert_eq!(evidence.status, WriteStatus::Acknowledged);
    assert!(!evidence.authority_current);
    assert!(evidence.attempted);
    Ok(())
}

#[tokio::test]
async fn a_lost_reply_is_unknown_after_one_actual_post_without_an_implicit_retry() -> DomainResult<()> {
    let server = Server::start(|_| Ok(privatelink_provisioning_transport_support::Reply::lost())).await?;
    let evidence = dispatch_once(
        &client(&server)?,
        &target().prepare(Id::new())?,
        &Authority::default(),
        Instant::now() + Duration::from_secs(3),
    )
    .await?;
    server.settled(1).await?;
    assert_eq!(evidence.status, WriteStatus::Unknown);
    assert!(evidence.attempted && evidence.provider_request_id.is_none());
    assert!(evidence.endpoint_id.is_none());
    Ok(())
}

#[tokio::test]
async fn original_budget_expiry_keeps_one_unknown_attempt_even_if_a_reply_arrives_later() -> DomainResult<()> {
    let gate = Arc::new(Gate::default());
    let release = gate.release_on_drop();
    let held = gate.clone();
    let server = Server::start(move |_| Ok(ack().held(&held))).await?;
    let evidence = dispatch_once(
        &client(&server)?,
        &target().prepare(Id::new())?,
        &Authority::default(),
        Instant::now() + Duration::from_secs(1),
    )
    .await?;
    gate.wait_entered().await?;
    drop(release);
    server.settled(1).await?;
    assert_eq!(evidence.status, WriteStatus::Unknown);
    assert!(!evidence.original_deadline_current);
    assert!(evidence.attempted);
    Ok(())
}
