use super::*;
use crate::http::RpcResponse;
use agf_core::error::{DomainError, DomainResult};
use serde_json::{Value, json};

pub(super) fn scope() -> Scope {
    Scope { cluster_id: "cluster-agf-demo".into(), app_name: "app-agf-demo".into() }
}

pub(super) fn response(body: Value) -> RpcResponse {
    RpcResponse { status: 200, body, raw: String::new() }
}

pub(super) fn fixture() -> DomainResult<(RpcResponse, RpcResponse)> {
    let fixture: Value = serde_json::from_str(include_str!("owned_fixture.json"))?;
    Ok((response(fixture["GetApp"].clone()), response(fixture["ListJobs"].clone())))
}

pub(super) fn page(number: u32, total: u32, first: u32, length: u32) -> RpcResponse {
    let records: Vec<_> = (first..first + length)
        .map(|id| json!({"JobId":id,"AppName":"app-agf-demo","Name":format!("job-{id}"),"JobType":"http"}))
        .collect();
    response(json!({"Code":200,"Success":true,"RequestId":format!("req-page-{number}"),
        "Data":{"Total":total,"PageNumber":number,"PageSize":100,"Records":records}}))
}

#[test]
fn the_owned_fixture_is_complete_but_does_not_prove_http_or_utc_defaults() -> DomainResult<()> {
    let (app, page) = fixture()?;
    let observation = parse_current(&scope(), &app, &[page])?;
    assert_eq!(observation.app().id, "9007199254740993");
    assert_eq!(observation.pagination().total, 6);
    assert!(observation.pagination().listing_complete);
    assert!(!observation.pagination().strong_snapshot);
    assert_eq!(observation.jobs()[0].schedule.utc, Some(true));
    assert_eq!(observation.jobs()[0].shard_count, None);
    assert_eq!(observation.jobs()[2].schedule.utc, None);
    assert_eq!(observation.jobs()[3].schedule.utc, Some(false));
    assert_eq!(observation.jobs()[5].enabled, None);
    assert!(!observation.jobs()[5].http_job);
    assert!(observation.jobs().iter().all(|job| !job.http.verified));
    Ok(())
}

#[test]
fn secret_bodies_never_appear_in_serialized_or_debug_observations() -> DomainResult<()> {
    let (app, page) = fixture()?;
    let observation = parse_current(&scope(), &app, &[page])?;
    let serialized = serde_json::to_string(&observation)?;
    let debug = format!("{observation:?}");
    for secret in ["SYNTHETIC-APP-TOKEN", "SYNTHETIC-CALLBACK-TOKEN", "SYNTHETIC-SCRIPT-BODY", "opaque-http-handler"] {
        assert!(!serialized.contains(secret));
        assert!(!debug.contains(secret));
    }
    assert_eq!(observation.jobs()[0].http.parameters, CarrierPresence::Present);
    assert_eq!(observation.jobs()[1].http.parameters, CarrierPresence::Empty);
    assert_eq!(observation.jobs()[2].http.parameters, CarrierPresence::Null);
    assert_eq!(observation.jobs()[3].http.parameters, CarrierPresence::Missing);
    Ok(())
}

#[test]
fn receipts_and_application_tokens_do_not_change_the_fingerprint_but_carrier_changes_do() -> DomainResult<()> {
    let (mut app, mut page) = fixture()?;
    let original = parse_current(&scope(), &app, &[page.clone()])?;
    app.body["RequestId"] = json!("new-app-receipt");
    app.body["Data"]["AccessToken"] = json!("new-synthetic-secret");
    page.body["RequestId"] = json!("new-page-receipt");
    let fresh = parse_current(&scope(), &app, &[page.clone()])?;
    assert_eq!(fresh.fingerprint(), original.fingerprint());
    page.body["Data"]["Records"][0]["Parameters"] = json!("changed-private-body");
    let changed = parse_current(&scope(), &app, &[page])?;
    assert_ne!(changed.fingerprint(), original.fingerprint());
    Ok(())
}

#[test]
fn an_explicit_zero_has_a_real_page_and_is_distinct_from_no_evidence() -> DomainResult<()> {
    let (app, _) = fixture()?;
    let empty = parse_current(&scope(), &app, &[page(1, 0, 1, 0)])?;
    assert_eq!(empty.pagination().total, 0);
    assert!(empty.jobs().is_empty());
    assert!(matches!(parse_current(&scope(), &app, &[]), Err(DomainError::PreconditionFailed(_))));
    Ok(())
}

#[test]
fn complete_multi_page_observation_preserves_large_int64_string_ids() -> DomainResult<()> {
    let (app, _) = fixture()?;
    let observation = parse_current(&scope(), &app, &[page(1, 101, 1, 100), page(2, 101, 101, 1)])?;
    assert_eq!(observation.jobs().len(), 101);
    assert_eq!(observation.pagination().pages.len(), 2);
    let mut maximum = page(1, 1, 1, 1);
    maximum.body["Data"]["Records"][0]["JobId"] = json!(i64::MAX.to_string());
    let exact = parse_current(&scope(), &app, &[maximum])?;
    assert_eq!(exact.jobs()[0].id, "9223372036854775807");
    Ok(())
}

#[test]
fn all_paging_drift_duplicates_and_incomplete_shapes_are_rejected() -> DomainResult<()> {
    let (app, _) = fixture()?;
    assert!(parse_current(&scope(), &app, &[page(1, 101, 1, 100)]).is_err());
    assert!(parse_current(&scope(), &app, &[page(1, 101, 1, 100), page(2, 102, 101, 2)]).is_err());
    assert!(parse_current(&scope(), &app, &[page(1, 101, 1, 100), page(2, 101, 1, 1)]).is_err());
    assert!(parse_current(&scope(), &app, &[page(2, 1, 1, 1)]).is_err());
    assert!(parse_current(&scope(), &app, &[page(1, 101, 1, 99), page(2, 101, 100, 2)]).is_err());
    assert!(parse_current(&scope(), &app, &[page(1, 101, 1, 100), page(2, 101, 101, 0)]).is_err());
    assert!(parse_current(&scope(), &app, &[page(1, 1, 1, 1), page(2, 1, 2, 0)]).is_err());
    for key in ["Total", "PageNumber", "PageSize", "Records"] {
        let mut missing = page(1, 1, 1, 1);
        if let Some(data) = missing.body["Data"].as_object_mut() {
            data.remove(key);
        }
        assert!(parse_current(&scope(), &app, &[missing]).is_err());
    }
    Ok(())
}

#[test]
fn mock_observation_never_initializes_and_repeated_explicit_seed_preserves_the_example() -> DomainResult<()> {
    let mut mock = MockState::default();
    assert!(matches!(mock.observe(&scope()), Err(DomainError::PreconditionFailed(_))));
    assert!(!format!("{mock:?}").contains("SYNTHETIC"));
    mock.seed_owned_fixture(&scope())?;
    let original = mock.observe(&scope())?;
    mock.seed_owned_fixture(&scope())?;
    assert_eq!(original, mock.observe(&scope())?);
    let unknown = Scope { cluster_id: "other-cluster".into(), app_name: "app-agf-demo".into() };
    assert!(mock.observe(&unknown).is_err());
    assert!(mock.seed_owned_fixture(&unknown).is_err());
    assert_eq!(original, mock.observe(&scope())?);
    Ok(())
}
