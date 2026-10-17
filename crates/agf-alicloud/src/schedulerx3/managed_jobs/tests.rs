use super::*;
use crate::{
    http::RpcResponse,
    schedulerx3::native_observation::{Observation, Scope, parse_current},
};
use agf_core::error::{DomainError, DomainResult};
use serde_json::{Value, json};

fn fixture() -> DomainResult<(RpcResponse, RpcResponse)> {
    let fixture: Value = serde_json::from_str(include_str!("../native_observation/owned_fixture.json"))?;
    Ok((response(fixture["GetApp"].clone()), response(fixture["ListJobs"].clone())))
}
fn response(body: Value) -> RpcResponse {
    RpcResponse { status: 200, body, raw: String::new() }
}
fn observed(app: &RpcResponse, page: &RpcResponse) -> DomainResult<Observation> {
    parse_current(
        &Scope { cluster_id: "cluster-agf-demo".into(), app_name: "app-agf-demo".into() },
        app,
        std::slice::from_ref(page),
    )
}
fn selection(current: &Observation, index: usize) -> Selection {
    Selection {
        kind: Kind::Report,
        app_id: current.app().id.clone(),
        job_id: current.jobs()[index].id.clone(),
        observation_fingerprint: current.fingerprint().into(),
    }
}
fn update() -> Change {
    Change::UpdateSchedule { patch: SchedulePatch { max_attempt: Some(0), ..SchedulePatch::default() } }
}

#[test]
fn canonical_large_ids_and_explicit_null_boundaries_are_preserved() -> DomainResult<()> {
    assert_eq!(validate::identifier("9223372036854775807")?, i64::MAX);
    for id in ["", "0", "+1", "01", " 1", "9223372036854775808"] {
        assert!(validate::identifier(id).is_err());
    }
    for raw in [json!({"max_attempt":null}), json!({"timezone":null}), json!({"parameters":"opaque"})] {
        assert!(serde_json::from_value::<SchedulePatch>(raw).is_err());
    }
    for action in ["enable", "disable"] {
        for field in ["status", "parameters", "callback_token"] {
            assert!(serde_json::from_value::<Change>(json!({"action":action,field:null})).is_err());
        }
        let exact = json!({"action":action});
        let parsed: Change = serde_json::from_value(exact.clone())?;
        assert_eq!(serde_json::to_value(parsed)?, exact);
    }
    assert!(serde_json::from_value::<Change>(json!({"action":"enable","status":1})).is_err());
    assert!(SchedulePatch::default().validate().is_err());
    assert!(SchedulePatch { time_type: Some(2), ..SchedulePatch::default() }.validate().is_err());
    Ok(())
}

#[test]
fn update_changes_only_reviewed_controls_and_never_implicitly_enables() -> DomainResult<()> {
    let (app, mut page) = fixture()?;
    let current = observed(&app, &page)?;
    let plan = prepare(&current, &selection(&current, 0), &update())?;
    assert_eq!(plan.action(), "UpdateJob");
    assert_eq!(
        plan.input(),
        &json!({"ClusterId":"cluster-agf-demo","AppName":"app-agf-demo",
        "JobId":9_007_199_254_741_001_i64,"MaxAttempt":0})
    );
    page.body["Data"]["Records"][0]["MaxAttempt"] = json!(0);
    assert_eq!(compare_readback(&plan, &observed(&app, &page)?), Readback::Matched);
    assert_eq!(current.jobs()[0].max_attempt, Some(1));
    assert_eq!(current.jobs()[0].enabled, Some(false));
    assert!(!serde_json::to_string(plan.input())?.contains("SYNTHETIC"));
    Ok(())
}

#[test]
fn active_unknown_and_non_http_jobs_cannot_be_updated_or_implicitly_disabled() -> DomainResult<()> {
    let (app, mut page) = fixture()?;
    let current = observed(&app, &page)?;
    for index in [1, 4, 5] {
        assert!(prepare(&current, &selection(&current, index), &update()).is_err());
    }
    assert!(prepare(&current, &selection(&current, 0), &Change::Disable).is_err());
    assert!(prepare(&current, &selection(&current, 1), &Change::Enable).is_err());
    let disable = prepare(&current, &selection(&current, 1), &Change::Disable)?;
    assert_eq!(disable.action(), "OperateDisableJobs");
    assert_eq!(disable.input()["JobIds"], json!([9_007_199_254_741_002_i64]));
    page.body["Data"]["Records"][1]["Status"] = json!(0);
    let disabled = observed(&app, &page)?;
    assert_eq!(compare_readback(&disable, &disabled), Readback::Matched);
    assert_eq!(prepare(&disabled, &selection(&disabled, 1), &Change::Enable)?.action(), "OperateEnableJobs");
    Ok(())
}

#[test]
fn source_app_and_opaque_carrier_drift_invalidate_the_original_selection() -> DomainResult<()> {
    let (app, mut page) = fixture()?;
    let current = observed(&app, &page)?;
    let mut selected = selection(&current, 0);
    selected.app_id = "1".into();
    assert!(prepare(&current, &selected, &update()).is_err());
    selected = selection(&current, 0);
    page.body["Data"]["Records"][0]["Parameters"] = json!("changed-private-value");
    assert!(prepare(&observed(&app, &page)?, &selected, &update()).is_err());
    selected.observation_fingerprint = "A".repeat(64);
    assert!(prepare(&current, &selected, &update()).is_err());
    Ok(())
}

#[test]
fn matching_status_does_not_hide_carrier_or_unmanaged_schedule_changes() -> DomainResult<()> {
    let (app, page) = fixture()?;
    let current = observed(&app, &page)?;
    let plan = prepare(&current, &selection(&current, 0), &Change::Enable)?;
    let mut enabled = page.clone();
    enabled.body["Data"]["Records"][0]["Status"] = json!(1);
    assert_eq!(compare_readback(&plan, &observed(&app, &enabled)?), Readback::Matched);
    for (field, value) in [
        ("Parameters", json!("other carrier")),
        ("RouteStrategy", json!(3)),
        ("Name", json!("changed name")),
        ("TimeExpression", json!("0 0/10 * * * ?")),
        ("MaxAttempt", json!(2)),
    ] {
        let mut changed = enabled.clone();
        changed.body["Data"]["Records"][0][field] = value;
        assert_eq!(compare_readback(&plan, &observed(&app, &changed)?), Readback::Different);
    }
    let unknown = WriteEvidence {
        attempted: true,
        status: WriteStatus::Unknown,
        provider_request_id: None,
        authority_current: true,
        original_deadline_current: true,
    };
    assert_eq!(unknown.status, WriteStatus::Unknown);
    Ok(())
}

#[test]
fn none_schedule_needs_explicit_expression_clear_and_calendar_clear_is_preserved() -> DomainResult<()> {
    let (app, page) = fixture()?;
    let current = observed(&app, &page)?;
    let mut patch = SchedulePatch { time_type: Some(-1), ..SchedulePatch::default() };
    assert!(prepare(&current, &selection(&current, 0), &Change::UpdateSchedule { patch: patch.clone() }).is_err());
    patch.time_expression = Some(String::new());
    patch.calendar = Some(String::new());
    let plan = prepare(&current, &selection(&current, 0), &Change::UpdateSchedule { patch })?;
    assert_eq!(plan.input()["TimeExpression"], json!(""));
    assert_eq!(plan.input()["Calendar"], json!(""));
    Ok(())
}

#[test]
fn six_mock_declarations_are_explicit_single_worker_and_never_a_live_http_carrier() -> DomainResult<()> {
    let (app, page) = fixture()?;
    let current = observed(&app, &page)?;
    for kind in
        [Kind::AssetInventory, Kind::LogPull, Kind::RedteamCruise, Kind::RuleHotReload, Kind::Report, Kind::Archive]
    {
        let declaration = MockDeclaration {
            kind,
            name: kind.runtime_name().into(),
            total: 1,
            schedule: SchedulePatch {
                time_type: Some(1),
                time_expression: Some("0 0/5 * * * ?".into()),
                timezone: Some("UTC".into()),
                max_attempt: Some(1),
                attempt_interval: Some(30),
                calendar: None,
            },
        };
        declaration.validate()?;
        assert!(matches!(
            prepare(&current, &selection(&current, 0), &Change::CreateDisabled { declaration: declaration.clone() }),
            Err(DomainError::PreconditionFailed(_))
        ));
        assert!(MockDeclaration { total: 2, ..declaration }.validate().is_err());
    }
    assert_eq!(Kind::Report.runtime_name(), "report-generate");
    assert_eq!(Kind::Archive.runtime_name(), "cold-archive");
    Ok(())
}
