use super::{
    MAX_EVIDENCE_BYTES, MAX_JOBS, MAX_RESPONSE_BYTES, parse_current,
    tests::{fixture, page, scope},
};
use agf_core::error::{DomainError, DomainResult};
use serde_json::json;

#[test]
fn foreign_application_identity_and_bad_job_ids_never_publish() -> DomainResult<()> {
    let (app, original) = fixture()?;
    let mut foreign_app = app.clone();
    foreign_app.body["Data"]["AppName"] = json!("other-app");
    assert!(parse_current(&scope(), &foreign_app, std::slice::from_ref(&original)).is_err());
    for (key, value) in [("AppName", json!("other-app")), ("AppGroupId", json!(123)), ("AppGroupId", json!({}))] {
        let mut foreign_job = original.clone();
        foreign_job.body["Data"]["Records"][0][key] = value;
        assert!(parse_current(&scope(), &app, &[foreign_job]).is_err());
    }
    for id in [json!(0), json!(-1), json!(1.5), json!("01"), json!("+1"), json!("9223372036854775808"), json!(null)] {
        let mut invalid = original.clone();
        invalid.body["Data"]["Records"][0]["JobId"] = id;
        assert!(parse_current(&scope(), &app, &[invalid]).is_err());
    }
    Ok(())
}

#[test]
fn optional_fields_preserve_unknown_and_reject_explicit_bad_types_or_conflicting_aliases() -> DomainResult<()> {
    let (app, original) = fixture()?;
    let mut absent = page(1, 1, 1, 1);
    absent.body["Data"]["Records"][0]["Status"] = json!(null);
    let observation = parse_current(&scope(), &app, &[absent])?;
    assert_eq!(observation.jobs()[0].enabled, None);
    assert_eq!(observation.jobs()[0].schedule.zone, None);
    for (key, value) in [
        ("Status", json!(2)),
        ("Status", json!(false)),
        ("TimeType", json!("1")),
        ("Parameters", json!({"headers":{}})),
        ("MaxAttempt", json!(-1)),
        ("Name", json!("forged\nname")),
    ] {
        let mut invalid = original.clone();
        invalid.body["Data"]["Records"][0][key] = value;
        assert!(parse_current(&scope(), &app, &[invalid]).is_err());
    }
    let mut aliases = original.clone();
    aliases.body["Data"]["Records"][0]["TimeZone"] = json!("Asia/Shanghai");
    assert!(parse_current(&scope(), &app, &[aliases]).is_err());
    let mut aliases = original.clone();
    aliases.body["Data"]["Records"][0]["XAttrs"] = json!("secret-other-attributes");
    assert!(parse_current(&scope(), &app, &[aliases]).is_err());
    let mut equal = original;
    equal.body["Data"]["Records"][0]["TimeZone"] = json!("UTC");
    equal.body["Data"]["Records"][0]["XAttrs"] = json!(null);
    parse_current(&scope(), &app, &[equal])?;
    Ok(())
}

#[test]
fn provider_http_and_envelope_errors_are_redacted_and_never_mean_empty() -> DomainResult<()> {
    let (app, original) = fixture()?;
    for status in [401, 403, 404, 500] {
        let mut failed = original.clone();
        failed.status = status;
        failed.body["Message"] = json!("SYNTHETIC-SECRET-IN-ERROR");
        let error = parse_current(&scope(), &app, &[failed]).err();
        assert!(error.is_some());
        assert!(!format!("{error:?}").contains("SYNTHETIC-SECRET"));
        if status == 403 {
            assert!(matches!(error, Some(DomainError::Forbidden(_))));
        }
    }
    for (key, value) in [
        ("Code", json!("200")),
        ("Success", json!(false)),
        ("RequestId", json!("")),
        ("RequestId", json!("forged\nreceipt")),
    ] {
        let mut failed = original.clone();
        failed.body[key] = value;
        assert!(parse_current(&scope(), &app, &[failed]).is_err());
    }
    Ok(())
}

#[test]
fn record_response_carrier_and_accumulated_evidence_budgets_are_enforced() -> DomainResult<()> {
    let (app, original) = fixture()?;
    assert!(parse_current(&scope(), &app, &[page(1, MAX_JOBS + 1, 1, 100)]).is_err());
    let mut oversized = original.clone();
    oversized.body["Data"]["IgnoredField"] = json!("x".repeat(MAX_RESPONSE_BYTES));
    assert!(parse_current(&scope(), &app, &[oversized]).is_err());
    let mut carrier = original;
    carrier.body["Data"]["Records"][0]["Parameters"] = json!("x".repeat(65_537));
    assert!(parse_current(&scope(), &app, &[carrier]).is_err());
    let pad = "x".repeat(MAX_EVIDENCE_BYTES / 3);
    let mut pages = [page(1, 201, 1, 100), page(2, 201, 101, 100), page(3, 201, 201, 1)];
    for page in &mut pages {
        page.body["Data"]["IgnoredField"] = json!(pad);
        assert!(serde_json::to_vec(&page.body)?.len() < MAX_RESPONSE_BYTES);
    }
    assert!(parse_current(&scope(), &app, &pages).is_err());
    Ok(())
}

#[test]
fn exactly_twenty_complete_pages_are_allowed_and_provider_order_does_not_change_the_fingerprint() -> DomainResult<()> {
    let (app, original) = fixture()?;
    let pages: Vec<_> = (1..=20).map(|number| page(number, 2_000, (number - 1) * 100 + 1, 100)).collect();
    let full = parse_current(&scope(), &app, &pages)?;
    assert_eq!(full.jobs().len(), 2_000);
    assert_eq!(full.pagination().pages.len(), 20);
    let baseline = parse_current(&scope(), &app, std::slice::from_ref(&original))?;
    let mut reordered = original;
    if let Some(records) = reordered.body["Data"]["Records"].as_array_mut() {
        records.reverse();
    }
    let fresh = parse_current(&scope(), &app, &[reordered])?;
    assert_eq!(baseline.fingerprint(), fresh.fingerprint());
    Ok(())
}
