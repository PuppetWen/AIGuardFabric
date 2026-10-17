//! Deterministic precision boundaries reproduce the cause of intermittent receipt failures.
use super::super::{records::Values, tests_proof_support as fixture, util};
use super::{
    codec,
    input::ApplyInput,
    model::{Operation, State},
    mutation,
};
use crate::state::AppState;
use agf_alicloud::schedulerx3::managed_jobs::{Kind, Readback, WriteEvidence, WriteStatus};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};
use serde_json::json;
use std::collections::BTreeMap;

fn state() -> DomainResult<AppState> {
    let config: BTreeMap<String, String> = [
        ("AGF_ENV", "test"),
        ("AGF_MOCK_MODE", "1"),
        ("AGF_JWT_SECRET", "owned-size-test-secret-at-least-32-bytes"),
        ("AGF_MASTER_KEY_BASE64", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    AppState::offline(agf_core::config::from_env_map(&config)?)
}
fn at(text: &str) -> DomainResult<Timestamp> {
    Timestamp::parse_rfc3339(text).map_err(DomainError::Config)
}
fn row() -> DomainResult<Operation> {
    let target = fixture::target()?;
    let now = at("2026-10-02T00:00:00Z")?;
    Ok(Operation {
        tenant: target.tenant,
        request_id: Id::new(),
        actor: Id::new(),
        claim_id: Id::new(),
        input_hash: String::new(),
        input: ApplyInput {
            preview_id: Id::new(),
            preview_fingerprint: "a".repeat(64),
            confirm_no_cloud_cas: true,
            confirm_callback_unknown: true,
            confirm_live: false,
            confirm_unknown_overlap: false,
        },
        target,
        preview: None,
        started_at: now,
        submitted_at: now,
        expires_at: now.offset_secs(120),
        finished_at: Some(now),
        state: State::Complete,
        write: Some(WriteEvidence {
            attempted: false,
            status: WriteStatus::Accepted,
            provider_request_id: Some("owned-size-ack".into()),
            authority_current: true,
            original_deadline_current: true,
        }),
        readback: Readback::Matched,
        job_id: Some("9007199254741001".into()),
        action: "enable".into(),
        kind: Kind::Report,
        readback_at: None,
        readback_fingerprint: None,
        archived_at: Some(now),
        detail_bytes: 0,
    })
}
#[tokio::test]
async fn different_fractional_precision_changes_envelope_size_without_changing_plaintext() -> DomainResult<()> {
    let state = state()?;
    let row = row()?;
    let key = codec::key(row.tenant, row.request_id, super::model::OPERATION);
    let seconds = codec::seal_at(&state, row.tenant, &key, &row, at("2026-10-02T00:00:00Z")?)?;
    let nanos = codec::seal_at(&state, row.tenant, &key, &row, at("2026-10-02T00:00:00.000000001Z")?)?;
    assert!(serde_json::to_vec(&nanos)?.len() > serde_json::to_vec(&seconds)?.len());
    let first: Operation = codec::decode(&state, row.tenant, &key, &seconds)?;
    let second: Operation = codec::decode(&state, row.tenant, &key, &nanos)?;
    assert_eq!(serde_json::to_value(first)?, serde_json::to_value(second)?);
    Ok(())
}
#[tokio::test]
async fn stored_size_converges_at_all_precisions_and_old_size_digit_boundaries() -> DomainResult<()> {
    let state = state()?;
    for time in [
        "2026-10-02T00:00:00Z",
        "2026-10-02T00:00:00.001Z",
        "2026-10-02T00:00:00.000001Z",
        "2026-10-02T00:00:00.000000001Z",
    ] {
        for previous_size in [0, 9, 9_999, 999_999] {
            let mut row = row()?;
            row.input_hash = codec::hash(super::model::Purpose::Apply, &row.input)?;
            row.detail_bytes = previous_size;
            let mut values = Values::new();
            let time = at(time)?;
            mutation::operation_at(&state, &mut values, &mut row, time)?;
            codec::operation(&row, row.tenant, row.request_id)?;
            let key = codec::key(row.tenant, row.request_id, super::model::OPERATION);
            let sealed = values.get(&key).and_then(Option::as_ref).ok_or_else(util::corrupt)?;
            assert_eq!(serde_json::to_vec(sealed)?.len(), row.detail_bytes);
            assert_eq!(sealed["secret"]["encrypted_at"], json!(time));
            let restored: Operation = codec::decode(&state, row.tenant, &key, sealed)?;
            assert_eq!(serde_json::to_value(restored)?, serde_json::to_value(&row)?);
            assert!(row.detail_bytes <= super::model::MAX_DETAIL);
        }
    }
    Ok(())
}
