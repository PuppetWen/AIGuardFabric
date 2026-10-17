//! Inactive SDK outbox inspection and tenant-RLS ledger/raw/Event/delivery evidence.
use super::{fail, owned::Owned, platform::Platform, subprocess};
use agf_api::agentteams_audit::binding::Binding;
use agf_core::{error::DomainResult, ids::Id};
use serde_json::{Value, json};
use std::path::Path;

pub(super) async fn inspect(owned: &Owned, dir: &Path, language: &str, key: &str) -> DomainResult<Value> {
    let script = dir.join("inspect_queue.py");
    let mut command = subprocess::command(subprocess::executable("AGF_ZERO_CODE_PYTHON")?, owned, dir)?;
    command.args(["-I", "-B"]).arg(&script).arg(dir.join("spool")).arg(language);
    subprocess::run(command, Some(key), true).await
}
pub(super) async fn snapshot(platform: &Platform, source: Id) -> DomainResult<Value> {
    let db = platform.state.store.database().ok_or_else(|| fail("durable database absent"))?;
    let mut tx = db.db().begin_tenant(platform.tenant).await?;
    let ledger: Vec<Value> = sqlx::query_scalar("SELECT payload FROM agentteams_audit WHERE source_id=$1 ORDER BY id")
        .bind(source.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| fail("ledger query"))?;
    let raw: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',id,'payload_b64',payload_b64) FROM raw_logs WHERE source_id=$1 ORDER BY id",
    )
    .bind(source.as_uuid())
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| fail("raw query"))?;
    let events:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'raw',raw,'message',message,'extra',extra,'ai',ai) FROM events WHERE source_id=$1 ORDER BY id")
        .bind(source.as_uuid()).fetch_all(&mut *tx).await.map_err(|_|fail("events query"))?;
    let outbox:i64=sqlx::query_scalar("SELECT count(*) FROM event_delivery_outbox o JOIN events e ON o.tenant_id=e.tenant_id AND o.event_id=e.id WHERE e.source_id=$1")
        .bind(source.as_uuid()).fetch_one(&mut *tx).await.map_err(|_|fail("delivery outbox query"))?;
    tx.commit().await?;
    Ok(json!({"ledger":ledger,"raw":raw,"events":events,"delivery":outbox}))
}
pub(super) async fn isolated(platform: &Platform) -> DomainResult<()> {
    let foreign =
        agf_api::tenant_directory::new(format!("zero-code-foreign-{}", Id::new()), "Owned foreign RLS tenant".into());
    agf_api::tenant_directory::save(&platform.state, foreign.clone(), true).await?;
    let database = platform.state.store.database().ok_or_else(|| fail("SQL backend required"))?;
    let mut tx = database.db().begin_tenant(foreign.id).await?;
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM agentteams_audit),(SELECT count(*) FROM raw_logs),(SELECT count(*) FROM events)",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| fail("foreign RLS counts"))?;
    assert_eq!(counts, (0, 0, 0), "new genuine tenant must not see prior SDK evidence");
    tx.commit().await?;
    Ok(())
}
pub(super) fn verify(snapshot: &Value, binding: &Binding, tenant: agf_core::ids::TenantId, key: &str, queued: &Value) {
    let ledger = snapshot["ledger"].as_array().unwrap();
    assert_eq!(ledger.len(), 4, "one root Task, two actual Calls and one failing Task");
    assert_eq!(snapshot["raw"].as_array().unwrap().len(), 4);
    assert_eq!(snapshot["events"].as_array().unwrap().len(), 4);
    assert_eq!(snapshot["delivery"], 4);
    assert_eq!(ledger.iter().filter(|row| row["kind"] == "call").count(), 2);
    assert_eq!(ledger.iter().filter(|row| row["kind"] == "task").count(), 2);
    assert_eq!(ledger.iter().filter(|row| row["status"] == "error").count(), 1);
    let queued = queued["rows"].as_array().unwrap();
    assert_eq!(queued.len(), 4);
    let ids: std::collections::BTreeSet<_> = queued.iter().map(|row| row["id"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), 4);
    let root = ledger.iter().find(|row| row["parent_span_id"].is_null() && row["status"] == "success").unwrap();
    for row in ledger {
        assert_eq!(row["tenant_id"], json!(tenant));
        assert_eq!(row["binding_id"], json!(binding.binding_id));
        assert_eq!(row["scope_id"], json!(binding.scope_id));
        assert_eq!(row["source_id"], json!(binding.source_id));
        assert_eq!(row["from_worker"], "worker-demo");
        assert_eq!(row["from_asset"], json!(binding.members["worker-demo"].asset_id));
        assert_eq!(row["mocked"], true);
        assert_eq!(row["message_preview"], "");
        assert!(ids.contains(row["external_event_id"].as_str().unwrap()));
        assert_eq!(row["trace_id"], root["trace_id"]);
        if row["id"] != root["id"] {
            assert_eq!(row["parent_span_id"], root["span_id"]);
        }
    }
    let encoded = snapshot.to_string();
    assert!(!encoded.contains(key));
    assert!(!encoded.contains("business-secret"));
    assert!(!encoded.contains("13800138000"));
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    for raw in snapshot["raw"].as_array().unwrap() {
        let bytes = STANDARD.decode(raw["payload_b64"].as_str().unwrap()).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.get("message").is_none() || value["message"].is_null());
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains(key));
        assert!(!text.contains("business-secret"));
    }
}
