#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod agentteams_orchestration_database_support;
mod common;
use agentteams_orchestration_database_support::Case;
use agf_core::ids::Id;
use common::*;
use futures::FutureExt;
const BASE: &str = "/api/v1/alicloud/agentteams/orchestration-definitions";
const KIND: &str = "agentteams-application-orchestration";
async fn prepare(h: &Harness) -> Value {
    let saved = h
        .request(
            "PUT",
            "/api/v1/alicloud/connections/alicloud-agentteams",
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":true,
        "settings":{"instance_id":"owned-sql-orchestration","region_id":"cn-hangzhou","account_id":"owned-no-cloud"}})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(
        h.post(
            "/api/v1/alicloud/agentteams/sync",
            json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false})
        )
        .await
        .status,
        StatusCode::OK
    );
    let response = h.get(BASE).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()["teams"][0].clone()
}
fn uri(target: &Value) -> String {
    format!("{BASE}/teams/{}", target["teamName"].as_str().unwrap())
}
fn input(target: &Value) -> Value {
    let mut document = target["template"].clone();
    document["nodes"] = json!([{"node_id":"owned-node","name":"Declaration, never business execution",
        "agent_ids":[target["workers"][0]["name"]],"depends_on":[],"trigger":"manual"}]);
    json!({"request_id":Id::new(),"expected_version":0,"configuration_version":1,"inventory_fingerprint":target["source"]["inventoryFingerprint"],
        "change":{"action":"save_definition","definition":document},"confirm_application_owned":true,"confirm_mock_sync":false,"confirm_source_change":false})
}
async fn save(h: &Harness, target: &Value, input: Value) -> Resp {
    h.request("PUT", &uri(target), Some(&h.admin), Some(input)).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires separate exact-owner AgentTeams orchestration PostgreSQL"]
async fn independent_instances_commit_one_cas_and_replay_one_original_fact_without_reaudit() {
    let case = Case::open("orch-concurrent").await;
    let target = prepare(&case.h).await;
    let other = case.second().await;
    let before = case.h.state.store.audit_stats_durable(case.h.tenant).await.unwrap();
    let a = input(&target);
    let b = input(&target);
    let (left, right) = tokio::join!(save(&case.h, &target, a.clone()), save(&other, &target, b.clone()));
    assert_eq!([left.status, right.status].iter().filter(|code| **code == StatusCode::OK).count(), 1);
    assert_eq!([left.status, right.status].iter().filter(|code| **code == StatusCode::CONFLICT).count(), 1);
    let (original, body) = if left.status == StatusCode::OK { (left, a) } else { (right, b) };
    assert_eq!(original.json()["durable"], true);
    assert_eq!(original.json()["consumerApplied"], Value::Null);
    let after = case.h.state.store.audit_stats_durable(case.h.tenant).await.unwrap();
    assert_eq!(after.0, before.0 + 1);
    assert_eq!(save(&other, &target, body.clone()).await.json(), original.json());
    assert_eq!(
        other.get(&format!("{BASE}/requests/{}", body["request_id"].as_str().unwrap())).await.json(),
        original.json()
    );
    assert_eq!(case.h.state.store.audit_stats_durable(case.h.tenant).await.unwrap(), after);
    let foreign = case.foreign().await;
    assert_eq!(
        foreign.get(&format!("{BASE}/requests/{}", body["request_id"].as_str().unwrap())).await.status,
        StatusCode::NOT_FOUND
    );
    assert!(case.h.state.store.audit_verify_durable(case.h.tenant).await.unwrap().passed);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires separate exact-owner AgentTeams orchestration PostgreSQL"]
async fn audit_failure_rolls_back_definition_intent_and_ledger_together_then_same_intent_can_commit() {
    let case = Case::open("orch-audit-fault").await;
    let target = prepare(&case.h).await;
    let body = input(&target);
    let before = case.h.state.store.audit_stats_durable(case.h.tenant).await.unwrap();
    case.fault(|| async {
        assert!(save(&case.h, &target, body.clone()).await.status.is_server_error());
        assert!(case.h.state.configurations.list::<Value>(case.h.tenant, KIND).await.unwrap().is_empty());
        assert_eq!(case.h.state.store.audit_stats_durable(case.h.tenant).await.unwrap(), before);
        assert_eq!(
            case.h.get(&format!("{BASE}/requests/{}", body["request_id"].as_str().unwrap())).await.status,
            StatusCode::NOT_FOUND
        );
    })
    .await;
    let success = save(&case.h, &target, body.clone()).await;
    assert_eq!(success.status, StatusCode::OK, "{}", success.text);
    assert_eq!(
        case.second().await.get(&format!("{BASE}/requests/{}", body["request_id"].as_str().unwrap())).await.json(),
        success.json()
    );
    assert_eq!(case.h.state.store.audit_stats_durable(case.h.tenant).await.unwrap().0, before.0 + 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires separate exact-owner AgentTeams orchestration PostgreSQL"]
async fn ciphertext_and_foreign_aad_tamper_fail_closed_without_extra_audit_or_source_calls() {
    let case = Case::open("orch-aad").await;
    let target = prepare(&case.h).await;
    assert_eq!(save(&case.h, &target, input(&target)).await.status, StatusCode::OK);
    let before = case.h.state.store.audit_stats_durable(case.h.tenant).await.unwrap();
    case.check().await;
    let (id, payload): (uuid::Uuid, Value) = sqlx::query_as(
        "SELECT id,payload FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND deleted_at IS NULL",
    )
    .bind(case.h.tenant.as_uuid())
    .bind(KIND)
    .fetch_one(&case.pool)
    .await
    .unwrap();
    for key in ["aad", "ciphertext_b64"] {
        let mut invalid = payload.clone();
        invalid["secret"][key] = json!(if key == "aad" { "foreign-tenant-and-purpose" } else { "AAAA" });
        case.check().await;
        sqlx::query("UPDATE console_configurations SET payload=$3 WHERE tenant_id=$1 AND kind=$2 AND id=$4")
            .bind(case.h.tenant.as_uuid())
            .bind(KIND)
            .bind(invalid)
            .bind(id)
            .execute(&case.pool)
            .await
            .unwrap();
        let checked = std::panic::AssertUnwindSafe(async {
            assert!(case.h.get(BASE).await.status.is_server_error());
            assert_eq!(case.h.state.store.audit_stats_durable(case.h.tenant).await.unwrap(), before);
        })
        .catch_unwind()
        .await;
        case.check().await;
        sqlx::query("UPDATE console_configurations SET payload=$3 WHERE tenant_id=$1 AND kind=$2 AND id=$4")
            .bind(case.h.tenant.as_uuid())
            .bind(KIND)
            .bind(&payload)
            .bind(id)
            .execute(&case.pool)
            .await
            .unwrap();
        if let Err(error) = checked {
            std::panic::resume_unwind(error);
        }
    }
    assert_eq!(case.second().await.get(BASE).await.status, StatusCode::OK);
}

async fn complete_snapshot(h: &Harness) -> Value {
    json!({"definition":h.state.configurations.list::<Value>(h.tenant,KIND).await.unwrap(),
        "connection":h.state.configurations.list::<Value>(h.tenant,"cloud-integration").await.unwrap(),
        "inventory":h.state.configurations.list::<Value>(h.tenant,"cloud-inventory").await.unwrap(),
        "audit":h.state.store.audit_stats_durable(h.tenant).await.unwrap()})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires separate exact-owner AgentTeams orchestration PostgreSQL"]
async fn invalid_connection_aead_rolls_back_new_intents_and_restart_receipts_remain_readonly() {
    let case = Case::open("orch-source-aead").await;
    let target = prepare(&case.h).await;
    let first = input(&target);
    let original = save(&case.h, &target, first.clone()).await;
    assert_eq!(original.status, StatusCode::OK);
    let receipt_uri = format!("{BASE}/requests/{}", first["request_id"].as_str().unwrap());
    let id = agf_api::integration_store::id(case.h.tenant, "alicloud-agentteams");
    case.check().await;
    let payload: Value = sqlx::query_scalar(
        "SELECT payload FROM console_configurations WHERE tenant_id=$1 AND kind='cloud-integration' AND id=$2 AND deleted_at IS NULL",
    ).bind(case.h.tenant.as_uuid()).bind(id.as_uuid()).fetch_one(&case.pool).await.unwrap();
    for key in ["aad", "ciphertext_b64"] {
        let mut invalid = payload.clone();
        invalid["private"][key] = json!(if key == "aad" { "foreign-tenant-and-source" } else { "AAAA" });
        case.check().await;
        assert_eq!(sqlx::query("UPDATE console_configurations SET payload=$3 WHERE tenant_id=$1 AND kind='cloud-integration' AND id=$2 AND deleted_at IS NULL")
            .bind(case.h.tenant.as_uuid()).bind(id.as_uuid()).bind(invalid).execute(&case.pool).await.unwrap().rows_affected(), 1);
        let checked = std::panic::AssertUnwindSafe(async {
            let second = case.second().await;
            let before = complete_snapshot(&case.h).await;
            let mut next = input(&target);
            next["expected_version"] = json!(1);
            assert_eq!(
                second.post(&format!("{}/preview", uri(&target)), next.clone()).await.status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid connection AEAD must reject preview"
            );
            assert_eq!(
                save(&second, &target, next.clone()).await.status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid connection AEAD must reject new durable publication"
            );
            assert_eq!(
                second.get(&format!("{BASE}/requests/{}", next["request_id"].as_str().unwrap())).await.status,
                StatusCode::NOT_FOUND
            );
            let historical = second.get(&receipt_uri).await;
            assert_eq!(historical.status, StatusCode::OK);
            assert_eq!(historical.json(), original.json());
            assert_eq!(historical.json()["providerCalled"], false);
            assert!(
                complete_snapshot(&case.h).await == before,
                "all registry, intent, source, and audit records must remain unchanged"
            );
            assert!(case.h.state.store.audit_verify_durable(case.h.tenant).await.unwrap().passed);
        })
        .catch_unwind()
        .await;
        case.check().await;
        assert_eq!(sqlx::query("UPDATE console_configurations SET payload=$3 WHERE tenant_id=$1 AND kind='cloud-integration' AND id=$2 AND deleted_at IS NULL")
            .bind(case.h.tenant.as_uuid()).bind(id.as_uuid()).bind(&payload).execute(&case.pool).await.unwrap().rows_affected(), 1);
        if let Err(error) = checked {
            std::panic::resume_unwind(error);
        }
    }
}
