//! Real router/schema checks for application-owned declarations, never vendor execution.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod agentteams_orchestration_openapi_support;
mod common;
use agentteams_orchestration_openapi_support::*;
use agf_core::{error::DomainResult, ids::Id};
use common::*;

#[tokio::test]
async fn five_operations_describe_local_reads_and_explicit_administrator_commits() -> DomainResult<()> {
    let h = setup().await;
    let document = openapi(&h).await;
    for (path, method, response) in [
        (BASE, "get", "ApplicationOrchestrationState"),
        ("/api/v1/alicloud/agentteams/orchestration-definitions/teams/{team}", "get", "ApplicationOrchestrationRecord"),
        ("/api/v1/alicloud/agentteams/orchestration-definitions/teams/{team}", "put", "ApplicationOrchestrationIntent"),
        (
            "/api/v1/alicloud/agentteams/orchestration-definitions/teams/{team}/preview",
            "post",
            "ApplicationOrchestrationPreview",
        ),
        (
            "/api/v1/alicloud/agentteams/orchestration-definitions/requests/{request}",
            "get",
            "ApplicationOrchestrationIntent",
        ),
    ] {
        let operation = &document["paths"][path][method];
        assert!(operation["operationId"].is_string());
        assert_eq!(
            operation["x-required-permissions"],
            if method == "get" {
                json!(["alicloud:read"])
            } else {
                json!(["platform:admin", "alicloud:read", "alicloud:write"])
            }
        );
        assert_eq!(
            operation["security"],
            if method == "get" { json!([{"bearerAuth":[]},{"apiKey":[]}]) } else { json!([{"bearerAuth":[]}]) }
        );
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            format!("#/components/schemas/{response}")
        );
        assert_eq!(operation["parameters"][0]["name"], "X-AGF-Tenant");
    }
    let team = "/api/v1/alicloud/agentteams/orchestration-definitions/teams/{team}";
    assert_eq!(document["paths"][team]["put"]["x-max-request-bytes"], 300 * 1024);
    assert_eq!(document["paths"][format!("{team}/preview")]["post"]["x-preview-only"], true);
    assert!(document["paths"][format!("{team}/preview")]["post"].get("x-max-request-bytes").is_none());
    let reader = h
        .post("/api/v1/settings/api-keys", json!({"name":"owned-orchestration-reader","scopes":["alicloud:read"]}))
        .await;
    assert_eq!(reader.status, StatusCode::CREATED);
    let token = format!("Bearer {}", reader.json()["plaintext"].as_str().unwrap());
    let before = snapshot(&h).await?;
    let state = h.request_with("GET", BASE, &[("authorization", &token)], None).await;
    assert_eq!(state.status, StatusCode::OK);
    assert!(matches(&document, schema(&document, "ApplicationOrchestrationState"), &state.json()));
    assert_eq!(state.json()["modeSupported"], false);
    assert_eq!(state.json()["teams"], json!([]));
    assert_eq!(state.json()["records"], json!([]));
    assert_eq!(h.request("GET", BASE, None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.request("GET", BASE, Some(&h.viewer), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.get(&format!("{BASE}/requests/{}", Id::new())).await.status, StatusCode::NOT_FOUND);
    assert_eq!(snapshot(&h).await?, before);
    Ok(())
}

#[tokio::test]
async fn real_mock_preview_commit_push_and_historical_reads_match_direct_schemas_without_redispatch() -> DomainResult<()>
{
    let (h, target) = prepared().await;
    let document = openapi(&h).await;
    let first = input(&target, 0, json!({"action":"save_definition","definition":definition(&target)}));
    assert!(matches(&document, schema(&document, "ApplicationOrchestrationCommitInput"), &first));
    let mut preview_input = first.clone();
    for name in ["confirm_application_owned", "confirm_mock_sync", "confirm_source_change"] {
        preview_input.as_object_mut().unwrap().remove(name);
    }
    assert!(matches(&document, schema(&document, "ApplicationOrchestrationPreviewInput"), &preview_input));
    assert!(!matches(&document, schema(&document, "ApplicationOrchestrationCommitInput"), &preview_input));
    let before = snapshot(&h).await?;
    assert!(matches(&document, schema(&document, "ApplicationOrchestrationState"), &h.get(BASE).await.json()));
    let preview = h.post(&format!("{}/preview", path(&target)), preview_input).await;
    assert_eq!(preview.status, StatusCode::OK);
    assert!(matches(&document, schema(&document, "ApplicationOrchestrationPreview"), &preview.json()));
    assert_eq!(preview.json()["previewOnly"], true);
    assert_eq!(snapshot(&h).await?, before);
    let original = save(&h, &target, first.clone()).await;
    assert_eq!(original.status, StatusCode::OK);
    assert!(matches(&document, schema(&document, "ApplicationOrchestrationIntent"), &original.json()));
    assert_eq!(original.json()["providerCalled"], false);
    assert_eq!(original.json()["consumerApplied"], Value::Null);
    assert_eq!(original.json()["durable"], false);
    assert_eq!(original.json()["receiverHash"], Value::Null);
    let push = input(&target, 1, json!({"action":"sync","direction":"push"}));
    assert!(matches(&document, schema(&document, "ApplicationOrchestrationCommitInput"), &push));
    let pushed = save(&h, &target, push).await;
    assert_eq!(pushed.status, StatusCode::OK);
    assert!(matches(&document, schema(&document, "ApplicationOrchestrationIntent"), &pushed.json()));
    assert_eq!(pushed.json()["localHash"], pushed.json()["receiverHash"]);
    let record = h.get(&path(&target)).await;
    assert_eq!(record.status, StatusCode::OK);
    assert!(matches(&document, schema(&document, "ApplicationOrchestrationRecord"), &record.json()));
    assert_eq!(record.json()["version"], 2);
    assert_eq!(record.json()["vendorDagAvailable"], false);
    assert_eq!(h.request("PUT", CONFIG, Some(&h.admin), Some(configuration(false, 1))).await.status, StatusCode::OK);
    let readonly = snapshot(&h).await?;
    let receipt = h.get(&format!("{BASE}/requests/{}", first["request_id"].as_str().unwrap())).await;
    assert_eq!(receipt.status, StatusCode::OK);
    assert_eq!(receipt.json(), original.json());
    assert!(matches(&document, schema(&document, "ApplicationOrchestrationIntent"), &receipt.json()));
    assert_eq!(save(&h, &target, first).await.json(), original.json());
    let state = h.get(BASE).await.json();
    assert!(matches(&document, schema(&document, "ApplicationOrchestrationState"), &state));
    assert_eq!(state["modeSupported"], false);
    assert_eq!(state["records"][0], record.json());
    assert_eq!(snapshot(&h).await?, readonly);
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
async fn strict_wire_fields_and_semantic_cycles_reject_without_committing_intents() -> DomainResult<()> {
    let (h, target) = prepared().await;
    let document = openapi(&h).await;
    let first = input(&target, 0, json!({"action":"save_definition","definition":definition(&target)}));
    let before = snapshot(&h).await?;
    let mut unknown = first.clone();
    unknown["provider_execution"] = json!(true);
    let mut node_unknown = first.clone();
    node_unknown["change"]["definition"]["nodes"][0]["command"] = json!("unsupported");
    let mut repeated = first.clone();
    repeated["change"]["definition"]["nodes"][0]["agent_ids"] =
        json!([target["workers"][0]["name"], target["workers"][0]["name"]]);
    let mut unconfirmed = first.clone();
    unconfirmed["confirm_application_owned"] = json!(false);
    for invalid in [unknown, node_unknown, repeated, unconfirmed] {
        assert!(!matches(&document, schema(&document, "ApplicationOrchestrationCommitInput"), &invalid));
        assert_eq!(save(&h, &target, invalid).await.status, StatusCode::BAD_REQUEST);
    }
    let mut cycle = first.clone();
    cycle["change"]["definition"]["nodes"][0]["depends_on"] = json!(["first"]);
    // JSON shape is valid; the actual trusted inventory/DAG validator must reject it.
    assert!(matches(&document, schema(&document, "ApplicationOrchestrationPreviewInput"), &cycle));
    assert_eq!(h.post(&format!("{}/preview", path(&target)), cycle).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(snapshot(&h).await?, before);
    let reader = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"owned-orchestration-no-admin","scopes":["alicloud:read","alicloud:write"]}),
        )
        .await;
    assert_eq!(reader.status, StatusCode::CREATED);
    let token = format!("Bearer {}", reader.json()["plaintext"].as_str().unwrap());
    let after_key = snapshot(&h).await?;
    for (method, uri) in [("POST", format!("{}/preview", path(&target))), ("PUT", path(&target))] {
        assert_eq!(
            h.request_with(method, &uri, &[("authorization", &token)], Some(first.clone())).await.status,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(snapshot(&h).await?, after_key);
    assert_eq!(before["definitions"], after_key["definitions"]);
    assert_eq!(before["connections"], after_key["connections"]);
    assert_eq!(before["inventory"], after_key["inventory"]);
    assert_eq!(save(&h, &target, first.clone()).await.status, StatusCode::OK);
    let committed = snapshot(&h).await?;
    let mut reused = first;
    reused["change"] = json!({"action":"sync","direction":"push"});
    assert_eq!(save(&h, &target, reused).await.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&h).await?, committed);
    Ok(())
}
