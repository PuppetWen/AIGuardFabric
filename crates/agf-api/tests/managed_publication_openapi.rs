//! Actual router/document checks; no cloud, deployment or consumer claim.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod managed_publication_openapi_support;
use agf_core::{error::DomainResult, ids::Id};
use common::*;
use managed_publication_openapi_support::*;

#[tokio::test]
async fn document_lists_exact_eight_methods_each_and_keeps_existing_managed_contracts() {
    let h = setup().await;
    let document = ok(&h, "GET", "/api/v1/openapi.json", None).await;
    let mut ids = std::collections::BTreeSet::new();
    for path in document["paths"].as_object().unwrap().values() {
        for method in ["get", "post", "put", "delete", "patch"] {
            if let Some(id) = path[method]["operationId"].as_str() {
                assert!(ids.insert(id), "duplicate operationId");
            }
        }
    }
    for (root, expected) in [(APIG, 8), (JOBS, 8)] {
        let count = document["paths"]
            .as_object()
            .unwrap()
            .iter()
            .filter(|(path, _)| path.starts_with(root))
            .map(|(_, methods)| ["get", "post", "put"].iter().filter(|method| methods[**method].is_object()).count())
            .sum::<usize>();
        assert_eq!(count, expected);
        for (path, item) in document["paths"].as_object().unwrap().iter().filter(|(path, _)| path.starts_with(root)) {
            for method in ["get", "post", "put"] {
                let op = &item[method];
                if !op.is_object() {
                    continue;
                }
                assert!(!op["security"].as_array().unwrap().is_empty());
                assert!(op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].is_string());
                if root == JOBS && method != "get" {
                    assert_eq!(op["x-required-subject-kind"], "user");
                    assert_eq!(
                        op["x-required-permissions"],
                        json!(["platform:admin", "alicloud:read", "alicloud:write"])
                    );
                    assert_eq!(op["security"], json!([{"bearerAuth":[]}]));
                } else if method == "get" || path.ends_with("/observe") {
                    assert_eq!(op["x-required-permissions"], json!(["alicloud:read"]));
                }
            }
        }
    }
    for path in [
        "/api/v1/alicloud/cms/queue",
        "/api/v1/alicloud/privatelink/provisioning",
        "/api/v1/alicloud/apig/policy-publication",
        "/api/v1/gateway/attempts/{id}",
    ] {
        assert!(document["paths"][path].is_object(), "existing managed path missing");
    }
    assert_eq!(
        document["components"]["schemas"]["ScanBody"]["properties"]["targets"]["items"]["$ref"],
        "#/components/schemas/ScanTargetBody"
    );
    assert!(document["components"]["schemas"]["ScanTargetBody"].is_object());
    references(&document, &document);
}

#[tokio::test]
async fn strict_inputs_match_casing_confirmations_archive_limits_and_recovery_bodies() {
    let h = setup().await;
    let doc = ok(&h, "GET", "/api/v1/openapi.json", None).await;
    let schemas = &doc["components"]["schemas"];
    for (name, max) in [("ApigConfigurationArchiveInput", 100), ("SchedulerManagedArchiveInput", 48)] {
        assert_eq!(schemas[name]["properties"]["request_ids"]["maxItems"], max);
        assert_eq!(schemas[name]["properties"]["request_ids"]["uniqueItems"], true);
        assert_eq!(schemas[name]["additionalProperties"], false);
    }
    for name in ["ApigConfigurationEmptyInput", "SchedulerManagedEmptyInput"] {
        assert!(matches(&doc, &schemas[name], &json!({})));
        assert!(!matches(&doc, &schemas[name], &json!({"retry":true})));
        assert!(!matches(&doc, &schemas[name], &Value::Null));
    }
    assert_eq!(
        schemas["ApigConfigurationObserveInput"]["properties"]["configuration_version"]["maximum"],
        json!(u64::MAX)
    );
    assert_eq!(
        schemas["ApigConfigurationOriginalObserveInput"]["properties"]["initialize_mock_fixture"]["const"],
        false
    );
    let base = json!({"request_id":Id::new(),"configuration_version":1,"observation_id":Id::new(),"expected_state_version":0,
        "change":{"action":"content","settings":{"enabled":true,"checkRequest":true,"checkResponse":false,"denyCode":403}}});
    assert!(matches(&doc, &schemas["ApigConfigurationPreviewInput"], &base));
    let mut invalid = base;
    invalid["change"]["settings"]["accessKey"] = json!("forbidden");
    assert!(!matches(&doc, &schemas["ApigConfigurationPreviewInput"], &invalid));
    let r = h.post(&format!("{APIG}/previews"), invalid).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    for root in [APIG, JOBS] {
        let r = h.post(&format!("{root}/operations/{}/recover", Id::new()), json!({"retry":true})).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
    }
    let required = &schemas["ApigConfigurationApplyInput"]["required"];
    for field in [
        "confirm_apply",
        "confirm_preserved_private_configuration",
        "confirm_streaming_or_shared_impact",
        "confirm_no_cloud_cas",
    ] {
        assert!(required.as_array().unwrap().contains(&json!(field)));
        assert_eq!(schemas["ApigConfigurationApplyInput"]["properties"][field]["const"], true);
    }
}

#[tokio::test]
async fn read_key_state_unknown_receipts_and_anonymous_reads_never_initialize_or_write() -> DomainResult<()> {
    let h = setup().await;
    let issued = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("alicloud:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "owned-openapi-reader", Timestamp::now())
    });
    h.state.store.api_key_insert(issued.record)?;
    let before = snapshot(&h).await?;
    let doc = ok(&h, "GET", "/api/v1/openapi.json", None).await;
    for (root, schema) in [(APIG, "ApigConfigurationState"), (JOBS, "SchedulerManagedState")] {
        let r = h.request("GET", root, None, None).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        let r = h.request("GET", root, Some(&issued.plaintext), None).await;
        assert_eq!(r.status, StatusCode::OK);
        shape(&doc, schema, &r.json());
        let r = h.request("GET", &format!("{root}/operations/{}", Id::new()), Some(&issued.plaintext), None).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);
    }
    let r = h.request("GET", &format!("{JOBS}/previews/{}", Id::new()), Some(&issued.plaintext), None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(before == snapshot(&h).await?, "read operations changed full records or audit");
    Ok(())
}

#[tokio::test]
async fn explicitly_seeded_mock_observation_and_managed_previews_match_safe_output_schemas() {
    let h = setup().await;
    let doc = ok(&h, "GET", "/api/v1/openapi.json", None).await;
    ok(&h,"PUT","/api/v1/alicloud/connections/alicloud-apig",Some(json!({"expected_version":0,"enabled":true,"mock":true,"secrets":{},
        "settings":{"region_id":"cn-hangzhou","account_id":"owned-openapi-account","configuration_kind":"content",
        "configuration_http_api_id":"api-owned","configuration_gateway_id":"gw-owned","configuration_environment_id":"env-owned",
        "configuration_attachment_id":"pa-owned","configuration_plugin_id":"pl-owned","configuration_class_id":"cls-owned",
        "configuration_class_version":"1.0.0","managed_configuration_confirmed":true}}))).await;
    let observation = ok(
        &h,
        "POST",
        &format!("{APIG}/observe"),
        Some(json!({"request_id":Id::new(),"configuration_version":1,"initialize_mock_fixture":true})),
    )
    .await;
    shape(&doc, "ApigConfigurationObservation", &observation);
    let state = ok(&h, "GET", APIG, None).await;
    shape(&doc, "ApigConfigurationState", &state);
    let preview = ok(
        &h,
        "POST",
        &format!("{APIG}/previews"),
        Some(json!({"request_id":Id::new(),"configuration_version":1,
        "observation_id":observation["id"],"expected_state_version":state["stateVersion"],"change":{"action":"content",
        "settings":{"enabled":true,"checkRequest":true,"checkResponse":true,"denyCode":451}}})),
    )
    .await;
    shape(&doc, "ApigConfigurationPreview", &preview);
    ok(&h,"PUT","/api/v1/alicloud/connections/alicloud-schedulerx3",Some(json!({"expected_version":0,"enabled":true,"mock":true,"secrets":{},
        "settings":{"region_id":"cn-hangzhou","cluster_id":"cluster-agf-demo","app_name":"app-agf-demo","account_id":"owned-openapi-account"}}))).await;
    let observed = ok(
        &h,
        "POST",
        "/api/v1/alicloud/schedulerx3/native/observe",
        Some(json!({"request_id":Id::new(),"configuration_version":1,"initialize_mock_fixture":true})),
    )
    .await;
    let state = ok(&h, "GET", JOBS, None).await;
    shape(&doc, "SchedulerManagedState", &state);
    let preview=ok(&h,"POST",&format!("{JOBS}/previews"),Some(json!({"request_id":Id::new(),"configuration_version":1,
        "expected_binding_version":state["bindingVersion"],"observation_id":observed["requestId"],
        "change":{"action":"create_disabled","declaration":{"kind":"report","name":"owned-contract-report","total":1,
            "schedule":{"time_type":1,"time_expression":"0 0/5 * * * ?","timezone":"UTC","max_attempt":0,"attempt_interval":0}}}}))).await;
    shape(&doc, "SchedulerManagedPreview", &preview);
    assert_eq!(preview["desired"]["enabled"], false);
    assert_eq!(preview["callbackBindingEnforced"], false);
    assert!(preview["deploymentVerified"].is_null());
}

// 驱动真实 build_router：版本前缀由外层只添加一次，读取与写入仍要求认证。
#[tokio::test]
async fn managed_collection_routes_use_one_version_prefix_and_keep_authentication() {
    let h = setup().await;
    for (root, mutation) in
        [("/api/v1/alicloud/cms/queue", "enqueue"), ("/api/v1/alicloud/privatelink/provisioning", "preview")]
    {
        assert_eq!(h.get(root).await.status, StatusCode::OK, "公开集合地址未接线: {root}");
        assert_eq!(h.request("GET", root, None, None).await.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            h.request("POST", &format!("{root}/{mutation}"), None, Some(json!({}))).await.status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(h.get(&format!("/api/v1{root}")).await.status, StatusCode::NOT_FOUND);
        assert_eq!(h.post(&format!("/api/v1{root}/{mutation}"), json!({})).await.status, StatusCode::NOT_FOUND);
    }
}
