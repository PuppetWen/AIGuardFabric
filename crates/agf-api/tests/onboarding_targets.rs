//! Real read-only HTTP plans, actual source binding and protocol separation.
mod common;
use agf_api::agentteams_audit::binding;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use common::*;

const PLAN: &str = "/api/v1/agents/onboarding-plan";
async fn snapshot(h: &Harness) -> DomainResult<Value> {
    let mut records = BTreeMap::new();
    for kind in [
        binding::KIND,
        "log-source",
        "cloud-integration",
        "signed-policy-registry",
        "model-endpoint",
        "cloud-inventory",
    ] {
        records.insert(kind, h.state.configurations.list::<Value>(h.tenant, kind).await?);
    }
    Ok(json!({"records":records,"audit":h.state.store.audit_chain_durable(h.tenant, 0, 1000).await?,
        "keys":h.state.store.api_key_list_durable(h.tenant).await?,"inventory":h.state.store.platform_snapshot_durable(h.tenant).await?,
        "raw":h.state.ingest_sink.raw_count(h.tenant).await?,"events":h.state.ingest_sink.event_count(h.tenant).await?}))
}
async fn fixture() -> DomainResult<(Harness, binding::Binding)> {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let saved = h
        .request(
            "PUT",
            "/api/v1/alicloud/connections/alicloud-agentteams",
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":true,"settings":{"instance_id":"inst-onboarding"}})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK);
    let sync = h
        .post(
            "/api/v1/alicloud/agentteams/sync",
            json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false}),
        )
        .await;
    assert_eq!(sync.status, StatusCode::OK);
    let created =
        h.post("/api/v1/ingest/sources", json!({"name":"owned-onboarding-source","protocol":"http-webhook"})).await;
    assert_eq!(created.status, StatusCode::CREATED);
    let source =
        created.json()["id"].as_str().ok_or_else(|| DomainError::Config("Source id absent".into()))?.to_owned();
    let source_id = Id::parse(&source).map_err(|_| DomainError::Config("Source UUID invalid".into()))?;
    assert_eq!(
        h.request(
            "PUT",
            &format!("/api/v1/alicloud/agentteams/audit-sources/{source}"),
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true}))
        )
        .await
        .status,
        StatusCode::OK
    );
    let current = binding::load(&h.state, h.tenant, source_id)
        .await?
        .ok_or_else(|| DomainError::Config("Binding absent".into()))?;
    Ok((h, current))
}
fn descriptor(current: &binding::Binding, node: bool) -> DomainResult<Value> {
    let worker =
        current.members.keys().next().ok_or_else(|| DomainError::Config("Actual Worker inventory empty".into()))?;
    Ok(json!({"source_id":current.source_id,"binding_id":current.binding_id,"worker":worker,"team":null,"kind":"task",
        "callee_worker":null,"callee_team":null,"operation":"owned-task","module":if node { "" } else { "business.tasks" },
        "callable":"run","entry":if node { "E:/owned/app.cjs" } else { "business.main" },"sdk_directory":"E:/owned/sdk",
        "spool_directory":"E:/owned/spool","configuration_file":"E:/owned/startup.json",
        "target_file":if node { json!("E:/owned/task.cjs") } else { Value::Null },"async_mode":if node { json!("promise") } else { Value::Null }}))
}
fn request(target: &str, sdk: Value) -> Value {
    json!({"mode":"sdk-inject","target":target,"platform":"windows-amd64","locale":"en-US","public_base":"https://platform.example.test","sdk":sdk})
}

#[tokio::test]
async fn all_modes_have_explicit_defaults_and_invalid_combinations_never_downgrade() -> DomainResult<()> {
    let h = setup().await;
    let before = snapshot(&h).await?;
    for (mode, target) in
        [("sidecar", "collector"), ("sdk-inject", "python-startup"), ("gateway-register", "model-openai")]
    {
        let response = h.post(PLAN, json!({"mode":mode})).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.json()["target"], target);
        assert_eq!(response.json()["ready"], mode == "sidecar");
    }
    for (mode, target) in
        [("sidecar", "python-startup"), ("sdk-inject", "model-openai"), ("gateway-register", "collector")]
    {
        assert_eq!(h.post(PLAN, json!({"mode":mode,"target":target})).await.status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        h.get(&format!("{PLAN}?mode=sdk-inject&target=node-cjs-startup")).await.json()["target"],
        "node-cjs-startup"
    );
    assert_eq!(h.request("POST", PLAN, None, Some(json!({}))).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(snapshot(&h).await?, before);
    Ok(())
}

#[tokio::test]
async fn python_and_node_configuration_use_real_worker_scope_and_exact_sdk_keys() -> DomainResult<()> {
    let (h, current) = fixture().await?;
    let before = snapshot(&h).await?;
    for (node, target) in [(false, "python-startup"), (true, "node-cjs-startup")] {
        let response = h.post(PLAN, request(target, descriptor(&current, node)?)).await;
        assert_eq!(response.status, StatusCode::OK);
        let body = response.json();
        assert_eq!(body["ready"], true);
        let configuration: Value = serde_json::from_str(
            body["configuration_json"].as_str().ok_or_else(|| DomainError::Config("Configuration absent".into()))?,
        )?;
        assert_eq!(configuration["targets"][0]["worker"]["name"], descriptor(&current, node)?["worker"]);
        assert!(configuration["targets"][0].get("prompt").is_none());
        if node {
            assert_eq!(configuration["keyEnv"], "AGF_STARTUP_KEY");
            assert_eq!(configuration["targets"][0]["mode"], "promise");
            assert!(body["env_snippet"].as_str().is_some_and(|value| value.contains(&current.scope_id.to_string())));
        } else {
            assert!(configuration.get("keyEnv").is_none());
            assert_eq!(configuration["collector"]["expected_scope"], json!(current.scope_id));
            assert_eq!(configuration["collector"]["expected_mocked"], true);
            assert_eq!(configuration["collector"]["binding_id"], json!(current.binding_id));
        }
        assert!(body["steps"][1]["command"].as_str().is_some_and(|value| value.contains("--drain-only")));
        let mut call = descriptor(&current, node)?;
        call["kind"] = json!("call");
        call["callee_worker"] = call["worker"].clone();
        let called = h.post(PLAN, request(target, call.clone())).await;
        assert_eq!(called.status, StatusCode::OK);
        let config: Value = serde_json::from_str(
            called.json()["configuration_json"]
                .as_str()
                .ok_or_else(|| DomainError::Config("Call configuration absent".into()))?,
        )?;
        assert_eq!(config["targets"][0][if node { "to" } else { "callee" }]["name"], call["worker"]);
    }
    assert_eq!(snapshot(&h).await?, before);
    Ok(())
}

#[tokio::test]
async fn inventory_mismatch_foreign_binding_and_missing_read_permissions_produce_no_plan_or_writes() -> DomainResult<()>
{
    let (h, current) = fixture().await?;
    let mut input = descriptor(&current, false)?;
    let before = snapshot(&h).await?;
    for (field, value) in [
        ("worker", json!("not-in-inventory")),
        ("team", json!("not-in-inventory")),
        ("binding_id", json!(Id::new())),
        ("configuration_file", json!("https://example.test/key")),
        ("operation", json!("raw prompt text")),
    ] {
        let mut invalid = input.clone();
        invalid[field] = value;
        let response = h.post(PLAN, request("python-startup", invalid)).await;
        assert!(matches!(response.status, StatusCode::BAD_REQUEST | StatusCode::CONFLICT));
    }
    let issued = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("agents:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "onboarding-reader", Timestamp::now())
    });
    h.state.store.api_key_insert(issued.record)?;
    let after_key = snapshot(&h).await?;
    assert_eq!(
        h.request("POST", PLAN, Some(&issued.plaintext), Some(request("python-startup", input.clone()))).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(snapshot(&h).await?, after_key);
    input["source_id"] = json!(Id::new());
    assert_eq!(h.post(PLAN, request("python-startup", input)).await.status, StatusCode::CONFLICT);
    // The only deliberate mutation between snapshots above was issuing the independently scoped key.
    assert_eq!(after_key["records"], before["records"]);
    assert_eq!(after_key["inventory"], before["inventory"]);
    Ok(())
}

#[tokio::test]
async fn disabled_binding_is_excluded_and_original_launch_arguments_are_never_sent_to_plan_api() -> DomainResult<()> {
    let (h, current) = fixture().await?;
    assert_eq!(
        h.request(
            "PUT",
            &format!("/api/v1/alicloud/agentteams/audit-sources/{}", current.source_id),
            Some(&h.admin),
            Some(json!({"expected_version":current.version,"enabled":false}))
        )
        .await
        .status,
        StatusCode::OK
    );
    let before = snapshot(&h).await?;
    let choices = h.get(&format!("{PLAN}?mode=sdk-inject&target=python-startup")).await;
    assert_eq!(choices.status, StatusCode::OK);
    assert_eq!(choices.json()["sdk_sources"], json!([]));
    assert_eq!(
        h.post(PLAN, request("python-startup", descriptor(&current, false)?)).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        h.post(PLAN, json!({"mode":"sidecar","target":"mcp-stdio","original_args":["raw-business-body"]})).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(snapshot(&h).await?, before);
    Ok(())
}

#[tokio::test]
async fn model_protocol_origins_and_stdio_template_do_not_execute_or_auto_select_a_model() -> DomainResult<()> {
    let h = setup().await;
    // Register an owned model through the real HTTP API; setup intentionally has no implicit endpoint.
    let registered = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({
        "name":"owned-onboarding-model","provider":"mock","model":"owned-onboarding-model",
        "base_url":"http://mock.invalid/v1"}),
        )
        .await;
    assert_eq!(registered.status, StatusCode::CREATED);
    let rows = h
        .state
        .configurations
        .list::<agf_api::model_gateway::StoredEndpoint>(h.tenant, agf_api::model_gateway::ENDPOINT_KIND)
        .await?;
    let model = rows
        .iter()
        .find(|row| row.endpoint.enabled)
        .ok_or_else(|| DomainError::Config("Seed model absent".into()))?
        .endpoint
        .model
        .clone();
    let before = snapshot(&h).await?;
    for (target, suffix, key) in
        [("model-openai", "/v1", "OPENAI_BASE_URL"), ("model-anthropic", "", "ANTHROPIC_BASE_URL")]
    {
        let result=h.post(PLAN,json!({"mode":"gateway-register","target":target,"model":model,"public_base":"https://platform.example.test"})).await;
        assert_eq!(result.status, StatusCode::OK);
        assert_eq!(result.json()["endpoint"], format!("https://platform.example.test{suffix}"));
        assert!(result.json()["env_snippet"].as_str().is_some_and(|value| value.contains(key)));
    }
    assert_eq!(h.post(PLAN, json!({"mode":"gateway-register","model":"auto"})).await.status, StatusCode::BAD_REQUEST);
    let stdio = h.post(PLAN, json!({"mode":"sidecar","target":"mcp-stdio"})).await;
    let encoded = stdio.json()["configuration_json"]
        .as_str()
        .ok_or_else(|| DomainError::Config("stdio template absent".into()))?
        .to_owned();
    let template: Value = serde_json::from_str(&encoded)?;
    assert!(template["mcpServers"]["guarded"].get("env").is_none());
    assert_eq!(template["mcpServers"]["guarded"]["args"][0], "mcp-proxy");
    assert_eq!(snapshot(&h).await?, before);
    Ok(())
}

#[tokio::test]
async fn multiple_teams_require_explicit_sender_and_callee_membership_for_both_startups() -> DomainResult<()> {
    let (h, original) = fixture().await?;
    // An owned, coherent inventory fixture; the real binding API still derives and verifies membership.
    let mut inventory = agf_api::cloud_inventory::load(&h.state, h.tenant)
        .await?
        .ok_or_else(|| DomainError::Config("Inventory absent".into()))?;
    let workers: Vec<_> = inventory.assets.keys().cloned().collect();
    let teams = ["owned-team-one", "owned-team-two"];
    inventory.teams = teams
        .iter()
        .map(|name| {
            json!({"Name":name,"InstanceId":inventory.instance_id,
        "WorkerNames":workers,"TeamMembers":[]})
        })
        .collect();
    inventory.workers = workers
        .iter()
        .map(|name| {
            json!({"Name":name,"InstanceId":inventory.instance_id,
        "Groups":teams.iter().map(|team|json!({"Type":"team","Name":team})).collect::<Vec<_>>()})
        })
        .collect();
    inventory.checked_at = Timestamp::now();
    let cfg = agf_api::cloud_store::load(&h.state, h.tenant, agf_api::cloud_inventory::NAME)
        .await?
        .ok_or_else(|| DomainError::Config("Connection absent".into()))?;
    let mut private = agf_api::integration_store::Private::default();
    private.settings.insert("snapshot".into(), serde_json::to_value(&inventory)?);
    let sealed = agf_api::integration_store::Stored {
        private: agf_api::model_gateway::encrypt(&h.state, h.tenant, cfg.id, serde_json::to_string(&private)?)?,
        updated_at: inventory.checked_at,
        ..cfg
    };
    h.state.configurations.put(h.tenant, "cloud-inventory", sealed.id, &sealed).await?;
    assert_eq!(
        h.request(
            "PUT",
            &format!("/api/v1/alicloud/agentteams/audit-sources/{}", original.source_id),
            Some(&h.admin),
            Some(json!({"expected_version":original.version,"enabled":true}))
        )
        .await
        .status,
        StatusCode::OK
    );
    let current = binding::load(&h.state, h.tenant, original.source_id)
        .await?
        .ok_or_else(|| DomainError::Config("Rebound inventory absent".into()))?;
    let before = snapshot(&h).await?;
    for (node, target) in [(false, "python-startup"), (true, "node-cjs-startup")] {
        let mut input = descriptor(&current, node)?;
        let worker = input["worker"].as_str().ok_or_else(|| DomainError::Config("Worker absent".into()))?.to_owned();
        assert_eq!(current.members[&worker].teams.len(), 2);
        let missing = h.post(PLAN, request(target, input.clone())).await;
        assert_eq!(missing.status, StatusCode::BAD_REQUEST);
        assert!(missing.json().get("configuration_json").is_none());
        input["team"] = json!(teams[0]);
        let task = h.post(PLAN, request(target, input.clone())).await;
        assert_eq!(task.status, StatusCode::OK);
        assert_eq!(task.json()["ready"], true);
        input["kind"] = json!("call");
        input["callee_worker"] = json!(worker);
        assert_eq!(h.post(PLAN, request(target, input.clone())).await.status, StatusCode::BAD_REQUEST);
        input["callee_team"] = json!(teams[1]);
        let call = h.post(PLAN, request(target, input.clone())).await;
        assert_eq!(call.status, StatusCode::OK);
        assert_eq!(call.json()["ready"], true);
        let config: Value = serde_json::from_str(
            call.json()["configuration_json"]
                .as_str()
                .ok_or_else(|| DomainError::Config("Call configuration absent".into()))?,
        )?;
        assert_eq!(config["targets"][0]["worker"]["team"], teams[0]);
        assert_eq!(config["targets"][0][if node { "to" } else { "callee" }]["team"], teams[1]);
        let mut event: agf_api::agentteams_audit::contract::Input = serde_json::from_value(json!({
            "event_id":"owned-multi-team-call","event_time":Timestamp::now(),"kind":"call",
            "from_worker":worker,"to_worker":worker,"from_team":teams[0],"to_team":teams[1]}))?;
        let expected = current.members[&worker].asset_id;
        assert_eq!(
            agf_api::agentteams_audit::contract::validate(&mut event, &current, Timestamp::now())?,
            (Some(expected), Some(expected))
        );
        event.to_team = None;
        assert!(matches!(
            agf_api::agentteams_audit::contract::validate(&mut event, &current, Timestamp::now()),
            Err(DomainError::Validation(_))
        ));
    }
    assert!(snapshot(&h).await? == before, "Plan reads and participant validation must preserve the full state");
    Ok(())
}
