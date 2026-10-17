//! 由 `agentteams.rs` 拆分：`live_path_builds_list_teams_request` 等 2 个函数（纯搬移，逻辑不变）。
use super::*;

#[tokio::test]
pub(crate) async fn live_path_builds_list_teams_request() {
    let transport = crate::test_support::ScriptedTransport::new(vec![
        serde_json::json!({"Items": [{"Name":"t-live","WorkerNames":[]}], "TotalCount":1}),
        serde_json::json!({"Items":[],"TotalCount":0}),
        serde_json::json!({"Data":{"Name":"t-live","InstanceId":"inst-live","WorkerNames":[]}}),
    ]);
    let mut adapter = AgentTeamsAdapter::new();
    let mut config = fixture_config(AliCloudService::AgentTeams, false);
    config.settings.insert("instance_id".into(), serde_json::json!("inst-live"));
    config.secret_refs.insert("access_key_id".to_string(), Id::new());
    config.secret_refs.insert("access_key_secret".to_string(), Id::new());
    assert!(adapter.init(&config).await.is_ok());
    adapter.core_mut().set_credential(Some(crate::credential::CloudCredential::long_term("ak", "sk")));
    assert!(adapter.with_recording_transport(transport.clone()).is_ok());
    let teams = adapter.pull_teams().await;
    assert_eq!(teams.as_ref().ok().map(Vec::len), Some(1));
    if let Ok(teams) = teams {
        assert_eq!(teams[0].cloud_team_id, "t-live");
    }
    let requests = transport.requests.lock().unwrap();
    assert!(requests[0].query.contains("Action=ListTeams"));
    assert!(requests[1].query.contains("Action=ListWorkers"));
    assert!(requests[2].query.contains("Action=GetTeam"));
}

#[tokio::test]
pub(crate) async fn self_check_and_descriptor() {
    let mut adapter = AgentTeamsAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::AgentTeams, true)).await.is_ok());
    let health = adapter.self_check().await;
    assert!(health.is_ok());
    if let Ok(health) = health {
        assert!(health.message.unwrap_or_default().contains("未公布 RAM Action"));
    }
    let descriptor = AgentTeamsAdapter::new().descriptor();
    assert_eq!(descriptor.name, "alicloud-agentteams");
    assert!(descriptor.capabilities.contains(&agf_core::adapter::AdapterCapability::PullInventory));
    assert!(descriptor.capabilities.contains(&agf_core::adapter::AdapterCapability::SubscribeEvents));
    assert!(descriptor.mock_location.ends_with("#mock_agentteams"));
    assert!(descriptor.degradation.contains("平台为准"));
}
