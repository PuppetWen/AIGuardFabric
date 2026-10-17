use super::*;
use crate::{
    credential::CloudCredential,
    test_support::{ScriptedTransport, fixture_config_with_secrets},
};
use serde_json::{Value, json};

async fn adapter(responses: Vec<Value>) -> (AgentTeamsAdapter, Arc<ScriptedTransport>) {
    let mut config = fixture_config_with_secrets(AliCloudService::AgentTeams, false);
    for (name, value) in [("instance_id", "inst-live"), ("worker_name", "worker-one"), ("quota_period", "day")] {
        config.settings.insert(name.into(), json!(value));
    }
    let mut adapter = AgentTeamsAdapter::new();
    adapter.init(&config).await.unwrap();
    adapter.core_mut().set_credential(Some(CloudCredential::long_term("ak", "sk")));
    let transport = ScriptedTransport::new(responses);
    adapter.with_recording_transport(transport.clone()).unwrap();
    (adapter, transport)
}

fn worker(limit: i64, period: &str) -> Value {
    json!({"Data":{"InstanceId":"inst-live","Name":"worker-one",
        "LimitConfig":{"LimitType":"token","PeriodType":period,"UsageLimit":limit}}})
}

#[tokio::test]
async fn actual_team_pages_read_worker_details_without_inventing_human_agents_or_dags() {
    let (adapter, transport) = adapter(vec![
        json!({"Items":[{"Name":"first","WorkerNames":["worker-one"],"TeamMembers":[{"Name":"alice"}]}],"NextToken":"more","TotalCount":2}),
        json!({"Items":[{"Name":"second","WorkerNames":[]}],"TotalCount":2}),
        json!({"Items":[{"InstanceId":"inst-live","Name":"worker-one","Groups":[{"Type":"team","Name":"first","Role":"member"}]}]}),
        json!({"Data":{"InstanceId":"inst-live","Name":"first","WorkerNames":["worker-one"],
            "TeamMembers":[{"Name":"alice"}],"UpdatedAt":"2026-09-01T00:00:00Z"}}),
        json!({"Data":{"InstanceId":"inst-live","Name":"second","WorkerNames":[]}}),
        json!({"Data":{"InstanceId":"inst-live","Name":"worker-one","Status":"Running", "Model":{"ModelName":"qwen"},
            "McpServers":[{"Name":"search"}],"Groups":[{"Type":"team","Name":"first","Role":"member"}]}}),
    ]).await;
    let teams = adapter.pull_teams().await.unwrap();
    assert_eq!(teams.len(), 2);
    assert_eq!(teams[0].cloud_team_id, "first");
    assert_eq!(teams[0].agents.len(), 1);
    assert_eq!(teams[0].agents[0].name, "worker-one");
    assert_eq!(teams[0].agents[0].models, ["qwen"]);
    assert_eq!(teams[0].agents[0].tools, ["mcp:search"]);
    assert_eq!(teams[0].roles[0].name, "member");
    assert!(teams[0].orchestration.is_empty());
    assert!(teams[0].agents[0].asset_id.is_none());
    assert!(teams[0].cloud_updated_at.is_some(), "GetTeam detail provides the actual update timestamp");
    let requests = transport.requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .all(|request| request.query.contains("Version=2026-06-05")
                && request.query.contains("InstanceId=inst-live"))
    );
    assert!(requests[1].query.contains("NextToken=more"));
    assert_eq!(requests.len(), 6);
    assert!(requests[2].query.contains("Action=ListWorkers"));
    assert!(requests[3].query.contains("Action=GetTeam"));
    assert!(requests[3].query.contains("Name=first"));
    assert!(requests[4].query.contains("Action=GetTeam"));
    assert!(requests[5].query.contains("Action=GetWorker"));
}

fn relationship_responses(names: Option<Value>, groups: Option<Value>) -> Vec<Value> {
    let mut team = json!({"InstanceId":"inst-live","Name":"first","TeamMembers":[{"Name":"worker-one"}]});
    let mut worker = json!({"InstanceId":"inst-live","Name":"worker-one","Status":"Running"});
    if let Some(names) = names {
        team["WorkerNames"] = names;
    }
    if let Some(groups) = groups {
        worker["Groups"] = groups;
    }
    vec![
        json!({"Items":[team.clone()],"TotalCount":1}),
        json!({"Items":[worker.clone()],"TotalCount":1}),
        json!({"Data":team}),
        json!({"Data":worker}),
    ]
}

#[tokio::test]
async fn complete_groups_fallback_and_explicit_membership_with_unknown_roles_are_real_observations() {
    for (names, groups, role_known) in [
        (None, Some(json!([{"Type":"team","Name":"first","Role":"member"}])), true),
        (Some(json!(["worker-one"])), None, false),
        (Some(json!(["worker-one"])), Some(json!([{"Type":"team","Name":"first","Role":null}])), false),
    ] {
        let (adapter, transport) = adapter(relationship_responses(names, groups)).await;
        let teams = adapter.pull_teams().await.unwrap();
        assert_eq!(teams[0].agents.len(), 1);
        if role_known {
            assert_eq!(teams[0].agents[0].role_names, ["member"]);
        } else {
            assert!(teams[0].agents[0].role_names.is_empty());
            assert!(teams[0].roles.is_empty());
        }
        assert!(teams[0].orchestration.is_empty());
        assert_eq!(transport.requests.lock().unwrap().len(), 4);
    }
}

#[tokio::test]
async fn human_names_never_create_workers_and_explicit_empty_groups_differ_from_missing_groups() {
    let (empty, _) = adapter(relationship_responses(Some(json!([])), Some(json!([])))).await;
    let teams = empty.pull_teams().await.unwrap();
    assert!(teams[0].agents.is_empty(), "human named worker-one is not a Worker membership");
    for (names, groups) in [
        (None, None),
        (Some(json!(["worker-one"])), Some(json!([]))),
        (Some(json!([])), Some(json!([{"Type":"team","Name":"first","Role":"member"}]))),
    ] {
        let (adapter, transport) = adapter(relationship_responses(names, groups)).await;
        assert!(adapter.pull_teams().await.is_err());
        assert!(
            transport
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|request| !request.query.contains("Action=Create") && !request.query.contains("Action=Update"))
        );
    }
}

#[tokio::test]
async fn list_get_conflicts_and_wrong_detail_instances_are_not_silently_normalized() {
    for target in ["team-members", "worker-groups", "team-instance", "worker-instance"] {
        let mut responses = relationship_responses(
            Some(json!(["worker-one"])),
            Some(json!([{"Type":"team","Name":"first","Role":"member"}])),
        );
        match target {
            "team-members" => responses[2]["Data"]["TeamMembers"] = json!([]),
            "worker-groups" => responses[3]["Data"]["Groups"] = json!([]),
            "team-instance" => responses[2]["Data"]["InstanceId"] = json!("another-instance"),
            _ => responses[3]["Data"]["InstanceId"] = json!("another-instance"),
        }
        let (adapter, _) = adapter(responses).await;
        assert!(adapter.pull_teams().await.is_err(), "{target}");
    }
}

#[tokio::test]
async fn quota_conflict_writes_worker_limit_then_requires_consistent_readback() {
    let (adapter, transport) = adapter(vec![worker(200, "day"), json!({"Success":true}), worker(300, "day")]).await;
    let report = adapter.sync_quotas(Id::new(), &[(QuotaDimension::Tokens, 300)]).await.unwrap();
    assert!(report.has_conflict());
    assert_eq!(report.effective["tokens"], 300);
    assert_eq!(report.states[0].cloud_value, 200);
    {
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[1].query.contains("Action=UpdateWorker"));
        assert!(requests[1].query.contains("LimitConfig="));
        assert!(requests[1].body.contains("ClientToken="));
        assert!(!requests[1].query.contains("Model="));
    }
    let (adapter, _) = self::adapter(vec![worker(200, "day"), json!({"Success":true}), worker(200, "day")]).await;
    assert!(adapter.sync_quotas(Id::new(), &[(QuotaDimension::Tokens, 300)]).await.is_err());
}

#[tokio::test]
async fn unsupported_quotas_and_mismatched_periods_do_not_write() {
    let (adapter, transport) = adapter(vec![worker(200, "month")]).await;
    assert!(adapter.sync_quotas(Id::new(), &[(QuotaDimension::Concurrency, 4)]).await.is_err());
    assert!(transport.requests.lock().unwrap().is_empty());
    assert!(adapter.sync_quotas(Id::new(), &[(QuotaDimension::Tokens, 300)]).await.is_err());
    assert_eq!(transport.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn no_fake_call_or_audit_api_and_no_implicit_demo_writes() {
    let (adapter, transport) = adapter(vec![]).await;
    assert!(adapter.pull_cross_team_calls(None).await.is_err());
    assert!(adapter.pull_audit_events(None).await.is_err());
    assert!(adapter.sync(SyncDirection::Both, &PullRequest::default()).await.is_err());
    assert!(adapter.sync_teams(&[], SyncDirection::Push).await.is_err());
    assert!(transport.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn malformed_or_incomplete_inventory_is_not_success() {
    for body in [json!({"Teams":[]}), json!({"Items":[],"TotalCount":1})] {
        let (adapter, transport) = adapter(vec![body]).await;
        assert!(matches!(adapter.pull_teams().await, Err(DomainError::Parse(_))));
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
    }
    // Missing relationships are checked after the complete resource details, not at ListTeams.
    let (adapter, transport) = adapter(vec![
        json!({"Items":[{"Name":"t"}],"TotalCount":1}),
        json!({"Items":[{"InstanceId":"inst-live","Name":"worker-one"}],"TotalCount":1}),
        json!({"Data":{"InstanceId":"inst-live","Name":"t"}}),
        json!({"Data":{"InstanceId":"inst-live","Name":"worker-one"}}),
    ])
    .await;
    assert!(matches!(adapter.pull_teams().await, Err(DomainError::PreconditionFailed(_))));
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    for (request, action) in requests.iter().zip(["ListTeams", "ListWorkers", "GetTeam", "GetWorker"]) {
        assert!(request.query.contains(&format!("Action={action}")));
    }
}
