//! Complete directory evidence, safe role projection and fail-closed relationship publication.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
#[path = "cloud_relations_helpers/mod.rs"]
mod relations;
use common::*;
use relations::*;

#[tokio::test]
async fn cloud_users_are_separate_from_workers_and_group_roles_are_observed_not_invented() {
    let f = Fixture::new().await;
    let mut directory = Directory::valid();
    directory.team_field("TeamMembers", Some(json!([{"Name":WORKER},{"Name":"human-local"}])));
    directory.tasks =
        vec![json!({"TaskId":"task-local","TaskTitle":"Actual cloud metadata","AssignedTo":"human-local"})];
    let teams = f.succeed(&directory).await;
    let team = row(&teams, TEAM);
    assert_eq!(team["relationshipAvailable"], true);
    assert_eq!(team["relationshipEvidence"], "team-worker-names");
    assert_eq!(team["memberCount"], 1);
    assert_eq!(team["members"][0]["id"], WORKER);
    assert_eq!(team["members"][0]["cloudRole"], "member");
    assert_eq!(team["members"][0]["role"], "member");
    assert_eq!(team["humanMembersAvailable"], true);
    assert_eq!(team["humanMemberCount"], 2);
    assert_eq!(team["humanMembers"].as_array().unwrap().len(), 2);
    assert_eq!(team["dagAvailable"], false);
    assert_eq!(team["dagEvidence"], "not-provided");
    assert_eq!(team["dag"], json!([]));
    assert_eq!(team["tasks"][0]["assignedTo"], "human-local");
    let assets = f.h.state.store.asset_list_all(f.h.tenant).unwrap();
    assert_eq!(assets.len(), 1, "cloud users and task assignees must not become Agent assets");
    assert_eq!(assets[0].name, WORKER);
    assert!(!teams.to_string().contains("LOOPBACK-SECRET"));
}

#[tokio::test]
async fn absent_or_null_worker_names_can_be_derived_only_from_complete_explicit_groups() {
    let f = Fixture::new().await;
    for names in [None, Some(Value::Null)] {
        let mut directory = Directory::valid();
        directory.team_field("WorkerNames", names);
        directory.add_worker("ungrouped-worker", Some(json!([])));
        let teams = f.succeed(&directory).await;
        let team = row(&teams, TEAM);
        assert_eq!(team["relationshipAvailable"], true);
        assert_eq!(team["relationshipEvidence"], "worker-groups");
        assert_eq!(team["memberCount"], 1);
        assert_eq!(team["members"][0]["cloudRole"], "member");
        assert_eq!(f.h.state.store.asset_list_all(f.h.tenant).unwrap().len(), 2);
    }
}

#[tokio::test]
async fn missing_one_workers_groups_is_unknown_and_preserves_the_entire_governed_snapshot() {
    let f = Fixture::new().await;
    let before = f.governed_baseline().await;
    for groups in [None, Some(Value::Null)] {
        let mut directory = Directory::valid();
        directory.team_field("WorkerNames", None);
        directory.add_worker("unobserved-worker", groups);
        let rejected = f.reject(&directory, &before, "unobserved unlisted membership").await;
        assert_eq!(rejected.status, StatusCode::PRECONDITION_FAILED);
    }
}

#[tokio::test]
async fn explicit_team_membership_with_unknown_groups_or_role_retains_membership_without_a_fake_role() {
    let f = Fixture::new().await;
    for groups in [
        None,
        Some(Value::Null),
        Some(json!([{"Type":"team","Name":TEAM}])),
        Some(json!([{"Type":"team","Name":TEAM,"Role":null}])),
    ] {
        let mut directory = Directory::valid();
        directory.worker_field("Groups", groups);
        let teams = f.succeed(&directory).await;
        let team = row(&teams, TEAM);
        assert_eq!(team["relationshipAvailable"], true);
        assert_eq!(team["memberCount"], 1);
        assert_eq!(team["members"][0]["cloudRole"], Value::Null);
        assert_eq!(team["members"][0]["role"], Value::Null);
    }
}

#[tokio::test]
async fn newly_unobserved_worker_fields_clear_old_cloud_values_without_clearing_manual_governance() {
    let f = Fixture::new().await;
    let mut directory = Directory::valid();
    for (field, value) in [
        ("AgentType", json!("Qwenpaw")),
        ("DeployType", json!("Managed")),
        ("Skills", json!([{"Name":"observed-skill"}])),
        ("McpServers", json!([{"Name":"observed-mcp","Transport":"sse"}])),
    ] {
        directory.worker_field(field, Some(value));
    }
    f.succeed(&directory).await;
    let snapshot = agf_api::cloud_inventory::load(&f.h.state, f.h.tenant).await.unwrap().unwrap();
    let mut manual = f.h.state.store.asset_get(f.h.tenant, snapshot.assets[WORKER]).unwrap().unwrap();
    manual.owner = Some("manual-owner".into());
    manual.data_class = agf_core::enums::DataClass::Confidential;
    manual.lifecycle = agf_core::enums::LifecycleState::Production;
    manual.attributes.insert("manual-note".into(), json!("retain approved ownership"));
    f.h.state.store.asset_upsert(&manual).unwrap();
    for (index, field) in
        ["Status", "AgentType", "DeployType", "Groups", "Model", "Skills", "McpServers"].into_iter().enumerate()
    {
        assert!(!manual.attributes[&format!("cloud_{field}")].is_null(), "baseline {field} must be observed");
        directory.worker_field(field, if index % 2 == 0 { None } else { Some(Value::Null) });
    }
    let teams = f.succeed(&directory).await;
    assert_eq!(row(&teams, TEAM)["relationshipAvailable"], true);
    assert_eq!(row(&teams, TEAM)["members"][0]["cloudRole"], Value::Null);
    let asset = f.h.state.store.asset_get(f.h.tenant, manual.id).unwrap().unwrap();
    for field in ["Status", "AgentType", "DeployType", "Groups", "Model", "Skills", "McpServers"] {
        assert_eq!(asset.attributes.get(&format!("cloud_{field}")), Some(&Value::Null), "{field} is now unknown");
    }
    assert_eq!(asset.owner, manual.owner);
    assert_eq!(asset.data_class, manual.data_class);
    assert_eq!(asset.lifecycle, manual.lifecycle);
    assert_eq!(asset.attributes["manual-note"], manual.attributes["manual-note"]);
    assert_eq!(asset.fingerprint, manual.fingerprint);
}

#[tokio::test]
async fn explicit_empty_arrays_are_observed_empty_but_null_cloud_users_are_unknown() {
    let f = Fixture::new().await;
    let mut directory = Directory::valid();
    directory.team_field("WorkerNames", Some(json!([])));
    directory.worker_field("Groups", Some(json!([])));
    for people in [None, Some(Value::Null), Some(json!([]))] {
        let known = people.as_ref().is_some_and(Value::is_array);
        directory.team_field("TeamMembers", people);
        let teams = f.succeed(&directory).await;
        let team = row(&teams, TEAM);
        assert_eq!(team["relationshipAvailable"], true);
        assert_eq!(team["memberCount"], 0);
        assert_eq!(team["members"], json!([]));
        assert_eq!(team["humanMembersAvailable"], known);
        assert_eq!(team["humanMemberCount"], if known { json!(0) } else { Value::Null });
    }
}

#[tokio::test]
async fn clearly_conflicting_directions_or_roles_never_replace_the_complete_snapshot() {
    let f = Fixture::new().await;
    let before = f.governed_baseline().await;
    let mut cases = Vec::new();
    let mut team_empty = Directory::valid();
    team_empty.team_field("WorkerNames", Some(json!([])));
    cases.push(("empty Team versus positive Groups", team_empty));
    let mut groups_empty = Directory::valid();
    groups_empty.worker_field("Groups", Some(json!([])));
    cases.push(("positive Team versus empty Groups", groups_empty));
    let mut other_team = Directory::valid();
    other_team.add_team("other-team", json!([WORKER]));
    other_team.worker_field("Groups", Some(json!([{"Type":"team","Name":"other-team","Role":"member"}])));
    cases.push(("positive Team versus another Group", other_team));
    let mut roles = Directory::valid();
    roles.worker_field(
        "Groups",
        Some(json!([{"Type":"team","Name":TEAM,"Role":"member"},
        {"Type":"team","Name":TEAM,"Role":"owner"}])),
    );
    cases.push(("conflicting roles for one edge", roles));
    for (label, directory) in cases {
        f.reject(&directory, &before, label).await;
    }
}

#[tokio::test]
async fn malformed_non_null_relationship_fields_and_unknown_references_are_not_silently_filtered() {
    let f = Fixture::new().await;
    let before = f.governed_baseline().await;
    let mut cases = Vec::new();
    for value in [json!(42), json!({}), json!([42]), json!([""]), json!(["missing-worker"])] {
        let mut directory = Directory::valid();
        directory.team_field("WorkerNames", Some(value));
        cases.push(directory);
    }
    for value in [
        json!(42),
        json!({}),
        json!([42]),
        json!([{}]),
        json!([{"Type":"team","Name":""}]),
        json!([{"Type":"team","Name":TEAM,"Role":42}]),
        json!([{"Type":"team","Name":"missing-team","Role":"member"}]),
    ] {
        let mut directory = Directory::valid();
        directory.worker_field("Groups", Some(value));
        cases.push(directory);
    }
    for value in [json!(42), json!({}), json!([42]), json!([{}]), json!([{"Name":42}])] {
        let mut directory = Directory::valid();
        directory.team_field("TeamMembers", Some(value));
        cases.push(directory);
    }
    for (index, directory) in cases.iter().enumerate() {
        f.reject(directory, &before, &format!("invalid relation case {index}")).await;
    }
}

#[tokio::test]
async fn list_and_detail_explicit_relationships_must_agree_instead_of_overwriting_each_other() {
    let f = Fixture::new().await;
    let before = f.governed_baseline().await;
    for field in ["WorkerNames", "TeamMembers", "Groups"] {
        let mut directory = Directory::valid();
        if field == "Groups" {
            directory.worker_details[0][field] = json!([]);
        } else {
            directory.team_details[0][field] = json!([]);
        }
        f.reject(&directory, &before, &format!("List/Get disagree on {field}")).await;
    }
}

#[tokio::test]
async fn list_only_references_are_checked_but_do_not_turn_unknown_details_into_trusted_membership() {
    let f = Fixture::new().await;
    let before = f.governed_baseline().await;
    for (target, listed) in [
        ("team", json!(["missing-worker"])),
        ("team", json!([])),
        ("worker", json!([{"Type":"team","Name":"missing-team","Role":"member"}])),
        ("worker", json!([])),
    ] {
        let mut directory = Directory::valid();
        if target == "team" {
            directory.teams[0]["WorkerNames"] = listed;
            directory.team_details[0]["WorkerNames"] = Value::Null;
        } else {
            directory.workers[0]["Groups"] = listed;
            directory.worker_details[0]["Groups"] = Value::Null;
        }
        let rejected = f.reject(&directory, &before, "list-only reference contradicts complete details").await;
        assert_eq!(rejected.status, StatusCode::BAD_REQUEST, "{}", rejected.text);
    }
    let mut unknown = Directory::valid();
    unknown.team_details[0]["WorkerNames"] = Value::Null;
    unknown.worker_field("Groups", None);
    let rejected = f.reject(&unknown, &before, "listed membership does not prove missing detail relationships").await;
    assert_eq!(rejected.status, StatusCode::PRECONDITION_FAILED, "{}", rejected.text);
}

#[tokio::test]
async fn details_and_non_empty_list_instance_ids_must_match_the_requested_resources() {
    let f = Fixture::new().await;
    let before = f.governed_baseline().await;
    for (resource, field, value) in [
        ("team", "Name", json!("foreign-team")),
        ("team", "InstanceId", json!("foreign-instance")),
        ("team", "InstanceId", Value::Null),
        ("worker", "Name", json!("foreign-worker")),
        ("worker", "InstanceId", json!("foreign-instance")),
        ("team-list", "InstanceId", json!("foreign-instance")),
        ("worker-list", "InstanceId", json!("foreign-instance")),
    ] {
        let mut directory = Directory::valid();
        let row = match resource {
            "team" => &mut directory.team_details[0],
            "worker" => &mut directory.worker_details[0],
            "team-list" => &mut directory.teams[0],
            _ => &mut directory.workers[0],
        };
        row[field] = value;
        f.reject(&directory, &before, &format!("{resource} {field} identity mismatch")).await;
    }
}

#[tokio::test]
async fn normalized_sets_allow_reordering_and_identical_edges_without_losing_cloud_roles() {
    let f = Fixture::new().await;
    let mut directory = Directory::valid();
    directory.add_worker("second-worker", Some(json!([{"Type":"team","Name":TEAM,"Role":"reviewer"}])));
    directory.team_field("WorkerNames", Some(json!([WORKER, "second-worker", WORKER])));
    directory.team_details[0]["WorkerNames"] = json!(["second-worker", WORKER]);
    directory.team_field("TeamMembers", Some(json!([{"Name":"human-a"},{"Name":"human-b"}])));
    directory.team_details[0]["TeamMembers"] = json!([{"Name":"human-b"},{"Name":"human-a"}]);
    directory.worker_field(
        "Groups",
        Some(json!([{"Type":"team","Name":TEAM,"Role":"member"},
        {"Type":"team","Name":TEAM,"Role":"member"},{"Type":"project","Name":"project-local","Role":"reader"}])),
    );
    directory.worker_details[0]["Groups"] = json!([{"Type":"project","Name":"project-local","Role":"reader"},
        {"Type":"team","Name":TEAM,"Role":"member"}]);
    let teams = f.succeed(&directory).await;
    let team = row(&teams, TEAM);
    assert_eq!(team["memberCount"], 2);
    let members = team["members"].as_array().unwrap();
    assert_eq!(members.iter().find(|row| row["id"] == WORKER).unwrap()["cloudRole"], "member");
    assert_eq!(members.iter().find(|row| row["id"] == "second-worker").unwrap()["cloudRole"], "reviewer");
}

#[tokio::test]
async fn unresolved_old_snapshots_remain_unknown_and_cannot_create_a_trusted_audit_binding() {
    let f = Fixture::new().await;
    f.succeed(&Directory::valid()).await;
    let mut snapshot = agf_api::cloud_inventory::load(&f.h.state, f.h.tenant).await.unwrap().unwrap();
    snapshot.teams[0].as_object_mut().unwrap().remove("WorkerNames");
    snapshot.workers[0].as_object_mut().unwrap().remove("Groups");
    store_snapshot(&f.h, &snapshot).await;
    let result = f.h.get(TEAMS).await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    let teams = result.json();
    let team = row(&teams, TEAM);
    assert_eq!(team["relationshipAvailable"], false);
    assert_eq!(team["relationshipEvidence"], "unverified");
    assert_eq!(team["memberCount"], Value::Null);
    assert_eq!(team["members"], json!([]));
    assert_eq!(team["mocked"], false);
    let source =
        f.h.post("/api/v1/ingest/sources", json!({"name":"unverified-relations","protocol":"http-webhook"})).await;
    assert_eq!(source.status, StatusCode::CREATED, "{}", source.text);
    let path = format!("{SOURCES}/{}", source.json()["id"].as_str().unwrap());
    let bind = f.h.request("PUT", &path, Some(&f.h.admin), Some(json!({"expected_version":0,"enabled":true}))).await;
    assert_eq!(bind.status, StatusCode::PRECONDITION_FAILED, "{}", bind.text);
    assert!(f.h.get(SOURCES).await.json()["items"].as_array().unwrap().is_empty());
}
