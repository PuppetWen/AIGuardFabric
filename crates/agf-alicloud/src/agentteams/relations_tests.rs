use super::relations::{self, RelationshipEvidence, ResourceKind};
use agf_core::error::DomainError;
use serde_json::{Value, json};

fn team(workers: Value) -> Value {
    json!({"Name":"team-one","InstanceId":"inst-one","WorkerNames":workers})
}
fn worker(groups: Value) -> Value {
    json!({"Name":"worker-one","InstanceId":"inst-one","Groups":groups})
}
fn groups(role: Value) -> Value {
    json!([{"Type":"team","Name":"team-one","Role":role}])
}

#[test]
fn explicit_team_membership_needs_no_invented_role_or_permissions() {
    let mut team = team(json!(["worker-one"]));
    team["TeamMembers"] = json!([{"Name":"worker-one"},{"Name":"human-only"}]);
    let graph = relations::parse_inventory("inst-one", &[team], &[worker(Value::Null)]).unwrap();
    graph.require_complete().unwrap();
    let team = &graph.teams["team-one"];
    assert_eq!(team.evidence, RelationshipEvidence::TeamWorkerNames);
    assert_eq!(team.workers.as_ref().unwrap().len(), 1);
    assert_eq!(team.workers.as_ref().unwrap()["worker-one"], None);
    assert_eq!(team.humans.as_ref().unwrap().len(), 2);
    assert_eq!(graph.workers.len(), 1);
}

#[test]
fn missing_and_null_are_unknown_but_explicit_empty_is_observed() {
    for field in [None, Some(Value::Null)] {
        let mut team = team(Value::Null);
        let mut worker = worker(Value::Null);
        if field.is_none() {
            team.as_object_mut().unwrap().remove("WorkerNames");
            worker.as_object_mut().unwrap().remove("Groups");
        }
        let graph = relations::parse_inventory("inst-one", &[team], &[worker]).unwrap();
        assert!(graph.teams["team-one"].workers.is_none());
        assert_eq!(graph.teams["team-one"].evidence, RelationshipEvidence::Unverified);
        assert!(matches!(graph.require_complete(), Err(DomainError::PreconditionFailed(_))));
    }
    let graph = relations::parse_inventory("inst-one", &[team(json!([]))], &[worker(json!([]))]).unwrap();
    graph.require_complete().unwrap();
    assert!(graph.teams["team-one"].workers.as_ref().unwrap().is_empty());
    assert!(graph.teams["team-one"].humans.is_none());
}

#[test]
fn worker_groups_fallback_requires_negative_evidence_for_every_worker() {
    let first = worker(groups(json!("custom-reviewer")));
    let unknown = json!({"Name":"worker-two","InstanceId":"inst-one"});
    let graph = relations::parse_inventory("inst-one", &[team(Value::Null)], &[first.clone(), unknown]).unwrap();
    assert!(graph.teams["team-one"].workers.is_none());
    let empty = json!({"Name":"worker-two","InstanceId":"inst-one","Groups":[]});
    let graph = relations::parse_inventory("inst-one", &[team(Value::Null)], &[first, empty]).unwrap();
    graph.require_complete().unwrap();
    assert_eq!(graph.teams["team-one"].evidence, RelationshipEvidence::WorkerGroups);
    let members = graph.teams["team-one"].workers.as_ref().unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members["worker-one"].as_deref(), Some("custom-reviewer"));
}

#[test]
fn explicit_bidirectional_contradictions_reject_the_entire_graph() {
    for (names, groups) in [
        (json!([]), groups(json!("member"))),
        (json!(["worker-one"]), json!([])),
        (json!(["worker-one"]), json!([{"Type":"workspace","Name":"team-one"}])),
    ] {
        assert!(relations::parse_inventory("inst-one", &[team(names)], &[worker(groups)]).is_err());
    }
}

#[test]
fn unknown_worker_or_team_references_are_never_dropped() {
    assert!(relations::parse_inventory("inst-one", &[team(json!(["ghost"]))], &[worker(Value::Null)]).is_err());
    let ghost = json!([{"Type":"team","Name":"ghost"}]);
    assert!(relations::parse_inventory("inst-one", &[team(Value::Null)], &[worker(ghost)]).is_err());
    let valid = relations::parse_inventory("inst-one", &[team(json!([]))], &[worker(Value::Null)]).unwrap();
    assert!(relations::verify_list_references(&[team(json!(["ghost"]))], &[], &valid).is_err());
    let listed = worker(json!([{"Type":"team","Name":"ghost"}]));
    assert!(relations::verify_list_references(&[], &[listed], &valid).is_err());
}

#[test]
fn all_nonnull_relationship_fields_and_entries_have_strict_types() {
    for value in [json!("[]"), json!({}), json!(false), json!(1), json!([null])] {
        assert!(relations::parse_inventory("inst-one", &[team(value.clone())], &[worker(Value::Null)]).is_err());
        assert!(relations::parse_inventory("inst-one", &[team(json!([]))], &[worker(value.clone())]).is_err());
        let mut human = team(json!([]));
        human["TeamMembers"] = value;
        assert!(relations::parse_inventory("inst-one", &[human], &[]).is_err());
    }
    for group in [
        json!({"Name":"team-one"}),
        json!({"Type":"team","Name":true}),
        json!({"Type":"team","Name":"team-one","Role":false}),
        json!({"Type":"team","Name":"team-one","Role":""}),
    ] {
        assert!(relations::parse_inventory("inst-one", &[team(Value::Null)], &[worker(json!([group]))]).is_err());
    }
}

#[test]
fn duplicates_normalize_but_conflicting_roles_and_duplicate_resources_reject() {
    let duplicate = json!([
        {"Type":"team","Name":"team-one","Role":"member"},
        {"Type":"team","Name":"team-one","Role":"member"}
    ]);
    let graph =
        relations::parse_inventory("inst-one", &[team(json!(["worker-one", "worker-one"]))], &[worker(duplicate)])
            .unwrap();
    assert_eq!(graph.teams["team-one"].workers.as_ref().unwrap().len(), 1);
    let conflict = json!([
        {"Type":"team","Name":"team-one","Role":"member"},
        {"Type":"team","Name":"team-one","Role":"other"}
    ]);
    assert!(relations::parse_inventory("inst-one", &[team(json!(["worker-one"]))], &[worker(conflict)]).is_err());
    assert!(relations::parse_inventory("inst-one", &[team(json!([])), team(json!([]))], &[]).is_err());
    assert!(
        relations::parse_inventory("inst-one", &[team(json!([]))], &[worker(Value::Null), worker(Value::Null)])
            .is_err()
    );
}

#[test]
fn list_and_detail_identity_and_explicit_membership_must_match() {
    let listed = team(json!(["worker-one"]));
    for (field, value) in [
        ("Name", json!("another")),
        ("InstanceId", json!("other-instance")),
        ("WorkerNames", json!([])),
        ("WorkerNames", json!(false)),
    ] {
        let mut detail = listed.clone();
        detail[field] = value;
        assert!(relations::verify_detail(&listed, &detail, "inst-one", ResourceKind::Team).is_err());
    }
    let mut list_human = listed.clone();
    list_human["TeamMembers"] = json!([{"Name":"a"}]);
    let mut detail_human = listed.clone();
    detail_human["TeamMembers"] = json!([{"Name":"b"}]);
    assert!(relations::verify_detail(&list_human, &detail_human, "inst-one", ResourceKind::Team).is_err());
    relations::verify_detail(&listed, &team(Value::Null), "inst-one", ResourceKind::Team).unwrap();
    let mut wrong_list_instance = listed.clone();
    wrong_list_instance["InstanceId"] = json!("wrong");
    assert!(relations::verify_detail(&wrong_list_instance, &listed, "inst-one", ResourceKind::Team).is_err());
}

#[test]
fn ordered_sets_compare_equal_and_missing_roles_do_not_claim_contradiction() {
    let listed = worker(groups(json!("member")));
    relations::verify_detail(&listed, &worker(groups(Value::Null)), "inst-one", ResourceKind::Worker).unwrap();
    assert!(
        relations::verify_detail(&listed, &worker(groups(json!("other"))), "inst-one", ResourceKind::Worker).is_err()
    );
    let mut a = team(json!(["second", "first"]));
    let mut b = team(json!(["first", "second", "first"]));
    a["TeamMembers"] = json!([{"Name":"b"},{"Name":"a"}]);
    b["TeamMembers"] = json!([{"Name":"a"},{"Name":"b"}]);
    relations::verify_detail(&a, &b, "inst-one", ResourceKind::Team).unwrap();
}

#[test]
fn explicit_empty_humans_and_zero_workers_remain_independent() {
    let mut team = team(Value::Null);
    team["TeamMembers"] = json!([]);
    let graph = relations::parse_inventory("inst-one", &[team], &[]).unwrap();
    graph.require_complete().unwrap();
    assert_eq!(graph.teams["team-one"].evidence, RelationshipEvidence::WorkerGroups);
    assert!(graph.teams["team-one"].workers.as_ref().unwrap().is_empty());
    assert!(graph.teams["team-one"].humans.as_ref().unwrap().is_empty());
}

#[test]
fn identity_is_case_sensitive_and_rejects_control_characters() {
    for name in ["", "worker\none", " Worker", "worker "] {
        let mut worker = worker(Value::Null);
        worker["Name"] = json!(name);
        assert!(relations::parse_inventory("inst-one", &[team(json!([]))], &[worker]).is_err());
    }
    assert!(relations::parse_inventory("inst-one", &[team(json!(["Worker-One"]))], &[worker(Value::Null)]).is_err());
}
