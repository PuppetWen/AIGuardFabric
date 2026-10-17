#![allow(clippy::unwrap_used, clippy::panic)]
use super::{contract::Scope, parse};
use serde_json::{Value, json};

fn scope() -> Scope {
    Scope { instance_id: "owned-instance".into(), namespace_id: String::new(), ..Scope::default() }
}

#[test]
fn explicit_zero_is_observed_and_missing_counts_remain_unknown() {
    let value = json!({"TotalCount":2,"PageNumber":1,"PageSize":100,"Data":[
        {"Name":"zero","GroupName":"group","IpCount":0,"HealthyInstanceCount":0,"ClusterCount":0},
        {"Name":"unknown","GroupName":"group","HealthyInstanceCount":null,"Metadata":{"secret":"must not persist"}}
    ]});
    let page = parse::page(&value, &scope(), 1).unwrap();
    assert_eq!(page.services[0].instance_count, Some(0));
    assert_eq!(page.services[0].healthy_count, Some(0));
    assert_eq!(page.services[1].instance_count, None);
    assert_eq!(page.services[1].healthy_count, None);
    assert!(!serde_json::to_string(&page.services).unwrap().contains("must not persist"));
}

#[test]
fn malformed_identity_or_pagination_never_becomes_a_valid_empty_inventory() {
    let valid = json!({"TotalCount":1,"PageNumber":1,"PageSize":100,"Data":[{"Name":"service","GroupName":"group"}]});
    let variants: Vec<Value> = vec![
        json!({"Data":[]}),
        json!({"TotalCount":null,"Data":[]}),
        json!({"TotalCount":2001,"Data":[]}),
        json!({"TotalCount":0,"Data":null}),
        json!({"TotalCount":0,"Data":[],"InstanceId":"foreign"}),
        json!({"TotalCount":0,"Data":[],"NamespaceId":"foreign"}),
    ];
    for value in variants {
        assert!(parse::page(&value, &scope(), 1).is_err(), "{value}");
    }
    for (field, value) in [("PageNumber", json!(2)), ("PageSize", json!(99)), ("TotalCount", json!("1"))] {
        let mut malformed = valid.clone();
        malformed[field] = value;
        assert!(parse::page(&malformed, &scope(), 1).is_err());
    }
    for (field, value) in [
        ("Name", json!("bad\nname")),
        ("GroupName", json!([])),
        ("IpCount", json!(-1)),
        ("IpCount", json!("1")),
        ("HealthyInstanceCount", json!(true)),
        ("Source", json!({})),
    ] {
        let mut malformed = valid.clone();
        malformed["Data"][0][field] = value;
        assert!(parse::page(&malformed, &scope(), 1).is_err(), "{malformed}");
    }
    let inconsistent =
        json!({"TotalCount":1,"Data":[{"Name":"service","GroupName":"group","IpCount":1,"HealthyInstanceCount":2}]});
    assert!(parse::page(&inconsistent, &scope(), 1).is_err());
}

#[test]
fn service_identity_is_unambiguous_for_delimiter_names() {
    let page = parse::page(
        &json!({"TotalCount":2,"Data":[
            {"Name":"c","GroupName":"a:b"},{"Name":"b:c","GroupName":"a"}
        ]}),
        &scope(),
        1,
    )
    .unwrap();
    assert_ne!(page.services[0].key, page.services[1].key);
}
