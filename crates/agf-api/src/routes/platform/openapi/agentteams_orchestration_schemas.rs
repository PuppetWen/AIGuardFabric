//! Exact wire spellings: strict snake-case input/DAG; camel-case direct views.
use serde_json::{Value, json};
fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
fn object(properties: Value) -> Value {
    let required = properties.as_object().map(|p| p.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
    json!({"type":"object","additionalProperties":false,"properties":properties,"required":required})
}
fn fixed(value: Value) -> Value {
    json!({"enum":[value]})
}
fn nullable(value: Value) -> Value {
    json!({"anyOf":[value,{"type":"null"}]})
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid","description":"Same-tenant identity; a new commit must use a non-nil intent UUID."})
}
fn version(min: u64) -> Value {
    json!({"type":"integer","minimum":min,"maximum":u64::MAX})
}
fn boolean() -> Value {
    json!({"type":"boolean"})
}
fn timestamp() -> Value {
    json!({"type":"string","format":"date-time"})
}
fn label(max: usize) -> Value {
    json!({"type":"string","minLength":1,"maxLength":max,"x-max-utf8-bytes":max,"description":"Exact safe text; no surrounding whitespace or control characters."})
}
fn array(rule: Value) -> Value {
    json!({"type":"array","items":rule})
}
fn bounded_array(rule: Value, max: usize) -> Value {
    let mut a = array(rule);
    a["maxItems"] = json!(max);
    a
}
fn hash() -> Value {
    json!({"type":"string","pattern":"^[a-f0-9]{64}$"})
}

pub(super) fn describe(schemas: &mut Value) {
    let mut node = object(json!({"node_id":label(128),"name":label(256),"agent_ids":bounded_array(label(512),32),
        "depends_on":bounded_array(label(128),128),"trigger":{"type":"string","enum":["manual","event","cron"]},
        "cron":nullable(label(128))}));
    node["required"] = json!(["node_id", "name", "agent_ids", "trigger"]);
    node["properties"]["agent_ids"]["minItems"] = json!(1);
    node["properties"]["agent_ids"]["uniqueItems"] = json!(true);
    node["properties"]["depends_on"]["uniqueItems"] = json!(true);
    node["properties"]["depends_on"]["default"] = json!([]);
    node["description"] = json!(
        "All agent_ids must be actual current Team Worker IDs. Node IDs unique, parents known, no self-edge/cycle. cron requires safe cron text; manual/event require cron absent or null. Cron is a declaration, never cloud registration or a timer. Unknown node fields rejected."
    );
    schemas["ApplicationOrchestrationNode"] = node;
    let doc = object(json!({"schema_version":fixed(json!(1)),"tenant_id":uuid(),"cloud_team_id":label(256),
        "inventory_fingerprint":hash(),"nodes":bounded_array(reference("ApplicationOrchestrationNode"),128)}));
    schemas["ApplicationOrchestrationDocument"] = doc;
    let save = object(
        json!({"action":fixed(json!("save_definition")),"definition":reference("ApplicationOrchestrationDocument")}),
    );
    let sync =
        object(json!({"action":fixed(json!("sync")),"direction":{"type":"string","enum":["pull","push","both"]}}));
    schemas["ApplicationOrchestrationChange"] = json!({"anyOf":[save.clone(),sync.clone()]});
    let mut input =
        object(json!({"request_id":uuid(),"expected_version":version(0),"configuration_version":version(1),
        "inventory_fingerprint":hash(),"change":reference("ApplicationOrchestrationChange"),
        "confirm_application_owned":boolean(),"confirm_mock_sync":boolean(),"confirm_source_change":boolean()}));
    input["required"] =
        json!(["request_id", "expected_version", "configuration_version", "inventory_fingerprint", "change"]);
    for name in ["confirm_application_owned", "confirm_mock_sync", "confirm_source_change"] {
        input["properties"][name]["default"] = json!(false);
    }
    input["description"] = json!(
        "Preview-only strict input. No permanent intent is saved; confirmation flags default false. Current source-change fence still applies. Same intended immutable UUID/body should be retained for an explicit commit."
    );
    schemas["ApplicationOrchestrationPreviewInput"] = input.clone();
    input["properties"]["confirm_application_owned"] = fixed(json!(true));
    input["required"] = json!([
        "request_id",
        "expected_version",
        "configuration_version",
        "inventory_fingerprint",
        "change",
        "confirm_application_owned"
    ]);
    let mut save_input = input.clone();
    save_input["properties"]["change"] = save;
    let mut sync_input = input;
    sync_input["properties"]["change"] = sync;
    sync_input["properties"]["confirm_mock_sync"] = fixed(json!(true));
    sync_input["required"] = json!([
        "request_id",
        "expected_version",
        "configuration_version",
        "inventory_fingerprint",
        "change",
        "confirm_application_owned",
        "confirm_mock_sync"
    ]);
    schemas["ApplicationOrchestrationCommitInput"] = json!({"anyOf":[save_input,sync_input],"description":"Explicit immutable commit. CAS0 only new local record; exact current positive CAS otherwise. Source changes require confirm_source_change=true. Sync pull adopts current known receiver; push/both use saved local declaration. No vendor or consumer execution."});
    schemas["ApplicationOrchestrationSource"] =
        object(json!({"configurationVersion":version(1),"region":{"type":"string"},"instanceId":{"type":"string"},
        "inventoryFingerprint":hash(),"mocked":fixed(json!(true)),"source":fixed(json!("application_owned"))}));
    schemas["ApplicationOrchestrationDifference"] = object(
        json!({"added":bounded_array(label(128),128),"removed":bounded_array(label(128),128),"changed":bounded_array(label(128),128)}),
    );
    schemas["ApplicationOrchestrationRecord"] = object(
        json!({"teamName":label(256),"version":version(1),"source":reference("ApplicationOrchestrationSource"),
        "local":nullable(reference("ApplicationOrchestrationDocument")),"receiver":nullable(reference("ApplicationOrchestrationDocument")),
        "receiverAvailable":boolean(),"updatedAt":timestamp(),"vendorDagAvailable":fixed(json!(false)),"consumerApplied":fixed(json!(null)),"providerCalled":fixed(json!(false))}),
    );
    schemas["ApplicationOrchestrationIntent"] = object(
        json!({"requestId":uuid(),"teamName":label(256),"bodyHash":hash(),"version":version(1),
        "source":reference("ApplicationOrchestrationSource"),"action":{"type":"string","enum":["save_definition","sync"]},
        "direction":nullable(json!({"type":"string","enum":["pull","push","both"]})),"status":fixed(json!("committed")),
        "localHash":nullable(hash()),"receiverHash":nullable(hash()),"localNodeCount":nullable(json!({"type":"integer","minimum":0,"maximum":128})),
        "receiverNodeCount":nullable(json!({"type":"integer","minimum":0,"maximum":128})),"difference":reference("ApplicationOrchestrationDifference"),
        "committedAt":timestamp(),"durable":boolean(),"immutable":fixed(json!(true)),"providerCalled":fixed(json!(false)),"consumerApplied":fixed(json!(null))}),
    );
    schemas["ApplicationOrchestrationPreview"] = object(
        json!({"teamName":label(256),"requestId":uuid(),"expectedVersion":version(0),"configurationVersion":version(1),
        "difference":reference("ApplicationOrchestrationDifference"),"result":reference("ApplicationOrchestrationRecord"),
        "providerCalled":fixed(json!(false)),"consumerApplied":fixed(json!(null)),"previewOnly":fixed(json!(true))}),
    );
    schemas["ApplicationOrchestrationWorker"] = object(json!({"name":label(512),"assetId":uuid()}));
    schemas["ApplicationOrchestrationTeam"] = object(
        json!({"teamName":label(256),"source":reference("ApplicationOrchestrationSource"),
        "workers":array(reference("ApplicationOrchestrationWorker")),"template":reference("ApplicationOrchestrationDocument"),
        "current":nullable(reference("ApplicationOrchestrationRecord")),"sourceCurrent":nullable(boolean())}),
    );
    schemas["ApplicationOrchestrationState"] = object(
        json!({"modeSupported":boolean(),"canManage":boolean(),"durable":boolean(),"generation":version(0),
        "intentCount":{"type":"integer","minimum":0,"maximum":512},"teams":array(reference("ApplicationOrchestrationTeam")),
        "records":bounded_array(reference("ApplicationOrchestrationRecord"),64),"consumerApplied":fixed(json!(null)),
        "limits":object(json!({"maxTeams":fixed(json!(64)),"maxIntents":fixed(json!(512)),"maxBytes":fixed(json!(3*1024*1024)),
        "maxNodes":fixed(json!(128)),"maxDocumentBytes":fixed(json!(256*1024))}))}),
    );
}
