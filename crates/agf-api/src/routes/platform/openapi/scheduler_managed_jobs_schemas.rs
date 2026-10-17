//! Scheduling input stays typed; opaque HTTP carriers never cross this contract.
use serde_json::{Value, json};

fn object(properties: Value) -> Value {
    let required = properties.as_object().map(|v| v.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}
fn input(properties: Value, required: &[&str]) -> Value {
    let mut result = object(properties);
    result["required"] = json!(required);
    result
}
fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
fn optional(rule: Value) -> Value {
    json!({"oneOf":[rule,{"type":"null"}]})
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid","not":{"const":"00000000-0000-0000-0000-000000000000"}})
}
fn number(minimum: u64) -> Value {
    json!({"type":"integer","minimum":minimum,"maximum":u64::MAX})
}
fn boolean() -> Value {
    json!({"type":"boolean"})
}
fn time() -> Value {
    json!({"type":"string","format":"date-time"})
}
fn digest() -> Value {
    json!({"type":"string","pattern":"^[0-9a-f]{64}$"})
}
fn job_id() -> Value {
    json!({"type":"string","pattern":"^[1-9][0-9]{0,18}$","maxLength":19,
        "description":"Canonical positive int64 decimal string, at most 9223372036854775807; never a floating point ID."})
}
fn kinds() -> Value {
    json!({"enum":["asset-inventory","log-pull","redteam-cruise","rule-hot-reload","report","archive"]})
}
fn array(rule: Value, max: usize) -> Value {
    json!({"type":"array","maxItems":max,"items":rule})
}

pub(super) fn describe(document: &mut Value) {
    let schemas = &mut document["components"]["schemas"];
    let patch = input(
        json!({"time_type":{"enum":[-1,1,3,5,100]},
        "time_expression":{"type":"string","maxLength":256},"calendar":{"type":"string","maxLength":256},
        "timezone":{"type":"string","maxLength":64},"max_attempt":{"type":"integer","minimum":0,"maximum":1000},
        "attempt_interval":{"type":"integer","minimum":0,"maximum":86_400}}),
        &[],
    );
    schemas["SchedulerManagedSchedulePatch"] = patch;
    schemas["SchedulerManagedSchedulePatch"]["minProperties"] = json!(1);
    schemas["SchedulerManagedSchedulePatch"]["description"] = json!(
        "Nonempty patch; null is invalid, omitted fields are preserved. Text is trimmed and control-free. Kinds -1/100 cannot have a nonempty time_expression. This edit never enables or disables a job."
    );
    let mut schedule = schemas["SchedulerManagedSchedulePatch"].clone();
    schedule["required"] = json!(["time_type", "timezone", "max_attempt", "attempt_interval"]);
    schedule["properties"]["timezone"]["minLength"] = json!(1);
    schedule["allOf"] = json!([{"if":{"properties":{"time_type":{"enum":[1,3,5]}}},
        "then":{"required":["time_expression"],"properties":{"time_expression":{"minLength":1}}}}]);
    schemas["SchedulerManagedDeclaration"] = object(json!({"kind":kinds(),
        "name":{"type":"string","minLength":1,"maxLength":200},"schedule":schedule,"total":{"const":1}}));
    schemas["SchedulerManagedSelection"] = object(json!({"kind":kinds(),"app_id":job_id(),"job_id":job_id(),
        "observation_fingerprint":digest()}));
    let common = json!({"request_id":uuid(),"configuration_version":number(1),"expected_binding_version":number(0),
        "observation_id":uuid()});
    let mut create = common.clone();
    create["change"] =
        object(json!({"action":{"const":"create_disabled"},"declaration":reference("SchedulerManagedDeclaration")}));
    let mut manage = common;
    manage["selection"] = reference("SchedulerManagedSelection");
    manage["change"] = json!({"oneOf":[
        object(json!({"action":{"const":"update_schedule"},"patch":reference("SchedulerManagedSchedulePatch")})),
        object(json!({"action":{"const":"disable"}})),object(json!({"action":{"const":"enable"}}))]});
    schemas["SchedulerManagedPreviewInput"] = json!({"oneOf":[object(create),object(manage)]});
    schemas["SchedulerManagedApplyInput"] = input(
        json!({"preview_id":uuid(),"preview_fingerprint":digest(),
        "confirm_no_cloud_cas":{"const":true},"confirm_callback_unknown":{"const":true},
        "confirm_live":{"type":"boolean","default":false},"confirm_unknown_overlap":{"type":"boolean","default":false}}),
        &["preview_id", "preview_fingerprint", "confirm_no_cloud_cas", "confirm_callback_unknown"],
    );
    schemas["SchedulerManagedEmptyInput"] = object(json!({}));
    schemas["SchedulerManagedArchiveInput"] = object(json!({"expected_generation":number(0),
        "request_ids":{"type":"array","minItems":1,"maxItems":48,"uniqueItems":true,"items":uuid()},
        "confirm_loss_of_preview":{"const":true}}));
    let common_preview = json!({"id":uuid(),"actorId":uuid(),"target":reference("SchedulerNativeSource"),
        "configurationVersion":number(1),"createdAt":time(),"fingerprint":digest(),"operationId":optional(uuid()),
        "cloudCasAvailable":{"const":false},"callbackConfigured":{"type":"null"},
        "callbackBindingEnforced":{"const":false},"deploymentVerified":{"type":"null"}});
    let mut content = common_preview.clone();
    for (name, rule) in [
        ("expiresAt", time()),
        ("input", reference("SchedulerManagedPreviewInput")),
        ("appId", job_id()),
        ("baselineFingerprint", digest()),
        ("before", optional(reference("SchedulerNativeJob"))),
        ("desired", reference("SchedulerNativeJob")),
        ("archived", json!({"const":false})),
        ("canApply", boolean()),
        ("archivable", boolean()),
    ] {
        content[name] = rule;
    }
    let mut archived = common_preview;
    archived["archivedAt"] = time();
    archived["archived"] = json!({"const":true});
    archived["canApply"] = json!({"const":false});
    archived["archivable"] = json!({"const":false});
    schemas["SchedulerManagedPreview"] = json!({"oneOf":[object(content),object(archived)]});
    schemas["SchedulerManagedWrite"] = object(json!({"attempted":boolean(),
        "status":{"enum":["accepted","rejected","unknown"]},"providerRequestId":optional(json!({"type":"string"})),
        "authorityCurrent":boolean(),"originalDeadlineCurrent":boolean()}));
    schemas["SchedulerManagedOperation"] = object(json!({
        "requestId":uuid(),"actorId":uuid(),"claimId":uuid(),"inputHash":digest(),"configurationVersion":number(1),
        "target":reference("SchedulerNativeSource"),"previewId":uuid(),
        "action":{"enum":["create_disabled","update_schedule","disable","enable"]},"kind":kinds(),
        "runtimeName":{"enum":["asset-inventory","log-pull","redteam-cruise","rule-hot-reload","report-generate","cold-archive"]},
        "jobId":optional(job_id()),"startedAt":time(),"submittedAt":time(),"expiresAt":time(),"finishedAt":optional(time()),
        "status":{"enum":["started","accepted","rejected","uncertain","archived"]},
        "completionState":{"enum":["complete","pending_audit","running"]},"originalWrite":optional(reference("SchedulerManagedWrite")),
        "readback":{"enum":["matched","different","unknown"]},"readbackAt":optional(time()),"readbackFingerprint":optional(digest()),
        "sourceCurrent":optional(boolean()),"currentConfigurationVersion":optional(number(1)),
        "archived":boolean(),"archivedAt":optional(time()),"archivable":boolean(),
        "allowedActions":array(json!({"enum":["read_receipt","recover_local","observe"]}),3),
        "consumerApplied":{"type":"null"},"callbackConfigured":{"type":"null"},"callbackBindingEnforced":{"const":false},
        "deploymentVerified":{"type":"null"},"cloudCasAvailable":{"const":false},
        "preview":optional(object(json!({"before":optional(reference("SchedulerNativeJob")),"desired":reference("SchedulerNativeJob"),
            "fingerprint":digest(),"baselineFingerprint":digest()})))}));
    schemas["SchedulerManagedDefinition"] =
        object(json!({"scope_id":uuid(),"kind":kinds(),"job_id":job_id(),"request_id":uuid(),"total":{"const":1}}));
    schemas["SchedulerManagedUncertain"] = object(json!({"resource":object(json!({"tenant":uuid(),
        "clusterId":{"type":"string"},"appName":{"type":"string"}})),"request_id":uuid(),"scope_id":uuid(),"expires_at":time()}));
    schemas["SchedulerManagedState"] = object(json!({
        "target":optional(reference("SchedulerNativeSource")),"sourceState":{"enum":["available","disabled_or_missing","unavailable"]},
        "canManage":boolean(),"canPrepare":boolean(),"stateVersion":number(0),"generation":number(0),"archivedCount":number(0),
        "storedContentBytes":number(0),"activeRequestId":optional(uuid()),"latestObservationId":optional(uuid()),"bindingVersion":number(0),
        "definitions":array(reference("SchedulerManagedDefinition"),768),"unknownScopes":array(reference("SchedulerManagedUncertain"),128),
        "previews":array(reference("SchedulerManagedPreview"),50),"operations":array(reference("SchedulerManagedOperation"),50),
        "consistency":{"const":"statement"},"previewTotal":{"type":"integer","minimum":0,"maximum":128},
        "operationTotal":{"type":"integer","minimum":0,"maximum":128},"previewsTruncated":boolean(),"operationsTruncated":boolean(),
        "limits":object(json!({"maxPreviews":{"const":128},"maxOperations":{"const":128},"maxStoredBytes":{"const":67_108_864},
            "maxDetailBytes":{"const":262_144},"maxArchive":{"const":48},"pageSize":{"const":50},"maxMockJobs":{"const":128},"previewSeconds":{"const":120}})),
        "cloudCasAvailable":{"const":false},"callbackBindingEnforced":{"const":false},"callbackConfigured":{"type":"null"},"deploymentVerified":{"type":"null"}}));
    schemas["SchedulerManagedArchiveResult"] = object(json!({"generation":number(0),"archivedCount":number(0),
        "storedContentBytes":number(0),"stateVersion":number(0)}));
}
