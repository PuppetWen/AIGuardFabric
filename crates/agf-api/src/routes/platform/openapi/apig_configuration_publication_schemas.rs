//! Safe configuration DTOs exclude raw plugin configuration and credentials.
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
fn text() -> Value {
    json!({"type":"string"})
}
fn digest() -> Value {
    json!({"type":"string","pattern":"^[0-9a-f]{64}$"})
}
fn time() -> Value {
    json!({"type":"string","format":"date-time"})
}
fn boolean() -> Value {
    json!({"type":"boolean"})
}
fn array(rule: Value, max: usize) -> Value {
    json!({"type":"array","maxItems":max,"items":rule})
}

pub(super) fn describe(document: &mut Value) {
    let schemas = &mut document["components"]["schemas"];
    schemas["ApigConfigurationModelBinding"] = object(json!({
        "httpApiId":text(),"gatewayId":text(),"environmentId":text()}));
    schemas["ApigConfigurationContentBinding"] = object(json!({
        "model":reference("ApigConfigurationModelBinding"),"attachmentId":text(),"pluginId":text(),
        "classId":text(),"classVersion":text()}));
    let binding = json!({"oneOf":[
        object(json!({"kind":{"const":"content"},"binding":reference("ApigConfigurationContentBinding")})),
        object(json!({"kind":{"const":"models"},"binding":reference("ApigConfigurationModelBinding")}))]});
    schemas["ApigConfigurationTarget"] = object(json!({
        "targetScopeId":uuid(),"writeResourceId":uuid(),"configurationId":uuid(),"configurationVersion":number(1),
        "sourceLabel":text(),"region":text(),"endpoint":text(),"binding":binding,"mocked":boolean(),
        "transportMode":{"enum":["mock","live","loopback-test"]}}));
    schemas["ApigConfigurationContentSettings"] = object(json!({
        "enabled":boolean(),"checkRequest":boolean(),"checkResponse":boolean(),
        "denyCode":{"type":"integer","minimum":100,"maximum":599}}));
    schemas["ApigConfigurationService"] = object(json!({
        "serviceId":text(),"version":optional(text()),"modelName":text(),
        "weight":{"type":"integer","minimum":1,"maximum":100}}));
    let mut patch = schemas["ApigConfigurationService"].clone();
    patch["properties"]["expectedModelName"] = text();
    patch["required"] = json!(["serviceId", "expectedModelName", "modelName", "weight"]);
    schemas["ApigConfigurationServicePatch"] = patch;
    schemas["ApigConfigurationSafeView"] = json!({"oneOf":[
        object(json!({"settings":reference("ApigConfigurationContentSettings"),"responseMayBecomeNonStreaming":boolean()})),
        object(json!({"services":array(reference("ApigConfigurationService"),32),
            "backendScene":{"enum":["SingleService","MultiServiceByRatio"]},"basePath":text(),
            "selectedDeploymentIndex":{"type":"integer","minimum":0,"maximum":99},
            "configurationOnly":{"const":true},"deploymentVerified":{"type":"null"},"consumerApplied":{"type":"null"}}))]});
    schemas["ApigConfigurationDiff"] = object(json!({
        "before":reference("ApigConfigurationSafeView"),"after":reference("ApigConfigurationSafeView"),
        "baselineHash":digest(),"desiredHash":digest(),"cloudCas":{"const":false},
        "deploymentVerified":{"type":"null"},"consumerApplied":{"type":"null"}}));
    let observed = json!({"request_id":uuid(),"configuration_version":number(1),
        "confirm_live":{"type":"boolean","default":false},
        "initialize_mock_fixture":{"type":"boolean","default":false}});
    schemas["ApigConfigurationObserveInput"] = input(observed.clone(), &["request_id", "configuration_version"]);
    let mut original = observed;
    original["initialize_mock_fixture"]["const"] = json!(false);
    schemas["ApigConfigurationOriginalObserveInput"] = input(original, &["request_id", "configuration_version"]);
    schemas["ApigConfigurationPreviewInput"] = input(
        json!({
        "request_id":uuid(),"configuration_version":number(1),"observation_id":uuid(),"expected_state_version":number(0),
        "acknowledge_unknown_operation_id":uuid(),"change":{"oneOf":[
            object(json!({"action":{"const":"content"},"settings":reference("ApigConfigurationContentSettings")})),
            object(json!({"action":{"const":"models"},"services":{"type":"array","minItems":1,"maxItems":32,
                "items":reference("ApigConfigurationServicePatch")}})),
            object(json!({"action":{"const":"rollback"},"publication_id":uuid()}))]}}),
        &["request_id", "configuration_version", "observation_id", "expected_state_version", "change"],
    );
    schemas["ApigConfigurationApplyInput"] = input(
        json!({
        "request_id":uuid(),"preview_id":uuid(),"expected_state_version":number(0),
        "confirm_apply":{"const":true},"confirm_preserved_private_configuration":{"const":true},
        "confirm_streaming_or_shared_impact":{"const":true},"confirm_no_cloud_cas":{"const":true},
        "confirm_live":{"type":"boolean","default":false},"confirm_unknown_overlap":{"type":"boolean","default":false}}),
        &[
            "request_id",
            "preview_id",
            "expected_state_version",
            "confirm_apply",
            "confirm_preserved_private_configuration",
            "confirm_streaming_or_shared_impact",
            "confirm_no_cloud_cas",
        ],
    );
    schemas["ApigConfigurationEmptyInput"] = object(json!({}));
    schemas["ApigConfigurationArchiveInput"] = object(json!({"expected_generation":number(0),
        "request_ids":{"type":"array","minItems":1,"maxItems":100,"uniqueItems":true,"items":uuid()}}));
    schemas["ApigConfigurationObservation"] = object(json!({
        "id":uuid(),"requestId":uuid(),"target":reference("ApigConfigurationTarget"),"startedAt":time(),"observedAt":time(),
        "fingerprint":digest(),"view":reference("ApigConfigurationSafeView"),"contentHash":digest(),
        "contentBytes":{"type":"integer","minimum":0,"maximum":655_360},"usable":boolean(),"reason":optional(text()),
        "deploymentVerified":{"type":"null"},"consumerApplied":{"type":"null"}}));
    schemas["ApigConfigurationPreview"] = object(json!({
        "id":uuid(),"requestId":uuid(),"target":reference("ApigConfigurationTarget"),"stateVersion":number(0),
        "action":{"enum":["publish","rollback"]},"sourcePublicationId":optional(uuid()),"observationId":uuid(),
        "baselineObservedAt":time(),"baselineFingerprint":digest(),"desiredHash":digest(),
        "desiredBytes":{"type":"integer","minimum":0,"maximum":655_360},"diff":reference("ApigConfigurationDiff"),
        "expiresAt":time(),"previewUsable":boolean(),"consumedBy":optional(uuid()),"reason":optional(text()),
        "acknowledgeUnknownOperationId":optional(uuid()),"unknownOverlapWarning":boolean(),
        "allowedActions":array(json!({"enum":["apply","read_receipt"]}),2),"noCloudCas":{"const":true},
        "deploymentVerified":{"type":"null"},"consumerApplied":{"type":"null"}}));
    let status = json!({"enum":["started","verified","conflict","failed","uncertain","superseded","archived"]});
    schemas["ApigConfigurationOperation"] = object(json!({
        "requestId":uuid(),"previewId":uuid(),"target":reference("ApigConfigurationTarget"),
        "action":{"enum":["publish","rollback"]},"sourcePublicationId":optional(uuid()),"startedAt":time(),"submittedAt":time(),
        "finishedAt":optional(time()),"leaseExpiresAt":time(),"status":status,"originalStatus":optional(status),
        "archived":boolean(),"archivedAt":optional(time()),"archivable":boolean(),
        "cloudWrite":object(json!({"status":{"enum":["not_attempted","attempting","accepted","unknown"]},"providerRequestId":optional(text())})),
        "readback":object(json!({"status":{"enum":["not_attempted","matched","different","unavailable"]},
            "observedAt":optional(time()),"currentHash":optional(digest())})),
        "localPublication":object(json!({"status":{"enum":["not_staged","pending_audit","published"]}})),
        "completionState":{"enum":["complete","pending_audit","running"]},"safeReason":optional(text()),
        "consumerApplied":{"type":"null"},"supersededBy":optional(uuid()),"sourceCurrent":optional(boolean()),
        "configurationObserved":boolean(),"deploymentVerified":{"type":"null"},"recoveryScopeId":optional(uuid()),
        "recoveryConfigurationVersion":optional(number(1)),
        "allowedActions":array(json!({"enum":["read_receipt","observe","recover_local","archive"]}),4)}));
    schemas["ApigConfigurationHistory"] =
        object(json!({"publicationId":uuid(),"target":reference("ApigConfigurationTarget"),
        "verifiedAt":optional(time()),"contentHash":digest(),"diff":reference("ApigConfigurationDiff"),
        "rollbackAvailable":boolean(),"reason":optional(text())}));
    schemas["ApigConfigurationState"] = object(json!({
        "configured":boolean(),"enabled":optional(boolean()),"binding":optional(reference("ApigConfigurationTarget")),
        "bindingReason":optional(text()),"stateVersion":number(0),"generation":number(0),"busy":boolean(),
        "leaseExpiresAt":optional(time()),"canObserve":boolean(),"canInitializeMockFixture":boolean(),"canPrepare":boolean(),
        "canApply":boolean(),"unresolvedOperationId":optional(uuid()),"observation":optional(reference("ApigConfigurationObservation")),
        "operations":array(reference("ApigConfigurationOperation"),50),"history":array(reference("ApigConfigurationHistory"),50),
        "detailedRunCount":{"type":"integer","minimum":0,"maximum":128},"archivedCount":number(0),"storedContentBytes":number(0),
        "limits":object(json!({"maxDetailedRuns":{"const":128},"maxPreviews":{"const":32},"maxObservations":{"const":8},
            "maxArchive":{"const":100},"maxContentBytes":{"const":655_360},"maxRecordBytes":{"const":1_048_576},
            "maxStoredContentBytes":{"const":67_108_864},"maxServices":{"const":32},"maxDriverSeconds":{"const":30},
            "maxOperationSeconds":{"const":110},"leaseSeconds":{"const":120},"previewSeconds":{"const":120},"observationSeconds":{"const":300}})),
        "configurationObserved":boolean(),"deploymentVerified":{"type":"null"},"consumerApplied":{"type":"null"},"noCloudCas":{"const":true}}));
    schemas["ApigConfigurationArchiveResult"] = object(json!({"generation":number(0),"archivedCount":number(0),
        "archivedRequestIds":array(uuid(),100),"unchanged":boolean()}));
}
