//! Views deliberately exclude plaintext configuration bodies and credential material.
use serde_json::{Value, json};

fn object(properties: Value) -> Value {
    let required = properties.as_object().map(|fields| fields.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
    json!({"type":"object","required":required,"properties":properties})
}
fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
fn nullable(name: &str) -> Value {
    json!({"oneOf":[reference(name),{"type":"null"}]})
}
fn array(name: &str, maximum: usize) -> Value {
    json!({"type":"array","maxItems":maximum,"items":reference(name)})
}

pub(super) fn describe(document: &mut Value) {
    let uuid = json!({"type":"string","format":"uuid"});
    let optional_uuid = json!({"type":["string","null"],"format":"uuid"});
    let time = json!({"type":"string","format":"date-time"});
    let optional_time = json!({"type":["string","null"],"format":"date-time"});
    let text = json!({"type":"string"});
    let optional_text = json!({"type":["string","null"]});
    let count = json!({"type":"integer","minimum":0});
    let positive = json!({"type":"integer","minimum":1});
    let policy_version = json!({"type":"integer","minimum":1,"maximum":4_294_967_295_u64});
    let boolean = json!({"type":"boolean"});
    let sha256 = json!({"type":"string","pattern":"^[a-f0-9]{64}$"});
    let md5 = json!({"type":"string","pattern":"^[a-f0-9]{32}$"});
    let schemas = &mut document["components"]["schemas"];
    schemas["MseConfigPolicyRevisionInput"] = object(json!({"policy_id":uuid,"version":policy_version}));
    schemas["MseConfigPolicyRevisionInput"]["additionalProperties"] = json!(false);
    schemas["MseConfigPolicyRevision"] = object(json!({"policyId":uuid,"version":policy_version}));
    schemas["MseConfigTarget"] = object(json!({
        "targetScopeId":uuid,"configurationId":uuid,"configurationVersion":positive,
        "sourceLabel":text,"region":text,"instanceId":text,"engineOrigin":{"type":"string","format":"uri"},
        "namespaceId":{"type":"string","description":"精确namespace ID；空字符串是明确默认namespace"},
        "group":text,"dataId":text,"dialect":{"const":"nacos-http-v2-cas"},"mocked":boolean,
        "transportMode":{"enum":["mock","live","loopback-test"]}
    }));
    schemas["MseConfigObservation"] = object(json!({
        "id":uuid,"requestId":uuid,"target":reference("MseConfigTarget"),"startedAt":time,"observedAt":time,
        "contentMd5":md5,"contentHash":sha256,"contentBytes":count,"contentEmpty":boolean,
        "usable":boolean,"reason":optional_text
    }));
    schemas["MseConfigPreview"] = object(json!({
        "id":uuid,"requestId":uuid,"target":reference("MseConfigTarget"),"stateVersion":count,
        "action":{"enum":["publish","rollback"]},"sourcePublicationId":optional_uuid,
        "observationId":uuid,"baselineObservedAt":time,"baselineMd5":md5,"baselineHash":sha256,
        "baselineBytes":count,"desiredHash":sha256,"desiredBytes":{"type":"integer","minimum":0,"maximum":262_144},
        "sourcePolicyVersions":array("MseConfigPolicyRevision",20),"currentPolicyVersions":array("MseConfigPolicyRevision",20),
        "expiresAt":time,"previewUsable":boolean,"reason":optional_text,"consumedBy":optional_uuid,
        "casSemantics":{"const":"content-md5-upsert"},"consumerApplied":{"type":"null"},
        "acknowledgeUnknownOperationId":optional_uuid,"unknownOverlapWarning":boolean,
        "allowedActions":{"type":"array","uniqueItems":true,"items":{"enum":["apply","read_receipt"]}}
    }));
    schemas["MseConfigOperation"] = object(json!({
        "requestId":uuid,"previewId":uuid,"target":reference("MseConfigTarget"),
        "action":{"enum":["publish","rollback"]},"sourcePublicationId":optional_uuid,
        "startedAt":time,"submittedAt":time,"finishedAt":optional_time,"leaseExpiresAt":time,
        "status":{"enum":["started","verified","conflict","failed","uncertain","superseded","archived"]},
        "originalStatus":{"type":["string","null"]},"archived":boolean,"archivedAt":optional_time,"archivable":boolean,
        "cloudWrite":object(json!({"status":{"enum":["not_attempted","attempting","accepted","conflict","rejected","unknown"]}})),
        "readback":object(json!({"status":{"enum":["not_attempted","matched","different","unavailable"]},
            "observedAt":optional_time,"currentHash":optional_text})),
        "localPublication":object(json!({"status":{"enum":["not_staged","pending_audit","published"]}})),
        "completionState":{"enum":["running","pending_audit","complete"]},"safeReason":optional_text,
        "consumerApplied":{"type":"null"},"supersededBy":optional_uuid,"sourceCurrent":{"type":["boolean","null"]},
        "currentPolicyVersions":{"oneOf":[array("MseConfigPolicyRevision",20),{"type":"null"}]},
        "recoveryScopeId":optional_uuid,"recoveryConfigurationVersion":{"type":["integer","null"],"minimum":1},
        "allowedActions":{"type":"array","uniqueItems":true,"items":{"enum":["read_receipt","observe","recover_local","archive"]}}
    }));
    schemas["MseConfigPublicationHistory"] = object(json!({
        "publicationId":uuid,"target":reference("MseConfigTarget"),"verifiedAt":time,
        "contentHash":sha256,"contentBytes":count,"sourcePolicyVersions":array("MseConfigPolicyRevision",20),
        "rollbackAvailable":boolean,"reason":optional_text
    }));
    schemas["MseConfigLimits"] = object(json!({
        "maxPolicies":{"const":20},"maxContentBytes":{"const":262_144},"maxRecordBytes":{"const":1_048_576},
        "maxMainBytes":{"const":4_194_304},"maxAggregateAgentIds":{"const":500},
        "maxStoredContentBytes":{"const":67_108_864},"maxDetailedRuns":{"const":128},
        "maxPreviews":{"const":32},"maxObservations":{"const":8},"maxArchive":{"const":100},
        "maxDriverSeconds":{"const":30},"maxOperationSeconds":{"const":110},"leaseSeconds":{"const":120},
        "previewSeconds":{"const":120},"observationSeconds":{"const":300}
    }));
    schemas["MseConfigPublicationState"] = object(json!({
        "configured":boolean,"enabled":{"type":["boolean","null"]},"binding":nullable("MseConfigTarget"),
        "stateVersion":count,"generation":count,"canObserve":boolean,"canPrepare":boolean,"canApply":boolean,
        "bindingReason":optional_text,"busy":boolean,"leaseExpiresAt":optional_time,"unresolvedOperationId":optional_uuid,
        "observation":nullable("MseConfigObservation"),"operations":array("MseConfigOperation",50),
        "history":array("MseConfigPublicationHistory",50),"detailedRunCount":count,"archivedCount":count,
        "storedContentBytes":count,"limits":reference("MseConfigLimits"),"consumerApplied":{"type":"null"}
    }));
    schemas["MseConfigArchiveResult"] = object(json!({
        "generation":count,"archivedCount":count,"unchanged":boolean,
        "archivedRequestIds":{"type":"array","maxItems":100,"uniqueItems":true,"items":uuid}
    }));
}
