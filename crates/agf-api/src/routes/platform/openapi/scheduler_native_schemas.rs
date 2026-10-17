//! Schemas describe the actual safe DTO; opaque provider bodies and deployment secrets have no fields.
use serde_json::{Value, json};

fn object(properties: Value) -> Value {
    let required = properties.as_object().map(|fields| fields.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}
fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
fn nullable_reference(name: &str) -> Value {
    json!({"oneOf":[reference(name),{"type":"null"}]})
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid"})
}
fn number() -> Value {
    json!({"type":"integer","minimum":0})
}
fn job_id() -> Value {
    json!({"type":"string","pattern":"^[1-9][0-9]{0,18}$","maxLength":19,
        "description":"规范正int64十进制字符串，最大9223372036854775807；不能用浏览器浮点数"})
}
fn nullable(kind: &str) -> Value {
    json!({"type":[kind,"null"]})
}
fn kinds() -> Value {
    json!({"enum":["asset-inventory","log-pull","redteam-cruise","rule-hot-reload","report","archive"]})
}

pub(super) fn describe(document: &mut Value) {
    let schemas = &mut document["components"]["schemas"];
    schemas["SchedulerNativeSource"] = object(json!({
        "tenant":uuid(),"configurationId":uuid(),"configurationVersion":{"type":"integer","minimum":1},
        "scopeId":uuid(),"fingerprint":{"type":"string","pattern":"^[0-9a-f]{64}$"},
        "region":{"type":"string"},"rpcOrigin":{"type":"string","format":"uri"},
        "configuredAccountId":nullable("string"),"accountIdentityVerified":{"const":false},
        "clusterId":{"type":"string"},"appName":{"type":"string"},"mocked":{"type":"boolean"},
        "transportMode":{"enum":["mock","live","loopback_test"]}
    }));
    schemas["SchedulerNativeApp"] = object(json!({
        "id":job_id(),"name":{"type":"string"},"title":nullable("string"),"kind":nullable("integer")
    }));
    schemas["SchedulerNativeJob"] = object(json!({
        "id":job_id(),"appName":{"type":"string"},"appId":nullable("string"),
        "name":{"type":"string"},"kind":nullable("string"),"httpJob":{"type":"boolean"},
        "status":nullable("integer"),"enabled":nullable("boolean"),
        "schedule":object(json!({"kind":nullable("integer"),"expression":nullable("string"),
            "calendar":nullable("string"),"zone":nullable("string"),"utc":nullable("boolean")})),
        "maxAttempt":nullable("integer"),"attemptInterval":nullable("integer"),"routeStrategy":nullable("integer"),
        "shardCount":{"type":"null"},"updateTimeNative":nullable("string"),
        "http":object(json!({"verified":{"const":false},
            "parameters":{"enum":["missing","null","empty","present"]},
            "handler":{"enum":["missing","null","empty","present"]},
            "attributes":{"enum":["missing","null","empty","present"]},
            "script":{"enum":["missing","null","empty","present"]},
            "fingerprint":{"type":"string","pattern":"^[0-9a-f]{64}$"}}))
    }));
    schemas["SchedulerNativeObservationPage"] = object(json!({
        "scope":object(json!({"clusterId":{"type":"string"},"appName":{"type":"string"}})),
        "app":reference("SchedulerNativeApp"),"pagination":object(json!({
            "total":number(),"listingComplete":{"const":true},"strongSnapshot":{"const":false},
            "pages":{"type":"array","minItems":1,"maxItems":20,"items":object(json!({
                "number":{"type":"integer","minimum":1,"maximum":20},"size":{"const":100},
                "records":{"type":"integer","minimum":0,"maximum":100},"requestId":{"type":"string"}}))}})),
        "fingerprint":{"type":"string"},"jobs":{"type":"array","maxItems":100,"items":reference("SchedulerNativeJob")},
        "page":{"type":"integer","minimum":1},"pageSize":{"type":"integer","minimum":1,"maximum":100},
        "total":{"type":"integer","minimum":0,"maximum":2000},"totalPages":{"type":"integer","minimum":1}
    }));
    schemas["SchedulerNativeBinding"] = object(json!({
        "version":number(),"adoptionVersion":number(),"locallyEnabled":{"type":"boolean"},
        "status":{"enum":["disabled","stale","partial","associated","revoked","unverified"]},"current":{"type":"boolean"},
        "eligibility":{"enum":["eligible","revoked","unverified"]},"qualificationVerified":{"type":"boolean"},
        "sourceCurrent":{"type":"boolean"},
        "evidenceFresh":{"type":"boolean"},"observationId":nullable("string"),"appId":nullable("string"),
        "verifiedAt":nullable("string"),"sourceTarget":nullable_reference("SchedulerNativeSource"),
        "items":{"type":"array","maxItems":6,"items":object(json!({
            "kind":kinds(),"runtimeName":{"type":"string"},"jobId":job_id(),
            "eligibility":{"enum":["eligible","revoked","unverified"]},
            "reason":{"enum":[null,"proof_unavailable","app_changed","job_missing","job_disabled","job_not_http","job_type_unknown","job_status_unknown"]},
            "decisionObservationId":nullable("string"),"decisionAt":nullable("string"),
            "adoptedProof":nullable_reference("SchedulerNativeAdoptedProof"),
            "currentEvidence":nullable_reference("SchedulerNativeQualificationEvidence")}))},
        "callbackBindingEnforced":{"const":false},"deploymentVerified":{"type":"null"},"callbackConfigured":{"type":"null"}
    }));
    schemas["SchedulerNativeAdoptedProof"] = object(json!({
        "proofId":uuid(),"adoptionVersion":{"type":"integer","minimum":1},
        "sourceTarget":reference("SchedulerNativeSource"),"observationId":uuid(),"observedAt":{"type":"string","format":"date-time"},
        "appId":job_id(),"jobId":job_id(),"kind":kinds(),"httpJob":{"const":true},"enabled":{"const":true}
    }));
    schemas["SchedulerNativeQualificationEvidence"] = object(json!({
        "observationId":uuid(),"observedAt":{"type":"string","format":"date-time"},
        "sourceTarget":reference("SchedulerNativeSource"),"appId":job_id(),"jobPresent":{"type":"boolean"},
        "jobKind":nullable("string"),"httpJob":nullable("boolean"),"enabled":nullable("boolean")
    }));
    schemas["SchedulerNativeReceipt"] = summary();
    schemas["SchedulerNativeReceipt"]["properties"]["observation"] =
        nullable_reference("SchedulerNativeObservationPage");
    if let Some(fields) = schemas["SchedulerNativeReceipt"]["required"].as_array_mut() {
        fields.push(json!("observation"));
    }
    schemas["SchedulerNativeSummary"] = summary();
    schemas["SchedulerNativeState"] = object(json!({
        "tenantId":uuid(),"configured":{"type":"boolean"},"enabled":{"type":"boolean"},
        "sourceTarget":nullable_reference("SchedulerNativeSource"),"stateVersion":number(),"generation":number(),
        "busy":{"type":"boolean"},"leaseExpiresAt":nullable("string"),"canObserve":{"type":"boolean"},
        "canInitMock":{"type":"boolean"},"canBind":{"type":"boolean"},
        "latestObservation":nullable_reference("SchedulerNativeSummary"),"bindings":reference("SchedulerNativeBinding"),
        "recentObservations":{"type":"array","maxItems":50,"items":reference("SchedulerNativeSummary")},
        "detailedObservationCount":{"type":"integer","minimum":0,"maximum":128},
        "archivedCount":number(),"storedContentBytes":number(),"callbackBindingEnforced":{"const":false},
        "deploymentVerified":{"type":"null"},"callbackConfigured":{"type":"null"},"limits":{"type":"object"}
    }));
    schemas["SchedulerNativeObserveInput"] = object(json!({
        "request_id":uuid(),"configuration_version":{"type":"integer","minimum":1},
        "confirm_live":{"type":"boolean","default":false},"initialize_mock_fixture":{"type":"boolean","default":false}
    }));
    schemas["SchedulerNativeObserveInput"]["required"] = json!(["request_id", "configuration_version"]);
    schemas["SchedulerNativeBindingInput"] = json!({"oneOf":[
        object(json!({"action":{"const":"replace"},"request_id":uuid(),"expected_version":number(),
            "configuration_version":{"type":"integer","minimum":1},"observation_id":uuid(),
            "bindings":{"type":"array","maxItems":6,"items":object(json!({"kind":kinds(),"job_id":job_id()}))},
            "confirm_local_only":{"const":true}})),
        object(json!({"action":{"const":"disable"},"request_id":uuid(),"expected_version":number()}))
    ]});
    schemas["SchedulerNativeArchiveInput"] = object(json!({
        "expected_generation":number(),"request_ids":{"type":"array","minItems":1,"maxItems":100,
            "uniqueItems":true,"items":uuid()}
    }));
    schemas["SchedulerNativeArchiveResult"] = object(json!({
        "generation":number(),"archivedCount":number(),"storedContentBytes":number(),"stateVersion":number()
    }));
}

fn summary() -> Value {
    object(json!({
        "requestId":uuid(),"status":{"enum":["reading","observed","failed","interrupted","archived"]},
        "originalStatus":{"type":"string"},"originalTarget":nullable_reference("SchedulerNativeSource"),
        "applicationScopeId":nullable("string"),"claimId":uuid(),"submittedAt":{"type":"string","format":"date-time"},
        "startedAt":{"type":"string","format":"date-time"},"observedAt":nullable("string"),
        "finishedAt":nullable("string"),"leaseExpiresAt":{"type":"string","format":"date-time"},
        "archived":{"type":"boolean"},"archivedAt":nullable("string"),"available":{"type":"boolean"},
        "current":{"type":"boolean"},"archivable":{"type":"boolean"},"reason":nullable("string"),
        "total":nullable("integer"),"appId":nullable("string"),"fingerprint":nullable("string"),
        "listingComplete":{"type":"boolean"},"strongSnapshot":{"const":false},
        "callbackBindingEnforced":{"const":false},"deploymentVerified":{"type":"null"},"callbackConfigured":{"type":"null"},"authorizationAllowed":{"type":"null"},
        "callbackReachability":{"type":"null"},"allowedActions":{"type":"array","items":{"enum":["read_receipt","archive"]}}
    }))
}
