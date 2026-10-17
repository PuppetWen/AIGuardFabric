use serde_json::{Value, json};
pub(super) fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
fn object(properties: Value) -> Value {
    let required = properties.as_object().map(|fields| fields.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}
fn nullable(value: Value) -> Value {
    json!({"anyOf":[value,{"type":"null"}]})
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid","description":"Non-nil tenant-owned UUID."})
}
fn integer(minimum: u64) -> Value {
    json!({"type":"integer","minimum":minimum,"maximum":u64::MAX})
}
fn timestamp() -> Value {
    json!({"type":"string","format":"date-time"})
}
fn array(value: Value, max: usize) -> Value {
    json!({"type":"array","items":value,"maxItems":max})
}
fn boolean() -> Value {
    json!({"type":"boolean"})
}
fn fixed(value: Value) -> Value {
    json!({"enum":[value]})
}
fn name(max: usize) -> Value {
    json!({"type":"string","minLength":1,"maxLength":max,"x-max-utf8-bytes":max})
}
fn optional(schema: &mut Value, key: &str) {
    if let Some(required) = schema["required"].as_array_mut() {
        required.retain(|field| field != key);
    }
    schema["properties"][key]["default"] = json!(false);
}
pub(super) fn register(schemas: &mut Value) {
    schemas["CmsQueueSource"] =
        object(json!({"configurationId":uuid(),"configurationVersion":integer(1),"groupId":name(128),
        "region":name(128),"transportMode":{"enum":["mock","live","loopback_test"]},"mocked":boolean()}));
    schemas["CmsQueueOutcome"] = object(json!({"delivery":{"enum":["not_sent","accepted","rejected","unknown"]},
        "providerRequestId":nullable(name(128)),"finishedAt":timestamp()}));
    schemas["CmsQueueAttempt"] = object(
        json!({"id":uuid(),"requestId":uuid(),"phase":{"enum":["admitted","started","complete"]},
        "admittedAt":timestamp(),"startedAt":nullable(timestamp()),"leaseExpiresAt":timestamp(),
        "completionState":{"enum":["complete","pending_audit","uncertain","in_flight"]},"outcome":nullable(reference("CmsQueueOutcome")),
        "pendingAudit":boolean(),"mocked":boolean(),"providerWriteAttempted":nullable(boolean()),"consumerApplied":fixed(json!("unknown"))}),
    );
    schemas["CmsQueueItem"] = object(
        json!({"id":uuid(),"enqueueRequestId":uuid(),"name":name(128),"action":{"enum":["PutCustomEvent","PutCustomMetric"]},
        "payloadHash":{"type":"string","pattern":"^[0-9a-f]{64}$"},"payloadBytes":integer(0),"queuedAt":timestamp(),"archivedAt":nullable(timestamp()),
        "originalSource":reference("CmsQueueSource"),"sourceCurrent":boolean(),"attemptCount":{"type":"integer","minimum":0,"maximum":5},
        "lastAttempt":nullable(reference("CmsQueueAttempt")),"deadLetter":boolean(),"canSend":boolean(),"canRecoverLocal":boolean(),"canArchive":boolean()}),
    );
    schemas["CmsQueueReceipt"] = object(
        json!({"id":uuid(),"purpose":{"enum":["enqueue","send","archive"]},"inputHash":{"type":"string","pattern":"^[0-9a-f]{64}$"},
        "submittedAt":timestamp(),"generation":integer(1),"changedCount":integer(0),"itemIds":array(uuid(),32),"attemptIds":array(uuid(),20),
        "items":array(reference("CmsQueueItem"),32),"originalAttempts":array(reference("CmsQueueAttempt"),20),"immutableIntent":fixed(json!(true)),"automaticRetry":fixed(json!(false))}),
    );
    schemas["CmsQueueLimits"] = object(
        json!({"detailedItems":fixed(json!(128)),"permanentFacts":fixed(json!(4096)),"attemptsPerItem":fixed(json!(5)),
        "enqueueBatch":fixed(json!(20)),"sendBatch":fixed(json!(20)),"archiveBatch":fixed(json!(32)),"contentBytes":fixed(json!(2*1024*1024))}),
    );
    schemas["CmsQueueState"] = object(
        json!({"generation":integer(0),"storedContentBytes":integer(0),"permanentFactCount":integer(0),"page":integer(1),"pageSize":integer(1),
        "total":integer(0),"items":array(reference("CmsQueueItem"),50),"source":nullable(reference("CmsQueueSource")),"limits":reference("CmsQueueLimits"),
        "automaticRetry":fixed(json!(false)),"exactlyOnce":fixed(json!(false)),"consumerApplied":fixed(json!("unknown"))}),
    );
    let event = object(json!({"kind":fixed(json!("event")),"name":name(128),"content":name(4096),"at":timestamp()}));
    let metric = object(
        json!({"kind":fixed(json!("metric")),"name":name(128),"value":{"type":"number","description":"Finite raw numeric value."},
        "dimensions":{"type":"object","maxProperties":16,"propertyNames":name(128),"additionalProperties":name(256)},"at":timestamp()}),
    );
    schemas["CmsQueuePayload"] = json!({"oneOf":[event,metric],"x-max-encoded-json-bytes":16*1024});
    let mut enqueue = object(
        json!({"request_id":uuid(),"configuration_version":integer(1),"expected_generation":integer(0),
        "items":{"type":"array","minItems":1,"maxItems":20,"items":reference("CmsQueuePayload")},"initialize_mock_fixture":boolean()}),
    );
    optional(&mut enqueue, "initialize_mock_fixture");
    schemas["CmsQueueEnqueueInput"] = enqueue;
    let ids = json!({"type":"array","minItems":1,"maxItems":20,"uniqueItems":true,"items":uuid()});
    let mut send =
        object(json!({"request_id":uuid(),"expected_generation":integer(0),"item_ids":ids,"confirm_live":boolean()}));
    optional(&mut send, "confirm_live");
    schemas["CmsQueueSendInput"] = send;
    schemas["CmsQueueArchiveInput"] = object(
        json!({"request_id":uuid(),"expected_generation":integer(0),"item_ids":{"type":"array","minItems":1,"maxItems":32,"uniqueItems":true,"items":uuid()}}),
    );
    schemas["CmsQueueRecoverInput"] = object(json!({}));
}
