//! Safe bounded inputs and receipts; credentials, notes and artifact paths are absent.
use serde_json::{Value, json};

fn object(properties: Value) -> Value {
    let required = properties.as_object().into_iter().flat_map(|fields| fields.keys().cloned()).collect::<Vec<_>>();
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}
fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid"})
}
fn hash() -> Value {
    json!({"type":"string","pattern":"^[0-9a-f]{64}$"})
}
fn id() -> Value {
    json!({"type":"string","pattern":"^[1-9][0-9]{0,18}$","maxLength":19,
    "description":"规范正int64字符串，最大9223372036854775807"})
}
fn positive() -> Value {
    json!({"type":"integer","minimum":1})
}
fn timestamp() -> Value {
    json!({"type":"string","format":"date-time"})
}
fn optional(value: Value) -> Value {
    json!({"oneOf":[value,{"type":"null"}]})
}
fn kind() -> Value {
    json!({"enum":["asset-inventory","log-pull","redteam-cruise","rule-hot-reload","report","archive"]})
}

pub(super) fn describe(document: &mut Value) {
    let schemas = &mut document["components"]["schemas"];
    schemas["SchedulerCallbackAdmissionInput"] = object(json!({
        "request_id":uuid(),"kind":kind(),"app_id":id(),"job_id":id(),
        "job_execution_id":{"type":"string","minLength":1,"maxLength":160,"pattern":"^[A-Za-z0-9_: .-]+$",
            "description":"不得含首尾空白或控制字符"},
        "partition_index":{"type":"integer","minimum":0,"maximum":255},
        "partition_total":{"type":"integer","minimum":1,"maximum":256},
        "binding_version":positive(),"configuration_version":positive(),"source_fingerprint":hash()
    }));
    schemas["SchedulerCallbackStartInput"] = object(json!({"claim_id":uuid()}));
    schemas["SchedulerCallbackArtifactDigest"] = object(json!({
        "sha256":hash(),"bytes":{"type":"integer","minimum":0}
    }));
    schemas["SchedulerCallbackOutcome"] = object(json!({
        "ok":{"type":"boolean"},"skipped":{"type":"boolean"},"degraded":{"type":"boolean"},
        "artifacts":{"type":"array","maxItems":64,"items":reference("SchedulerCallbackArtifactDigest")}
    }));
    schemas["SchedulerCallbackCompleteInput"] = object(json!({
        "claim_id":uuid(),"outcome":reference("SchedulerCallbackOutcome")
    }));
    schemas["SchedulerCallbackExecution"] = object(json!({
        "factId":uuid(),"claimId":uuid(),"requestId":uuid(),"tenantId":uuid(),"kind":kind(),
        "appId":id(),"jobId":id(),"jobExecutionId":{"type":"string","minLength":1,"maxLength":160},
        "partitionIndex":{"type":"integer","minimum":0,"maximum":255},
        "partitionTotal":{"type":"integer","minimum":1,"maximum":256},
        "bindingVersion":positive(),"adoptionVersion":positive(),"originalTarget":reference("SchedulerNativeSource"),
        "submittedAt":timestamp(),"startLeaseExpiresAt":timestamp(),"startedAt":optional(timestamp()),
        "executionLeaseExpiresAt":optional(timestamp()),"finishedAt":optional(timestamp()),
        "state":{"enum":["admitted","running","succeeded","failed","uncertain"]},
        "mayConfirmStart":{"type":"boolean"},"mayExecute":{"type":"boolean"},
        "outcome":optional(reference("SchedulerCallbackOutcome")),
        "completionState":{"enum":["admitted","pending_audit","complete"]},"sourceCurrent":{"type":"boolean"}
    }));
}
