//! Candidate increment: local same-actor publication of immutable model settlement evidence.
use serde_json::{Value, json};
const ROOT: &str = "/api/v1/gateway/attempts/{id}";
const RECOVER: &str = "/api/v1/gateway/attempts/{id}/recover";
const LOOKUP: &str = "/api/v1/gateway/attempts/by-idempotency-key";
pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post};
    [
        (ROOT, Get, "gatewayAttemptReceipt", "Read original model settlement evidence"),
        (RECOVER, Post, "recoverGatewaySettlement", "Publish known original model evidence locally"),
        (LOOKUP, Get, "lookupGatewayAdmissionKey", "Find original model attempt by caller header key"),
    ]
    .into_iter()
    .map(|(path, method, id, summary)| super::EndpointSpec {
        path,
        method,
        id,
        summary,
        tag: "models",
        implemented: true,
    })
    .collect()
}
pub(super) fn describe(doc: &mut Value) {
    doc["components"]["schemas"]["GatewaySettlementRecovery"] =
        json!({"type":"object","additionalProperties":false,"properties":{}});
    doc["components"]["schemas"]["GatewaySettlementReceipt"] = json!({"type":"object","additionalProperties":false,
    "required":["attemptId","usageId","state","originalSubmittedAt","originalExecuteBefore","chargeState","auditId","outcomeEvidence","outcomeHash","components","mayExecute","recoveryAvailable"],
    "properties":{
        "attemptId":{"type":"string","format":"uuid"},"usageId":{"type":"string","format":"uuid"},
        "state":{"type":"string","enum":["reserved","pending-audit","conservatively-settled","settled"]},
        "originalSubmittedAt":{"type":"string","format":"date-time"},"originalExecuteBefore":{"type":"string","format":"date-time"},
        "chargeState":{"type":["string","null"],"enum":["reserved","conservative","actual",null]},
        "auditId":{"type":["string","null"],"format":"uuid"},"outcomeHash":{"type":["string","null"],"pattern":"^[a-f0-9]{64}$"},
        "outcomeEvidence":{"type":["string","null"],"enum":["not-sent","local-reply","sent-usage-known","sent-usage-partial","sent-usage-unknown",null]},
        "components":{"type":["array","null"],"maxItems":8,"description":"Additional stable usage components only: up to seven fallback chat candidates and one embedding. Primary chat is the top-level usageId; NotSent candidates have zero consumption.","items":{"type":"object","additionalProperties":false,"required":["usageId","evidence","costMicro"],"properties":{
            "usageId":{"type":"string","format":"uuid"},"evidence":{"type":"string","enum":["not-sent","local-reply","sent-usage-known","sent-usage-partial","sent-usage-unknown"]},
            "costMicro":{"type":["integer","null"],"minimum":0}}}},
        "mayExecute":{"const":false},"recoveryAvailable":{"type":"boolean"}
    }});
    for (path, method, permission) in [(ROOT, "get", "models:read"), (RECOVER, "post", "models:write")] {
        let op = &mut doc["paths"][path][method];
        op["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        op["x-required-permissions"] = json!([permission]);
        op["parameters"] =
            json!([{"name":"id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}]);
        op["responses"] = json!({"200":{"description":"Safe original fact, no model response or private input","content":{"application/json":{"schema":{"$ref":"#/components/schemas/GatewaySettlementReceipt"}}}}});
        for (code, description) in [
            ("400", "Invalid UUID or unsupported recovery fields"),
            ("401", "Current authentication or original publication access lease expired"),
            ("403", "Current grant, tenant or original subject unavailable"),
            ("404", "Tenant owns no requested attempt"),
            ("409", "Conflicting immutable evidence"),
            ("412", "Known evidence is absent or inconsistent"),
            ("500", "Authenticated ciphertext or atomic publication failure"),
        ] {
            op["responses"][code] = json!({"description":description,"content":{"application/problem+json":{"schema":{"$ref":"#/components/schemas/ProblemDetails"}}}});
        }
    }
    doc["paths"][ROOT]["get"]["description"] = json!(
        "Pure local read. No initialization, maintenance, audit, recovery, model request or renewed execution grant. Actual tenant and original subject must match; current models:read and current authentication remain required."
    );
    let recovery = &mut doc["paths"][RECOVER]["post"];
    recovery["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/GatewaySettlementRecovery"}}}});
    recovery["description"] = json!(
        "Explicit empty-body local publication. Same original subject and bound Agent, current models:write and current identity are required. Publishes authenticated existing complete/partial/unknown safe evidence in one governance transaction with stable Usage rows, both quota ledgers, Meter checkpoint and real tenant audit. Does not dispatch, rerun a task, renew the original execution deadline or replace the actor. Duplicate returns original receipt without another charge/audit. Durable bounded chat chains cover nonstream and stream, with at most eight ordered chat candidates. Partial usage is a proven lower bound, charged conservatively at least its original estimate; unknown sent candidates retain their own estimates. Stream success termination is withheld until atomic commit and fresh delivery authorization. Internal/offline or unsupported capacity uses the legacy lane."
    );
    let original_responses = doc["paths"][ROOT]["get"]["responses"].clone();
    let lookup = &mut doc["paths"][LOOKUP]["get"];
    lookup["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
    lookup["x-required-permissions"] = json!(["models:read"]);
    lookup["parameters"] = json!([{"name":"Idempotency-Key","in":"header","required":true,
        "schema":{"type":"string","minLength":1,"maxLength":200,"pattern":"^[!-~]+$"}}]);
    lookup["responses"] = original_responses;
    lookup["responses"]["400"]["description"] =
        json!("Missing, duplicate or invalid original header key, or unsupported URL query");
    lookup["responses"]["404"]["description"] =
        json!("No durable admission index for this current actor and header key; absence never authorizes retry");
    lookup["responses"]["412"]["description"] =
        json!("No durable store is configured or original evidence is unavailable");
    lookup["description"] = json!(
        "Pure tenant-local SQL lookup under the current original subject and bound Agent with models:read. Original User may use a new valid login; another User or administrator cannot substitute for the original Key. Header is never an URL parameter or response field. No source/provider/STS calls, initialization, maintenance, writes, quota changes or audit append. Returns the existing safe receipt, never a persisted model response. A missing index can mean an unsupported legacy lane or a request rejected before reservation; 404 is not proof that no provider request occurred."
    );
    for path in ["/api/v1/chat/completions", "/v1/chat/completions"] {
        let operation = &mut doc["paths"][path]["post"];
        if !operation["parameters"].is_array() {
            operation["parameters"] = json!([]);
        }
        if let Some(parameters) = operation["parameters"].as_array_mut() {
            parameters.push(json!({"name":"Idempotency-Key","in":"header","required":false,
                "schema":{"type":"string","minLength":1,"maxLength":200,"pattern":"^[!-~]+$"},
                "description":"Durable externally-authenticated bounded chat-chain admission, including stream and explicit fallback. First reservation requires models:write; revealing a duplicate original ID additionally requires models:read. Input bytes, business headers and concrete alias/query are bound; both aliases share one actor/key namespace."}));
        }
        operation["responses"]["409"] = json!({"description":"Already admitted or different input under the same permanent key; no new model/embedding dispatch. Safe original attempt ID is returned only after current original-actor models:read/write authorization. No fabricated 200/model-response replay.",
            "headers":{"x-agf-attempt-id":{"schema":{"type":"string","format":"uuid"}}},
            "content":{"application/problem+json":{"schema":{"$ref":"#/components/schemas/ProblemDetails"}}}});
        operation["responses"]["429"] = json!({"description":"Permanent per-tenant admission key capacity (16384) is full; no eviction or dispatch"});
        operation["x-durable-idempotency-lane"] = json!(
            "externally-authenticated durable bounded chain (at most eight chat candidates), stream or nonstream; no-key calls remain atomic but lack caller-header lookup, while internal/offline and unsupported capacity retain legacy semantics"
        );
    }
}
