//! Platform policy publication uses reviewed revisions, trusted history and atomic success audit.
use agf_core::enums::{InterceptPoint, PolicyAction, RiskDomain, Severity};
use serde_json::{Value, json};

const ROOT: &str = "/api/v1/policies";
const CURRENT: &str = "/api/v1/policies/{id}";
const HISTORY: &str = "/api/v1/policies/{id}/versions";
const RESTORE: &str = "/api/v1/policies/{id}/versions/{version}/restore";
const BOUNDARY: &str = "Enabled publication affects subsequent platform runtime requests. Dry-run observes without enforcement. It does not publish to cloud MSE/API gateways or prove that external consumers reloaded a policy.";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post};
    [
        (HISTORY, Get, "policyVersions", "读取可信签名策略版本历史"),
        (RESTORE, Post, "restorePolicy", "按当前版本条件恢复历史为新的签名版本"),
    ]
    .into_iter()
    .map(|(path, method, id, summary)| super::EndpointSpec {
        path,
        method,
        id,
        summary,
        tag: "policies",
        implemented: true,
    })
    .collect()
}

fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid"})
}
fn revision() -> Value {
    json!({"type":"integer","minimum":1,"maximum":u32::MAX})
}
fn expected() -> Value {
    json!({"type":"integer","format":"uint64","minimum":1,"maximum":u64::MAX,
        "description":"The exact current server revision reviewed by this caller; never guessed or automatically rebased."})
}
fn response(name: &str) -> Value {
    json!({"description":"Actual tenant-owned platform result",
        "content":{"application/json":{"schema":reference(name)}}})
}
fn request(name: &str) -> Value {
    json!({"required":true,"content":{"application/json":{"schema":reference(name)}}})
}
fn problem(description: &str) -> Value {
    json!({"description":description,
        "content":{"application/problem+json":{"schema":reference("ProblemDetails")}}})
}

pub(super) fn describe(document: &mut Value) {
    inputs(&mut document["components"]["schemas"]);
    outputs(&mut document["components"]["schemas"]);
    for (path, method, permission, result) in [
        (ROOT, "get", "policies:read", "SignedPolicyPage"),
        (ROOT, "post", "policies:write", "SignedPolicyEnvelope"),
        (CURRENT, "get", "policies:read", "SignedPolicyEnvelope"),
        (CURRENT, "put", "policies:write", "SignedPolicyEnvelope"),
        (CURRENT, "delete", "policies:delete", "DeletedPolicyEnvelope"),
        (HISTORY, "get", "policies:read", "SignedPolicyHistory"),
        (RESTORE, "post", "policies:write", "SignedPolicyEnvelope"),
    ] {
        let operation = &mut document["paths"][path][method];
        operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        operation["x-required-permissions"] = json!([permission]);
        let mut responses = json!({});
        responses[if method == "post" && path == ROOT { "201" } else { "200" }] = response(result);
        for (code, detail) in [
            ("400", "Malformed input/query, unsupported fields, invalid candidate or version."),
            ("401", "Unauthenticated or the original access token expired before commit."),
            ("403", "Current tenant, identity, original session or required permission is unavailable."),
            ("412", "Stored policy signature is missing or invalid; no unverified policy is used."),
            ("429", "Request rate limit exceeded."),
            (
                "500",
                "Stored tenant/policy identity, version or content hash is invalid, or atomic configuration/audit commit failed.",
            ),
        ] {
            responses[code] = problem(detail);
        }
        if path != ROOT {
            responses["404"] = problem("This tenant has no requested policy or retained historical revision.");
        }
        if method != "get" {
            responses["409"] = problem(
                "Name exists, current revision changed, selected history changed, or version exhausted; keep the draft and explicitly review again.",
            );
            operation["x-runtime-boundary"] = json!(BOUNDARY);
            operation["x-atomic-success-audit"] = json!({"target":"policy","configurationAndHistory":true,
                "sql":"same transaction","offline":"same process guarded publication"});
        }
        operation["responses"] = responses;
        if path != ROOT {
            operation["parameters"] = json!([{"name":"id","in":"path","required":true,"schema":uuid()}]);
        }
    }
    operations(document);
}

fn operations(document: &mut Value) {
    let list = &mut document["paths"][ROOT]["get"];
    list["description"] = json!(
        "Current non-deleted signed policies in this tenant. Every stored current/history row is verified before use. Optional fields projection returns only selected fields; it does not return an unsigned policy."
    );
    list["parameters"] = json!([
        {"name":"page","in":"query","schema":{"type":"integer","minimum":1,"default":1},"description":"Invalid values normalize to 1."},
        {"name":"page_size","in":"query","schema":{"type":"integer","minimum":1,"maximum":200,"default":20},"description":"Values normalize to the 1..200 bounds."},
        {"name":"q","in":"query","schema":{"type":"string"},"description":"Case-insensitive name, description and action search."},
        {"name":"enabled","in":"query","schema":{"type":"string"},"description":"true/false, 1/0 or yes/no; other values return400."},
        {"name":"action","in":"query","schema":{"type":"string"},"description":"Exact PolicyAction.as_str value, including circuit-break."},
        {"name":"sort","in":"query","schema":{"type":"string"},"description":"A supplied value sorts by name; leading '-' descends."},
        {"name":"fields","in":"query","schema":{"type":"string"},"description":"Comma-separated raw response field names; omitted returns all fields."}
    ]);
    let create = &mut document["paths"][ROOT]["post"];
    create["requestBody"] = request("CreateSignedPolicy");
    create["description"] = json!(format!(
        "Create only an absent active tenant-local name; expected_version may be missing, null or 0. Any positive value returns400 before duplicate-name checking; a duplicate active name returns409 and is never overwritten. Server validates and compiles, then signs version1 and commits its success audit. {BOUNDARY}"
    ));
    document["paths"][CURRENT]["get"]["description"] = json!(
        "Return the verified current non-deleted policy. Deleted current returns404; its retained signed history remains accessible."
    );
    let update = &mut document["paths"][CURRENT]["put"];
    update["requestBody"] = request("UpdateSignedPolicy");
    update["description"] = json!(format!(
        "Full candidate update, using the positive current expected_version. Missing/null/0 returns400; stale positive version409. The server preserves ID, tenant, name and created_at, and increments/signs the version. Omitted optional candidate fields use PolicyBody defaults, rather than patching old fields. Candidate/authority/audit failure preserves current and history. {BOUNDARY}"
    ));
    let delete = &mut document["paths"][CURRENT]["delete"];
    delete["parameters"] = json!([
        {"name":"id","in":"path","required":true,"schema":uuid()},
        {"name":"expected_version","in":"query","required":true,"schema":expected()}
    ]);
    delete["description"] = json!(
        "The query must contain exactly one expected_version positive integer and no other field. Missing, duplicate or extra fields return400; stale revision409. Soft deletion increments and signs a disabled current version with deleted_at, retains history, and commits Delete success audit atomically. It does not delete external cloud configuration."
    );
    document["paths"][HISTORY]["get"]["description"] = json!(
        "Verified signed history in ascending version order, at most100 previous revisions plus current. Soft-deleted current is included with enabled=false/deleted_at. No such tenant-owned history returns404. Enclosing tenant/policy identity, content_hash, HMAC signature and strictly increasing unique versions must validate; invalid stored signature returns412, identity/hash/version inconsistency500, without repair."
    );
    let restore = &mut document["paths"][RESTORE]["post"];
    restore["parameters"] = json!([
        {"name":"id","in":"path","required":true,"schema":uuid()},
        {"name":"version","in":"path","required":true,"schema":revision()}
    ]);
    restore["requestBody"] = request("RestoreSignedPolicy");
    restore["description"] = json!(format!(
        "Strict JSON {{version,expected_version}}. Positive body.version must equal the selected path version. Server copies retained trusted history, recompiles and signs a new current revision; it never accepts caller-supplied historical source/signature. Current may be soft-deleted: use its latest deleted revision as expected_version to revive. ID/name/created_at remain; deleted_at clears, historical enabled/dry_run settings remain. Restore records Update success audit with current/history in one commit. {BOUNDARY}"
    ));
}

fn inputs(schemas: &mut Value) {
    let properties = json!({
        "name":{"type":"string","minLength":1,"maxLength":128,"description":"Non-whitespace; no control characters; at most128 UTF-8 bytes. Immutable on update."},
        "description":{"type":"string","default":""},
        "language":{"type":["string","null"],"default":"structured","description":"rego/opa, cel, structured/form; case-insensitive. Missing/null uses structured."},
        "source":{"type":"string","default":"","maxLength":65536,"x-max-utf8-bytes":65536},
        "structured":reference("StructuredPolicyCondition"),
        "action":{"type":["string","null"],"default":"audit","description":"allow, deny/block, audit, quota, redact/mask, throttle/rate-limit, degrade/fallback, circuit-break/breaker, isolate/quarantine, approval/manual-approval. Case/underscore normalized; missing/null uses audit."},
        "priority":{"type":["integer","null"],"minimum":0,"maximum":u32::MAX,"default":100},
        "intercept_points":{"type":"array","items":{"type":"string"},"default":[],"description":"mcp-proxy, ai-gateway, process-hook, collector; trimmed case/underscore normalized."},
        "scope_agent_ids":{"type":"array","maxItems":2000,"uniqueItems":true,"items":uuid(),"default":[],"description":"Current tenant live Agent UUIDs; non-nil. Empty applies to all Agents."},
        "scope_departments":{"type":"array","items":{"type":"string"},"default":[]},
        "enabled":{"type":"boolean","default":true},"dry_run":{"type":"boolean","default":false},
        "quota_id":{"type":["string","null"],"format":"uuid","description":"Optional current tenant enabled quota; non-nil if supplied."},
        "degrade_endpoint_id":{"type":["string","null"],"format":"uuid","description":"Required non-nil enabled tenant model endpoint for action=degrade."}
    });
    let mut create = json!({"type":"object","additionalProperties":false,"required":["name"],"properties":properties});
    create["properties"]["expected_version"] = json!({"type":["integer","null"],"enum":[0,null],"description":"Optional absent-only create condition; omit/null/0 never upserts an existing active name."});
    let mut update = create.clone();
    update["required"] = json!(["name", "expected_version"]);
    update["properties"]["expected_version"] = expected();
    schemas["CreateSignedPolicy"] = create;
    schemas["UpdateSignedPolicy"] = update;
    schemas["RestoreSignedPolicy"] = json!({"type":"object","additionalProperties":false,
        "required":["version","expected_version"],"properties":{"version":revision(),"expected_version":expected()}});
    structured(schemas);
}

fn structured(schemas: &mut Value) {
    let mut properties = json!({});
    for name in [
        "command_deny",
        "tool_allowlist",
        "tool_denylist",
        "domain_allowlist",
        "domain_denylist",
        "path_allowlist",
        "path_denylist",
    ] {
        properties[name] = json!({"type":"array","items":{"type":"string"},"default":[]});
    }
    properties["domains"] = json!({"type":"array","default":[],"items":{"type":"string","enum":
        [RiskDomain::PromptAttack,RiskDomain::CredentialLeak,RiskDomain::RagPoison,RiskDomain::ToolAbuse,RiskDomain::ModelData]}});
    properties["min_severity"] = json!({"type":["string","null"],"enum":[Severity::Info,Severity::Low,Severity::Medium,Severity::High,Severity::Critical,null]});
    properties["max_payload_bytes"] = json!({"type":["integer","null"],"minimum":0,"maximum":u64::MAX});
    properties["require_approval"] = json!({"type":"boolean","default":false});
    schemas["StructuredPolicyCondition"] = json!({"type":"object","additionalProperties":true,"properties":properties,
        "description":"StructuredCondition defaults every omitted field. Unknown nested fields are ignored by its current serde contract; top-level PolicyBody remains strict."});
}

fn outputs(schemas: &mut Value) {
    let mut properties = json!({
        "id":uuid(),"tenant_id":uuid(),"name":{"type":"string"},"description":{"type":"string"},
        "language":{"type":"string","enum":["rego","cel","structured"]},"source":{"type":"string"},
        "structured":reference("StructuredPolicyCondition"),"action":{"type":"string","enum":
            [PolicyAction::Allow,PolicyAction::Deny,PolicyAction::Audit,PolicyAction::Quota,PolicyAction::Redact,
                PolicyAction::Throttle,PolicyAction::Degrade,PolicyAction::CircuitBreak,PolicyAction::Isolate,PolicyAction::Approval]},
        "priority":{"type":"integer","minimum":0,"maximum":u32::MAX},
        "intercept_points":{"type":"array","items":{"type":"string","enum":
            [InterceptPoint::McpProxy,InterceptPoint::AiGateway,InterceptPoint::ProcessHook,InterceptPoint::Collector]}},
        "scope_agent_ids":{"type":"array","items":uuid()},"scope_departments":{"type":"array","items":{"type":"string"}},
        "enabled":{"type":"boolean"},"dry_run":{"type":"boolean"},"quota_id":uuid(),"degrade_endpoint_id":uuid(),
        "content_hash":{"type":"string","pattern":"^[0-9a-f]{64}$","description":"Server-computed SHA256 over the canonical signed content."},
        "signature":{"type":"string","pattern":"^hmac256:[0-9a-f]{64}$","description":"Server HMAC-SHA256 over content_hash, serialized as hmac256: plus64 lowercase hex characters; no public verification key or external reload proof."},
        "version":revision()
    });
    for name in ["created_at", "updated_at", "deleted_at"] {
        properties[name] = json!({"type":"string","format":"date-time"});
    }
    schemas["SignedPlatformPolicy"] = json!({"type":"object","additionalProperties":false,
        "required":["id","tenant_id","name","description","language","source","structured","action","priority",
            "intercept_points","scope_agent_ids","scope_departments","enabled","dry_run","content_hash","signature","version","created_at","updated_at"],
        "properties":properties,"description":"Raw server snake_case Policy; optional quota_id/degrade_endpoint_id/deleted_at are omitted when absent. Action enum follows serde JSON (CircuitBreak serializes as circuitbreak)."});
    schemas["ProjectedSignedPolicy"] = json!({"type":"object","additionalProperties":false,"properties":properties,
        "description":"Only fields explicitly selected from a verified signed Policy by the list fields query."});
    schemas["SignedPolicyEnvelope"] = json!({"type":"object","additionalProperties":false,"required":["policy"],"properties":{"policy":reference("SignedPlatformPolicy")}});
    schemas["SignedPolicyHistory"] = json!({"type":"object","additionalProperties":false,"required":["versions"],"properties":{
        "versions":{"type":"array","maxItems":101,"items":reference("SignedPlatformPolicy")}}});
    schemas["DeletedPolicyEnvelope"] =
        json!({"type":"object","additionalProperties":false,"required":["deleted"],"properties":{"deleted":uuid()}});
    schemas["SignedPolicyPage"] = json!({"type":"object","additionalProperties":false,
        "required":["items","total","page","page_size","has_more","next_cursor"],"properties":{
            "items":{"type":"array","maxItems":200,"items":{"anyOf":[reference("SignedPlatformPolicy"),reference("ProjectedSignedPolicy")]}},
            "total":{"type":"integer","minimum":0},"page":{"type":"integer","minimum":1},
            "page_size":{"type":"integer","minimum":1,"maximum":200},"has_more":{"type":"boolean"},"next_cursor":{"type":["string","null"]}}});
}
