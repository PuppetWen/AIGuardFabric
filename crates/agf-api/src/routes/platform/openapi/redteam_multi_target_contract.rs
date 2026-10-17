//! A protected-canary observation is not a claim of external defense enforcement.
use serde_json::{Value, json};
mod compatibility;
const ROOT: &str = "/api/v1/redteam/multi-target";
const PATHS: [(&str, &str, &str); 6] = [
    ("/api/v1/redteam/multi-target/playbook", "get", "RedteamMultiPlaybook"),
    ("/api/v1/redteam/multi-target/preview", "post", "RedteamMultiPreview"),
    ("/api/v1/redteam/multi-target/runs", "post", "RedteamMultiRun"),
    ("/api/v1/redteam/multi-target/runs/{id}", "get", "RedteamMultiRun"),
    ("/api/v1/redteam/multi-target/runs/{id}/cancel", "post", "RedteamMultiRun"),
    ("/api/v1/redteam/multi-target/runs/{id}/recover", "post", "RedteamMultiRun"),
];
pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post};
    let mut specs: Vec<_> = PATHS
        .into_iter()
        .enumerate()
        .map(|(i, (path, method, _))| super::EndpointSpec {
            path,
            method: if method == "get" { Get } else { Post },
            id: [
                "getRedteamMultiPlaybook",
                "previewRedteamMultiTopology",
                "executeRedteamMultiTopology",
                "getRedteamMultiReceipt",
                "cancelRedteamMultiRun",
                "recoverRedteamMultiRun",
            ][i],
            summary: "固定三步跨目标只读红队及原UUID本地证据",
            tag: "redteam",
            implemented: true,
        })
        .collect();
    specs.extend(compatibility::endpoint_specs());
    specs
}
fn object(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object","additionalProperties":false,"properties":properties,"required":required})
}
fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
fn nullable(schema: Value) -> Value {
    json!({"anyOf":[schema,{"type":"null"}]})
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid"})
}
fn digest() -> Value {
    json!({"type":"string","pattern":"^[0-9a-f]{64}$"})
}
fn request(schema: Value) -> Value {
    json!({"required":true,"content":{"application/json":{"schema":schema}}})
}
pub(super) fn describe(document: &mut Value) {
    for (path, method, response) in PATHS {
        let operation = &mut document["paths"][path][method];
        let read = method == "get";
        operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        operation["x-required-permissions"] =
            json!([if read { "redteam:read" } else { "redteam:execute" }, "agents:read", "mcps:read"]);
        operation["x-pure-local-read"] = json!(read);
        operation["x-recovery-never-dispatches"] = json!(path.ends_with("/recover"));
        operation["description"] = json!(
            "Fixed Agent A → verified read-only MCP → Agent B. Original same owner/current identity, JWT/session/Key and exact registered versions are checked. 110s original outbound budget; no network retry. GET and same UUID replay are pure. A pending known result can only be locally published; unknown never authorizes resend. Normal public HTTPS supported. Test literal127 capability is default-off and tenant/profile/port-bound. SQL terminal Fact/findings/one audit are atomic; legacy MCP quota/usage remains separate. Protected canary outcome is not exhaustive or external consumer enforcement."
        );
        operation["responses"]["200"] = json!({"description":"安全元数据或原不可变事实及当前资格","content":{"application/json":{"schema":reference(response)}}});
        for status in ["400", "404", "409", "412", "500", "504"] {
            operation["responses"][status] = json!({"description":"严格输入、归属、版本、SQL/来源/哨兵契约或原期限检查失败；无自动重试","content":{"application/problem+json":{"schema":reference("ProblemDetails")}}});
        }
        if path.contains("{id}") {
            operation["parameters"] = json!([{"name":"id","in":"path","required":true,"schema":uuid()}]);
        }
        if !read {
            let schema = if path.ends_with("/preview") {
                object(json!({"targets":reference("RedteamMultiSelections")}), &["targets"])
            } else if path.strip_prefix(ROOT) == Some("/runs") {
                object(
                    json!({"request_id":uuid(),"targets":reference("RedteamMultiSelections"),"reviewed_topology_sha256":digest(),
                "confirm_registered_targets":{"type":"boolean"},"confirm_live":{"type":"boolean"}}),
                    &[
                        "request_id",
                        "targets",
                        "reviewed_topology_sha256",
                        "confirm_registered_targets",
                        "confirm_live",
                    ],
                )
            } else {
                object(json!({}), &[])
            };
            operation["requestBody"] = request(schema);
        }
    }
    let schemas = &mut document["components"]["schemas"];
    schemas["RedteamMultiSelection"] = object(
        json!({"kind":{"type":"string","enum":["agent-http","mcp-http"]},"profile_id":uuid(),"expected_version":{"type":"integer","minimum":1,"maximum":u64::MAX}}),
        &["kind", "profile_id", "expected_version"],
    );
    schemas["RedteamMultiSelections"] = json!({"type":"array","minItems":3,"maxItems":3,"items":reference("RedteamMultiSelection"),"description":"Exact role order Agent A, MCP, Agent B; three distinct profiles and two distinct current Agent assets"});
    schemas["RedteamMultiTarget"] = object(
        json!({"kind":{"type":"string","enum":["agent-http","mcp-http"]},"profileId":uuid(),"version":{"type":"integer","minimum":1},"assetId":uuid(),
        "profileSha256":digest(),"registrySha256":digest(),"transportMode":{"type":"string","enum":["https-live","test-loopback"]}}),
        &["kind", "profileId", "version", "assetId", "profileSha256", "registrySha256", "transportMode"],
    );
    schemas["RedteamMultiPlaybook"] = object(
        json!({"version":{"const":"cross-service-readonly-v1"},"steps":{"type":"array","minItems":3,"maxItems":3,"items":{"type":"string"}},
        "maximumTargets":{"const":3},"maximumSteps":{"const":3},"declarativeYamlSha256":digest(),"arbitraryYamlAccepted":{"const":false},"protectedCanaryOnly":{"const":true},"externalDefenseVerified":{"const":false}}),
        &[
            "version",
            "steps",
            "maximumTargets",
            "maximumSteps",
            "declarativeYamlSha256",
            "arbitraryYamlAccepted",
            "protectedCanaryOnly",
            "externalDefenseVerified",
        ],
    );
    schemas["RedteamMultiPreview"] = object(
        json!({"topology":{"type":"object","properties":{"playbook":reference("RedteamMultiPlaybook"),"targets":{"type":"array","items":reference("RedteamMultiTarget")}},"additionalProperties":true},
        "topologySha256":digest(),"requiresDatabase":{"const":true}}),
        &["topology", "topologySha256", "requiresDatabase"],
    );
    schemas["RedteamMultiEvidence"] = object(
        json!({"step":{"type":"integer","minimum":0,"maximum":2},"profileId":uuid(),"requestSha256":nullable(digest()),"responseSha256":nullable(digest()),"relaySha256":nullable(digest()),
        "responseBytes":nullable(json!({"type":"integer","minimum":0,"maximum":65536})),"completed":{"type":"boolean"},"protectedCanaryObserved":nullable(json!({"type":"boolean"})),
        "dispatch":{"type":"string","enum":["known_response","not_confirmed"]},"reason":nullable(json!({"type":"string","maxLength":64}))}),
        &[
            "step",
            "profileId",
            "requestSha256",
            "responseSha256",
            "relaySha256",
            "responseBytes",
            "completed",
            "protectedCanaryObserved",
            "dispatch",
            "reason",
        ],
    );
    schemas["RedteamMultiRun"] = object(
        json!({"requestId":uuid(),"campaignId":uuid(),"playbookVersion":{"const":"cross-service-readonly-v1"},"targets":{"type":"array","minItems":3,"maxItems":3,"items":reference("RedteamMultiTarget")},
        "status":{"type":"string","enum":["running","uncertain","completed","failed","cancelled"]},"completionState":{"type":"string","enum":["in_progress","pending_audit","complete"]},
        "submittedAt":{"type":"string","format":"date-time"},"deadlineAt":{"type":"string","format":"date-time"},"finishedAt":nullable(json!({"type":"string","format":"date-time"})),
        "evidence":{"type":"array","maxItems":3,"items":reference("RedteamMultiEvidence")},"findingIds":{"type":"array","maxItems":3,"items":uuid()},"auditId":nullable(uuid()),"sourceCurrent":nullable(json!({"type":"boolean"})),
        "localFixture":{"type":"boolean"},"externalDefenseVerified":{"const":false},"defensePassed":nullable(json!({"type":"boolean"})),"canRetryDispatch":{"const":false},"rawBodiesStored":{"const":false}}),
        &[
            "requestId",
            "campaignId",
            "playbookVersion",
            "targets",
            "status",
            "completionState",
            "submittedAt",
            "deadlineAt",
            "finishedAt",
            "evidence",
            "findingIds",
            "auditId",
            "sourceCurrent",
            "localFixture",
            "externalDefenseVerified",
            "defensePassed",
            "canRetryDispatch",
            "rawBodiesStored",
        ],
    );
    compatibility::describe(document);
}
