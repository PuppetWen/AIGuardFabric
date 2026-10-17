use super::*;
const MANAGED: &str = "/api/v1/redteam/multi-target/profiles/{kind}/{id}/transport";
const RUNS: &str = "/api/v1/redteam/multi-target/runs";
const ARCHIVE: &str = "/api/v1/redteam/multi-target/runs/{id}/archive";
pub(super) fn endpoint_specs() -> Vec<super::super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post, Put};
    [
        (RUNS, Get, "listMyRedteamMultiRecentRuns"),
        (ARCHIVE, Post, "archiveReviewedRedteamMultiRun"),
        (MANAGED, Get, "getManagedRedteamTransport"),
        (MANAGED, Put, "saveManagedRedteamTransport"),
    ]
    .into_iter()
    .map(|(path, method, id)| super::super::EndpointSpec {
        path,
        method,
        id,
        summary: "准确主体近期UUID、审查归档与托管传输批准",
        tag: "redteam",
        implemented: true,
    })
    .collect()
}
fn version(minimum: u64) -> Value {
    json!({"type":"integer","minimum":minimum,"maximum":u64::MAX})
}
fn revision() -> Value {
    json!({"type":"string","enum":["2026-07-28","2025-11-25"]})
}
pub(super) fn describe(document: &mut Value) {
    for (path, method, response) in [
        (RUNS, "get", "RedteamMultiRecent"),
        (ARCHIVE, "post", "RedteamMultiRun"),
        (MANAGED, "get", "RedteamManagedView"),
        (MANAGED, "put", "RedteamManagedSettings"),
    ] {
        let op = &mut document["paths"][path][method];
        let managed = path == MANAGED;
        op["security"] = if managed { json!([{"bearerAuth":[]}]) } else { json!([{"bearerAuth":[]},{"apiKey":[]}]) };
        op["x-required-permissions"] = if managed {
            json!(["platform:admin", "redteam:execute", "agents:read", "mcps:read"])
        } else {
            json!([if method == "get" { "redteam:read" } else { "redteam:execute" }, "agents:read", "mcps:read"])
        };
        op["x-pure-local-read"] = json!(method == "get");
        op["x-never-dispatches"] = json!(true);
        op["description"] = json!(
            "Owner recent window is at most 256 UUIDs; exact old UUID GET remains available. 128 retained bodies, 16,384 permanent tenant facts; archive never restores dispatch or permanent UUID capacity. Archive uses reviewed generation; same review is a no-op, other review 409. Current User administrator can CAS approve only an exact registered profile/version/URL with all RFC1918/ULA addresses and exact port. Private HTTP needs explicit consent; absent approval only public HTTPS. Current authorization is checked after audit waits; no proxy/redirect/mixed DNS. MCP explicit 2026-07-28 metadata/header encoding and bounded JSON/SSE; explicit 2025-11-25 initialize/initialized and private session. No protocol fallback or business-call replay."
        );
        op["responses"]["200"] = json!({"description":"安全当前设置、原主体近期UUID或原永久事实","content":{"application/json":{"schema":reference(response)}}});
        for status in ["400", "401", "403", "404", "409", "412", "500", "504"] {
            op["responses"][status] = json!({"description":"权限、版本、容量、来源或原期限拒绝；禁止自动重派","content":{"application/problem+json":{"schema":reference("ProblemDetails")}}});
        }
        if path == RUNS {
            op["parameters"] = json!([{"name":"limit","in":"query","schema":{"type":"integer","minimum":1,"maximum":50,"default":20}},
                {"name":"offset","in":"query","schema":{"type":"integer","minimum":0,"maximum":255,"default":0}}]);
            op["x-reject-unknown-or-duplicate-query"] = json!(true);
        } else {
            let mut parameters = vec![json!({"name":"id","in":"path","required":true,"schema":uuid()})];
            if managed {
                parameters.push(json!({"name":"kind","in":"path","required":true,"schema":{"type":"string","enum":["agent-http","mcp-http"]}}));
            }
            op["parameters"] = json!(parameters);
        }
        if path == ARCHIVE {
            op["requestBody"] = request(object(json!({"expected_generation":version(1)}), &["expected_generation"]));
        }
        if managed && method == "put" {
            op["requestBody"] = request(reference("RedteamManagedInput"));
        }
    }
    let schemas = &mut document["components"]["schemas"];
    schemas["RedteamMultiTarget"]["properties"]["transportMode"] =
        json!({"type":"string","enum":["https-live","approved-private-http","approved-private-https","test-loopback"]});
    for (name, schema) in [
        ("managedProfileVersion", nullable(version(1))),
        ("managedProfileSha256", nullable(digest())),
        ("mcpProtocolRevision", nullable(revision())),
    ] {
        schemas["RedteamMultiTarget"]["properties"][name] = schema;
        if let Some(required) = schemas["RedteamMultiTarget"]["required"].as_array_mut() {
            required.push(json!(name));
        }
    }
    schemas["RedteamMultiEvidence"]["properties"]["transportProofSha256"] = nullable(digest());
    if let Some(required) = schemas["RedteamMultiEvidence"]["required"].as_array_mut() {
        required.push(json!("transportProofSha256"));
    }
    schemas["RedteamMultiRun"]["properties"]["status"] =
        json!({"type":"string","enum":["running","uncertain","completed","failed","cancelled","archived"]});
    for (name, schema) in [
        ("generation", version(1)),
        ("archivedAt", nullable(json!({"type":"string","format":"date-time"}))),
        ("originalStatus", nullable(json!({"type":"string","enum":["completed","failed","cancelled"]}))),
        ("archivedEvidenceSha256", nullable(digest())),
        ("archiveAuditId", nullable(uuid())),
    ] {
        schemas["RedteamMultiRun"]["properties"][name] = schema;
        if let Some(required) = schemas["RedteamMultiRun"]["required"].as_array_mut() {
            required.push(json!(name));
        }
    }
    schemas["RedteamMultiRecentItem"] = object(
        json!({"requestId":uuid(),"status":schemas["RedteamMultiRun"]["properties"]["status"].clone(),
        "completionState":schemas["RedteamMultiRun"]["properties"]["completionState"].clone(),
        "submittedAt":{"type":"string","format":"date-time"},"finishedAt":nullable(json!({"type":"string","format":"date-time"})),
        "generation":version(1),"archived":{"type":"boolean"},"originalStatus":schemas["RedteamMultiRun"]["properties"]["originalStatus"].clone()}),
        &[
            "requestId",
            "status",
            "completionState",
            "submittedAt",
            "finishedAt",
            "generation",
            "archived",
            "originalStatus",
        ],
    );
    schemas["RedteamMultiRecent"] = object(
        json!({"items":{"type":"array","maxItems":50,"items":reference("RedteamMultiRecentItem")},
        "total":{"type":"integer","minimum":0,"maximum":256},"offset":{"type":"integer","minimum":0,"maximum":255},
        "limit":{"type":"integer","minimum":1,"maximum":50},"truncated":{"type":"boolean"},"completeHistory":{"const":false},
        "getNeverDispatches":{"const":true},"limits":object(json!({"retainedBodies":{"const":128},"permanentUuidFacts":{"const":16384},"recentOwnerUuids":{"const":256}}),
            &["retainedBodies","permanentUuidFacts","recentOwnerUuids"])}),
        &["items", "total", "offset", "limit", "truncated", "completeHistory", "limits", "getNeverDispatches"],
    );
    let network = object(
        json!({"addresses":{"type":"array","minItems":1,"maxItems":8,"uniqueItems":true,"items":{"type":"string","maxLength":45}},
        "port":{"type":"integer","minimum":1,"maximum":65535},"allowPlainHttp":{"type":"boolean"}}),
        &["addresses", "port", "allowPlainHttp"],
    );
    let private_input = object(
        json!({"addresses":network["properties"]["addresses"].clone(),"port":network["properties"]["port"].clone(),
        "allow_plain_http":{"type":"boolean"},"confirm_exact_private_network":{"type":"boolean"}}),
        &["addresses", "port", "allow_plain_http", "confirm_exact_private_network"],
    );
    schemas["RedteamManagedInput"] = object(
        json!({"expected_version":version(0),"profile_version":version(1),"url":{"type":"string","maxLength":2048},
        "enabled":{"type":"boolean"},"mcp_protocol_revision":revision(),"private_network":nullable(private_input)}),
        &["expected_version", "profile_version", "url", "enabled", "mcp_protocol_revision"],
    );
    schemas["RedteamManagedSettings"] = object(
        json!({"kind":{"type":"string","enum":["agent-http","mcp-http"]},"profileId":uuid(),"profileVersion":version(1),
        "version":version(1),"url":{"type":"string","maxLength":2048},"enabled":{"type":"boolean"},"mcpProtocolRevision":revision(),"privateNetwork":nullable(network),
        "defaultPrivateAccess":{"const":false},"automaticProtocolFallback":{"const":false}}),
        &[
            "kind",
            "profileId",
            "profileVersion",
            "version",
            "url",
            "enabled",
            "mcpProtocolRevision",
            "privateNetwork",
            "defaultPrivateAccess",
            "automaticProtocolFallback",
        ],
    );
    schemas["RedteamManagedView"] = object(
        json!({"configured":{"type":"boolean"},"profileId":uuid(),"profileVersion":version(1),"url":{"type":"string","maxLength":2048},
        "version":version(0),"settings":nullable(reference("RedteamManagedSettings")),"defaultPrivateAccess":{"const":false},
        "defaultMcpProtocolRevision":{"const":"2026-07-28"},"supportedMcpProtocolRevisions":{"type":"array","minItems":2,"maxItems":2,"items":revision()},
        "requiresDurableDatabase":{"const":true},"businessDispatched":{"const":false}}),
        &[
            "configured",
            "profileId",
            "profileVersion",
            "url",
            "version",
            "settings",
            "defaultPrivateAccess",
            "defaultMcpProtocolRevision",
            "supportedMcpProtocolRevisions",
            "requiresDurableDatabase",
            "businessDispatched",
        ],
    );
}
