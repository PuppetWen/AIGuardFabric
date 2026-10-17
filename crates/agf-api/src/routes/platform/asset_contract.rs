//! Query contract used by inventory clients and the review form.
use serde_json::{Value, json};

pub(super) fn describe(document: &mut Value) {
    describe_package(document);
    for (path, method, schema) in [
        ("/api/v1/skills/{id}/status", "post", "SkillStatusBody"),
        ("/api/v1/skills/{id}/whitelist", "put", "SkillWhitelistBody"),
    ] {
        document["paths"][path][method]["requestBody"] = json!({"required":true,"content":{
            "application/json":{"schema":{"$ref":format!("#/components/schemas/{schema}")}}}});
        document["paths"][path][method]["responses"]["409"] = json!({"description":"Stale revision or illegal lifecycle operation; compare the current Skill before saving"});
        document["paths"][path][method]["description"] = json!(
            "Requires skills:write. Submit expected_updated_at from skill.review.updatedAt to prevent stale overwrites. Lifecycle follows inventory allowed_next; production requires owner and data_class, every review requires note. Allowlist requires both arrays, supports 100 entries each, and cannot change an archived/rejected Skill. This updates inventory metadata; runtime enforcement must be configured separately."
        );
    }
    document["components"]["securitySchemes"]["bearerAuth"] =
        json!({"type":"http","scheme":"bearer","bearerFormat":"JWT"});
    for (path, method, description) in [
        (
            "/api/v1/assets/register",
            "post",
            "Register an asset application in requested state. Requires assets:write. Retry with the identical request_id and body; another inventory key owner returns 409.",
        ),
        (
            "/api/v1/assets/inventory",
            "get",
            "List daily inventory runs, 20 per page. Includes automatic_enabled and can_write. Requires assets:read.",
        ),
        (
            "/api/v1/assets/inventory",
            "post",
            "Complete today's UTC inventory once, or return the existing run. PostgreSQL required. Requires assets:write.",
        ),
        (
            "/api/v1/assets/inventory/{id}/changes",
            "get",
            "Read one run's changes, 50 per page. Requires assets:read; foreign tenant run IDs return 404.",
        ),
    ] {
        document["paths"][path][method] = json!({"tags":["assets"],"description":description,
            "security":[{"bearerAuth":[]}],"responses":{"200":{"description":"Success"},"400":{"description":"Invalid input"},
            "401":{"description":"Authentication required"},"403":{"description":"Permission denied"}}});
        if method == "get" {
            document["paths"][path][method]["parameters"] = json!([{"name":"page","in":"query","schema":{"type":"integer","minimum":1,"maximum":1_000_000,"default":1}}]);
        }
    }
    if let Some(params) = document["paths"]["/api/v1/assets/inventory/{id}/changes"]["get"]["parameters"].as_array_mut()
    {
        params.push(json!({"name":"id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}));
    }
    document["paths"]["/api/v1/assets/register"]["post"]["requestBody"] =
        json!({"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Registration"}}}});
    let parameters = [
        ("page","integer","Page number, starting at 1"),
        ("page_size","integer","Rows per page, 1..200"),
        ("sort","string","name, risk_score, exposure_score, last_seen_at, created_at, updated_at, kind or lifecycle; prefix - for descending"),
        ("q","string","Case-insensitive literal search, at most 512 bytes"),
        ("fields","string","Comma-separated response field names"),
        ("kinds","string","Comma-separated asset kinds; UI aliases mcp, model, skill, datasource and endpoint are supported"),
        ("lifecycles","string","Comma-separated core states or planned/onboarding/active/deprecated/retired"),
        ("classifications","string","Comma-separated public/internal/confidential/restricted"),
        ("departments","string","Comma-separated exact department names"),
        ("exposures","string","Comma-separated public-internet/partner/intranet/isolated/unknown"),
        ("min_exposure","integer","Minimum exposure score, 0..100"),
    ].into_iter().map(|(name,kind,description)|json!({"name":name,"in":"query","required":false,
        "description":description,"schema":{"type":kind}})).collect::<Vec<_>>();
    document["paths"]["/api/v1/assets"]["get"]["parameters"] = json!(parameters);
    document["paths"]["/api/v1/assets"]["get"]["description"] = json!(
        "Risk scores remain null when unassessed and sort last. Exposure uses explicit network_zone metadata, never exposure points. open_findings counts active tenant findings and is null without findings:read. Zero is not proof of scanning or safety. All filters apply before pagination and total count. Values within each filter use OR, filters combine with AND. Singular kind/lifecycle/data_class/department/exposure aliases remain supported. SQL reads use tenant row isolation; unsupported sorts and invalid defined filter values return 400."
    );
    for (path, schema) in [("/api/v1/assets/{id}/transition", "TransitionBody"), ("/api/v1/assets/drift", "DriftBody")]
    {
        document["paths"][path]["post"]["requestBody"] = json!({"required":true,"content":{
            "application/json":{"schema":{"$ref":format!("#/components/schemas/{schema}")}}}});
    }
    document["paths"]["/api/v1/assets/{id}/transition"]["post"]["responses"]["409"] = json!({"description":"Lifecycle transition is invalid or expected_updated_at is stale; refresh and compare before saving"});
    let binding = &mut document["paths"]["/api/v1/assets/{id}/edr-host"]["put"];
    binding["description"] = json!(
        "Requires assets:write. Bind or clear a verified EDR host ID on an existing asset. Submit governance.updated_at as expected_updated_at and a reason; stale revisions return 409. Approved isolation accepts only the bound ID."
    );
    binding["parameters"] =
        json!([{"name":"id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}]);
    binding["requestBody"] =
        json!({"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/BindEdrHost"}}}});
    binding["responses"]["409"] =
        json!({"description":"Asset changed; reload and compare the current binding before saving"});
    document["paths"]["/api/v1/assets/drift"]["post"]["description"] =
        json!("Requires assets:write because it persists the current baseline and drift history.");
}

fn describe_package(document: &mut Value) {
    let schemas = &mut document["components"]["schemas"];
    schemas["SkillPackageObservation"] = json!({"type":"object","additionalProperties":false,
        "required":["algorithm","status"],"properties":{
            "algorithm":{"type":"string","const":"sha256-tree-v1"},
            "status":{"type":"string","enum":["verified","unreadable","too-large","too-many-entries",
                "too-deep","unsupported-path","not-regular-file","changed-during-read","link-not-allowed"]},
            "sha256":{"type":"string","pattern":"^[0-9a-fA-F]{64}$"},
            "files":{"type":"integer","minimum":1,"maximum":4096},
            "bytes":{"type":"integer","minimum":0,"maximum":67_108_864}
        },"oneOf":[
            {"required":["sha256","files","bytes"],"properties":{"status":{"const":"verified"}}},
            {"properties":{"status":{"not":{"const":"verified"}}},
             "not":{"anyOf":[{"required":["sha256"]},{"required":["files"]},{"required":["bytes"]}]}}
        ],"description":"A complete directory observation or an unavailable reason. Includes relative names, directories and regular file contents. No file contents are uploaded. 4 MiB/file, 64 MiB total, 4096 files, 8192 entries, depth 16. Links/reparse points are rejected. Not an atomic snapshot; ACLs, permissions and alternate streams are excluded."});
    document["paths"]["/api/v1/ingest/agent"]["post"]["description"] = json!(
        "Requires sources:write (and configured collector/mTLS binding). extras.skills[] accepts optional package (SkillPackageObservation) only for kind=skill. Manifest content_sha256 remains separate. The first directory observation is informational; compatible digest changes require review. Missing package preserves the last observation without advancing its timestamp; an unavailable observation clears the current digest and retains the last complete one for recovery comparison."
    );
    document["paths"]["/api/v1/assets/{id}"]["get"]["description"] = json!(
        "Requires assets:read. Returns asset, latest 100 changes, governance, content_observation (manifest/file) and package_observation: current, received_at, last_verified, last_verified_at. Receipt timestamps are set by the server. last_verified is historical and does not prove current integrity."
    );
}
