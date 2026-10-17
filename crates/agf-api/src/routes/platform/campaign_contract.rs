//! The public campaign contract: asynchronous execution, provenance and saved evidence.
use serde_json::{Value, json};

pub(super) fn describe(document: &mut Value) {
    let root = "/api/v1/redteam/campaigns";
    document["paths"][root]["post"]["description"] = json!(
        "Requires redteam:execute. Returns 202 after durable input commit. Simulator mode never contacts assets. Agent-http mode also requires agents:read, a version-pinned target profile, explicit supported case keys and 1–20 cases; it contacts the registered Agent chat endpoint. Names: 200 UTF-8 bytes, simulator guard_strength: 0–100, expiry: 600 seconds. Unknown fields/categories/keys are rejected. Thresholds apply to successful evaluated cases at that severity or above; completed does not imply CI passed. PostgreSQL mode preserves inputs and results across restarts."
    );
    document["paths"][root]["post"]["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/CampaignBody"},
        "example":{"name":"CI simulation","execution_mode":"simulator","categories":["direct-injection"],"max_cases":200,"guard_strength":30,"ci_gate":true,"severity_threshold":"high"}}}});
    document["paths"][root]["post"]["parameters"] = json!([{"in":"header","name":"Idempotency-Key","required":false,"schema":{"type":"string","minLength":1,"maxLength":200},"description":"Printable ASCII. Scoped to tenant and caller. Same normalized request returns its saved task even if the case library changed; different request returns 409. No automatic rerun of interrupted tasks."}]);
    document["paths"][root]["post"]["responses"]["200"] =
        json!({"description":"Explicitly scheduled partition has no cases; skipped=true, no task created"});
    document["components"]["schemas"]["CampaignBody"]["properties"]["severity_threshold"] =
        json!({"type":"string","enum":["info","low","medium","high","critical"],"default":"high"});
    document["components"]["schemas"]["CampaignBody"]["properties"]["execution_mode"] =
        json!({"type":"string","enum":["simulator","agent-http","mcp-http"],"default":"simulator"});
    document["components"]["schemas"]["CampaignBody"]["properties"]["target_profile_id"] =
        json!({"type":"string","format":"uuid","nullable":true,"description":"Required for agent-http"});
    document["components"]["schemas"]["CampaignBody"]["properties"]["target_profile_version"] =
        json!({"type":"integer","minimum":1,"nullable":true,"description":"Required for agent-http"});
    document["paths"][root]["post"]["responses"]["202"] = json!({"description":"Persisted queued task; poll GET /{id}","content":{"application/json":{"schema":{"type":"object","required":["task_id","campaign"],"properties":{"task_id":{"type":"string","format":"uuid"},"campaign":{"type":"object"}}}}}});
    document["paths"][root]["get"]["description"] = json!(
        "Requires redteam:read. Tenant-scoped history supports page/page_size/q/state/fields and name or created_at sorting. Returns can_execute for the current principal. Unknown success rate/CI results are null. Simulator and unknown historical provenance are excluded from live overview metrics."
    );
    document["paths"][format!("{root}/{{id}}/report")]["get"]["description"] = json!(
        "Requires redteam:read. Report is null until completion. CI is null when disabled or no completed report exists. Read the persisted threshold and execution mode before using ci_passed."
    );
    document["paths"][format!("{root}/{{id}}/evidence")]["get"]["description"] = json!(
        "Requires redteam:read. Returns agf-redteam-evidence-v1 containing immutable case versions, configuration, transcripts, signals and report. Foreign tenant IDs return 404."
    );
    document["paths"][format!("{root}/{{id}}/cancel")]["post"]["description"] = json!(
        "Requires redteam:execute. Cancellation and completion serialize on one row. Terminal results remain unchanged; cancelled runs cannot publish later evidence."
    );
    document["paths"][format!("{root}/{{id}}/retest")]["post"]["description"] = json!(
        "Requires redteam:read and redteam:execute; real Agent retest also requires agents:read. Uses saved case versions without rereading the library. Simulator accepts an optional guard_strength. Agent HTTP requires the current target_profile_version, an enabled profile linked to the same active Agent asset, and sends real requests. Only completed comparable baselines yield improvement comparisons."
    );
    document["paths"][format!("{root}/{{id}}/retest")]["post"]["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"required":["name"],"properties":{"name":{"type":"string","minLength":1},"guard_strength":{"type":"integer","minimum":0,"maximum":100},"target_profile_version":{"type":"integer","minimum":1,"description":"Required for Agent HTTP; forbidden for simulator"}}}}}});
    let targets = "/api/v1/redteam/agent-targets";
    document["paths"][targets]["get"]["description"] = json!(
        "Requires redteam:read and agents:read. Tenant-scoped list of at most 64 Agent targets. Credentials and protected canaries are always redacted."
    );
    document["paths"][targets]["post"]["description"] = json!(
        "Requires redteam:execute, agents:read and agents:write. Links an active Agent asset to a chat-completions compatible URL. Secrets are encrypted and never returned. Supply expected_version=0 to create; updates require the current version. Changing URL or asset requires a new canary and an explicit token decision."
    );
    document["paths"][targets]["post"]["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
        "type":"object","additionalProperties":false,"required":["expected_version","asset_id","name","url","model","enabled"],
        "properties":{"id":{"type":"string","format":"uuid"},"expected_version":{"type":"integer","minimum":0},
            "asset_id":{"type":"string","format":"uuid"},"name":{"type":"string","maxLength":160},
            "url":{"type":"string","format":"uri"},"model":{"type":"string","maxLength":160},
            "enabled":{"type":"boolean"},"bearer_token":{"type":"string","writeOnly":true},
            "protected_canary":{"type":"string","minLength":16,"maxLength":128,"writeOnly":true}}
    }}}});
    document["paths"][format!("{targets}/{{id}}")]["get"]["description"] = json!(
        "Requires redteam:read and agents:read. Returns the redacted target and its revision; foreign-tenant IDs return 404."
    );
    document["paths"][format!("{targets}/{{id}}")]["delete"]["description"] = json!(
        "Requires redteam:execute and agents:write. Pass expected_version to prevent deleting a concurrently edited target."
    );
    document["paths"][format!("{targets}/{{id}}")]["delete"]["requestBody"] = json!({"required":true,
        "content":{"application/json":{"schema":{"type":"object","additionalProperties":false,
            "required":["expected_version"],"properties":{"expected_version":{"type":"integer","minimum":1}}}}}});
    let mcp = "/api/v1/redteam/mcp-targets";
    document["paths"][mcp]["get"]["description"] =
        json!("Requires redteam:read and mcps:read. Lists tenant-scoped MCP profiles without secrets.");
    document["paths"][mcp]["post"]["description"] = json!(
        "Requires redteam:execute, mcps:read and mcps:write. Binds a versioned active MCP Server asset to a 2026-07-28 Streamable HTTP JSON endpoint and one read-only query tool, with an optional distinct read-only detail tool for RT-MCP-003. Secrets are encrypted; changing URL, asset or either tool requires a new canary and explicit token decision."
    );
    document["paths"][mcp]["post"]["requestBody"] = json!({"required":true,
    "content":{"application/json":{"schema":{"type":"object","additionalProperties":false,
        "required":["expected_version","asset_id","name","url","tool_name","argument_name","enabled"],
        "properties":{"id":{"type":"string","format":"uuid"},
            "expected_version":{"type":"integer","minimum":0},"asset_id":{"type":"string","format":"uuid"},
            "name":{"type":"string","maxLength":160},"url":{"type":"string","format":"uri"},
            "tool_name":{"type":"string","maxLength":160},"argument_name":{"type":"string","maxLength":160},
            "detail_tool_name":{"type":["string","null"],"maxLength":160},
            "detail_argument_name":{"type":["string","null"],"maxLength":160},
            "enabled":{"type":"boolean"},"bearer_token":{"type":"string","writeOnly":true},
            "protected_canary":{"type":"string","minLength":16,"maxLength":128,"writeOnly":true}}
    }}}});
    document["paths"][format!("{mcp}/{{id}}")]["get"]["description"] =
        json!("Requires redteam:read and mcps:read. Returns a redacted target and version.");
    document["paths"][format!("{mcp}/{{id}}/usage")]["get"]["description"] = json!(
        "Requires redteam:read and mcps:read. Cumulative direct red-team tool attempts and checked outcomes for this tenant's target profile, separate from the MCP proxy. No arguments, responses or canary values are returned."
    );
    document["paths"][format!("{mcp}/{{id}}")]["delete"]["description"] =
        json!("Requires redteam:execute and mcps:write. Supply expected_version to prevent stale deletes.");
    document["paths"][format!("{mcp}/{{id}}")]["delete"]["requestBody"] =
        document["paths"][format!("{targets}/{{id}}")]["delete"]["requestBody"].clone();
}
