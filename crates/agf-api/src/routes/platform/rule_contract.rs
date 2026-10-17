//! Version-aware rule editing and per-resource permission capabilities.
use serde_json::{Value, json};

pub(super) fn describe(document: &mut Value) {
    let version = json!({"type":"integer","minimum":0,"maximum":u32::MAX,
        "description":"Loaded current rule version; 0 for creation. A mismatch returns 409. Legacy clients may omit this guard."});
    let schemas = &mut document["components"]["schemas"];
    schemas["RulePublication"] = json!({"type":"object","required":["yaml"],"properties":{
        "yaml":{"type":"string","maxLength":262_144,"description":"Rule YAML, limited to 256 KiB UTF-8; positive/negative samples must pass."},
        "sourceKey":{"type":"string","description":"Stable key of an existing rule. Must equal the YAML key."},
        "expectedVersion":version
    }});
    schemas["RulePatch"] = json!({"type":"object","properties":{
        "enabled":{"type":"boolean"},"rolloutPercent":{"type":"integer","minimum":0,"maximum":100},
        "expectedVersion":version
    }});
    for (path, method, schema) in
        [("/api/v1/rules", "post", "RulePublication"), ("/api/v1/rules/{key}", "patch", "RulePatch")]
    {
        document["paths"][path][method]["requestBody"] = json!({"required":true,"content":{
            "application/json":{"schema":{"$ref":format!("#/components/schemas/{schema}")}}
        }});
    }
    for (path, method) in [
        ("/api/v1/rules", "post"),
        ("/api/v1/rules/{key}", "patch"),
        ("/api/v1/rules/{key}/versions/{version}/restore", "post"),
    ] {
        document["paths"][path][method]["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        document["paths"][path][method]["responses"]["409"] = json!({"description":"The current revision differs from expectedVersion. Reload, compare and retry; no revision was published."});
        document["paths"][path][method]["description"] = json!(
            "Requires rules:write. Positive and negative samples are rerun; a successful write creates a new revision. Histories retain the latest 100 revisions. Send expectedVersion to prevent overwriting a concurrent edit."
        );
    }
    let restore = &mut document["paths"]["/api/v1/rules/{key}/versions/{version}/restore"]["post"];
    if let Some(parameters) = restore["parameters"].as_array_mut() {
        parameters.push(json!({"name":"expectedVersion","in":"query","required":false,"schema":version}));
    } else {
        restore["parameters"] = json!([
            {"name":"key","in":"path","required":true,"schema":{"type":"string"}},
            {"name":"version","in":"path","required":true,"schema":{"type":"integer","minimum":1}},
            {"name":"expectedVersion","in":"query","required":false,"schema":version}
        ]);
    }
    document["paths"]["/api/v1/rules"]["get"]["description"] =
        json!("Requires rules:read. The paginated response includes can_write; each row includes read_only.");
    document["paths"]["/api/v1/rules/{key}"]["get"]["description"] = json!(
        "Requires rules:read. Returns rule, yaml, content_hash, validation, samples_complete and can_write. Use rule.version for expectedVersion."
    );
    document["paths"]["/api/v1/findings"]["get"]["description"] = json!(
        "Requires findings:read. The paginated response includes can_write for finding state changes; write permission is independently enforced."
    );
    document["paths"]["/api/v1/assets/drift"]["post"]["description"] = json!(
        "Requires assets:write. Preserves per-asset first-observation snapshots and compares current content with baseline_date (YYYY-MM-DD, today or earlier). Missing dates compare against an empty baseline. Repeated comparisons never append asset history. Response comparison_mode is first-observation; use /api/v1/assets/inventory for complete immutable daily snapshots."
    );
}
