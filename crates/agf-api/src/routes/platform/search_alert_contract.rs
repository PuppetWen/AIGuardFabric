//! Search and escalation request contracts used by UI and external clients.
use serde_json::{Value, json};

pub(super) fn describe(document: &mut Value) {
    document["paths"]["/api/v1/notifications/inbox"]["get"]["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
    document["paths"]["/api/v1/notifications/inbox/read"]["post"]["security"] = json!([{"bearerAuth":[]}]);
    document["paths"]["/api/v1/notifications/inbox"]["get"]["description"] = json!(
        "Latest 100 notifications, filtered by the associated resource's read permission before limiting. Unknown/test subjects require settings:read. Returns original message fields plus id, read and can_mark; read markers are personal and tenant-scoped."
    );
    document["paths"]["/api/v1/notifications/inbox/read"]["post"]["description"] = json!(
        "Personal accounts only. Every ID must occur in the caller's latest 100 accessible messages. Does not acknowledge or resolve the underlying alert. Repeat IDs are idempotent."
    );
    document["paths"]["/api/v1/notifications/inbox/read"]["post"]["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
        "type":"object","additionalProperties":false,"required":["ids"],"properties":{"ids":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"string","format":"uuid"}}}
    }}}});
    let schemas = &mut document["components"]["schemas"];
    schemas["EscalationTier"] = json!({"type":"object","additionalProperties":false,
    "required":["level","overdueMinutes","target","channels"],"properties":{
        "level":{"type":"integer","minimum":1,"maximum":3},
        "overdueMinutes":{"type":"integer","minimum":0,"maximum":43200},
        "target":{"type":"string","enum":["on-call","team-lead","security-owner","incident-commander"],
            "description":"Display/audit label; recipients come from notification-channel settings, not this role label"},
        "channels":{"type":"array","maxItems":9,"uniqueItems":true,"items":{"type":"string",
            "enum":["in-app","dingtalk","feishu","wecom","email","sms","webhook","pagerduty","slack"]}}
    }});
    schemas["EscalationRoute"] = json!({"type":"object","additionalProperties":false,
    "required":["severity","responseMinutes","enabled","tiers"],"properties":{
        "severity":{"type":"string","enum":["critical","high","medium","low","info"]},
        "responseMinutes":{"type":"integer","minimum":1,"maximum":43200},
        "enabled":{"type":"boolean"},"tiers":{"type":"array","maxItems":3,"items":{"$ref":"#/components/schemas/EscalationTier"}}
    }});
    schemas["EscalationChange"] = json!({"type":"object","additionalProperties":false,
    "required":["expectedVersion","routes","reason"],"properties":{
        "expectedVersion":{"type":"integer","minimum":0},
        "routes":{"type":"array","minItems":5,"maxItems":5,"description":"Exactly one route per severity; enabled routes need 1..3 strictly increasing tiers and configured channels",
            "items":{"$ref":"#/components/schemas/EscalationRoute"}},
        "reason":{"type":"string","minLength":1,"description":"Nonblank change reason, at most 2000 UTF-8 bytes"},
        "includeExisting":{"type":"boolean","default":false,"description":"Only changes activation scope for routes transitioning from disabled to enabled"}
    }});
    schemas["SearchHit"] = json!({"type":"object","required":["id","kind","label","hint","to"],"properties":{
        "id":{"type":"string"},"kind":{"type":"string","enum":["asset","finding","alert","case","rule","redteam"]},
        "label":{"type":"string"},"hint":{"type":"string"},"to":{"type":"string"}
    }});
    document["components"]["securitySchemes"]["apiKey"] = json!({"type":"apiKey","in":"header","name":"x-agf-key"});
    let search = &mut document["paths"]["/api/v1/search"]["get"];
    search["description"] = json!(
        "Tenant-scoped literal substring search. Independently requires the relevant resource read permission. Exact IDs/names first, remaining resource groups interleaved. Includes disabled rules. Detail links preserve object identity and never execute red-team cases."
    );
    search["parameters"] = json!([
        {"name":"q","in":"query","schema":{"type":"string","maxLength":128},"description":"Control characters rejected; empty query returns an empty array"},
        {"name":"limit","in":"query","schema":{"type":"integer","minimum":1,"maximum":50,"default":8}}
    ]);
    search["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
    search["responses"]["200"] = json!({"description":"Accessible matches","content":{"application/json":{"schema":{"type":"array","items":{"$ref":"#/components/schemas/SearchHit"}}}}});
    for path in ["/api/v1/alerts/escalation-config", "/api/v1/alerts/escalation-history"] {
        document["paths"][path]["get"]["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        document["paths"][path]["get"]["description"] = json!(
            "Requires alerts:read. Configuration includes canWrite, automaticAvailable, mockMode and last worker health. History records enqueued tiers with current delivery status; enqueued is not delivered."
        );
    }
    let save = &mut document["paths"]["/api/v1/alerts/escalation-config"]["put"];
    save["description"] = json!(
        "Requires a personal user with alerts:read/write. PostgreSQL is required to enable automatic execution. Atomically checks expectedVersion and stores a revision with actor/reason. Current publisher permissions are rechecked by the worker. Each alert/tier is automatically queued once, including after policy edits."
    );
    save["security"] = json!([{"bearerAuth":[]}]);
    save["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/EscalationChange"}}}});
    for (code, description) in [
        ("400", "Invalid policy"),
        ("403", "Personal account with alert read/write permissions required"),
        ("409", "Stale expectedVersion; retain draft and review latest version"),
        ("412", "Database or configured/enabled/severity-compatible channels required"),
    ] {
        save["responses"][code] = json!({"description":description});
    }
    document["paths"]["/api/v1/alerts/escalation-history"]["get"]["parameters"] = json!([
        {"name":"page","in":"query","schema":{"type":"integer","minimum":1,"default":1}},
        {"name":"page_size","in":"query","schema":{"type":"integer","minimum":1,"maximum":200,"default":20}}
    ]);
    document["paths"]["/api/v1/redteam/cases/{key}"]["get"]["parameters"] = json!([
        {"name":"key","in":"path","required":true,"schema":{"type":"string"}}
    ]);
    document["paths"]["/api/v1/redteam/cases/{key}"]["get"]["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
    document["paths"]["/api/v1/alerts"]["get"]["parameters"] = json!([
        {"name":"page","in":"query","schema":{"type":"integer","minimum":1,"default":1}},
        {"name":"page_size","in":"query","schema":{"type":"integer","minimum":1,"maximum":200,"default":20}},
        {"name":"state","in":"query","schema":{"type":"string"},"description":"Comma-separated open, acknowledged, escalated, suppressed, closed"},
        {"name":"severity","in":"query","schema":{"type":"string"},"description":"Comma-separated info, low, medium, high, critical"},
        {"name":"domain","in":"query","schema":{"type":"string"},"description":"Comma-separated risk domains"},
        {"name":"q","in":"query","schema":{"type":"string"},"description":"Literal ID, title, description or dedup key search"},
        {"name":"sort","in":"query","schema":{"type":"string"},"description":"severity, dedup_count, sla_due_at, title, first_seen_at, last_seen_at, created_at, updated_at; prefix - for descending"}
    ]);
}
