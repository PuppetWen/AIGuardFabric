//! Scan execution, permissions and terminal-state semantics for API consumers.
use serde_json::{Value, json};

pub(super) fn describe(document: &mut Value) {
    let root = "/api/v1/scans";
    document["paths"][root]["post"]["description"] = json!(
        "Requires scans:execute; use_llm_judge additionally requires models:write. Assess submitted content without executing commands or contacting targets. \
        1–100 targets; 1 MiB text per target, 4 MiB total, nonempty names up to 200 UTF-8 bytes. \
        Associated asset IDs require assets:read and must exist in this tenant. \
        wait defaults to true; wait=false returns 202 with task_id and poll. \
        Execution expires 120 seconds after creation. SQL atomically commits the summary and findings. \
        Task rows do not store input text; findings may retain evidence. A content score is not an overall asset assessment. \
        Model judgement shares gateway routing, classification, policy and quota controls; associated asset classification cannot be lowered. \
        judgement_count and judgement_failures distinguish completed and degraded judgements. Mock mode uses an explicitly labelled offline rule judge."
    );
    document["paths"][root]["post"]["requestBody"] = json!({"required":true,"content":{"application/json":{
        "schema":{"$ref":"#/components/schemas/ScanBody"},
        "example":{"job_name":"prompt-review","wait":false,"targets":[{"label":"sample","kind":"prompt","text":"hello"}]}}}});
    for status in ["200", "202"] {
        document["paths"][root]["post"]["responses"][status] = json!({"description":"Task created; inspect job.state for success or failure",
            "content":{"application/json":{"schema":{"type":"object","required":["task_id","job"],"properties":{
                "task_id":{"type":"string","format":"uuid"},"job":{"$ref":"#/components/schemas/ScanJob"},
                "poll":{"type":"string"}}}}}});
    }
    document["paths"][root]["get"]["description"] = json!(
        "Requires scans:read. Tenant-scoped task history supports page/page_size/q/state/fields; creation-time sorting. \
        Polling expires interrupted tasks after 120 seconds. Database-backed history survives restart; offline memory does not."
    );
    document["paths"]["/api/v1/scans/{task_id}"]["get"]["description"] = json!(
        "Requires scans:read. Returns job and terminal. Foreign tenant IDs return 404. \
        Failed, cancelled and interrupted jobs contain no newly committed findings."
    );
    document["paths"]["/api/v1/scans/{task_id}/cancel"]["post"]["description"] = json!(
        "Requires scans:execute. Cancellation and completion serialize on the task. \
        Whichever commits first wins; terminal tasks are returned unchanged. Cancellation prevents result publication, \
        but does not undo already completed tasks or retract their findings."
    );
    document["components"]["schemas"]["ScanJob"] = json!({"type":"object","properties":{
        "id":{"type":"string","format":"uuid"},"tenant_id":{"type":"string","format":"uuid"},"name":{"type":"string"},
        "state":{"enum":["queued","running","succeeded","failed","cancelled"]},"progress":{"type":"integer"},
        "targets":{"type":"integer"},"finding_count":{"type":"integer"},"finding_ids":{"type":"array","items":{"type":"string","format":"uuid"}},
        "risk_score":{"type":["integer","null"],"minimum":0,"maximum":100},"llm_mocked":{"type":["boolean","null"]},
        "use_llm_judge":{"type":"boolean"},"judgement_count":{"type":"integer","minimum":0},
        "judgement_failures":{"type":"integer","minimum":0},
        "error":{"type":["string","null"]},"summary":{"type":"string"},"created_at":{"type":"string","format":"date-time"},
        "finished_at":{"type":["string","null"],"format":"date-time"}}});
}
