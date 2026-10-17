//! Collector error annotations are local operator actions; no business replay is implemented.
use serde_json::{Value, json};
const ROOT: &str = "/api/v1/alicloud/agentteams/task-handling";
const EVENT: &str = "/api/v1/alicloud/agentteams/task-handling/events/{id}";
const RESOLVE: &str = "/api/v1/alicloud/agentteams/task-handling/events/{id}/resolution";
const ARCHIVE: &str = "/api/v1/alicloud/agentteams/task-handling/archive";
const REQUEST: &str = "/api/v1/alicloud/agentteams/task-handling/requests/{id}";
pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post, Put};
    [
        (ROOT, Get, "listAgentTeamsCollectorErrors", "读取 collector 报告的任务错误"),
        (EVENT, Get, "getAgentTeamsCollectorError", "读取原始错误身份及人工处理历史"),
        (RESOLVE, Put, "resolveAgentTeamsCollectorError", "以CAS提交人工处理标注"),
        (ARCHIVE, Post, "archiveAgentTeamsHandling", "显式归档人工处理历史并保存永久回执"),
        (REQUEST, Get, "getAgentTeamsHandlingRequest", "按原UUID纯读取永久人工处理回执"),
    ]
    .into_iter()
    .map(|(path, method, id, summary)| super::EndpointSpec {
        path,
        method,
        id,
        summary,
        tag: "alicloud",
        implemented: true,
    })
    .collect()
}
pub(super) fn describe(document: &mut Value) {
    for (path, method, schema, write) in [
        (ROOT, "get", "AgentTeamsHandlingInbox", false),
        (EVENT, "get", "AgentTeamsHandlingEvent", false),
        (RESOLVE, "put", "AgentTeamsResolutionReceipt", true),
        (ARCHIVE, "post", "AgentTeamsArchiveReceipt", true),
        (REQUEST, "get", "AgentTeamsHandlingReceipt", false),
    ] {
        let operation = &mut document["paths"][path][method];
        operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        operation["x-required-permissions"] =
            if write { json!(["alicloud:write", "sources:write"]) } else { json!(["alicloud:read", "sources:read"]) };
        operation["description"] = json!(
            "仅处理可信原始collector kind=task/status=error证据。collector_reported_error不是云端确认failed；三种decision仅代表操作人标注，不更改原事件、不调用云、不发送遥测、不重放业务。当前启用或停用但仍存在的来源均可按当前权限和来源CAS标注。已删除来源历史仍可读及显式归档；不能新增标注。原UUID同body/操作者/用途返回永久原回执且不写配置或审计，异body或用途409。新归档UUID即使changedCount=0仍写本地receipt并审计Create，generation保持；未知回复先GET原UUID，不自动重派。"
        );
        operation["responses"] = json!({"200":{"description":"直接安全DTO；人工处理不证明云执行成功",
            "content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{schema}")}}}},
            "400":{"description":"字段、类型、UUID、查询或游标无效；固定安全problem响应"},
            "401":{"description":"原认证失效或到期"},"403":{"description":"当前租户或两项权限不可用"},
            "404":{"description":"原证据或原请求不存在于当前租户"},
            "409":{"description":"版本、generation、来源fingerprint、用途或分页快照冲突；保留原状态"},
            "412":{"description":"无当前来源证明，不接受伪造来源版本或任务重放"},
            "500":{"description":"不可信持久身份/AEAD或审计失败；事务回滚"}});
        if path != ROOT && path != ARCHIVE {
            operation["parameters"] = json!([{"name":"id","in":"path","required":true,"schema":uuid()}]);
        }
        if write {
            operation["responses"]["413"] = json!({"description":"请求正文超过64KiB；不回显正文或诊断"});
        }
    }
    let operation = &mut document["paths"][ROOT]["get"];
    operation["description"] = json!(
        "默认最近24小时；from<=until<=now+60秒且窗口最多30天。source_id/scope_id仅筛原证据身份，不借当前binding覆盖历史。total与最新最多2000条证据来自同一SQL语句/内存锁；页1至100。opaque AEAD游标绑定租户/源/scope/窗口/接收水位/页大小/全快照摘要，30分钟过期，篡改400/快照改变409。complete=false，截断明确，不声称云任务错误全集。GET仅读取，不初始化配置、不写审计。处理状态是独立当前投影，不能作为原证据分页快照的一部分。"
    );
    operation["parameters"] = json!([
        {"name":"source_id","in":"query","schema":uuid()},{"name":"scope_id","in":"query","schema":uuid()},
        {"name":"from","in":"query","schema":time()},{"name":"until","in":"query","schema":time()},
        {"name":"limit","in":"query","schema":{"type":"integer","minimum":1,"maximum":100,"default":50}},
        {"name":"cursor","in":"query","schema":{"type":"string","maxLength":4096}}]);
    document["paths"][RESOLVE]["put"]["requestBody"] = body(
        json!({
        "request_id":uuid(),"expected_version":version(),"expected_cloud_configuration_version":positive(),
        "expected_source_fingerprint":fingerprint(),"decision":decision()}),
        &[
            "request_id",
            "expected_version",
            "expected_cloud_configuration_version",
            "expected_source_fingerprint",
            "decision",
        ],
    );
    document["paths"][ARCHIVE]["post"]["requestBody"] = body(
        json!({
        "request_id":uuid(),"expected_generation":version(),"expected_cloud_configuration_version":{"type":["integer","null"],"minimum":1},
        "event_ids":{"type":"array","minItems":1,"maxItems":99,"uniqueItems":true,"items":uuid()},
        "sources":{"type":"array","minItems":1,"maxItems":31,"items":object(json!({
            "source_id":uuid(),"fingerprint":{"type":["string","null"],"maxLength":8192}}),&["source_id","fingerprint"])}}),
        &["request_id", "expected_generation", "expected_cloud_configuration_version", "event_ids", "sources"],
    );
    let schemas = &mut document["components"]["schemas"];
    schemas["AgentTeamsSourceExpectation"] = object(
        json!({"sourceExists":{"type":"boolean"},"sourceGone":{"type":"boolean"},
        "sourceEnabled":{"type":["boolean","null"]},"sourceName":{"type":["string","null"]},
        "cloudConfigurationVersion":{"type":["integer","null"],"minimum":1},"cloudEnabled":{"type":["boolean","null"]},
        "fingerprint":{"type":["string","null"],"maxLength":8192,"description":"tenant域AEAD认证的opaque源配置证明，不能解析或构造"},
        "annotationAllowedWhenDisabled":{"const":true},"businessReplay":{"const":false}}),
        &[
            "sourceExists",
            "sourceGone",
            "sourceEnabled",
            "sourceName",
            "cloudConfigurationVersion",
            "cloudEnabled",
            "fingerprint",
            "annotationAllowedWhenDisabled",
            "businessReplay",
        ],
    );
    schemas["AgentTeamsHandlingRevision"] = object(
        json!({"requestId":uuid(),"version":positive(),"decision":decision(),
        "subjectId":uuid(),"subjectKind":{"type":"string"},"updatedAt":time()}),
        &["requestId", "version", "decision", "subjectId", "subjectKind", "updatedAt"],
    );
    schemas["AgentTeamsHandling"] = object(
        json!({"version":positive(),"decision":decision(),"updatedAt":time(),
        "subjectId":uuid(),"subjectKind":{"type":"string"},"archived":{"type":"boolean"},"archivedAt":{"type":["string","null"],"format":"date-time"},
        "history":{"type":"array","maxItems":20,"items":reference("AgentTeamsHandlingRevision")},"revisionCount":positive()}),
        &[
            "version",
            "decision",
            "updatedAt",
            "subjectId",
            "subjectKind",
            "archived",
            "archivedAt",
            "history",
            "revisionCount",
        ],
    );
    schemas["AgentTeamsHandlingEvent"] = object(
        json!({"id":uuid(),"category":{"const":"collector_reported_error"},"originalStatus":{"const":"error"},
        "externalEventId":{"type":"string"},"sourceId":uuid(),"scopeId":uuid(),"bindingId":uuid(),"eventTime":time(),"receivedAt":time(),
        "messagePreview":{"type":"string","maxLength":8192,"description":"Existing redacted, truncated collector preview; never raw message."},
        "fromTeam":{"type":["string","null"]},"fromWorker":{"type":["string","null"]},
        "taskId":{"type":["string","null"]},"traceId":{"type":["string","null"]},"mocked":{"type":"boolean"},"evidenceIdentityHash":hash(),
        "handling":{"anyOf":[reference("AgentTeamsHandling"),{"type":"null"}]},"currentSource":reference("AgentTeamsSourceExpectation"),
        "allowedActions":{"type":"array","items":{"type":"string","enum":["read","annotate","archive"]}},
        "cloudExecutionConfirmed":{"const":false},"businessReplayImplemented":{"const":false}}),
        &[
            "id",
            "category",
            "originalStatus",
            "externalEventId",
            "sourceId",
            "scopeId",
            "bindingId",
            "eventTime",
            "receivedAt",
            "messagePreview",
            "fromTeam",
            "fromWorker",
            "taskId",
            "traceId",
            "mocked",
            "evidenceIdentityHash",
            "handling",
            "currentSource",
            "allowedActions",
            "cloudExecutionConfirmed",
            "businessReplayImplemented",
        ],
    );
    schemas["AgentTeamsHandlingInbox"] = object(
        json!({"items":{"type":"array","maxItems":100,"items":reference("AgentTeamsHandlingEvent")},
        "total":version(),"nextCursor":{"type":["string","null"]},"truncated":{"type":"boolean"},"windowFrom":time(),"windowTo":time(),
        "asOfReceivedAt":time(),"evidenceLimit":{"const":2000},"consistency":{"const":"statement"},"complete":{"const":false},
        "category":{"const":"collector_reported_error"},"generation":version(),"activeHandledCount":{"type":"integer","minimum":0,"maximum":128},
        "archivedCount":version(),"businessReplayImplemented":{"const":false},"limits":{"type":"object"}}),
        &[
            "items",
            "total",
            "nextCursor",
            "truncated",
            "windowFrom",
            "windowTo",
            "asOfReceivedAt",
            "evidenceLimit",
            "consistency",
            "complete",
            "category",
            "generation",
            "activeHandledCount",
            "archivedCount",
            "businessReplayImplemented",
            "limits",
        ],
    );
    schemas["AgentTeamsResolutionReceipt"] = object(
        json!({"purpose":{"const":"operator-resolution"},"requestId":uuid(),"eventId":uuid(),
        "version":positive(),"decision":decision(),"updatedAt":time(),"evidenceIdentityHash":hash(),"cloudExecutionConfirmed":{"const":false},"businessReplay":{"const":false}}),
        &[
            "purpose",
            "requestId",
            "eventId",
            "version",
            "decision",
            "updatedAt",
            "evidenceIdentityHash",
            "cloudExecutionConfirmed",
            "businessReplay",
        ],
    );
    schemas["AgentTeamsArchiveReceipt"] = object(
        json!({"purpose":{"const":"operator-archive"},"requestId":uuid(),"generation":version(),
        "archivedCount":version(),"eventIds":{"type":"array","minItems":1,"maxItems":99,"items":uuid()},
        "changedCount":{"type":"integer","minimum":0,"maximum":99},"evidenceIdentityHash":hash(),"cloudExecutionConfirmed":{"const":false},"businessReplay":{"const":false}}),
        &[
            "purpose",
            "requestId",
            "generation",
            "archivedCount",
            "eventIds",
            "changedCount",
            "evidenceIdentityHash",
            "cloudExecutionConfirmed",
            "businessReplay",
        ],
    );
    schemas["AgentTeamsHandlingReceipt"] =
        json!({"oneOf":[reference("AgentTeamsResolutionReceipt"),reference("AgentTeamsArchiveReceipt")]});
}
fn body(properties: Value, required: &[&str]) -> Value {
    json!({"required":true,"content":{"application/json":{"schema":object(properties,required)}}})
}
fn object(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}
fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid"})
}
fn time() -> Value {
    json!({"type":"string","format":"date-time"})
}
fn hash() -> Value {
    json!({"type":"string","pattern":"^[0-9a-fA-F]{64}$"})
}
fn version() -> Value {
    json!({"type":"integer","minimum":0})
}
fn positive() -> Value {
    json!({"type":"integer","minimum":1})
}
fn fingerprint() -> Value {
    json!({"type":"string","minLength":1,"maxLength":8192})
}
fn decision() -> Value {
    json!({"type":"string","enum":["acknowledged","external_action_reported","resolved_by_operator"]})
}
