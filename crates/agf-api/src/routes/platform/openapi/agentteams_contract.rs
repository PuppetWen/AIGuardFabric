//! Collector body and permissions used by the first-party onboarding guide.
use serde_json::{Value, json};

pub(super) fn describe(document: &mut Value) {
    let root = "/api/v1/alicloud/agentteams";
    let binding = format!("{root}/audit-sources/{{id}}");
    document["paths"][&binding]["put"]["x-required-permissions"] = json!(["alicloud:write", "sources:write"]);
    document["paths"][&binding]["put"]["requestBody"] = body(json!({
        "type":"object","additionalProperties":false,"required":["expected_version","enabled"],
        "properties":{"expected_version":{"type":"integer","minimum":0},"enabled":{"type":"boolean"}}
    }));
    let endpoint = format!("{root}/audit-sources/{{id}}/events");
    let operation = &mut document["paths"][&endpoint]["post"];
    operation["x-required-permissions"] = json!(["sources:write"]);
    operation["description"] = json!(
        "认证采集器上报；租户由认证主体决定，成员与资产由绑定盘点映射。整批验证后同事务保存审计、原始证据、事件和投递队列。相同scope/event_id且内容相同幂等，冲突整批409。认证采集器不提供云端Worker身份背书或策略授权证明。"
    );
    let mut fields = json!({
        "event_id":{"type":"string","minLength":1,"maxLength":256,"pattern":"^[A-Za-z0-9_.:-]+$"},
        "event_time":{"type":"string","format":"date-time","description":"毫秒归一，不早于当前绑定；最多晚到30天或超前5分钟"},
        "kind":{"type":"string","enum":["call","message","task","heartbeat"]},
        "status":{"type":"string","enum":["success","error","unknown"],"default":"unknown"},
        "duration_ms":{"type":["integer","null"],"minimum":0,"maximum":604_800_000},
        "message":{"type":["string","null"],"description":"UTF-8长度最多16384字节；读取预览为脱敏后前512字符"}
    });
    for field in
        ["from_team", "from_worker", "to_team", "to_worker", "task_id", "trace_id", "span_id", "parent_span_id"]
    {
        fields[field] = json!({"type":["string","null"],"maxLength":if field.ends_with("team") || field.ends_with("worker") {512}else{128}});
    }
    operation["requestBody"] = body(
        json!({"type":"object","additionalProperties":false,"required":["binding_id","events"],
        "properties":{"binding_id":{"type":"string","format":"uuid"},"events":{"type":"array","minItems":1,"maxItems":1000,
            "items":{"type":"object","additionalProperties":false,"required":["event_id","event_time","kind"],"properties":fields}}}}),
    );
    operation["responses"]["409"] = json!({"description":"绑定/配置已改变，或同事件编号内容冲突；整批未入库"});
    operation["responses"]["400"] = json!({"description":"事件格式、时间、大小或盘点成员无效；整批未入库"});
    for path in [format!("{root}/audit-sources"), format!("{root}/audit-events")] {
        document["paths"][&path]["get"]["x-required-permissions"] = json!(["alicloud:read", "sources:read"]);
    }
    document["paths"][format!("{root}/audit-events")]["get"]["parameters"] = json!([
        {"name":"limit","in":"query","schema":{"type":"integer","minimum":1,"maximum":199,"default":50}},
        {"name":"cursor","in":"query","schema":{"type":"string","maxLength":2048},"description":"服务器游标；锁定同一24小时窗口，30分钟过期，刷新会清除"}
    ]);
}
fn body(schema: Value) -> Value {
    json!({"required":true,"content":{"application/json":{"schema":schema}}})
}
