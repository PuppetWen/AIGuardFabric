//! Native Team writes consume an immutable preview; recovery never replays a cloud write.
use serde_json::{Value, json};

const ROOT: &str = "/api/v1/alicloud/agentteams/team-management";
pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post};
    [
        (ROOT, Get, "listTeamManagement", "读取团队维护状态和持久请求结果"),
        ("/api/v1/alicloud/agentteams/team-management/users/observe", Post, "observeTeamUsers", "只读观察现有云人员"),
        ("/api/v1/alicloud/agentteams/team-management/previews", Post, "previewTeamChange", "生成团队变更预览"),
        ("/api/v1/alicloud/agentteams/team-management/previews/{id}", Get, "getTeamPreview", "读取一次性团队预览"),
        ("/api/v1/alicloud/agentteams/team-management/operations", Post, "applyTeamChange", "确认预览并执行团队变更"),
        (
            "/api/v1/alicloud/agentteams/team-management/operations/{id}",
            Get,
            "getTeamOperation",
            "读取持久团队操作回执",
        ),
        (
            "/api/v1/alicloud/agentteams/team-management/operations/{id}/observe",
            Post,
            "observeTeamOperation",
            "只读核对团队操作结果",
        ),
        (
            "/api/v1/alicloud/agentteams/team-management/operations/{id}/publish",
            Post,
            "publishTeamOperation",
            "重新完整盘点并发布台账",
        ),
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
    for (suffix, method, permissions) in [
        ("", "get", vec!["alicloud:read"]),
        ("/users/observe", "post", vec!["alicloud:read", "alicloud:write"]),
        ("/previews", "post", vec!["alicloud:read", "alicloud:write"]),
        ("/previews/{id}", "get", vec!["alicloud:read"]),
        ("/operations", "post", vec!["alicloud:read", "alicloud:write", "assets:write"]),
        ("/operations/{id}", "get", vec!["alicloud:read"]),
        ("/operations/{id}/observe", "post", vec!["alicloud:read", "alicloud:write"]),
        ("/operations/{id}/publish", "post", vec!["alicloud:read", "alicloud:write", "assets:write"]),
    ] {
        let path = format!("{ROOT}{suffix}");
        let operation = &mut document["paths"][&path][method];
        operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        operation["x-required-permissions"] = json!(permissions);
        if suffix.contains("{id}") {
            operation["parameters"] = json!([{"name":"id","in":"path","required":true,"schema":uuid()}]);
        }
        operation["responses"]["400"] = json!({"description":"输入无效；未知字段与显式 null 被拒绝"});
        operation["responses"]["409"] = json!({"description":"版本、资源、作用域或幂等请求冲突；不自动重发云写"});
        operation["responses"]["412"] =
            json!({"description":"未启用、关系未验证、预览失效或未确定删除；先核对并重新读取"});
    }
    document["paths"][ROOT]["get"]["parameters"] = json!([
        {"name":"request_id","in":"query","required":false,"schema":uuid(),"description":"仅查询当前租户持久操作；不重新发云写"}
    ]);
    let users = format!("{ROOT}/users/observe");
    set_body(
        document,
        &users,
        context(
            &["request_id", "configuration_version"],
            json!({
                "name_like":{"type":"string"},"cursor":{"type":"string","description":"服务端绑定范围、查询和分页链的游标"}
            }),
        ),
    );
    set_description(
        document,
        &users,
        "有效部分页可选择；complete 只说明当前查询链。保留未加载的原成员，过滤空结果不证明人员不存在。Live 须明确 confirm_live。安全响应只有 Name/DisplayName/Status，不含密码、Email、Note。",
        "post",
    );
    let previews = format!("{ROOT}/previews");
    set_body(
        document,
        &previews,
        context(
            &["request_id", "configuration_version", "expected_state_version", "change"],
            json!({
                "expected_state_version":revision(),"user_snapshot_id":uuid(),"change":change()
            }),
        ),
    );
    set_description(
        document,
        &previews,
        "只读校验后保存五分钟一次性预览。现有云人员经 GetUser 逐个核验，管理员资格仍未知。Update 不改团队名或管理员；名单省略为保持，明确 replace 与 [] 才全量替换/清空。厂商没有 CAS，外部控制台并发修改仍有竞争。",
        "post",
    );
    let operations = format!("{ROOT}/operations");
    set_description(
        document,
        &format!("{operations}/{{id}}"),
        "回执 configurationVersion/scopeId 保留原写入来源。仅服务端核对同账号摘要、实例、模式和当前资源版本后，才提供 recoveryConfigurationVersion/recoveryScopeId；恢复必须使用这两个当前字段及 allowedActions。换账号或较新团队操作使旧回执 superseded，只可读取，不可重发。",
        "get",
    );
    set_body(
        document,
        &operations,
        context(
            &["request_id", "preview_id", "configuration_version", "expected_state_version", "confirm_apply"],
            json!({
                "preview_id":uuid(),"expected_state_version":revision(),"confirm_apply":{"type":"boolean","const":true}
            }),
        ),
    );
    set_description(
        document,
        &operations,
        "消费持久预览，最多发送一次云写。分别返回 cloudWrite/readback/inventoryPublish 阶段；accepted 不代表 verified。Delete 为异步操作且没有 ClientToken，结果未知时只允许观察，新的请求编号不能绕过。响应丢失按原 request_id 查询。",
        "post",
    );
    for suffix in ["observe", "publish"] {
        let path = format!("{operations}/{{id}}/{suffix}");
        set_body(document, &path, context(&["request_id", "configuration_version"], json!({})));
        set_description(
            document,
            &path,
            if suffix == "observe" {
                "使用回执的当前 recoveryConfigurationVersion，只读 GetTeam 核对原操作，不重发创建、更新或删除。仅实际 HTTP 404、精确 Resource.NotFound 及有效厂商 RequestId 证明不存在；403、HTML、超时和错误字符串均不证明删除完成。"
            } else {
                "使用回执的当前 recoveryConfigurationVersion，重新完整读取并在同一事务发布资产、快照和阶段状态；不重发原云写。只有目标结果及完整关系一致才能成功，失败保留旧台账。"
            },
            "post",
        );
    }
}

fn change() -> Value {
    let team = json!({"type":"string","minLength":1});
    let names = json!({"type":"array","maxItems":200,"uniqueItems":true,"items":team});
    json!({"oneOf":[
        {"type":"object","additionalProperties":false,"required":["action","team_name","member_names"],
         "properties":{"action":{"const":"create"},"team_name":team,"description":{"type":"string"},
             "member_names":names,"admin_name":team}},
        {"type":"object","additionalProperties":false,"required":["action","team_name"],
         "anyOf":[{"required":["description"]},{"required":["members"]}],
         "properties":{"action":{"const":"update"},"team_name":team,"description":{"type":"string"},
             "members":{"type":"object","additionalProperties":false,"required":["mode","names","confirm_full_replacement"],
                 "properties":{"mode":{"const":"replace"},"names":names,"confirm_full_replacement":{"const":true,"type":"boolean"}}}}},
        {"type":"object","additionalProperties":false,"required":["action","team_name","confirm_team_name","confirm_async_cleanup"],
         "properties":{"action":{"const":"delete"},"team_name":team,"confirm_team_name":team,
             "confirm_async_cleanup":{"type":"boolean","const":true}}}
    ]})
}
fn context(required: &[&str], fields: Value) -> Value {
    let mut properties = json!({"request_id":uuid(),"configuration_version":revision(),
        "confirm_live":{"type":"boolean","default":false}});
    if let (Some(properties), Some(fields)) = (properties.as_object_mut(), fields.as_object()) {
        properties.extend(fields.clone());
    }
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}
fn set_body(document: &mut Value, path: &str, schema: Value) {
    document["paths"][path]["post"]["requestBody"] = json!({
        "required":true,"content":{"application/json":{"schema":schema}}
    });
}
fn set_description(document: &mut Value, path: &str, text: &str, method: &str) {
    document["paths"][path][method]["description"] = json!(text);
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid"})
}
fn revision() -> Value {
    json!({"type":"integer","minimum":0})
}
