//! Worker quota operations require current platform, binding and cloud revisions.
use serde_json::{Value, json};

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post, Put};
    [
        ("/api/v1/alicloud/agentteams/worker-quotas", Get, "listWorkerQuotas", "Worker 配额绑定与同步状态"),
        ("/api/v1/alicloud/agentteams/worker-quotas/{id}", Put, "bindWorkerQuota", "保存或停用 Worker 配额绑定"),
        (
            "/api/v1/alicloud/agentteams/worker-quotas/{id}/observe",
            Post,
            "observeWorkerQuota",
            "读取 Worker 云限制并生成预览",
        ),
        (
            "/api/v1/alicloud/agentteams/worker-quotas/{id}/sync",
            Post,
            "syncWorkerQuota",
            "按预览同步 Worker 限制并回读验证",
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
    let root = "/api/v1/alicloud/agentteams/worker-quotas";
    let binding = format!("{root}/{{id}}");
    add(document, root, "get", "listWorkerQuotas", &["alicloud:read", "quotas:read"]);
    add(document, &binding, "put", "bindWorkerQuota", &["alicloud:write", "quotas:write"]);
    set_body(
        document,
        &binding,
        "put",
        &["expected_version", "quota_id", "quota_version", "enabled"],
        json!({
            "expected_version":revision(), "quota_id":uuid(), "quota_version":revision(), "enabled":{"type":"boolean"}
        }),
    );
    document["paths"][&binding]["put"]["description"] = json!(
        "将当前盘点的有效 Agent 资产绑定到其专属已启用 tokens/day/deny 正整数配额；仅保存平台绑定，不调用云。停用需要当前绑定版本。"
    );
    for (suffix, operation, permissions) in [
        ("observe", "observeWorkerQuota", ["alicloud:write", "quotas:read"]),
        ("sync", "syncWorkerQuota", ["alicloud:write", "quotas:write"]),
    ] {
        let path = format!("{binding}/{suffix}");
        add(document, &path, "post", operation, &permissions);
        let mut required =
            vec!["request_id", "expected_binding_version", "expected_quota_version", "configuration_version"];
        let mut fields = json!({
            "request_id":uuid(), "expected_binding_version":revision(), "expected_quota_version":revision(),
            "configuration_version":revision(), "confirm_live":{"type":"boolean","default":false}
        });
        if suffix == "sync" {
            required.push("preview_id");
            fields["preview_id"] = uuid();
        }
        set_body(document, &path, "post", &required, fields);
        document["paths"][&path]["post"]["description"] = json!(if suffix == "observe" {
            "显式 GetWorker 只读观察；Live 调用需 confirm_live=true。差异产生关联资产的幂等告警；预览五分钟内有效，不修改云配额。"
        } else {
            "显式确认有效预览后按平台规则 UpdateWorker，并 GetWorker 回读验证。写前再次核对版本与云限制；同请求不重放云写入。失败/超时须重新观察。平台 UTC 日与云周期独立，verified 仅代表限制回读一致。"
        });
    }
}

fn add(document: &mut Value, path: &str, method: &str, operation: &str, permissions: &[&str]) {
    document["paths"][path][method] = json!({
        "operationId":operation,"tags":["alicloud"],"security":[{"bearerAuth":[]},{"apiKey":[]}],
        "x-required-permissions":permissions,"parameters":if path.contains("{id}") {
            json!([{"name":"id","in":"path","required":true,"description":"当前租户盘点的 Agent 资产 UUID","schema":uuid()}])
        }else{json!([])},
        "responses":{
            "200":{"description":"成功返回平台状态；云调用须根据 operation.status 和 Mock 标记核对"},
            "400":{"description":"输入格式无效或存在未知字段"},"401":{"description":"未认证"},
            "403":{"description":"权限或租户不可用"},"409":{"description":"版本/资源已改变、操作忙碌或预览过期；请刷新并重新观察"},
            "412":{"description":"规则不兼容或未确认 Live 操作"},"503":{"description":"依赖不可用；未知云写入不可自动重放"}
        }
    });
}
fn set_body(document: &mut Value, path: &str, method: &str, required: &[&str], properties: Value) {
    document["paths"][path][method]["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
        "type":"object","additionalProperties":false,"required":required,"properties":properties
    }}}});
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid"})
}
fn revision() -> Value {
    json!({"type":"integer","minimum":0})
}
