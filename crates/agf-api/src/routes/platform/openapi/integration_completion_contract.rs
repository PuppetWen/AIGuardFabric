//! Receipt recovery publishes local state only; it never repeats an external operation.
use serde_json::{Value, json};

const CLOUD: &str = "/api/v1/alicloud/connections/{name}/operations/{id}";
const VENDOR: &str = "/api/v1/integrations/adapters/{name}/operations/{id}";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post};
    [
        (
            "/api/v1/alicloud/connections/{name}/operations/{id}/recover",
            Post,
            "recoverCloudReceipt",
            "仅恢复本地回执与审计发布",
            "alicloud",
        ),
        (VENDOR, Get, "getIntegrationReceipt", "只读获取厂商集成持久回执", "integrations"),
        (
            "/api/v1/integrations/adapters/{name}/operations/{id}/recover",
            Post,
            "recoverIntegrationReceipt",
            "仅恢复厂商回执本地发布",
            "integrations",
        ),
    ]
    .into_iter()
    .map(|(path, method, id, summary, tag)| super::EndpointSpec { path, method, id, summary, tag, implemented: true })
    .collect()
}

pub(super) fn describe(document: &mut Value) {
    for (root, permission) in [(CLOUD, "alicloud:write"), (VENDOR, "integrations:write")] {
        describe_operation(document, root, "get", permission, false);
        describe_operation(document, &format!("{root}/recover"), "post", permission, true);
    }
    document["components"]["schemas"]["IntegrationReceipt"] = json!({
        "type":"object", "required":["id","request_id","adapter","operation","status","completion_state","mocked"],
        "properties":{
            "id":{"type":"string","format":"uuid"},"request_id":{"type":"string","format":"uuid"},
            "adapter":{"type":"string"},"operation":{"type":"string"},
            "configuration_version":{"type":"integer","minimum":0},"actor":{"type":"string"},
            "started_at":{"type":"string","format":"date-time"},
            "finished_at":{"type":["string","null"],"format":"date-time"},
            "mocked":{"type":"boolean"},
            "status":{"type":"string","enum":["started","succeeded","failed","uncertain"]},
            "completion_state":{"type":"string","enum":["running","pending_audit","complete"]},
            "provider_status":{"type":"string","enum":["succeeded","failed","uncertain"],
                "description":"仅待审计回执提供已知执行分类；不代表本地发布已成功，也不证明云业务最终状态"},
            "receipt":{"type":"object","description":"按当前租户解密且脱敏的回执；审计仅记录安全元数据"}
        }
    });
}

fn describe_operation(document: &mut Value, path: &str, method: &str, permission: &str, recover: bool) {
    let operation = &mut document["paths"][path][method];
    operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
    operation["x-required-permissions"] = json!([permission]);
    operation["parameters"] = json!([
        {"name":"name","in":"path","required":true,"schema":{"type":"string"}},
        {"name":"id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}
    ]);
    operation["description"] = json!(if recover {
        "空请求体。仅发布该租户、该适配器已经加密暂存的回执和审计；不调用远端、STS 或重新发送原操作，不要求原配置仍启用或保持旧版本。已完成请求零新增审计；缺少已知待发布回执返回 412，需人工核对远端状态。"
    } else {
        "严格只读，不完成发布或追加审计。pending_audit 时 status=uncertain，provider_status 保留已知执行分类；请显式调用 recover 完成本地审计发布。running 且没有待发布回执不能安全重新发送。"
    });
    operation["responses"] = json!({
        "200":{"description":"返回持久回执；按 status/completion_state/mocked 分别核对",
            "content":{"application/json":{"schema":{"$ref":"#/components/schemas/IntegrationReceipt"}}}},
        "401":{"description":"未认证"},"403":{"description":"当前租户或权限不可用"},
        "404":{"description":"该租户、该适配器下不存在此回执"},
        "409":{"description":"请求编号或待发布记录与原领取身份不一致"},
        "412":{"description":"没有已知可恢复的回执；不能重新发送远端操作"},
        "503":{"description":"本地存储或审计提交失败；保留原领取和已暂存回执，仅重试本地恢复"}
    });
}
