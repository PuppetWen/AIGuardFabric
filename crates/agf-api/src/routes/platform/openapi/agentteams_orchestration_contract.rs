//! Application-owned definitions and a persisted isolated Mock receiver, not vendor DAG APIs.
use serde_json::{Value, json};
const ROOT: &str = "/api/v1/alicloud/agentteams/orchestration-definitions";
const TEAM: &str = "/api/v1/alicloud/agentteams/orchestration-definitions/teams/{team}";
const PREVIEW: &str = "/api/v1/alicloud/agentteams/orchestration-definitions/teams/{team}/preview";
const REQUEST: &str = "/api/v1/alicloud/agentteams/orchestration-definitions/requests/{request}";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post, Put};
    [
        (ROOT, Get, "listApplicationOrchestrations", "纯读本地编排声明与真实Mock库存引用"),
        (TEAM, Get, "getApplicationOrchestration", "纯读已保存的本地和独立Mock接收侧声明"),
        (TEAM, Put, "saveApplicationOrchestrationIntent", "按CAS明确保存声明或同步Mock接收侧"),
        (PREVIEW, Post, "previewApplicationOrchestrationIntent", "只验证应用声明和双向差异，不提交意图"),
        (REQUEST, Get, "getApplicationOrchestrationIntent", "纯读永久原UUID本地提交回执"),
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
fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
pub(super) fn describe(document: &mut Value) {
    super::agentteams_orchestration_schemas::describe(&mut document["components"]["schemas"]);
    for (path, method, response) in [
        (ROOT, "get", "ApplicationOrchestrationState"),
        (TEAM, "get", "ApplicationOrchestrationRecord"),
        (TEAM, "put", "ApplicationOrchestrationIntent"),
        (PREVIEW, "post", "ApplicationOrchestrationPreview"),
        (REQUEST, "get", "ApplicationOrchestrationIntent"),
    ] {
        let operation = &mut document["paths"][path][method];
        let write = method != "get";
        operation["security"] =
            if write { json!([{"bearerAuth":[]}]) } else { json!([{"bearerAuth":[]},{"apiKey":[]}]) };
        operation["x-required-permissions"] =
            if write { json!(["platform:admin", "alicloud:read", "alicloud:write"]) } else { json!(["alicloud:read"]) };
        operation["description"] = json!(
            "应用拥有的明确编排定义，不是厂商DAG拉取、任务执行、角色授权或云注册。当前只有启用且可信的Mock库存支持新预览/提交；真实云模式返回412。相同租户/Team/Worker引用，DAG拒绝循环、未知引用、重复节点和不支持字段；cron只保存声明，不注册timer。GET纯读已保存状态或永久原UUID，不初始化、重派、调用provider或写审计；原回执不依赖当前连接启停/凭据。preview需要当前管理员User及alicloud读写，仅计算差异，不保存意图。PUT需要同权限、原JWT和当前Agent有效，CAS和当前源/库存围栏审计等待后仍检查。confirm_application_owned必需true；sync还需confirm_mock_sync=true，来源变化需显式confirm_source_change。原UUID同actor/Team/完整正文只返回原结果且零新增成功审计，异用途/正文409；unknown或404不能证明未提交，不自动重发新UUID。SQL持久跨实例，离线仅当前进程。local/receiver是平台保存的两个声明，vendorDagAvailable=false、consumerApplied=null、providerCalled=false。归档、业务Replay和真实vendor写操作不在此合同中。"
        );
        let mut parameters = vec![
            json!({"name":"X-AGF-Tenant","in":"header","required":false,"schema":{"type":"string","format":"uuid"},"description":"Explicit current tenant UUID; never a slug, token or cloud account."}),
        ];
        if path == TEAM || path == PREVIEW {
            parameters.push(json!({"name":"team","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":256,"x-max-utf8-bytes":256},"description":"Exact observed Team name, URL encoded; not an invented platform ID."}));
        }
        if path == REQUEST {
            parameters.push(json!({"name":"request","in":"path","required":true,"schema":{"type":"string","format":"uuid"},"description":"Original intent UUID; read never starts it again."}));
        }
        operation["parameters"] = json!(parameters);
        operation["responses"] = json!({"200":{"description":"Direct DTO; committed is local publication only, not consumer or cloud success","content":{"application/json":{"schema":reference(response)}}},
            "400":{"description":"Unknown fields, invalid declaration/UUID or bounded capacity; no intent committed"},
            "401":{"description":"Original identity/JWT expired or invalid"},"403":{"description":"Current grants/tenant/Agent invalid; writes require administrator User"},
            "404":{"description":"This tenant has no saved Team record or original UUID"},"409":{"description":"Reviewed CAS/source/inventory or permanent UUID mismatch; retain draft"},
            "412":{"description":"No enabled trusted Mock inventory/local definition/receiver, or explicit source-change confirmation required"},
            "500":{"description":"Authenticated connection/inventory/registry invalid, or atomic audit/publication failed; never fake success"}});
        if write {
            operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":reference(if method=="put" {"ApplicationOrchestrationCommitInput"} else {"ApplicationOrchestrationPreviewInput"})}}});
            operation["x-max-document-bytes"] = json!(256 * 1024);
        }
        if method == "put" {
            operation["x-max-request-bytes"] = json!(300 * 1024);
            operation["x-atomic-success-audit"] = json!({"action":"update","target":"agentteams-application-orchestration","sql":"same tenant configuration transaction","offline":"same-process guarded synchronous audit","originalAuthorityAfterAuditWait":true});
        }
        if method == "post" {
            operation["x-preview-only"] = json!(true);
        }
    }
}
