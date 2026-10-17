//! Internal service protocol: independent admission and a unique handler start fence.
mod schemas;
use serde_json::{Value, json};
use utoipa::openapi::path::HttpMethod::{Get, Post};

const ROOT: &str = "/api/v1/alicloud/schedulerx3/native/callback-executions";
const STATUS: &str = "/api/v1/alicloud/schedulerx3/native/callback-executions/{fact_id}";
const REQUEST: &str = "/api/v1/alicloud/schedulerx3/native/callback-executions/requests/{request_id}";
const START: &str = "/api/v1/alicloud/schedulerx3/native/callback-executions/{fact_id}/validate";
const COMPLETE: &str = "/api/v1/alicloud/schedulerx3/native/callback-executions/{fact_id}/complete";

pub(super) fn endpoint_specs() -> Vec<super::super::EndpointSpec> {
    [
        (ROOT, Post, "admitSchedulerCallbackExecution", "永久领取当前原生任务分片与依赖资格"),
        (STATUS, Get, "getSchedulerCallbackExecution", "仅本地读取原领取的安全状态"),
        (REQUEST, Get, "getSchedulerCallbackRequest", "按原请求编号只读查找永久事实"),
        (START, Post, "startSchedulerCallbackExecution", "一次性消费原领取的启动资格"),
        (COMPLETE, Post, "completeSchedulerCallbackExecution", "保存已知结果并原子出版终态审计"),
    ]
    .into_iter()
    .map(|(path, method, id, summary)| super::super::EndpointSpec {
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
    schemas::describe(document);
    for (path, method, body) in [
        (ROOT, "post", Some("SchedulerCallbackAdmissionInput")),
        (STATUS, "get", None),
        (REQUEST, "get", None),
        (START, "post", Some("SchedulerCallbackStartInput")),
        (COMPLETE, "post", Some("SchedulerCallbackCompleteInput")),
    ] {
        let operation = &mut document["paths"][path][method];
        operation["security"] = json!([{"apiKey":[]}]);
        operation["x-required-permissions"] = json!(["alicloud:read"]);
        operation["x-task-permissions"] = json!({
            "asset-inventory":["assets:read"], "log-pull":["sources:read","sources:write"],
            "redteam-cruise":["redteam:read","redteam:execute"],
            "rule-hot-reload":["policies:write"], "report":["reports:write"], "archive":["reports:write"]
        });
        operation["description"] = json!(
            "内部服务协议：本租户非空UUID与当前平台API Key，不接受用户JWT或callback token。每次保留原110秒请求预算并复核当前原Key/授权；GET无写入、云请求或审计。原App/Job/执行ID/分区全局身份永久去重，不能通过换kind/来源/版本/请求UUID重派。仅首次claim的mayConfirmStart允许确认启动，只有首次validate的mayExecute允许调用处理器。任一许可响应丢失、超时、失败或重复均不得从GET状态推断重派资格。已知结果只含有界摘要，是执行器报告，不保证外部效果恰好一次。"
        );
        let mut parameters = vec![json!({
            "name":"X-AGF-Tenant", "in":"header", "required":true,
            "schema":{"type":"string","format":"uuid"},
            "description":"非空UUID，必须与API Key原身份租户相同"
        })];
        if path != ROOT {
            parameters.push(json!({
                "name":if path == REQUEST {"request_id"} else {"fact_id"},
                "in":"path","required":true,"schema":{"type":"string","format":"uuid"}
            }));
        }
        operation["parameters"] = json!(parameters);
        if let Some(schema) = body {
            operation["requestBody"] = json!({"required":true,"content":{"application/json":{
                "schema":{"$ref":format!("#/components/schemas/{schema}")}}}});
        }
        operation["responses"]["200"] = json!({
            "description":"原事实的安全状态；GET和重复请求永不授权新执行",
            "content":{"application/json":{"schema":{"$ref":"#/components/schemas/SchedulerCallbackExecution"}}}
        });
        for code in ["400", "401", "403", "404", "409", "412", "413", "500", "503", "504"] {
            operation["responses"][code] = json!({
                "description":"输入、租户、当前原Key、来源/资格、原预算或审计出版失败；不重派业务处理器",
                "content":{"application/problem+json":{"schema":{"$ref":"#/components/schemas/ProblemDetails"}}}
            });
        }
    }
}
