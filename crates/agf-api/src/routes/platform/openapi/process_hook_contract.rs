//! 进程准入权限和事实边界；观察不宣称阻断，只有受管启动可在创建子进程前拒绝。
use serde_json::{Value, json};
const PATH: &str = "/api/v1/runtime/process/check";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    vec![super::EndpointSpec {
        path: PATH,
        method: utoipa::openapi::path::HttpMethod::Post,
        id: "checkBoundAgentProcess",
        summary: "绑定 Agent 的进程判定与脱敏审计提交",
        tag: "runtime",
        implemented: true,
    }]
}
pub(super) fn describe(document: &mut Value) {
    super::process_hook_schemas::register(&mut document["components"]["schemas"]);
    let operation = &mut document["paths"][PATH]["post"];
    operation["security"] = json!([{"apiKey":[]}]);
    operation["x-required-permissions"] = json!(["policies:read"]);
    operation["x-required-agent-binding"] = json!(true);
    operation["x-deadline-ms"] = json!(3000);
    operation["description"] = json!(
        "仅接受绑定到同租户存活 Agent 的 API Key，不接受 JWT、未绑定 Key 或 body 租户。严格 launch/observe/loss 合同；原 nonce 与完整请求摘要绑定三秒回执。当前权限、Agent 分类和签名策略再次核验，脱敏判定与管理审计提交后才返回；重复 nonce 返回409，超时或未知 ACK 不重新启动。SQL 部署原子持久保存，offline 明确仅内存。原路径/参数/策略原因不进审计。Linux sched_process_exec 与 Windows WMI 是事后观察，enforced=false；WMI 只有 ProcessName/PID，无完整路径、argv、单调时钟或完整丢失计量。只有显式 process-run 的本机启动器执行前可拒绝；Allow/Audit 或明确 dry_run 可启动，其它动作未实现则拒绝，不宣称任意宿主进程均被预阻断。"
    );
    operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
        "$ref":"#/components/schemas/ProcessRequest"}}}});
    operation["responses"]["200"] = json!({"description":"已提交脱敏判定，不证明 OS 已执行或阻断",
        "content":{"application/json":{"schema":{"$ref":"#/components/schemas/ProcessReceipt"}}}});
    for code in ["400", "401", "403", "409", "412", "500", "503", "504"] {
        operation["responses"][code] = json!({"description":"输入、绑定、当前权限/策略、原 nonce、预算或审计提交失败；不得启动",
            "content":{"application/problem+json":{"schema":{"$ref":"#/components/schemas/ProblemDetails"}}}});
    }
}
