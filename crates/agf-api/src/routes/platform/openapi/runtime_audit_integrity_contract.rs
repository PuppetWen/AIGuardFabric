//! 单条持久事实读取证明；不扩大旧 events 数组或管理审计的签名验证合同。
use serde_json::{Value, json};
const PATH: &str = "/api/v1/runtime/events/{id}/integrity";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    vec![super::EndpointSpec {
        path: PATH,
        method: utoipa::openapi::path::HttpMethod::Get,
        id: "verifyRuntimeRecordSummary",
        summary: "核对单条运行时记录与已提交管理审计摘要",
        tag: "runtime",
        implemented: true,
    }]
}

pub(super) fn describe(document: &mut Value) {
    let operation = &mut document["paths"][PATH]["get"];
    operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
    operation["x-required-permissions"] = json!(["policies:read"]);
    operation["parameters"] = json!([{"name":"id","in":"path","required":true,
        "schema":{"type":"string","format":"uuid"}}]);
    operation["description"] = json!(
        "仅读取当前认证租户内一条已保存事实及派生的精确管理审计编号，在同一配置锁内比较完整记录规范化 SHA、内部保存证明和管理审计摘要。missing-record、missing-proof、mismatch 均 summary_matches=false，不能降级为可信旧记录。matched-management-fact 仅表示摘要匹配，checkpoint_verified 始终 false；需另以 audit:read 调用 /api/v1/audit/verify 检查签名检查点与外部见证并核对 audit_sequence。原 /runtime/events 裸数组保留，包含诊断环形视图，不能据此声称每一行持久或已签名。此证明不表示上游实际执行成功。"
    );
    operation["responses"]["200"] = json!({"description":"有界只读摘要核对；不会追加审计或建立检查点",
        "content":{"application/json":{"schema":{"$ref":"#/components/schemas/RecordIntegrity"}}}});
    for code in ["400", "401", "403", "500"] {
        operation["responses"][code] = json!({"description":"参数、权限或读取失败",
            "content":{"application/problem+json":{"schema":{"$ref":"#/components/schemas/ProblemDetails"}}}});
    }
}
