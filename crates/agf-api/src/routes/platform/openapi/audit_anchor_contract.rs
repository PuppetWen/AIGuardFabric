//! 签名锚点的公开协议；身份来自有效 API Key，历史无锚定状态须显式返回。
use serde_json::{Value, json};

const ROOT: &str = "/api/v1/runtime/audit/anchors";
pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    vec![super::EndpointSpec {
        path: ROOT,
        method: utoipa::openapi::path::HttpMethod::Post,
        id: "appendAgentAuditAnchor",
        summary: "追加已认证 Agent 审计并取得签名确认",
        tag: "audit",
        implemented: true,
    }]
}

pub(super) fn describe(doc: &mut Value) {
    schemas(&mut doc["components"]["schemas"]);
    let op = &mut doc["paths"][ROOT]["post"];
    op["security"] = json!([{"apiKey":[]}]);
    op["x-required-permissions"] = json!(["policies:read"]);
    op["x-required-subject"] = json!("current-agent-bound-api-key");
    op["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/AgentAuditBatch"}}}});
    op["description"] = json!(
        "仅接收当前有效且绑定真实 Agent 资产的 API Key。租户和 Agent 身份来自认证，不能由请求体指定。链锁等待后在同一 SQL 事务重新核实租户、原 Key、原绑定 Agent、CIDR 与当前权限；记录及 HMAC 检查点原子提交后才推进项目数据目录内的持久见证并确认。首次空批次初始化身份；精确重试返回原检查点。PostgreSQL durable=true；离线 Mock durable=false，Agent 不将其视为持久确认。HMAC 主密钥不下发，Agent 通过已信任 HTTPS 接收及保存确认。"
    );
    op["responses"] = json!({"200":{"description":"已提交的签名确认；Mock 明确非持久化","content":{"application/json":{"schema":{"$ref":"#/components/schemas/AgentAuditAcknowledgement"}}}}});
    for (code, description) in [
        ("400", "JSON、链或字段格式无效"),
        ("401", "未认证或密钥失效"),
        ("403", "无当前权限、绑定身份失效或租户停用"),
        ("404", "绑定 Agent 不存在"),
        ("429", "请求限流"),
        ("500", "签名、连续性、持久见证或原子存储失败"),
    ] {
        op["responses"][code] = json!({"description":description,"content":{"application/problem+json":{"schema":{"$ref":"#/components/schemas/ProblemDetails"}}}});
    }
    let verify = &mut doc["paths"]["/api/v1/audit/verify"]["get"];
    verify["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
    verify["x-required-permissions"] = json!(["audit:read"]);
    verify["description"] = json!(
        "只读验证当前管理审计链及签名锚点，不创建检查点。旧链可以结构完整但未锚定，初次检查点不证明建立前历史；旧无签名行另行计数。数据库外见证仍保存在项目 AGF_DATA_DIR 下，允许可信祖先但 fully_anchored 仅在最近检查点及持久见证覆盖当前完整链时为真。旧 runtime 内存视图不属于本协议的持久覆盖。"
    );
    verify["responses"]["200"] = json!({"description":"兼容既有校验字段，另返回明确锚定状态","content":{"application/json":{"schema":{"$ref":"#/components/schemas/AnchoredAuditVerification"}}}});
}

fn schemas(out: &mut Value) {
    out["AuditChainAnchor"] = json!({"type":"object","required":["id","tenant_id","up_to_sequence","tail_hash","entry_count","created_at","signature"],"properties":{
        "id":{"type":"string","format":"uuid"},"tenant_id":{"type":"string","format":"uuid"},
        "up_to_sequence":{"type":"integer","minimum":0},"entry_count":{"type":"integer","minimum":0},
        "tail_hash":{"type":"string","pattern":"^[a-f0-9]{64}$"},"signature":{"type":"string","pattern":"^[a-f0-9]{64}$"},"created_at":{"type":"string","format":"date-time"}}});
    out["SignedAuditAnchor"] = json!({"type":"object","additionalProperties":false,"required":["kind","chain_id","anchor"],"properties":{
        "kind":{"type":"string","enum":["management","agent-runtime"]},"chain_id":{"type":"string","format":"uuid"},
        "agent_id":{"oneOf":[{"type":"null"},{"type":"string","format":"uuid"}]},
        "previous_anchor_id":{"oneOf":[{"type":"null"},{"type":"string","format":"uuid"}]},
        "previous_anchor_hash":{"oneOf":[{"type":"null"},{"type":"string","pattern":"^[a-f0-9]{64}$"}]},
        "anchor":{"$ref":"#/components/schemas/AuditChainAnchor"}}});
    out["AgentAuditActor"] = json!({"type":"object","required":["kind","name"],"properties":{
        "id":{"type":"string","format":"uuid"},"kind":{"type":"string"},"name":{"type":"string"},
        "source_ip":{"type":"string"},"user_agent":{"type":"string"},"session_id":{"type":"string"}}});
    out["AgentAuditTarget"] = json!({"type":"object","required":["kind"],"properties":{
        "kind":{"type":"string"},"id":{"type":"string"},"name":{"type":"string"}}});
    out["AgentAuditLog"] = json!({"type":"object","required":["id","tenant_id","sequence","action","outcome","actor","target","prev_hash","entry_hash","at"],"properties":{
        "id":{"type":"string","format":"uuid"},"tenant_id":{"type":"string","format":"uuid"},"sequence":{"type":"integer","minimum":1},
        "action":{"type":"string","enum":["login","logout","create","read","update","delete","export","execute","configure","grant","approve","contain","system"]},
        "outcome":{"type":"string","enum":["success","failure","denied"]},
        "actor":{"$ref":"#/components/schemas/AgentAuditActor"},"target":{"$ref":"#/components/schemas/AgentAuditTarget"},
        "before":{},"after":{},"changed_fields":{"type":"array","items":{"type":"string"}},
        "request_id":{"type":"string"},"error":{"type":"string"},"note":{"type":"string"},
        "prev_hash":{"type":"string","pattern":"^[a-f0-9]{64}$"},"entry_hash":{"type":"string","pattern":"^[a-f0-9]{64}$"},"at":{"type":"string","format":"date-time"}},
        "description":"每条完整序列化记录最多 16384 字节。租户及 actor.id/kind 必须与认证所得 Agent 相符；服务端校验原哈希，不重封装掩盖篡改。"});
    out["AgentAuditBatch"] = json!({"type":"object","additionalProperties":false,"required":["chain_id","entries"],"properties":{
        "chain_id":{"type":"string","format":"uuid"},"previous":{"oneOf":[{"type":"null"},{"$ref":"#/components/schemas/SignedAuditAnchor"}]},
        "entries":{"type":"array","maxItems":256,"items":{"$ref":"#/components/schemas/AgentAuditLog"}}}});
    out["AgentAuditAcknowledgement"] = json!({"type":"object","additionalProperties":false,"required":["checkpoint","durable","replayed"],"properties":{
        "checkpoint":{"$ref":"#/components/schemas/SignedAuditAnchor"},"durable":{"type":"boolean"},"replayed":{"type":"boolean"}}});
    out["AuditChainSummary"] = json!({"type":"object","additionalProperties":false,"required":["entries","tail_hash"],"properties":{
        "entries":{"type":"integer","minimum":0},"tail_hash":{"type":"string"},"source":{"type":"string","enum":["postgres","memory"]}}});
    out["AuditAnchoringState"] = json!({"type":"object","additionalProperties":false,"required":["valid","checkpoints_checked","unsigned_legacy_checkpoints","latest","fully_anchored","violations","durable","initial_checkpoint_required","historical_protection"],"properties":{
        "valid":{"type":"boolean"},"checkpoints_checked":{"type":"integer","minimum":0},"unsigned_legacy_checkpoints":{"type":"integer","minimum":0},
        "latest":{"oneOf":[{"type":"null"},{"$ref":"#/components/schemas/SignedAuditAnchor"}]},"fully_anchored":{"type":"boolean"},"violations":{"type":"array","items":{"type":"string"}},
        "durable":{"type":"boolean"},"initial_checkpoint_required":{"type":"boolean"},"historical_protection":{"type":"string"}}});
    out["AnchoredAuditVerification"] = json!({"type":"object","additionalProperties":false,"required":["checked","passed","violations","first_sequence","last_sequence","verified_at","chain","memory_chain","postgres_backed","anchoring","note"],"properties":{
        "checked":{"type":"integer","minimum":0},"passed":{"type":"boolean"},"violations":{"type":"array","items":{"type":"object","required":["entry_id","sequence","kind","detail"],"properties":{
            "entry_id":{"type":"string","format":"uuid"},"sequence":{"type":"integer"},"kind":{"type":"string"},"detail":{"type":"string"}}}},
        "first_sequence":{"oneOf":[{"type":"null"},{"type":"integer"}]},"last_sequence":{"oneOf":[{"type":"null"},{"type":"integer"}]},"verified_at":{"oneOf":[{"type":"null"},{"type":"string","format":"date-time"}]},
        "chain":{"$ref":"#/components/schemas/AuditChainSummary"},"memory_chain":{"oneOf":[{"type":"null"},{"$ref":"#/components/schemas/AuditChainSummary"}]},"postgres_backed":{"type":"boolean"},
        "anchoring":{"$ref":"#/components/schemas/AuditAnchoringState"},"note":{"type":"string"}}});
}
