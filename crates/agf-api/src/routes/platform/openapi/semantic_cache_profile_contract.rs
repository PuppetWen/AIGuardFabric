//! Default-disabled server configuration and inert semantic plans; no main-chat activation is implied.
use serde_json::{Value, json};
const ROOT: &str = "/api/v1/models/semantic-cache/profile";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Put};
    [
        (Get, "getSemanticCacheProfile", "纯读取默认关闭的服务器语义缓存配置"),
        (Put, "saveSemanticCacheProfile", "按CAS保存语义配置意图，不调用embedding"),
    ]
    .into_iter()
    .map(|(method, id, summary)| super::EndpointSpec {
        path: ROOT,
        method,
        id,
        summary,
        tag: "models",
        implemented: true,
    })
    .collect()
}
fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
fn object(properties: Value) -> Value {
    let required = properties.as_object().map(|fields| fields.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}
fn uint(minimum: u64, maximum: u64) -> Value {
    json!({"type":"integer","minimum":minimum,"maximum":maximum})
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid","description":"Existing same-tenant, non-nil endpoint identity."})
}
fn label() -> Value {
    json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.:/-]+$"})
}

pub(super) fn describe(document: &mut Value) {
    schemas(&mut document["components"]["schemas"]);
    for (method, permission) in [("get", "models:read"), ("put", "models:write")] {
        let operation = &mut document["paths"][ROOT][method];
        operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        operation["x-required-permissions"] = json!([permission]);
        operation["description"] = json!(
            "服务器配置默认为关闭。仅引用既有租户端点与密文凭据，不接受客户端URL、secret、domain、权限或placement证明。GET不初始化、不联网、不写审计。模型revision为操作人固定标签，厂商权重版本未知。placementVerified始终false：保存mock_vector只代表意图，不能证明后来端点仍是Mock；内部planner必须重读实际两端点。Public外发资格只能来自实际Agent和可信服务器floor，客户端分类只能提高；未知或Internal且无可信placement不做live embedding。默认不开主chat语义路径；配置和inert计划本身不代表付费embedding、semantic hit、配额或账本已经完成。真实cache hit仍须当前输出筛查，任何paid embedding须reserve后单POST并与Usage、双ledger和审计同事务结算。"
        );
        operation["responses"] = json!({"200":{"description":"直接安全配置DTO，不含凭据或raw源fingerprint",
            "content":{"application/json":{"schema":reference("SemanticCacheProfileView")}}},
            "400":{"description":"未知字段、类型、无效配置或超过16KiB；共享JSON提取的固定problem响应"},
            "401":{"description":"原认证失效、到期"},"403":{"description":"当前models权限或租户不可用"},
            "409":{"description":"配置CAS已改变；保留draft和原expected_version，不自动rebase或重试"},
            "412":{"description":"引用端点缺失、停用或版本/模型身份变化"},
            "500":{"description":"真实存储/身份/AEAD或原子审计失败；不可伪装为配置旁路"}});
        if method == "put" {
            operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":reference("SemanticCacheProfileInput")}}});
            operation["x-max-request-bytes"] = json!(16 * 1024);
            operation["x-atomic-success-audit"] = json!({"action":"configure","target":"semantic-cache-profile",
                "sql":"same configuration transaction","offline":"guarded same-process synchronous audit sink",
                "originalAuthorityAfterAuditWait":true});
        }
    }
}
fn schemas(schemas: &mut Value) {
    let settings = object(json!({"chat_endpoint_id":uuid(),"chat_model":label(),"chat_model_revision":label(),
        "embedding_endpoint_id":uuid(),"embedding_model":label(),"embedding_model_revision":label(),
        "dimensions":uint(1,4096),"send_dimensions":{"type":"boolean"},
        "max_input_tokens":uint(1,8192),"embedding_micro_per_1k":uint(0,u64::MAX / 1000),
        "threshold_ppm":uint(900_000,1_000_000),"ttl_seconds":uint(1,900),
        "classification_floor":{"type":"string","enum":["public","internal"]},
        "mode":{"type":"string","enum":["live","mock_vector"]}}));
    let mut live = settings.clone();
    live["properties"]["mode"] = json!({"enum":["live"]});
    live["properties"]["embedding_micro_per_1k"] = uint(1, u64::MAX / 1000);
    let mut mock = settings;
    mock["properties"]["mode"] = json!({"enum":["mock_vector"]});
    mock["properties"]["embedding_micro_per_1k"] = json!({"enum":[0]});
    schemas["SemanticCacheProfileSettings"] = json!({"anyOf":[live,mock]});
    schemas["SemanticCacheProfileSettings"]["description"] = json!(
        "All settings are explicit. Encoded settings <=8KiB. Live price is positive microcurrency/1000 input tokens; mock_vector price exactly 0 and both current endpoints must be actual Mock. Send dimensions only if this model supports it. Pinned revision labels do not verify vendor weights. Threshold ppm is manual and never auto-enables semantic caching; TTL is seconds. Classification serializes lowercase."
    );
    let nullable_settings = json!({"anyOf":[reference("SemanticCacheProfileSettings"),{"type":"null"}]});
    let mut disabled = json!({"type":"object","additionalProperties":false,
        "required":["expected_version","enabled"],"properties":{"expected_version":uint(0,u64::MAX),
        "enabled":{"enum":[false]},"settings":nullable_settings}});
    let mut enabled = disabled.clone();
    enabled["properties"]["enabled"] = json!({"enum":[true]});
    enabled["properties"]["settings"] = reference("SemanticCacheProfileSettings");
    enabled["required"] = json!(["expected_version", "enabled", "settings"]);
    disabled["description"] = json!(
        "Create expected_version=0; otherwise exact current CAS. Missing/null settings is legal when disabled. Explicit save only; unknown fields rejected, no automatic retry."
    );
    schemas["SemanticCacheProfileInput"] = json!({"anyOf":[disabled,enabled]});
    let disabled_view = object(json!({"version":uint(0,u64::MAX),"enabled":{"enum":[false]},
        "settings":nullable_settings,"placementVerified":{"enum":[false]},
        "providerWeightsRevisionVerified":{"enum":[false]}}));
    let mut enabled_view = disabled_view.clone();
    enabled_view["properties"]["enabled"] = json!({"enum":[true]});
    enabled_view["properties"]["version"] = uint(1, u64::MAX);
    enabled_view["properties"]["settings"] = reference("SemanticCacheProfileSettings");
    schemas["SemanticCacheProfileView"] = json!({"anyOf":[disabled_view,enabled_view]});
}
