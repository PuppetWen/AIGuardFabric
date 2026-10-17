//! Explicit content CAS and durable receipts never attest external consumer enforcement.
use serde_json::{Value, json};

#[path = "mse_config_publication_schemas.rs"]
mod schemas;
const ROOT: &str = "/api/v1/alicloud/mse/config-publication";
const OBSERVE: &str = "/api/v1/alicloud/mse/config-publication/observe";
const PREVIEW: &str = "/api/v1/alicloud/mse/config-publication/previews";
const APPLY: &str = "/api/v1/alicloud/mse/config-publication/operations";
const RECEIPT: &str = "/api/v1/alicloud/mse/config-publication/operations/{request_id}";
const READBACK: &str = "/api/v1/alicloud/mse/config-publication/operations/{request_id}/observe";
const RECOVER: &str = "/api/v1/alicloud/mse/config-publication/operations/{request_id}/recover";
const ARCHIVE: &str = "/api/v1/alicloud/mse/config-publication/operations/archive";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post};
    [
        (ROOT, Get, "getMseConfigPublication", "读取本地MSE策略发布绑定与台账"),
        (OBSERVE, Post, "observeMseConfig", "显式只读观察当前专用Nacos配置"),
        (PREVIEW, Post, "previewMseConfigPublication", "以可信平台策略或历史原字节生成本地预览"),
        (APPLY, Post, "applyMseConfigPublication", "永久领取唯一请求并执行内容CAS与回读"),
        (RECEIPT, Get, "getMseConfigPublicationReceipt", "只读原请求的本地发布回执"),
        (READBACK, Post, "observeMseConfigPublicationReceipt", "显式只读观察原请求的同一目标"),
        (RECOVER, Post, "recoverMseConfigPublicationReceipt", "仅本地恢复原发布结果及审计"),
        (ARCHIVE, Post, "archiveMseConfigPublicationReceipts", "归档详细正文并保留永久请求事实"),
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

fn body(properties: Value, required: &[&str]) -> Value {
    json!({"required":true,"content":{"application/json":{"schema":{
        "type":"object","additionalProperties":false,"required":required,"properties":properties}}}})
}

fn observe_body() -> Value {
    body(
        json!({"request_id":{"type":"string","format":"uuid"},
        "configuration_version":{"type":"integer","minimum":1},
        "confirm_live":{"type":"boolean","default":false}}),
        &["request_id", "configuration_version"],
    )
}

pub(super) fn describe(document: &mut Value) {
    for (path, method, response, write) in [
        (ROOT, "get", "MseConfigPublicationState", false),
        (OBSERVE, "post", "MseConfigObservation", false),
        (PREVIEW, "post", "MseConfigPreview", true),
        (APPLY, "post", "MseConfigOperation", true),
        (RECEIPT, "get", "MseConfigOperation", false),
        (READBACK, "post", "MseConfigObservation", false),
        (RECOVER, "post", "MseConfigOperation", true),
        (ARCHIVE, "post", "MseConfigArchiveResult", true),
    ] {
        let operation = &mut document["paths"][path][method];
        operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        operation["x-required-permissions"] = if write {
            json!(["alicloud:read", "alicloud:write", "policies:read"])
        } else {
            json!(["alicloud:read", "policies:read"])
        };
        operation["responses"]["200"] = json!({"description":"本次明确操作的结果；consumerApplied始终未知",
            "content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{response}")}}}});
        for code in ["400", "401", "403", "409", "412", "500"] {
            operation["responses"][code] = json!({"description":"输入、原会话、权限、目标、版本或持久提交失败；无隐式重派",
                "content":{"application/problem+json":{"schema":{"$ref":"#/components/schemas/ProblemDetails"}}}});
        }
        if [RECEIPT, READBACK, RECOVER].contains(&path) {
            operation["parameters"] = json!([{"name":"request_id","in":"path","required":true,
                "schema":{"type":"string","format":"uuid"}}]);
            operation["responses"]["404"] = json!({"description":"本租户不存在原请求事实"});
        }
    }
    document["paths"][ROOT]["get"]["description"] = json!(
        "纯本地读取，无初始化、Mock种子、STS、Nacos请求、恢复或审计写入。绑定来自alicloud-mse的cloud-integration加密配置；Console RPC endpoint不替代引擎engine_origin。can*及allowedActions分别反映当前读写权限和原回执操作资格。没有消费者回执，consumerApplied=null。"
    );
    document["paths"][OBSERVE]["post"]["requestBody"] = observe_body();
    document["paths"][OBSERVE]["post"]["description"] = json!(
        "显式查询当前启用且版本匹配的绑定，持久化精确UTF-8内容的MD5/SHA256/字节数，正文加密且不返回。Live需confirm_live；只查询不写云。空内容是有效观察，缺MD5/不支持协议不成为可信基线。观察有效300秒；失败刷新不能继续沿用旧观察。"
    );
    document["paths"][PREVIEW]["post"]["requestBody"] = body(
        json!({
            "request_id":{"type":"string","format":"uuid"},"configuration_version":{"type":"integer","minimum":1},
            "observation_id":{"type":"string","format":"uuid"},"expected_state_version":{"type":"integer","minimum":0},
            "acknowledge_unknown_operation_id":{"type":"string","format":"uuid"},
            "change":{"oneOf":[
                {"type":"object","additionalProperties":false,"required":["action","policies"],"properties":{
                    "action":{"const":"publish"},"policies":{"type":"array","minItems":1,"maxItems":20,
                        "items":{"$ref":"#/components/schemas/MseConfigPolicyRevisionInput"}}}},
                {"type":"object","additionalProperties":false,"required":["action","publication_id"],"properties":{
                    "action":{"const":"rollback"},"publication_id":{"type":"string","format":"uuid"}}}]}
        }),
        &["request_id", "configuration_version", "observation_id", "expected_state_version", "change"],
    );
    document["paths"][PREVIEW]["post"]["description"] = json!(
        "纯本地读取整个可信签名注册表及真实依赖，生成确定性规范HMAC策略包。政策ID唯一且当前正版本匹配；没有手填云正文/URL/凭据通道。回滚取同目标已verified、未归档历史的原字节，保留来源旧版本并以当前版本围栏，不倒退平台政策。预览120秒，消费一次。"
    );
    document["paths"][APPLY]["post"]["requestBody"] = body(
        json!({
            "request_id":{"type":"string","format":"uuid"},"preview_id":{"type":"string","format":"uuid"},
            "expected_state_version":{"type":"integer","minimum":0},
            "confirm_apply":{"type":"boolean","default":false},"confirm_upsert":{"type":"boolean","default":false},
            "confirm_live":{"type":"boolean","default":false},"confirm_unknown_overlap":{"type":"boolean","default":false}
        }),
        &["request_id", "preview_id", "expected_state_version", "confirm_apply", "confirm_upsert"],
    );
    document["paths"][APPLY]["post"]["description"] = json!(
        "唯一新增Nacos POST的入口：原UUID/预览永久领取与claim审计共同提交，再检查原会话、配置、政策和依赖，查询基线，发送一次casMd5内容upsert，再查询回读。本次接受、回读匹配、本地终态和唯一审计均提交后才verified。总110秒，driver30秒，lease120秒不续租。相同UUID/hash仅读原回执；不同输入409，不重试。内容CAS不能防删除后重建、ABA或证明消费者加载。未知旧写须过期后显式恢复本地、发起更晚的新观察、ack旧编号及confirm_unknown_overlap；旧远端请求仍可能迟到。"
    );
    document["paths"][RECEIPT]["get"]["description"] = json!(
        "原租户+请求UUID纯本地读取，不调用云/STS、不初始化/恢复审计。当前绑定变更或停用仍保留原来源。Pending仅展示加密可信结果证据，不称本地已发布；无pending的过期started只投影uncertain，显式recover才提交本地Unknown。"
    );
    document["paths"][READBACK]["post"]["requestBody"] = observe_body();
    document["paths"][READBACK]["post"]["description"] = json!(
        "只读观察原目标：当前绑定须启用、同targetScopeId且configuration_version匹配。不发送Nacos POST，不覆写原来源，当前内容matched不能把原unknown改成accepted/verified。"
    );
    document["paths"][RECOVER]["post"]["requestBody"] = body(json!({}), &[]);
    document["paths"][RECOVER]["post"]["description"] = json!(
        "严格{}，仅本地解密验证原claim的pending，以新鲜原权限提交原终态及唯一审计；没有pending且lease过期的started记录Unknown。无需当前云配置/凭据，不调用STS/Nacos，不重新发送旧请求，不把旧源版本替换为当前版本。"
    );
    document["paths"][ARCHIVE]["post"]["requestBody"] = body(
        json!({
            "expected_generation":{"type":"integer","minimum":0},
            "request_ids":{"type":"array","minItems":1,"maxItems":100,"uniqueItems":true,
                "items":{"type":"string","format":"uuid"}}
        }),
        &["expected_generation", "request_ids"],
    );
    document["paths"][ARCHIVE]["post"]["description"] = json!(
        "本地generation CAS确认1至100唯一终态记录，删除其加密详细正文和该条回滚内容、释放预算；永久轻量事实、原编号占用和未知远端写风险仍保留。当前云内容和最新观察不变。同代次已归档记录no-op不增审计；旧代次409。"
    );
    schemas::describe(document);
}
