//! Eight configuration-only operations; acknowledgement, readback and publication stay separate.
use serde_json::{Value, json};

#[path = "apig_configuration_publication_schemas.rs"]
mod schemas;

const ROOT: &str = "/api/v1/alicloud/apig/configuration-publication";
const OBSERVE: &str = "/api/v1/alicloud/apig/configuration-publication/observe";
const PREVIEW: &str = "/api/v1/alicloud/apig/configuration-publication/previews";
const APPLY: &str = "/api/v1/alicloud/apig/configuration-publication/operations";
const RECEIPT: &str = "/api/v1/alicloud/apig/configuration-publication/operations/{id}";
const READBACK: &str = "/api/v1/alicloud/apig/configuration-publication/operations/{id}/observe";
const RECOVER: &str = "/api/v1/alicloud/apig/configuration-publication/operations/{id}/recover";
const ARCHIVE: &str = "/api/v1/alicloud/apig/configuration-publication/operations/archive";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post};
    [
        (ROOT, Get, "getApigConfigurationPublication", "只读APIG配置受管状态"),
        (OBSERVE, Post, "observeApigConfiguration", "显式观察已绑定的配置"),
        (PREVIEW, Post, "previewApigConfiguration", "预览公开配置差异或可信回滚"),
        (APPLY, Post, "applyApigConfiguration", "唯一UUID领取并更新一次配置"),
        (RECEIPT, Get, "getApigConfigurationReceipt", "只读原UUID永久回执"),
        (READBACK, Post, "observeApigConfigurationReceipt", "独立观察原请求目标"),
        (RECOVER, Post, "recoverApigConfigurationReceipt", "只恢复本地结果和审计"),
        (ARCHIVE, Post, "archiveApigConfigurationReceipts", "归档加密正文并保留事实"),
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
    for (path, method, response, input, write) in [
        (ROOT, "get", "ApigConfigurationState", None, false),
        (OBSERVE, "post", "ApigConfigurationObservation", Some("ApigConfigurationObserveInput"), false),
        (PREVIEW, "post", "ApigConfigurationPreview", Some("ApigConfigurationPreviewInput"), true),
        (APPLY, "post", "ApigConfigurationOperation", Some("ApigConfigurationApplyInput"), true),
        (RECEIPT, "get", "ApigConfigurationOperation", None, false),
        (READBACK, "post", "ApigConfigurationObservation", Some("ApigConfigurationOriginalObserveInput"), false),
        (RECOVER, "post", "ApigConfigurationOperation", Some("ApigConfigurationEmptyInput"), true),
        (ARCHIVE, "post", "ApigConfigurationArchiveResult", Some("ApigConfigurationArchiveInput"), true),
    ] {
        let operation = &mut document["paths"][path][method];
        operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        operation["x-required-permissions"] =
            if write { json!(["alicloud:read", "alicloud:write"]) } else { json!(["alicloud:read"]) };
        operation["responses"]["200"] = json!({"description":"安全DTO；配置ACK、独立回读、本地审计发布互不替代",
            "content":{"application/json":{"schema":reference(response)}}});
        for code in ["400", "401", "403", "409", "412", "500", "503", "504"] {
            operation["responses"][code] = json!({"description":"输入、原权限、来源/版本或本地提交失败；不得自动更号重派",
                "content":{"application/problem+json":{"schema":reference("ProblemDetails")}}});
        }
        if let Some(input) = input {
            operation["requestBody"] =
                json!({"required":true,"content":{"application/json":{"schema":reference(input)}}});
            operation["x-max-body-bytes"] = json!(65_536);
        }
        if path.contains("{id}") {
            operation["parameters"] = json!([{"name":"id","in":"path","required":true,"schema":{
                "type":"string","format":"uuid","not":{"const":"00000000-0000-0000-0000-000000000000"}}}]);
            operation["responses"]["404"] = json!({"description":"本租户不存在该永久操作",
                "content":{"application/problem+json":{"schema":reference("ProblemDetails")}}});
        }
    }
    document["paths"][ROOT]["get"]["description"] = json!(
        "纯本地读取；不初始化配置/Mock，不调用STS/云、不调度写入或追加审计。完整证据只加密持久，DTO没有私密配置。云部署和消费者生效均未知。"
    );
    document["paths"][OBSERVE]["post"]["x-conditional-permissions"] = json!([
        {"when":{"initialize_mock_fixture":true},"required":["alicloud:write"]}]);
    document["paths"][OBSERVE]["post"]["description"] = json!(
        "显式GetPluginAttachment或GetHttpApi验证精确来源/资源和完整私密基线；Live必须confirm_live。初始化仅额外写权限的显式Mock POST且固定owned tuple，不是GET副作用。基线300秒；普通观察不授权配置更新。"
    );
    document["paths"][PREVIEW]["post"]["description"] = json!(
        "本地准备：ai-security-guard仅enabled/checkRequest/checkResponse/denyCode，ModelAPI仅已观察service/version/model槽和权重1..100。私密字段保留，拒绝未知字段、URL/原始正文/凭据。回滚把可信历史公开字段投射到新的当前基线，不覆盖外部新私密配置。预览120秒且一次消费；完整来源和本地stateVersion CAS不等于云CAS。"
    );
    document["paths"][APPLY]["post"]["description"] = json!(
        "四项确认必须true；唯一原UUID和预览领取后，原会话/当前来源/基线重新验证，只发一次配置PUT。driver30秒，总110秒含排队/STS，lease120秒不续期。Accepted+Matched+Published才能verified；不是发布部署证明，Model配置仍需云控制台正式发布。无云CAS，外部Get→PUT竞态存在，共享/流式影响须确认。Unknown不会因后续匹配升级，不重派旧请求；换标签/来源不能清除同资源风险，新独立意图须明确新观察、旧Unknown UUID及重叠确认。"
    );
    document["paths"][RECEIPT]["get"]["description"] = json!(
        "纯读原租户/UUID，保留原target和云因果；sourceCurrent与allowedActions是当前资格投影。GET不重试、回读或恢复。未知当前来源如实为null。"
    );
    document["paths"][READBACK]["post"]["description"] = json!(
        "返回新的Observation，独立查询原请求同目标。不是配置写入，也不改原ACK/Unknown；initialize_mock_fixture=true明确412。"
    );
    document["paths"][RECOVER]["post"]["description"] = json!(
        "严格{}；只验证AEAD pending并原子发布原本地结果和唯一审计，过期无可信结果固定Unknown。停用或来源换版仍保留原事实；不解密云凭据、不调用STS/云、不重派配置。"
    );
    document["paths"][ARCHIVE]["post"]["description"] = json!(
        "generation CAS一次1..100个已原子发布终态；删除加密正文，历史回滚内容不可再用，永久UUID/原回执/Unknown风险保留。不能把过期运行冒充终态。"
    );
    schemas::describe(document);
}
