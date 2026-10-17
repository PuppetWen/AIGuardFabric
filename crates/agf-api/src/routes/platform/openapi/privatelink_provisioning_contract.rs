//! Explicit consumer creation and independent provider acceptance; no network guarantee.
use serde_json::{Value, json};
#[path = "privatelink_provisioning_schemas.rs"]
mod schemas;
const ROOT: &str = "/api/v1/alicloud/privatelink/provisioning";
pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post};
    [
        (ROOT, Get, "getPrivateLinkProvisioning"),
        ("/api/v1/alicloud/privatelink/provisioning/requests/{id}", Get, "getPrivateLinkProvisioningRequest"),
        ("/api/v1/alicloud/privatelink/provisioning/preview", Post, "previewPrivateLinkProvisioning"),
        ("/api/v1/alicloud/privatelink/provisioning/apply", Post, "applyPrivateLinkProvisioning"),
        ("/api/v1/alicloud/privatelink/provisioning/observe", Post, "observePrivateLinkProvisioning"),
        (
            "/api/v1/alicloud/privatelink/provisioning/requests/{id}/recover-local",
            Post,
            "recoverPrivateLinkProvisioningLocal",
        ),
        ("/api/v1/alicloud/privatelink/provisioning/archive", Post, "archivePrivateLinkProvisioning"),
    ]
    .into_iter()
    .map(|(path, method, id)| super::EndpointSpec {
        path,
        method,
        id,
        summary: "受管PrivateLink原请求与独立资源观察",
        tag: "alicloud",
        implemented: true,
    })
    .collect()
}
fn body(schema: Value) -> Value {
    json!({"required":true,"content":{"application/json":{"schema":schema}}})
}
fn fields(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid","not":{"const":"00000000-0000-0000-0000-000000000000"}})
}
fn number() -> Value {
    json!({"type":"integer","minimum":0})
}
pub(super) fn describe(doc: &mut Value) {
    for spec in endpoint_specs() {
        let method = if spec.path == ROOT || spec.id == "getPrivateLinkProvisioningRequest" { "get" } else { "post" };
        let operation = &mut doc["paths"][spec.path][method];
        operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        operation["x-required-permissions"] =
            if method == "get" { json!(["alicloud:read"]) } else { json!(["alicloud:read", "alicloud:write"]) };
        operation["responses"]["200"] = json!({"description":"本地原事实；厂商ACK、完整观察、审计完成分别展示，不表示RAM归属或DNS/TCP/TLS/业务可达","content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{}",if spec.path==ROOT{"PrivateLinkProvisioningState"}else{"PrivateLinkProvisioningReceipt"})}}}});
        for code in ["400", "401", "403", "404", "409", "412", "500", "503", "504"] {
            operation["responses"][code] = json!({"description":"保留原UUID；无自动云重派或隐式新意图"});
        }
        if spec.path.contains("{id}") {
            operation["parameters"] = json!([{"name":"id","in":"path","required":true,"schema":uuid()}]);
        }
    }
    doc["paths"][ROOT]["get"]["parameters"] = json!([{"name":"page","in":"query","schema":{"type":"integer","minimum":1,"maximum":u32::MAX,"default":1}},{"name":"page_size","in":"query","schema":{"type":"integer","minimum":1,"maximum":50,"default":20}}]);
    doc["paths"][ROOT]["get"]["description"] = json!(
        "纯本地读取，不初始化Mock/STS/观察/审计；停用后原UUID历史保留。只有原主体可读单笔。完整既有端点来源必须原当前盘点scope，而非用户原始body。无限容量或云exactly-once不受保证。"
    );
    doc["paths"]["/api/v1/alicloud/privatelink/provisioning/preview"]["post"]["requestBody"] = body(fields(
        json!({"request_id":uuid(),"configuration_version":{"type":"integer","minimum":1},"expected_generation":number(),"selection":{"oneOf":[fields(json!({"action":{"const":"create"},"target":{"$ref":"#/components/schemas/PrivateLinkCreateTarget"}}),&["action","target"]),fields(json!({"action":{"const":"accept"},"observation_request_id":uuid()}),&["action","observation_request_id"])]}}),
        &["request_id", "configuration_version", "expected_generation", "selection"],
    ));
    doc["paths"]["/api/v1/alicloud/privatelink/provisioning/apply"]["post"]["requestBody"] = body(fields(
        json!({"request_id":uuid(),"preview_id":uuid(),"expected_generation":number(),"confirm_resources_and_cost":{"const":true},"confirm_current_role":{"const":true},"confirm_no_connectivity_proof":{"const":true},"confirm_live":{"type":"boolean","default":false},"initialize_mock_fixture":{"type":"boolean","default":false}}),
        &[
            "request_id",
            "preview_id",
            "expected_generation",
            "confirm_resources_and_cost",
            "confirm_current_role",
            "confirm_no_connectivity_proof",
        ],
    ));
    doc["paths"]["/api/v1/alicloud/privatelink/provisioning/observe"]["post"]["requestBody"] = body(fields(
        json!({"request_id":uuid(),"configuration_version":{"type":"integer","minimum":1},"original_create_request_id":{"type":["string","null"],"format":"uuid"},"inventory_scope_id":{"type":["string","null"],"format":"uuid"},"confirm_live":{"type":"boolean","default":false}}),
        &["request_id", "configuration_version"],
    ));
    doc["paths"]["/api/v1/alicloud/privatelink/provisioning/observe"]["post"]["description"] = json!(
        "两种来源恰选其一：原ACK创建/接纳请求三项真实完整读，或当前完整AEAD inventory_scope_id的既有端点证据。各自新Read UUID，不升级原Unknown。接纳只引用<=300秒此完整观察，当前provider来源独立捕获；既有接纳不构造创建载荷或猜测带宽。观察不能强制刷新原write回执。"
    );
    doc["paths"]["/api/v1/alicloud/privatelink/provisioning/apply"]["post"]["description"] = json!(
        "先SQL永久claim/预览一次消费再唯一CreateVpcEndpoint或EnableVpcEndpointConnection POST，ClientToken=原UUID；原110秒包含本地锁、同Entry排队、STS及发送。四类确认含Live条件；不会Create自动Accept。Unknown风险按tenant+service/VPC或service/endpoint保守保持，标签、凭据、region、版本换配置不能绕过。ACK独立stage后才本地terminal审计，取消只本地stage。未知不重试，厂商ClientToken不称外部恰好一次。"
    );
    doc["paths"]["/api/v1/alicloud/privatelink/provisioning/requests/{id}/recover-local"]["post"]["requestBody"] =
        body(fields(json!({}), &[]));
    doc["paths"]["/api/v1/alicloud/privatelink/provisioning/requests/{id}/recover-local"]["post"]["description"] = json!(
        "仅原主体当前读写权限，本地已知stage或已过租约事实结算；源停用可用，不调用provider/STS/原请求重派。已Started且无结果保持Unknown。"
    );
    doc["paths"]["/api/v1/alicloud/privatelink/provisioning/archive"]["post"]["requestBody"] = body(fields(
        json!({"request_id":uuid(),"expected_generation":number(),"request_ids":{"type":"array","minItems":1,"maxItems":32,"uniqueItems":true,"items":uuid()}}),
        &["request_id", "expected_generation", "request_ids"],
    ));
    doc["paths"]["/api/v1/alicloud/privatelink/provisioning/archive"]["post"]["description"] = json!(
        "<=32终态正文归档，<=98声明关联键；永久Fact/UUID/risk保留，无Delete云动作。新归档UUID即使0changed也配置写+Create审计；原UUID同body纯读，同UUID不同purpose/body409。不会以归档解除Unknown风险。离线Mock只本进程配置Store，SQL才能跨进程。"
    );
    schemas::register(&mut doc["components"]["schemas"]);
}
