//! Local Role constraints intersect existing Key scopes; cloud role strings grant no authority.
use serde_json::{Value, json};

const ROOT: &str = "/api/v1/alicloud/agentteams/role-mappings";
const ASSET: &str = "/api/v1/alicloud/agentteams/role-mappings/{asset}";
const REQUEST: &str = "/api/v1/alicloud/agentteams/role-mappings/{asset}/requests/{request}";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Put};
    [
        (ROOT, Get, "listAgentTeamsRoleMappings", "读取真实平台角色目录和本地Worker约束"),
        (ASSET, Get, "getAgentTeamsRoleMapping", "读取安全原始角色约束证明"),
        (ASSET, Put, "saveAgentTeamsRoleMapping", "显式采用或停用本地权限交集约束"),
        (REQUEST, Get, "getAgentTeamsRoleMappingRequest", "纯读取永久原UUID回执"),
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
fn object(properties: Value) -> Value {
    let required = properties.as_object().map(|fields| fields.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}
fn nullable(rule: Value) -> Value {
    json!({"anyOf":[rule,{"type":"null"}]})
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid","description":"Non-nil tenant-owned identity."})
}
fn version(minimum: u64) -> Value {
    json!({"type":"integer","minimum":minimum,"maximum":u64::MAX})
}
fn text() -> Value {
    json!({"type":"string"})
}
fn timestamp() -> Value {
    json!({"type":"string","format":"date-time"})
}
fn array(rule: Value) -> Value {
    json!({"type":"array","items":rule})
}
fn fixed(value: Value) -> Value {
    json!({"enum":[value]})
}

pub(super) fn describe(document: &mut Value) {
    schemas(&mut document["components"]["schemas"]);
    for (path, method, response) in [
        (ROOT, "get", "AgentTeamsRoleCatalog"),
        (ASSET, "get", "AgentTeamsRoleMapping"),
        (ASSET, "put", "AgentTeamsRoleIntent"),
        (REQUEST, "get", "AgentTeamsRoleIntent"),
    ] {
        let operation = &mut document["paths"][path][method];
        operation["security"] =
            if method == "put" { json!([{"bearerAuth":[]}]) } else { json!([{"bearerAuth":[]},{"apiKey":[]}]) };
        operation["x-required-permissions"] = if method == "put" {
            json!(["alicloud:read", "platform:admin", "assets:write"])
        } else {
            json!(["alicloud:read", "platform:admin"])
        };
        operation["description"] = json!(
            "仅本地权限约束。真实当前Key scopes与受支持的本租户平台Role取交集，不能扩权；superadmin/asset-owner的用户或ABAC语义不可转成平面Key权限。云Role仅为实采字符串，不是身份认证或云授权。永久marker与加密证明缺失、删除、停用或角色/来源/Agent变更fail closed；新正面盘点不自动恢复。300秒仅人工采用窗口，不是已保存权限TTL。GET不初始化、不调用provider、不写配置或审计。只有管理员User可PUT，SQL目录必需，离线新增管理412；永久原UUID同actor/asset/body回原receipt、不新增审计，异用途/body409。单条GET和receipt的currentQualified=null表示未在此读路径验证当前资格，列表逐项读取实际当前资格。"
        );
        operation["responses"] = json!({"200":{"description":"直接安全DTO；不证明云授权或业务执行",
            "content":{"application/json":{"schema":reference(response)}}},
            "400":{"description":"不支持的字段、类型、安全名称或确认无效"},
            "401":{"description":"原认证或JWT失效、到期"},
            "403":{"description":"当前租户/权限/角色证明无效；PUT仅User"},
            "404":{"description":"当前租户无该映射或原请求"},
            "409":{"description":"本地CAS、来源盘点或原UUID冲突；保留草稿，不自动重派"},
            "412":{"description":"SQL角色目录缺失、采用证据过时或角色需要不支持的ABAC语义"},
            "500":{"description":"持久身份/AEAD无效或原子审计失败，事务不发布"}});
        let mut parameters = Vec::new();
        if path != ROOT {
            parameters.push(json!({"name":"asset","in":"path","required":true,"schema":uuid()}));
        }
        if path == REQUEST {
            parameters.push(json!({"name":"request","in":"path","required":true,"schema":uuid()}));
        }
        operation["parameters"] = json!(parameters);
        if method == "put" {
            operation["requestBody"] =
                json!({"required":true,"content":{"application/json":{"schema":reference("AgentTeamsRoleInput")}}});
            operation["x-atomic-success-audit"] = json!({"action":"grant","target":"agentteams-role-governance",
                "configurationMarkerIntent":"same SQL transaction","originalAuthorityAfterAuditWait":true});
            operation["x-retained-record-byte-limit"] = json!(128 * 1024);
        }
    }
}
fn schemas(schemas: &mut Value) {
    let name = json!({"type":"string","minLength":1,"maxLength":256,"x-max-utf8-bytes":256,
        "description":"Exact observed safe name; no control characters or surrounding whitespace."});
    schemas["AgentTeamsRoleChange"] = json!({"anyOf":[object(json!({"action":fixed(json!("adopt")),
        "configuration_version":version(0),"observed_at":timestamp(),"worker_name":name,
        "team_name":name,"cloud_role":name,"role_id":uuid()})),object(json!({"action":fixed(json!("disable"))}))]});
    schemas["AgentTeamsRoleInput"] = object(json!({"request_id":uuid(),"expected_version":version(0),
        "confirm_local_constraint":fixed(json!(true)),"change":reference("AgentTeamsRoleChange")}));
    schemas["AgentTeamsRoleProof"] = object(json!({"configurationVersion":version(0),"mocked":{"type":"boolean"},
        "region":text(),"instanceId":text(),"workerName":text(),"teamName":text(),"cloudRole":text(),
        "observedAt":timestamp(),"platformRoleId":uuid(),"department":nullable(text()),
        "dataClass":{"type":"string","enum":["public","internal","confidential","restricted"]}}));
    let mut mapping = object(json!({"assetId":uuid(),"version":version(1),"governed":fixed(json!(true)),
        "eligibility":{"type":"string","enum":["eligible","revoked","unverified","disabled"]},
        "reason":nullable(text()),"updatedAt":timestamp(),"proof":reference("AgentTeamsRoleProof"),
        "currentQualified":{"type":"null"},"constraint":fixed(json!("key_scopes_intersection")),
        "cloudPermissionGranted":fixed(json!(false))}));
    schemas["AgentTeamsRoleMapping"] = mapping.clone();
    mapping["properties"]["currentQualified"] = json!({"type":"boolean"});
    mapping["properties"]["currentReason"] = nullable(text());
    if let Some(required) = mapping["required"].as_array_mut() {
        required.push(json!("currentReason"));
    }
    schemas["AgentTeamsRoleCurrentMapping"] = mapping;
    schemas["AgentTeamsRoleIntent"] = object(json!({"requestId":uuid(),"assetId":uuid(),
        "original":reference("AgentTeamsRoleMapping"),"immutable":fixed(json!(true)),"providerCalled":fixed(json!(false))}));
    schemas["AgentTeamsRoleCatalogEntry"] = object(json!({"id":uuid(),"name":text(),"displayName":text(),
        "permissions":array(text()),"selectable":{"type":"boolean"},"reason":nullable(text())}));
    schemas["AgentTeamsRoleWorker"] = object(json!({"assetId":nullable(uuid()),"workerName":text(),"teamName":text(),
        "cloudRole":nullable(text()),"configurationVersion":version(0),"observedAt":timestamp()}));
    let mut roles = array(reference("AgentTeamsRoleCatalogEntry"));
    roles["maxItems"] = json!(512);
    let mut items = array(reference("AgentTeamsRoleCurrentMapping"));
    items["maxItems"] = json!(512);
    schemas["AgentTeamsRoleOnlineCatalog"] = object(json!({"catalogAvailable":fixed(json!(true)),
        "canManage":{"type":"boolean"},"roles":roles,"items":items,"workers":array(reference("AgentTeamsRoleWorker")),
        "mappedCount":{"type":"integer","minimum":0,"maximum":512},"adoptionWindowSeconds":fixed(json!(300)),
        "permissionTTL":{"type":"null"},"providerCalled":fixed(json!(false)),
        "limits":object(json!({"workers":fixed(json!(512)),"immutableIntents":fixed(json!(2048))})),"note":text()}));
    schemas["AgentTeamsRoleOfflineCatalog"] = object(json!({"catalogAvailable":fixed(json!(false)),
        "canManage":fixed(json!(false)),"roles":fixed(json!([])),"items":fixed(json!([])),
        "workers":fixed(json!([])),"mappedCount":fixed(json!(0)),"note":text()}));
    schemas["AgentTeamsRoleCatalog"] =
        json!({"anyOf":[reference("AgentTeamsRoleOnlineCatalog"),reference("AgentTeamsRoleOfflineCatalog")]});
}
