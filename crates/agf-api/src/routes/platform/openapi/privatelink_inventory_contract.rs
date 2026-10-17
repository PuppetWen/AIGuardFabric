//! Selected-endpoint reference evidence never proves network reachability or RAM authorization.
use serde_json::{Value, json};

const ROOT: &str = "/api/v1/alicloud/privatelink/inventory";
const SYNC: &str = "/api/v1/alicloud/privatelink/inventory/sync";
const RECEIPT: &str = "/api/v1/alicloud/privatelink/inventory/operations/{request_id}";
const CANCEL: &str = "/api/v1/alicloud/privatelink/inventory/operations/{request_id}/cancel";
const ARCHIVE: &str = "/api/v1/alicloud/privatelink/operations/archive";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post};
    [
        (ROOT, Get, "getPrivateLinkInventory", "读取选定PrivateLink端点的参考拓扑"),
        (SYNC, Post, "syncPrivateLinkInventory", "显式只读盘点并原子发布端点拓扑"),
        (RECEIPT, Get, "getPrivateLinkInventoryReceipt", "按原UUID本地读取盘点回执"),
        (CANCEL, Post, "cancelPrivateLinkInventory", "取消后续读取和最终发布"),
        (ARCHIVE, Post, "archivePrivateLinkInventoryReceipts", "显式归档终态并永久保留领取事实"),
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
fn nullable_string() -> Value {
    json!({"type":["string","null"]})
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid"})
}
fn nonnil_uuid() -> Value {
    json!({"type":"string","format":"uuid","not":{"const":"00000000-0000-0000-0000-000000000000"}})
}
fn integer() -> Value {
    json!({"type":"integer","minimum":0})
}
fn body(fields: Value, required: &[&str]) -> Value {
    json!({"required":true,"content":{"application/json":{"schema":{
        "type":"object","additionalProperties":false,"required":required,"properties":fields}}}})
}

pub(super) fn describe(document: &mut Value) {
    for (path, method, schema, write) in [
        (ROOT, "get", "PrivateLinkInventory", false),
        (SYNC, "post", "PrivateLinkInventoryOperation", true),
        (RECEIPT, "get", "PrivateLinkInventoryOperation", false),
        (CANCEL, "post", "PrivateLinkInventoryOperation", true),
        (ARCHIVE, "post", "PrivateLinkInventoryArchiveResult", true),
    ] {
        let operation = &mut document["paths"][path][method];
        operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        operation["x-required-permissions"] =
            if write { json!(["alicloud:read", "alicloud:write", "assets:write"]) } else { json!(["alicloud:read"]) };
        operation["responses"]["200"] = json!({"description":"本地结果；Mock不证明真实网络和云权限",
            "content":{"application/json":{"schema":reference(schema)}}});
        for code in ["400", "401", "403", "409", "412", "500", "503", "504"] {
            operation["responses"][code] =
                json!({"description":"输入、权限、范围、完整性或原子提交失败；保留既有快照和资产"});
        }
        if path == RECEIPT || path == CANCEL {
            operation["parameters"] = json!([{"name":"request_id","in":"path","required":true,"schema":uuid()}]);
            operation["responses"]["404"] = json!({"description":"本租户未保存该原请求"});
        }
        if path == ARCHIVE {
            operation["responses"]["404"] = json!({"description":"本租户没有所选原请求；整批归档保持不变"});
        }
    }
    document["paths"][ROOT]["get"]["description"] = json!(
        "纯本地读取，不调用云或STS。只显示当前tenant/configuration/source/region/endpoint/mode完整匹配的快照；未观测时endpoint=null，空图不表示云端没有资源。成功后的明确[]才表示观察为空。来源摘要不证明RAM身份，networkReachability及authorizationAllowed始终null。最近50回执包含active，历史UUID可单独读取。"
    );
    document["paths"][SYNC]["post"]["requestBody"] = body(
        json!({"request_id":nonnil_uuid(),"configuration_version":integer(),
        "confirm_live":{"type":"boolean","default":false}}),
        &["request_id", "configuration_version"],
    );
    document["paths"][SYNC]["post"]["description"] = json!(
        "配置必须明确已有endpoint_id和region_id，Live需confirm_live。先永久领取原UUID，再GetVpcEndpointAttribute及两个endpoint-scoped子列表；每类最多20页/1000项/每页50，整体110秒。缺失/null/空NextToken终止，但必须数组、可核验TotalCount、无重复ID和总数一致；这是平台完整性要求，不声称所有官方字段必填。不完整不覆盖旧快照。一个Other端点资产、加密拓扑、终态和成功审计原子提交，保人工字段且不复活已删除资产。原UUID不重派，缺云结果不假定不存在。观测不是厂商强一致快照。Mock仅cn-hangzhou/ep-agf-demo固定现有示例，未知目标不创建。"
    );
    document["paths"][RECEIPT]["get"]["description"] = json!(
        "纯本地读取不可变原范围回执；配置停用可读，不恢复、不调用厂商。数据库永久保留UUID，archived返回originalStatus且永不重派。离线内存只保证当前进程事实。"
    );
    document["paths"][CANCEL]["post"]["requestBody"] = body(json!({}), &[]);
    document["paths"][CANCEL]["post"]["description"] = json!(
        "纯本地取消running，包括已过租约仍running的请求，阻止下一次读取及最终发布；已发送的只读请求不能撤回。不改变已提交端点或拓扑，停用连接仍可取消，当前权限及原提交session在事务等待后复查。"
    );
    document["paths"][ARCHIVE]["post"]["requestBody"] = body(
        json!({"expected_generation":integer(),
        "request_ids":{"type":"array","minItems":1,"maxItems":100,"uniqueItems":true,"items":nonnil_uuid()}}),
        &["expected_generation", "request_ids"],
    );
    document["paths"][ARCHIVE]["post"]["description"] = json!(
        "按当前generation明确归档1至100个唯一终态非active请求；running先显式取消。主台账最多512项/4MiB，归档释放容量但保留数据库永久轻量领取事实，旧UUID永不重派。snapshot/资产不变；停用配置仍可本地归档。冲突409需重新读取并确认，记录与成功审计同事务。"
    );
    let schemas = &mut document["components"]["schemas"];
    topology_schemas(schemas);
    receipt_schemas(schemas);
    view_schema(schemas);
}

fn topology_schemas(schemas: &mut Value) {
    schemas["PrivateLinkInventoryZone"] = json!({"type":"object","required":["zoneId","region","status","eniId","vSwitchId","eniIp","ipv6","domain"],
        "properties":{"zoneId":{"type":"string"},"region":nullable_string(),"status":nullable_string(),"eniId":nullable_string(),
            "vSwitchId":nullable_string(),"eniIp":nullable_string(),"ipv6":nullable_string(),"domain":nullable_string()}});
    schemas["PrivateLinkInventorySecurityGroup"] = json!({"type":"object","required":["securityGroupId","status"],
        "properties":{"securityGroupId":{"type":"string"},"status":nullable_string()}});
    schemas["PrivateLinkInventoryEndpoint"] = json!({"type":["object","null"],
        "required":["assetId","endpointId","name","region","vpcId","serviceId","serviceRegionId","domain","endpointType","endpointStatus",
            "connectionStatus","businessStatus","zonesAvailable","securityGroupsAvailable","zones","securityGroups"],
        "description":"仅选定端点纳管Other资产。nullable字段未知，ServiceRegionId独立于端点region；两个完整数组[]表示实测零项。",
        "properties":{"assetId":{"type":["string","null"],"format":"uuid"},"endpointId":{"type":"string"},"name":nullable_string(),
            "region":nullable_string(),"vpcId":nullable_string(),"serviceId":nullable_string(),"serviceRegionId":nullable_string(),
            "domain":nullable_string(),"endpointType":nullable_string(),"endpointStatus":nullable_string(),"connectionStatus":nullable_string(),
            "businessStatus":nullable_string(),"zonesAvailable":{"const":true},"securityGroupsAvailable":{"const":true},
            "zones":{"type":"array","maxItems":1000,"items":reference("PrivateLinkInventoryZone")},
            "securityGroups":{"type":"array","maxItems":1000,"items":reference("PrivateLinkInventorySecurityGroup")}}});
    schemas["PrivateLinkInventoryNode"] = json!({"type":"object","required":["id","kind","cloudId","assetId","referenceOnly","region"],
        "description":"id绑定当前tenant/source/config/mode scope。仅端点有平台assetId，其余referenceOnly=true；服务region仅明确ServiceRegionId，安全组region未知，不推断可达或权限。",
        "properties":{"id":uuid(),"kind":{"enum":["endpoint","zone","security_group","eni","vswitch","vpc","service"]},
            "cloudId":{"type":"string"},"assetId":{"type":["string","null"],"format":"uuid"},"referenceOnly":{"type":"boolean"},"region":nullable_string()}});
    schemas["PrivateLinkInventoryEdge"] = json!({"type":"object","required":["from","to","relation","evidenceAction","observedAt"],
        "description":"只使用接口明确返回ID形成引用边，不代表包流、规则许可、TLS或跨账号所有权。",
        "properties":{"from":uuid(),"to":uuid(),"relation":{"enum":["has_zone","has_security_group","in_vpc","references_service","zone_eni","zone_vswitch"]},
            "evidenceAction":{"enum":["GetVpcEndpointAttribute","ListVpcEndpointZones","ListVpcEndpointSecurityGroups"]},"observedAt":{"type":"string","format":"date-time"}}});
    schemas["PrivateLinkInventoryGraph"] = json!({"type":"object","required":["nodes","edges"],"properties":{
        "nodes":{"type":"array","maxItems":4003,"items":reference("PrivateLinkInventoryNode")},
        "edges":{"type":"array","maxItems":4002,"items":reference("PrivateLinkInventoryEdge")}}});
}

fn receipt_schemas(schemas: &mut Value) {
    schemas["PrivateLinkInventoryOperation"] = json!({"type":"object",
        "required":["requestId","scopeId","configurationVersion","mocked","region","endpointId","sourceIdentity","identityEvidence","status",
            "startedAt","finishedAt","leaseExpiresAt","pagesRead","endpointsObserved","zonesObserved","securityGroupsObserved","published","current",
            "canCancel","canRedispatch","note","archived","archivable","archivedAt","originalStatus"],
        "properties":{"requestId":uuid(),"scopeId":uuid(),"configurationVersion":integer(),"mocked":{"type":"boolean"},"region":{"type":"string"},
            "endpointId":{"type":"string"},"sourceIdentity":{"type":"string"},"identityEvidence":{"const":"configured_source_digest"},
            "status":{"enum":["running","succeeded","failed","cancelled","interrupted","superseded","archived"]},"startedAt":{"type":"string","format":"date-time"},
            "finishedAt":{"type":["string","null"],"format":"date-time"},"leaseExpiresAt":{"type":"string","format":"date-time"},
            "pagesRead":{"type":"integer","minimum":0,"maximum":40,"description":"仅统计两类子列表成功观察页，不计详情Get"},
            "endpointsObserved":{"type":"integer","minimum":0,"maximum":1},"zonesObserved":{"type":"integer","minimum":0,"maximum":1000},
            "securityGroupsObserved":{"type":"integer","minimum":0,"maximum":1000},"published":{"type":"boolean"},"current":{"type":"boolean"},
            "canCancel":{"type":"boolean"},"canRedispatch":{"const":false},"note":{"type":"string"},"archived":{"type":"boolean"},
            "archivable":{"type":"boolean"},"archivedAt":{"type":["string","null"],"format":"date-time"},"originalStatus":nullable_string()}});
    schemas["PrivateLinkInventoryArchiveResult"] = json!({"type":"object","required":["generation","archivedCount","archivedRequestIds"],
        "properties":{"generation":integer(),"archivedCount":integer(),"archivedRequestIds":{"type":"array","minItems":1,"maxItems":100,
            "uniqueItems":true,"items":nonnil_uuid()}}});
}

fn view_schema(schemas: &mut Value) {
    schemas["PrivateLinkInventory"] = json!({"type":"object",
        "required":["configured","scopeId","configurationVersion","sourceIdentity","identityEvidence","region","endpointId","mocked","topologyAvailable",
            "checkedAt","pagesRead","listingComplete","coverage","consistency","networkReachability","authorizationAllowed","endpoint","graph",
            "operations","generation","archivedCount","unavailableReason","limits"],
        "properties":{"configured":{"type":"boolean"},"scopeId":{"type":["string","null"],"format":"uuid"},"configurationVersion":{"type":["integer","null"],"minimum":0},
            "sourceIdentity":nullable_string(),"identityEvidence":{"const":"configured_source_digest"},"region":nullable_string(),"endpointId":nullable_string(),
            "mocked":{"type":["boolean","null"]},"topologyAvailable":{"type":"boolean"},"checkedAt":{"type":["string","null"],"format":"date-time"},
            "pagesRead":{"type":["integer","null"],"minimum":0,"maximum":40},"listingComplete":{"type":"boolean"},"coverage":{"const":"selected_endpoint"},
            "consistency":{"const":"not_strong_snapshot"},"networkReachability":{"type":"null"},"authorizationAllowed":{"type":"null"},
            "endpoint":reference("PrivateLinkInventoryEndpoint"),"graph":reference("PrivateLinkInventoryGraph"),
            "operations":{"type":"array","maxItems":50,"items":reference("PrivateLinkInventoryOperation")},"generation":integer(),"archivedCount":integer(),
            "unavailableReason":nullable_string(),"limits":{"type":"object","required":["maxPages","maxPagesPerList","pageSize","maxChildRecords","maxSeconds","maxRuns","maxRecordBytes"],
                "properties":{"maxPages":{"const":40},"maxPagesPerList":{"const":20},"pageSize":{"const":50},"maxChildRecords":{"const":2000},
                    "maxSeconds":{"const":110},"maxRuns":{"const":512},"maxRecordBytes":{"const":4_194_304}}}}});
}
