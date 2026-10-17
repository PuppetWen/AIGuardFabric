//! Explicit MSE discovery observes service metadata; it never invents runtime or network facts.
use serde_json::{Value, json};

const ROOT: &str = "/api/v1/alicloud/mse/inventory";
const RECEIPT: &str = "/api/v1/alicloud/mse/inventory/operations/{request_id}";
const CANCEL: &str = "/api/v1/alicloud/mse/inventory/operations/{request_id}/cancel";
const SYNC: &str = "/api/v1/alicloud/mse/inventory/sync";
const ARCHIVE: &str = "/api/v1/alicloud/mse/operations/archive";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post};
    [
        (ROOT, Get, "getMseInventory", "读取当前配置范围的MSE服务盘点及回执"),
        (SYNC, Post, "syncMseInventory", "显式分页读取MSE并原子发布服务资产"),
        (RECEIPT, Get, "getMseInventoryReceipt", "按原请求编号读取MSE同步回执"),
        (CANCEL, Post, "cancelMseInventory", "取消未结束MSE同步并阻止后续发布"),
        (ARCHIVE, Post, "archiveMseInventoryReceipts", "显式归档终态回执并保留永久领取记录"),
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

fn response(schema: &str) -> Value {
    json!({"description":"已提交的当前结果；Mock不证明真实云接入或授权",
        "content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{schema}")}}}})
}

fn body(fields: Value, required: &[&str]) -> Value {
    json!({"required":true,"content":{"application/json":{"schema":{
        "type":"object","additionalProperties":false,"required":required,"properties":fields}}}})
}

pub(super) fn describe(document: &mut Value) {
    for (path, method, schema, write) in [
        (ROOT, "get", "MseInventory", false),
        (SYNC, "post", "MseInventoryOperation", true),
        (RECEIPT, "get", "MseInventoryOperation", false),
        (CANCEL, "post", "MseInventoryOperation", true),
        (ARCHIVE, "post", "MseInventoryArchiveResult", true),
    ] {
        let operation = &mut document["paths"][path][method];
        operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        operation["x-required-permissions"] =
            if write { json!(["alicloud:read", "alicloud:write", "assets:write"]) } else { json!(["alicloud:read"]) };
        operation["responses"]["200"] = response(schema);
        for code in ["400", "401", "403", "409", "412", "500"] {
            operation["responses"][code] =
                json!({"description":"输入、权限、范围、版本或发布失败；保留既有资产和快照"});
        }
        if path == RECEIPT || path == CANCEL {
            operation["parameters"] = json!([{"name":"request_id","in":"path","required":true,
                "schema":{"type":"string","format":"uuid"}}]);
            operation["responses"]["404"] = json!({"description":"本租户未保存该请求"});
        }
    }
    document["paths"][ROOT]["get"]["description"] = json!(
        "纯本地读取，不调用云或STS；只呈现匹配租户、配置版本、来源摘要、region、instance及明确namespace的完整盘点。无有效快照时totalServices=null，有效空列表为0。来源摘要是配置身份而非已验证RAM账号；endpoint、协议、运行时、网络及metadata均保持未知。保留最近50个回执及active请求，归档历史可用原UUID单独读取。"
    );
    document["paths"][SYNC]["post"]["requestBody"] = body(
        json!({
            "request_id":{"type":"string","format":"uuid"},"configuration_version":{"type":"integer","minimum":0},
            "confirm_live":{"type":"boolean","default":false}
        }),
        &["request_id", "configuration_version"],
    );
    document["paths"][SYNC]["post"]["description"] = json!(
        "先持久领取原UUID，再以当前配置ListAnsServices分页读取；Live需明确confirm_live。明确默认namespace为空字符串；未配置namespace不自动猜默认。最多20页/2000服务/110秒，部分页、重复服务或总数矛盾不发布。资产观测、加密快照、终态及安全审计共同提交，保留人工字段；已删除资产不复活。原UUID不再次派发，超时或断线用原UUID读取回执，不自动生成新请求。读到的分页不等于厂商强一致快照。"
    );
    document["paths"][RECEIPT]["get"]["description"] = json!(
        "纯本地读取原始范围回执，配置停用后仍可读取；不恢复操作、不重发云请求。归档回执返回archived及originalStatus，永久保留旧UUID的领取事实。"
    );
    document["paths"][CANCEL]["post"]["requestBody"] = body(json!({}), &[]);
    document["paths"][CANCEL]["post"]["description"] = json!(
        "显式取消running请求（含租约过期），阻止下一页和最终发布；已经发送的只读请求无法撤回。纯本地取消，不撤销既有资产和完整快照。"
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
        "按当前台账generation确认1至100个唯一终态且非active请求。详情移到永久轻量归档，原UUID永不重新派发；snapshot和资产不变。台账变化返回409，running或active先显式取消。连接停用仍可本地归档；归档记录与成功审计共同提交。"
    );
    document["components"]["schemas"]["MseInventoryService"] = json!({"type":"object",
        "required":["key","name","groupName","assetId","instanceCount","healthyInstanceCount","clusterCount","source",
            "endpoint","protocol","runtime","networkZone","metadata","evidence"],
        "properties":{
            "key":{"type":"string"},"name":{"type":"string"},"groupName":{"type":"string"},
            "assetId":{"type":["string","null"],"format":"uuid"},
            "instanceCount":{"type":["integer","null"],"minimum":0},
            "healthyInstanceCount":{"type":["integer","null"],"minimum":0},
            "clusterCount":{"type":["integer","null"],"minimum":0},"source":{"type":["string","null"]},
            "endpoint":{"type":"null"},"protocol":{"type":"null"},"runtime":{"type":"null"},
            "networkZone":{"type":"null"},"metadata":{"type":"null"},"evidence":{"const":"ListAnsServices"}}});
    document["components"]["schemas"]["MseInventoryOperation"] = json!({"type":"object",
        "required":["requestId","scopeId","configurationVersion","mocked","region","instanceId","namespaceId",
            "sourceIdentity","identityEvidence","status","startedAt","finishedAt","leaseExpiresAt","pagesRead",
            "servicesObserved","published","current","canCancel","canRedispatch","note","archived","archivable",
            "archivedAt","originalStatus"],
        "properties":{
            "requestId":{"type":"string","format":"uuid"},"scopeId":{"type":"string","format":"uuid"},
            "configurationVersion":{"type":"integer","minimum":0},"mocked":{"type":"boolean"},
            "region":{"type":"string"},"instanceId":{"type":"string"},"namespaceId":{"type":"string"},
            "sourceIdentity":{"type":"string"},"identityEvidence":{"const":"configured_source_digest"},
            "status":{"enum":["running","succeeded","failed","cancelled","interrupted","superseded","archived"]},
            "startedAt":{"type":"string","format":"date-time"},"finishedAt":{"type":["string","null"],"format":"date-time"},
            "leaseExpiresAt":{"type":"string","format":"date-time"},"pagesRead":{"type":"integer","minimum":0},
            "servicesObserved":{"type":"integer","minimum":0},"published":{"type":"boolean"},"current":{"type":"boolean"},
            "canCancel":{"type":"boolean"},"canRedispatch":{"const":false},"note":{"type":"string"},
            "archived":{"type":"boolean"},"archivable":{"type":"boolean"},
            "archivedAt":{"type":["string","null"],"format":"date-time"},"originalStatus":{"type":["string","null"]}}});
    document["components"]["schemas"]["MseInventory"] = json!({"type":"object",
        "required":["configured","scopeId","configurationVersion","mocked","region","instanceId","namespaceId","sourceIdentity",
            "identityEvidence","inventoryAvailable","totalServices","checkedAt","pagesRead","listingComplete","coverage",
            "consistency","items","operations","generation","archivedCount","unavailableReason","limits"],
        "properties":{
            "configured":{"type":"boolean"},"scopeId":{"type":["string","null"],"format":"uuid"},
            "configurationVersion":{"type":["integer","null"],"minimum":0},"mocked":{"type":["boolean","null"]},
            "region":{"type":["string","null"]},"instanceId":{"type":["string","null"]},
            "namespaceId":{"type":["string","null"]},"sourceIdentity":{"type":["string","null"]},
            "identityEvidence":{"const":"configured_source_digest"},"inventoryAvailable":{"type":"boolean"},
            "totalServices":{"type":["integer","null"],"minimum":0},"checkedAt":{"type":["string","null"],"format":"date-time"},
            "pagesRead":{"type":["integer","null"],"minimum":0},"listingComplete":{"type":"boolean"},
            "coverage":{"const":"observed_pages"},"consistency":{"const":"not_strong_snapshot"},
            "items":{"type":"array","maxItems":2000,"items":{"$ref":"#/components/schemas/MseInventoryService"}},
            "operations":{"type":"array","maxItems":50,"items":{"$ref":"#/components/schemas/MseInventoryOperation"}},
            "generation":{"type":"integer","minimum":0},"archivedCount":{"type":"integer","minimum":0},
            "unavailableReason":{"type":["string","null"]},"limits":{"type":"object"}}});
    document["components"]["schemas"]["MseInventoryArchiveResult"] = json!({"type":"object",
        "required":["generation","archivedCount","archivedRequestIds"],"properties":{
            "generation":{"type":"integer","minimum":0},"archivedCount":{"type":"integer","minimum":0},
            "archivedRequestIds":{"type":"array","minItems":1,"maxItems":100,"uniqueItems":true,
                "items":{"type":"string","format":"uuid"}}}});
}
