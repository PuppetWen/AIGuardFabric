//! Conditional runtime quota writes, targeting and versioned list results.
use serde_json::{Value, json};

pub(super) fn describe(document: &mut Value) {
    let path = "/api/v1/quotas";
    let reference = json!({"$ref":"#/components/schemas/VersionedRuntimeQuota"});
    document["components"]["schemas"]["VersionedRuntimeQuota"] = json!({
        "type":"object","required":["id","tenant_id","name","scope","dimension","window","limit","enabled","version"],
        "properties":{
            "id":{"type":"string","format":"uuid"},"tenant_id":{"type":"string","format":"uuid"},
            "name":{"type":"string"},"version":{"type":"integer","minimum":0,"description":"该名称配额的版本，迁移旧规则从0开始"},
            "scope":{"type":"string","enum":["tenant","agent","session"]},
            "dimension":{"type":"string","enum":["tokens","requests","concurrency","cost"]},
            "window":{"type":"string","enum":["minute","hour","day","month","session","total"]},
            "limit":{"type":"integer","minimum":0},"soft_threshold":{"type":"integer","minimum":0},
            "on_exceed":{"type":"string","enum":["deny","throttle","quota","audit","allow"]},
            "enabled":{"type":"boolean"},"target_id":{"type":["string","null"],"format":"uuid"},
            "created_at":{"type":"string","format":"date-time"},"updated_at":{"type":"string","format":"date-time"}
        }
    });
    let schema = &mut document["components"]["schemas"]["QuotaBody"];
    schema["properties"]["expected_version"]["minimum"] = json!(0);
    schema["properties"]["expected_version"]["description"] =
        json!("编辑必须提供读取的quota.version；新建可省略或填0，旧版本409，漏填已有规则400");
    schema["properties"]["target_id"]["description"] =
        json!("仅agent作用域：当前租户有效Agent资产UUID；省略时分别应用于每个已认证Agent");
    let post = &mut document["paths"][path]["post"];
    post["x-required-permissions"] = json!(["quotas:write"]);
    post["description"] =
        json!("同租户名称唯一；完整配置按版本保存，保持ID和已有用量。成功配置与审计同数据库事务提交，审计失败回滚。");
    post["requestBody"] =
        json!({"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/QuotaBody"}}}});
    post["responses"]["200"] = json!({"description":"成功，返回新版本","content":{"application/json":{"schema":{"type":"object","required":["quota"],"properties":{"quota":reference}}}}});
    post["responses"]["409"] = json!({"description":"版本已改变或版本溢出；未保存，请重新读取并人工合并"});
    post["responses"]["400"] = json!({"description":"参数、目标或expected_version无效；编辑已有配置不可漏填版本"});
    let get = &mut document["paths"][path]["get"];
    get["x-required-permissions"] = json!(["quotas:read"]);
    get["responses"]["200"] = json!({"description":"分页配额与用量，每条quota含version","content":{"application/json":{"schema":{
        "type":"object","properties":{"items":{"type":"array","items":{"type":"object","properties":{"quota":reference,"used":{"type":"integer"},"remaining":{"type":"integer"}}}},"total":{"type":"integer"}}
    }}}});
}
