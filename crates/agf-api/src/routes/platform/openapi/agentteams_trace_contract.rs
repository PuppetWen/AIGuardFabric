//! Observed trace evidence is read only, bounded and never an authorization or replay contract.
use serde_json::{Value, json};

const PATH: &str = "/api/v1/alicloud/agentteams/traces/{trace_id}";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    vec![super::EndpointSpec {
        path: PATH,
        method: utoipa::openapi::path::HttpMethod::Get,
        id: "getAgentTeamsTrace",
        summary: "读取当前云范围内已采集的调用链证据",
        tag: "alicloud",
        implemented: true,
    }]
}

pub(super) fn describe(document: &mut Value) {
    let operation = &mut document["paths"][PATH]["get"];
    operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
    operation["x-required-permissions"] = json!(["alicloud:read", "sources:read"]);
    operation["description"] = json!(
        "仅查询当前租户、云配置范围内已采集的 Trace。默认最近24小时；窗口须为正且不超过30天，结束时间不得超过现在60秒。每页1至200事件，图最多2000节点；totalEvents为同一SQL语句快照的独立总量，截断不代表其它节点不存在。游标绑定租户、范围、Trace、时间窗及已接收水位，30分钟过期；原快照改变返回409，须显式刷新，不能拼接新旧分页。complete始终false，coverage=observed_only；只用唯一parent_span_id建立证据边，缺失、重复或环关系明确为unknown/conflict。Mock不证明云端调用、授权或完整覆盖；无盘点时总数null，盘点有效但未观测时为0。不会调用云端或重放业务。"
    );
    operation["parameters"] = json!([
        {"name":"trace_id","in":"path","required":true,
            "schema":{"type":"string","minLength":1,"maxLength":128}},
        {"name":"from","in":"query","required":false,
            "schema":{"type":"string","format":"date-time"}},
        {"name":"until","in":"query","required":false,
            "schema":{"type":"string","format":"date-time"}},
        {"name":"limit","in":"query","required":false,
            "schema":{"type":"integer","minimum":1,"maximum":200,"default":50}},
        {"name":"cursor","in":"query","required":false,
            "schema":{"type":"string","maxLength":4096}}
    ]);
    operation["responses"] = json!({
        "200":{"description":"返回当前范围内已观测证据；unknown/null与观测0分别表示",
            "content":{"application/json":{"schema":{"$ref":"#/components/schemas/AgentTeamsTrace"}}}},
        "400":{"description":"Trace、时间窗口、游标无效或改变查询条件"},
        "401":{"description":"未认证"},
        "403":{"description":"当前租户或两项读取权限不可用"},
        "409":{"description":"云范围或分页快照改变，请显式刷新查询"},
        "503":{"description":"审计存储不可用，不返回伪造的空链"}
    });
    document["components"]["schemas"]["AgentTeamsTrace"] = json!({
        "type":"object",
        "required":["traceId","scopeId","cloudVersion","mocked","inventoryAvailable",
            "windowFrom","windowTo","asOfReceivedAt","totalEvents","items","nextCursor",
            "truncated","nodeLimit","complete","coverage","consistency","timePrecision","graph"],
        "properties":{
            "traceId":{"type":"string"},
            "scopeId":{"type":["string","null"],"format":"uuid"},
            "cloudVersion":{"type":"integer","minimum":0},
            "mocked":{"type":["boolean","null"]},
            "inventoryAvailable":{"type":"boolean"},
            "windowFrom":{"type":"string","format":"date-time"},
            "windowTo":{"type":"string","format":"date-time"},
            "asOfReceivedAt":{"type":"string","format":"date-time"},
            "totalEvents":{"type":["integer","null"],"minimum":0},
            "items":{"type":"array","maxItems":200,"items":{"type":"object"}},
            "nextCursor":{"type":["string","null"],"description":"不透明游标；不得解析或自行修改"},
            "truncated":{"type":"boolean"},
            "nodeLimit":{"type":"integer","const":2000},
            "complete":{"type":"boolean","const":false},
            "coverage":{"type":"string","const":"observed_only"},
            "consistency":{"type":"string","const":"statement"},
            "timePrecision":{"type":"string","const":"microsecond"},
            "graph":{"$ref":"#/components/schemas/AgentTeamsTraceGraph"}
        }
    });
    document["components"]["schemas"]["AgentTeamsTraceGraph"] = json!({
        "type":"object","required":["status","nodes","edges","issues"],
        "properties":{
            "status":{"type":"string","enum":["unavailable","unobserved","observed","unknown","conflict"]},
            "nodes":{"type":"array","maxItems":2000,"items":{"type":"object",
                "properties":{"id":{"type":"string","format":"uuid"},
                    "resolution":{"type":"string","enum":["observed","unknown","conflict"]},
                    "authorizationStatus":{"type":"string","const":"unknown"},"authorized":{"type":"null"}}}},
            "edges":{"type":"array","maxItems":2000,"items":{"type":"object",
                "required":["fromNodeId","toNodeId","parentSpanId","evidence"],
                "properties":{"fromNodeId":{"type":"string","format":"uuid"},
                    "toNodeId":{"type":"string","format":"uuid"},"parentSpanId":{"type":"string"},
                    "evidence":{"type":"string","const":"parent_span_id"}}}},
            "issues":{"type":"array","items":{"type":"object"}}
        }
    });
}
