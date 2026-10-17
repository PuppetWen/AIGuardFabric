use super::cms_queue_schemas::{reference, register};
use serde_json::{Value, json};
const ROOT: &str = "/api/v1/alicloud/cms/queue";
const ITEM: &str = "/api/v1/alicloud/cms/queue/items/{id}";
const REQUEST: &str = "/api/v1/alicloud/cms/queue/requests/{id}";
const ENQUEUE: &str = "/api/v1/alicloud/cms/queue/enqueue";
const SEND: &str = "/api/v1/alicloud/cms/queue/send";
const RECOVER: &str = "/api/v1/alicloud/cms/queue/items/{id}/recover-local";
const ARCHIVE: &str = "/api/v1/alicloud/cms/queue/archive";
pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post};
    [
        (ROOT, Get, "readCmsQueue", "纯读CMS持久补传队列"),
        (ITEM, Get, "readCmsQueueItem", "读取原条目及发送事实"),
        (REQUEST, Get, "readCmsQueueRequest", "读取永久原UUID意图回执"),
        (ENQUEUE, Post, "enqueueCmsItems", "明确入队CMS事件或指标"),
        (SEND, Post, "sendCmsQueueItems", "新明确补传意图，仅未发或可信拒绝"),
        (RECOVER, Post, "recoverCmsQueueItemLocally", "仅本地结算，不重派provider"),
        (ARCHIVE, Post, "archiveCmsQueueContent", "归档正文，保留永久请求和发送事实"),
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
pub(super) fn describe(document: &mut Value) {
    register(&mut document["components"]["schemas"]);
    for (path, method, response, input) in [
        (ROOT, "get", "CmsQueueState", None),
        (ITEM, "get", "CmsQueueItem", None),
        (REQUEST, "get", "CmsQueueReceipt", None),
        (ENQUEUE, "post", "CmsQueueReceipt", Some("CmsQueueEnqueueInput")),
        (SEND, "post", "CmsQueueReceipt", Some("CmsQueueSendInput")),
        (RECOVER, "post", "CmsQueueItem", Some("CmsQueueRecoverInput")),
        (ARCHIVE, "post", "CmsQueueReceipt", Some("CmsQueueArchiveInput")),
    ] {
        let op = &mut document["paths"][path][method];
        op["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        op["x-required-permissions"] =
            if method == "get" { json!(["alicloud:read"]) } else { json!(["alicloud:read", "alicloud:write"]) };
        op["description"] = json!(
            "明确用户队列，不接管通用CMS或Scheduler直发。GET不发送、不初始化、不写审计。每条唯一POST；CMS无ClientToken，不保证外部恰好一次。Accepted永不重发；Unknown仅本地结算/人工处置；只有明确NotSent或可信Rejected可用新UUID/110秒发起新意图，每项最多5次。原请求UUID同owner/body/purpose只读复用，不能重新获发送许可；异body/purpose409。原Owner包括真实tenant/身份/Agent绑定，当前权限和原JWT在SQL及审计等待后复查。源版本/指纹改变或停用阻断新发送，历史、本地结算与终态归档仍可用。Live须SQL和confirm_live；Mock显式 owned seed只在Enqueue初始化，离线内存仅同进程持久。入队与云ACK、消费者处理分别记录；pending_audit不能视为审计已提交，匹配后续数据不能升级Unknown。归档释放正文而保留ITEM/ATTEMPT/REQUEST永久事实，容量满拒绝且不逐出身份。request.items为当前资格，originalAttempts为原请求各次不可换号发送事实。Key历史/恢复要求同原Key，管理员User不能代替。"
        );
        op["responses"] = json!({"200":{"description":"直接安全DTO，无payload正文/凭据","content":{"application/json":{"schema":reference(response)}}},
            "400":{"description":"未知字段、类型、JSON、分页或安全边界无效"},"401":{"description":"原认证/JWT过期"},
            "403":{"description":"当前权限/租户/原Owner不同"},"404":{"description":"本租户不存在该原事实"},
            "409":{"description":"CAS/原UUID/原来源改变；保留原UUID，不自动重派"},
            "412":{"description":"源停用、SQL/Mock seed缺失、Accepted/Unknown/active/archived不可发送或容量耗尽"},
            "500":{"description":"AEAD/身份/存储/原子审计失败，保留原事实"}});
        let mut parameters = Vec::new();
        if [ITEM, REQUEST, RECOVER].contains(&path) {
            parameters
                .push(json!({"name":"id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}));
        }
        if path == ROOT {
            parameters.extend([json!({"name":"page","in":"query","schema":{"type":"integer","minimum":1,"maximum":u32::MAX,"default":1}}),
                json!({"name":"page_size","in":"query","schema":{"type":"integer","minimum":1,"maximum":50,"default":20}})]);
        }
        op["parameters"] = json!(parameters);
        if let Some(input) = input {
            op["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":reference(input)}}});
            op["x-original-budget-seconds"] = json!(110);
            op["x-body-byte-limit"] = json!(512 * 1024);
        }
    }
}
