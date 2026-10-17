//! Complete safe observations and local job bindings; no provider job mutation or deployment.
mod callback;
use serde_json::{Value, json};
use utoipa::openapi::path::HttpMethod::{Get, Post, Put};

const ROOT: &str = "/api/v1/alicloud/schedulerx3/native";
const OBSERVE: &str = "/api/v1/alicloud/schedulerx3/native/observe";
const RECEIPT: &str = "/api/v1/alicloud/schedulerx3/native/observations/{id}";
const BINDINGS: &str = "/api/v1/alicloud/schedulerx3/native/bindings";
const ARCHIVE: &str = "/api/v1/alicloud/schedulerx3/native/observations/archive";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    let mut specs: Vec<_> = [
        (ROOT, Get, "getSchedulerNativeState", "读取本地观察与关联，不调用云"),
        (OBSERVE, Post, "observeSchedulerNativeJobs", "显式领取并读取完整应用和任务"),
        (RECEIPT, Get, "getSchedulerNativeObservation", "读取原编号的不可变安全观察页"),
        (BINDINGS, Put, "configureSchedulerNativeBindings", "按版本保存或停用本地任务关联"),
        (ARCHIVE, Post, "archiveSchedulerNativeObservations", "显式归档正文并保留永久编号"),
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
    .collect();
    specs.extend(callback::endpoint_specs());
    specs
}

fn request(schema: &str) -> Value {
    json!({"required":true,"content":{"application/json":{"schema":{
        "$ref":format!("#/components/schemas/{schema}")}}}})
}

pub(super) fn describe(document: &mut Value) {
    super::scheduler_native_schemas::describe(document);
    callback::describe(document);
    for (path, method, schema, write) in [
        (ROOT, "get", "SchedulerNativeState", false),
        (OBSERVE, "post", "SchedulerNativeReceipt", false),
        (RECEIPT, "get", "SchedulerNativeReceipt", false),
        (BINDINGS, "put", "SchedulerNativeBinding", true),
        (ARCHIVE, "post", "SchedulerNativeArchiveResult", true),
    ] {
        let operation = &mut document["paths"][path][method];
        operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        operation["x-required-permissions"] =
            if write { json!(["alicloud:read", "alicloud:write"]) } else { json!(["alicloud:read"]) };
        operation["responses"]["200"] = json!({"description":"安全本地事实；不证明云注册、HTTP配置或部署",
            "content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{schema}")}}}});
        for code in ["400", "401", "403", "409", "412", "500", "503", "504"] {
            operation["responses"][code] = json!({"description":"输入、当前权限、来源、版本、预算或原子出版失败",
                "content":{"application/problem+json":{"schema":{"$ref":"#/components/schemas/ProblemDetails"}}}});
        }
    }
    document["paths"][ROOT]["get"]["description"] = json!(
        "纯本地读取：不读云、STS、初始化Mock、领取、过期处理或追加审计。未观察时total未知，完整零任务才为0。状态展示实际来源和本地关联；callbackBindingEnforced=false，deploymentVerified/callbackConfigured未知。"
    );
    document["paths"][OBSERVE]["post"]["requestBody"] = request("SchedulerNativeObserveInput");
    document["paths"][OBSERVE]["post"]["x-conditional-permissions"] = json!({
        "initialize_mock_fixture=true":["alicloud:read","alicloud:write"]});
    document["paths"][OBSERVE]["post"]["description"] = json!(
        "先永久领取UUID，再用同租户同服务锁、原权限和截止时间读取GetApp及全部ListJobs页。Live明确confirm_live；显式Mock初始化仅固定所属tuple，另需write。最多20页/2000任务/110秒；部分或漂移不出版。旧UUID只回放本地事实，失败、取消、归档也不重新派发。原始AccessToken、HTTP参数/头/脚本只丢弃或保存存在性与摘要，不回显。"
    );
    let receipt = &mut document["paths"][RECEIPT]["get"];
    receipt["parameters"] = json!([
        {"name":"id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}},
        {"name":"page","in":"query","schema":{"type":"integer","minimum":1,"default":1}},
        {"name":"page_size","in":"query","schema":{"type":"integer","minimum":1,"maximum":100,"default":100}}
    ]);
    receipt["responses"]["404"] = json!({"description":"本租户无该观察编号"});
    receipt["description"] = json!(
        "固定原UUID及完整安全快照分页，GET不重读云或恢复出版。过期reading仅投影interrupted。归档后永久保留领取与摘要；正文不可重新采用。未知查询字段/零页/溢出/超出快照返回400。"
    );
    document["paths"][BINDINGS]["put"]["requestBody"] = request("SchedulerNativeBindingInput");
    document["paths"][BINDINGS]["put"]["description"] = json!(
        "严格Replace/Disable标签联合。采用≤300秒完整最新观察中的实际启用HTTP任务，真实AppId由GetApp而非输入取得；≤6唯一kind和唯一正int64字符串JobId。配置/来源和绑定版本必须当前。空关联明确清空，部分关联仅表示部分；保存不创建云任务、部署secret或保护回调。Disable无云来源依赖。"
    );
    document["paths"][ARCHIVE]["post"]["requestBody"] = request("SchedulerNativeArchiveInput");
    document["paths"][ARCHIVE]["post"]["description"] = json!(
        "当前generation CAS，1至100个唯一本租户观察UUID。有效读租约不可归档；过期领取仅本地隔离，不证明云读取已取消。释放详情容量但永久编号不删。停用来源仍可归档；幂等无变化不重复成功审计。"
    );
}
