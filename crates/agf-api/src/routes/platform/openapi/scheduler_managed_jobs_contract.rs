//! Managed job operations do not attest callback deployment or business execution.
use serde_json::{Value, json};

#[path = "scheduler_managed_jobs_schemas.rs"]
mod schemas;

const ROOT: &str = "/api/v1/alicloud/schedulerx3/native/jobs";
const PREVIEW: &str = "/api/v1/alicloud/schedulerx3/native/jobs/previews";
const PREVIEW_RECEIPT: &str = "/api/v1/alicloud/schedulerx3/native/jobs/previews/{id}";
const OPERATION: &str = "/api/v1/alicloud/schedulerx3/native/jobs/operations/{id}";
const READBACK: &str = "/api/v1/alicloud/schedulerx3/native/jobs/operations/{id}/observe";
const RECOVER: &str = "/api/v1/alicloud/schedulerx3/native/jobs/operations/{id}/recover";
const ARCHIVE: &str = "/api/v1/alicloud/schedulerx3/native/jobs/operations/archive";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post, Put};
    [
        (ROOT, Get, "getSchedulerManagedJobs", "只读Scheduler受管任务台账"),
        (PREVIEW, Post, "previewSchedulerManagedJob", "准备单个任务差异预览"),
        (PREVIEW_RECEIPT, Get, "getSchedulerManagedJobPreview", "读取原预览或归档墓碑"),
        (OPERATION, Put, "applySchedulerManagedJob", "永久领取唯一UUID并管理一个任务"),
        (OPERATION, Get, "getSchedulerManagedJobOperation", "纯读原任务操作回执"),
        (READBACK, Post, "observeSchedulerManagedJobOperation", "显式独立观察原任务"),
        (RECOVER, Post, "recoverSchedulerManagedJobOperation", "仅本地恢复原结果与审计"),
        (ARCHIVE, Post, "archiveSchedulerManagedJobs", "归档正文并保留UUID事实"),
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
        (ROOT, "get", "SchedulerManagedState", None, false),
        (PREVIEW, "post", "SchedulerManagedPreview", Some("SchedulerManagedPreviewInput"), true),
        (PREVIEW_RECEIPT, "get", "SchedulerManagedPreview", None, false),
        (OPERATION, "put", "SchedulerManagedOperation", Some("SchedulerManagedApplyInput"), true),
        (OPERATION, "get", "SchedulerManagedOperation", None, false),
        (READBACK, "post", "SchedulerManagedOperation", Some("SchedulerManagedEmptyInput"), true),
        (RECOVER, "post", "SchedulerManagedOperation", Some("SchedulerManagedEmptyInput"), true),
        (ARCHIVE, "post", "SchedulerManagedArchiveResult", Some("SchedulerManagedArchiveInput"), true),
    ] {
        let operation = &mut document["paths"][path][method];
        operation["security"] =
            if write { json!([{"bearerAuth":[]}]) } else { json!([{"bearerAuth":[]},{"apiKey":[]}]) };
        operation["x-required-permissions"] =
            if write { json!(["platform:admin", "alicloud:read", "alicloud:write"]) } else { json!(["alicloud:read"]) };
        if write {
            operation["x-required-subject-kind"] = json!("user");
        }
        operation["responses"]["200"] = json!({"description":"安全DTO；ACK、独立回读及本地完成互不替代，callback/消费者部署未知",
            "content":{"application/json":{"schema":reference(response)}}});
        for code in ["400", "401", "403", "409", "412", "500", "503", "504"] {
            operation["responses"][code] = json!({"description":"字段、原权限、来源/绑定/版本、协议或本地提交失败；没有业务补跑",
                "content":{"application/problem+json":{"schema":reference("ProblemDetails")}}});
        }
        if let Some(input) = input {
            operation["requestBody"] =
                json!({"required":true,"content":{"application/json":{"schema":reference(input)}}});
            operation["x-max-body-bytes"] = json!(65_536);
        }
        if path.contains("{id}") {
            operation["parameters"] = json!([{"name":"id","in":"path","required":true,
                "schema":{"type":"string","format":"uuid","not":{"const":"00000000-0000-0000-0000-000000000000"}}}]);
            operation["responses"]["404"] = json!({"description":"本租户没有该原预览/操作事实",
                "content":{"application/problem+json":{"schema":reference("ProblemDetails")}}});
        }
    }
    document["paths"][ROOT]["get"]["description"] = json!(
        "本地statement一致性有界台账：不调用GetApp/ListJobs/STS、不seed Mock、不延长租约、不修复或发送任务。复用原native观察/绑定；已保存定义不代表callback启用。"
    );
    document["paths"][PREVIEW]["post"]["description"] = json!(
        "管理要求当前管理员User+platform:admin/alicloud读写；引用当前完整成功native观察(300秒仅采用)和binding CAS。6类固定kind，report/archive映射report-generate/cold-archive。Mock可明确CreateDisabled(total=1)，Live HTTP carrier没有官方可写合同，CreateJob明确412。已有Live HTTP Job仅update_schedule/disable/enable；编辑调度须先独立停用，不隐式启停，不接受Parameters/JobHandler/凭据/URL。selection是规范正int64字符串，不能用浮点ID。"
    );
    document["paths"][PREVIEW_RECEIPT]["get"]["description"] =
        json!("纯本地原UUID读取；过期/已消费预览不能应用，归档只剩有身份和指纹的墓碑，不初始化或重新预览。");
    document["paths"][OPERATION]["put"]["description"] = json!(
        "路径id是永久requestUUID；同UUID异purpose/body/actor冲突409，原UUID不得更号重派。确认无云CAS与callback未知、Live显式确认。原110秒包含队列/STS和driver30秒；当前source/binding/完整基线再验后只发送一个管理动作。ACK后独立回读不升级Unknown；审计失败保可信pending仅本地恢复。风险资源tenant+cluster/app不随账号/region/endpoint/mode/source版本标签分裂。可能迟到的Unknown只能明确新意图重叠确认，非自动重试。没有云CAS或外部业务恰好一次保证。"
    );
    document["paths"][OPERATION]["get"]["description"] = json!(
        "原UUID纯本地读取，保原source/actor/claim和ACK因果；sourceCurrent nullable及allowedActions是当前资格，不是重新发送许可。"
    );
    document["paths"][READBACK]["post"]["description"] = json!(
        "严格{}，管理员显式重新GetApp+完整ListJobs观察原目标；返回原operation带独立readback。不是管理动作，不seed、不改原Unknown/ACK，不证明callback或consumer。"
    );
    document["paths"][RECOVER]["post"]["description"] = json!(
        "严格{}，当前原权限验证AEAD known阶段并原子固定本地终态/唯一Execute审计。没有pending且lease到期则固定Unknown；不读云/STS、不发管理请求，来源停用仍可读旧事实。"
    );
    document["paths"][ARCHIVE]["post"]["description"] = json!(
        "明确丢失预览正文，generation CAS每批1..48，使每项两related加journal仍在100相关记录界限。永久请求/purpose/Unknown风险保留，墓碑可读；不删除云任务、不授予callback执行。"
    );
    schemas::describe(document);
}
