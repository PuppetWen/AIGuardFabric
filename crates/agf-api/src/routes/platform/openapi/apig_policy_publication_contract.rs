//! Native APIG publication projects one numeric limit and never attests consumer enforcement.
use serde_json::{Value, json};

#[path = "apig_policy_publication_schemas.rs"]
mod schemas;

const ROOT: &str = "/api/v1/alicloud/apig/policy-publication";
const OBSERVE: &str = "/api/v1/alicloud/apig/policy-publication/observe";
const PREVIEW: &str = "/api/v1/alicloud/apig/policy-publication/previews";
const APPLY: &str = "/api/v1/alicloud/apig/policy-publication/operations";
const RECEIPT: &str = "/api/v1/alicloud/apig/policy-publication/operations/{request_id}";
const READBACK: &str = "/api/v1/alicloud/apig/policy-publication/operations/{request_id}/observe";
const RECOVER: &str = "/api/v1/alicloud/apig/policy-publication/operations/{request_id}/recover";
const ARCHIVE: &str = "/api/v1/alicloud/apig/policy-publication/operations/archive";

pub(super) fn endpoint_specs() -> Vec<super::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post};
    [
        (ROOT, Get, "getApigPolicyPublication", "只读APIG绑定、可信来源及本地台账"),
        (OBSERVE, Post, "observeApigPolicy", "显式查询既有APIG API、独立策略及挂载"),
        (PREVIEW, Post, "previewApigPolicyPublication", "生成单个可信阈值发布或回滚预览"),
        (APPLY, Post, "applyApigPolicyPublication", "永久领取唯一请求并发送一次策略更新"),
        (RECEIPT, Get, "getApigPolicyPublicationReceipt", "只读原请求的本地因果回执"),
        (READBACK, Post, "observeApigPolicyPublicationReceipt", "显式只读观察原请求的同目标"),
        (RECOVER, Post, "recoverApigPolicyPublicationReceipt", "仅本地恢复原结果及原子审计"),
        (ARCHIVE, Post, "archiveApigPolicyPublicationReceipts", "归档正文并保留永久请求及风险事实"),
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

fn body(properties: Value, required: &[&str]) -> Value {
    json!({"required":true,"content":{"application/json":{"schema":{
        "type":"object","additionalProperties":false,"required":required,"properties":properties}}}})
}

fn observe_body(original: bool) -> Value {
    let initialize = if original {
        json!({"type":"boolean","const":false,"default":false,
            "description":"原请求的只读观察不能初始化；true返回412"})
    } else {
        json!({"type":"boolean","default":false,
            "description":"仅Mock及额外alicloud:write授权的显式POST可初始化精确所属示例；GET从不初始化"})
    };
    body(
        json!({"request_id":{"type":"string","format":"uuid"},
            "configuration_version":{"type":"integer","minimum":1},
            "confirm_live":{"type":"boolean","default":false},"initialize_mock_fixture":initialize}),
        &["request_id", "configuration_version"],
    )
}

pub(super) fn describe(document: &mut Value) {
    for (path, method, response, write) in [
        (ROOT, "get", "ApigPolicyPublicationState", false),
        (OBSERVE, "post", "ApigPolicyObservation", false),
        (PREVIEW, "post", "ApigPolicyPreview", true),
        (APPLY, "post", "ApigPolicyOperation", true),
        (RECEIPT, "get", "ApigPolicyOperation", false),
        (READBACK, "post", "ApigPolicyObservation", false),
        (RECOVER, "post", "ApigPolicyOperation", true),
        (ARCHIVE, "post", "ApigPolicyArchiveResult", true),
    ] {
        let operation = &mut document["paths"][path][method];
        operation["security"] = json!([{"bearerAuth":[]},{"apiKey":[]}]);
        operation["x-required-permissions"] = if write {
            json!(["alicloud:read", "alicloud:write", "policies:read"])
        } else {
            json!(["alicloud:read", "policies:read"])
        };
        operation["responses"]["200"] = json!({"description":"直接安全DTO；云ACK、回读、本地发布是独立阶段，消费者生效未知",
            "content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{response}")}}}});
        for code in ["400", "401", "403", "409", "412", "413", "500", "503", "504"] {
            operation["responses"][code] = json!({"description":"输入、原会话、授权、来源、版本、协议或本地提交失败；无自动重派",
                "content":{"application/problem+json":{"schema":{"$ref":"#/components/schemas/ProblemDetails"}}}});
        }
        if [RECEIPT, READBACK, RECOVER].contains(&path) {
            operation["parameters"] = json!([{"name":"request_id","in":"path","required":true,
                "schema":{"type":"string","format":"uuid"}}]);
            operation["responses"]["404"] = json!({"description":"本租户不存在该操作事实",
                "content":{"application/problem+json":{"schema":{"$ref":"#/components/schemas/ProblemDetails"}}}});
        }
    }
    document["paths"][ROOT]["get"]["parameters"] = json!([
        {"name":"source_page","in":"query","schema":{"type":"integer","minimum":1,"maximum":4_294_967_295_u64,"default":1}},
        {"name":"source_page_size","in":"query","schema":{"type":"integer","minimum":1,"maximum":100,"default":100}},
        {"name":"source_eligible_only","in":"query","schema":{"type":"boolean","default":false}}
    ]);
    document["paths"][ROOT]["get"]["description"] = json!(
        "纯本地读取：不初始化配置/Mock、不调用STS或云、不恢复或追加审计。绑定来自alicloud-apig的明确既有五ID；来源验证完整签名注册表后分页，total为筛选总数，policyCount/eligibleCount为全体总数。未知query返回400。只有符合条件的数值蓝本可投射；没有完整DSL/策略翻译。consumerApplied与sharedPolicyImpact均为null。"
    );
    document["paths"][OBSERVE]["post"]["requestBody"] = observe_body(false);
    document["paths"][OBSERVE]["post"]["x-conditional-permissions"] = json!([
        {"when":{"initialize_mock_fixture":true},"required":["alicloud:write"]}
    ]);
    document["paths"][OBSERVE]["post"]["description"] = json!(
        "当前启用且版本匹配的绑定执行GetHttpApi/GetPolicy/GetPolicyAttachment，核对五ID与唯一deployment。完整证据加密持久，DTO只含身份、hash、字节和可写规则状态。Live需confirm_live，Mock/服务端typed loopback不称Live。基线300秒；失败或淘汰的原UUID不自动查询。显式initialize_mock_fixture仅写授权可seed精确所属Mock tuple，未知目标412，无示例兜底。"
    );
    document["paths"][PREVIEW]["post"]["requestBody"] = body(
        json!({
            "request_id":{"type":"string","format":"uuid"},"configuration_version":{"type":"integer","minimum":1},
            "observation_id":{"type":"string","format":"uuid"},"expected_state_version":{"type":"integer","minimum":0},
            "acknowledge_unknown_operation_id":{"type":"string","format":"uuid"},
            "change":{"oneOf":[
                {"type":"object","additionalProperties":false,"required":["action","policies"],"properties":{
                    "action":{"const":"publish"},"policies":{"type":"array","minItems":1,"maxItems":1,
                        "items":{"$ref":"#/components/schemas/ApigPolicyRevisionInput"}}}},
                {"type":"object","additionalProperties":false,"required":["action","publication_id"],"properties":{
                    "action":{"const":"rollback"},"publication_id":{"type":"string","format":"uuid"}}}]}
        }),
        &["request_id", "configuration_version", "observation_id", "expected_state_version", "change"],
    );
    document["paths"][PREVIEW]["post"]["description"] = json!(
        "纯本地预览：一条当前签名启用的无条件Structured AI网关quota策略，Tenant/minute/deny/soft0、tokens或requests；阈值1..2147483647。只替换独立AiTokenRateLimit现有唯一启用Global minute槽的数值，保留其它规则/metadata，不启用插件、不接受任意正文。非空挂载override拒写。平台Tenant和云API-global计量不同。回滚仅以历史previousLimit投射到新可信基线和同维度当前围栏，保留外部新规则，不回退平台注册表。预览120秒且一次消费。"
    );
    document["paths"][APPLY]["post"]["requestBody"] = body(
        json!({"request_id":{"type":"string","format":"uuid"},"preview_id":{"type":"string","format":"uuid"},
            "expected_state_version":{"type":"integer","minimum":0},
            "confirm_apply":{"type":"boolean"},"confirm_scope_difference":{"type":"boolean"},
            "confirm_shared_policy_impact":{"type":"boolean"},"confirm_no_cloud_cas":{"type":"boolean"},
            "confirm_live":{"type":"boolean","default":false},"confirm_unknown_overlap":{"type":"boolean","default":false}}),
        &[
            "request_id",
            "preview_id",
            "expected_state_version",
            "confirm_apply",
            "confirm_scope_difference",
            "confirm_shared_policy_impact",
            "confirm_no_cloud_cas",
        ],
    );
    document["paths"][APPLY]["post"]["description"] = json!(
        "四项确认必须显式true：执行、范围/周期差异、共享策略影响未知、无云CAS。永久UUID与一次预览领取同审计提交后，新鲜原会话/配置/完整quota围栏守卫下再读基线，仅发送一次UpdatePolicy PUT，独立回读并原子发布本地终态。Accepted ACK+Matched+Published才verified，consumerApplied仍null。无云CAS/版本令牌，最后Get到PUT外部竞态不能消除，独立policy可能影响其它引用。总110秒含排队/STS，driver30秒，lease120秒不续租。相同UUID/hash只返回原事实，异输入409。Unknown永不重派或因后续matched升级；过期本地恢复后须更晚新观察、ack旧UUID和confirm_unknown_overlap才能新独立意图，旧PUT仍可能迟到。风险以tenant+policyId隔离，换账号/挂载/slot不消除。"
    );
    document["paths"][RECEIPT]["get"]["description"] = json!(
        "原租户+UUID纯本地读取，不初始化、调用云/STS或恢复审计。原target/sourcePolicyVersions及云写因果保持，sourceCurrent/恢复字段只反映当前资格。Pending展示可信阶段但不称终态已发布；过期started无pending只投影uncertain，需显式本地recover。"
    );
    document["paths"][READBACK]["post"]["requestBody"] = observe_body(true);
    document["paths"][READBACK]["post"]["description"] = json!(
        "返回新的Observation，后续GET原receipt；启用当前绑定须同targetScopeId且配置版本匹配。只查询三个资源，不发送PUT，不初始化Mock（initialize_mock_fixture=true返回412），不改变原ACK/Unknown/Verified因果。"
    );
    document["paths"][RECOVER]["post"]["requestBody"] = body(json!({}), &[]);
    document["paths"][RECOVER]["post"]["description"] = json!(
        "严格{}，仅本地验证AEAD pending并以新鲜原权限原子发布原终态及唯一Execute审计；无pending且lease过期则明确记录Unknown。当前配置停用或换版仍可恢复；不取凭据、不调STS/云、不重发PUT、不替换原来源，不宣称消费者加载。"
    );
    document["paths"][ARCHIVE]["post"]["requestBody"] = body(
        json!({"expected_generation":{"type":"integer","minimum":0},
            "request_ids":{"type":"array","minItems":1,"maxItems":100,"uniqueItems":true,
                "items":{"type":"string","format":"uuid"}}}),
        &["expected_generation", "request_ids"],
    );
    document["paths"][ARCHIVE]["post"]["description"] = json!(
        "明确generation CAS归档1..100已原子发布且非active终态的加密正文，释放128 detailed-run及64MiB内容容量，该条回滚内容不可再用。永久Fact/原UUID/Unknown风险保留，原成功失败因果不重写，当前云/最新观察不变；云配置停用可仅本地归档。同代次重复已归档项no-op无新审计，旧代次409。"
    );
    schemas::describe(document);
}
