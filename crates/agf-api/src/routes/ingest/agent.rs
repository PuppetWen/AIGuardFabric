//! 采集器上行端点（`POST /api/v1/ingest/agent`）：mTLS 证书身份 + 既有接入流水线复用。
//!
//! ## 身份来源（两条路，**都走既有 RBAC**）
//!
//! | 来源 | 触发 | 主体与租户 | 权限判定 |
//! |---|---|---|---|
//! | **mTLS 客户端证书** | `AGF_AGENT_MTLS_TRUST_PROXY=1` 且网关透传 `X-SSL-Client-Cert` + `X-SSL-Client-Verify: SUCCESS` | 证书 subject/SAN 经 [`PrincipalMap`] 映射到 **角色 + 租户** | 同 Bearer：`sources:write` |
//! | `Authorization: Bearer` / `X-AGF-Key` | 无证书（或未开代理信任） | 既有 `Principal`（JWT/API Key） | 既有 `Principal::require` |
//!
//! **证书没有映射 ⇒ 403**（不做"有证书就全权"）；`AGF_AGENT_MTLS_REQUIRED=1` 时 Bearer 一律 401；
//! 两条路都不成立 ⇒ 401。证书字节解析见 [`super::agent_cert`]，映射策略见 [`super::agent_mtls`]。
//!
//! ## 载荷怎么进流水线（**复用，不另写一套**）
//!
//! | 载荷 | 去处 | 真实组件 |
//! |---|---|---|
//! | `raw_logs[]`（base64） | `IngestPipeline::ingest_batch`（按协议分桶） | `agf-ingest` 的解析器注册表 + 本地 Sink |
//! | `report`（`AgentReport`） | 同上（作为一条 MCP 载荷），并额外转 `DiscoveryBatch::from_agent_report` 落资产台账 | `agf-asset` 的发现归并（`/api/v1/assets`、`/api/v1/agents` 可观测） |
//!
//! 响应体与 webhook **同口径**（`accepted/total/matched/unmatched/parsers/deduped/event_ids`），直接复用
//! [`agf_ingest::receiver::WebhookReceiver::outcome_summary`]，不复制统计逻辑。
//!
//! ## 已知边界（如实标注）
//!
//! 本地 Sink 是 `InMemorySink`（与 `AppState.ingest_sink` 同款）：进程内、重启即丢，SQL 落库仍由
//! `TODO(ingest-sql-sink)` 承接；资产侧走既有写后持久化桥，**会落 PG**。每租户一份流水线实例
//! （含去重窗口），互不干扰，见 [`super::pipeline_registry`]。

use std::collections::BTreeMap;
use std::sync::Arc;

use agf_core::enums::IngestProtocol;
use agf_core::error::DomainError;
use agf_core::ids::{Id, TenantId};
use agf_ingest::pipeline::IngestOutcome;
use agf_ingest::receiver::WebhookReceiver;
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use agf_core::rbac::SubjectKind;

use crate::error::{ApiError, ApiResult};
use crate::middleware::Principal;
use crate::state::AppState;

use super::agent_body::{AgentUplinkBody, AgentUplinkItem};
use super::agent_cert::cert_from_headers;
use super::agent_mtls::{CertInfo, PrincipalMap, required_from_env, trust_proxy_from_env};
use super::pipeline_registry::{PipelineHandle, collector_source, pipeline_for};

/// 主体占位 id：证书身份没有用户行，但仍要能进 RBAC 判定与审计。
const CERT_SUBJECT_NAMESPACE: &str = "6f9619ff-8b86-d011-b42d-00c04fc964ff";

/// 本端点要求的权限点（与 `/sources`、`/ingest/replay` 同组：接入面写权限）。
const REQUIRED_GROUP: &str = "sources";
/// 本端点要求的动作。
const REQUIRED_ACTION: &str = "write";

/// 单次请求的原始日志条数上限（防御性；`IngestConfig::batch_limit` 另有背压）。
const MAX_RAW_LOGS: usize = 256;

/// 采集器上行路由。
///
/// `content_type` 兜底层把 axum 默认的 **415** 归一为 **400**：采集器上行契约里
/// "体不是 JSON"属于请求非法（400），而不是"媒体类型不受支持"。
pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/ingest/agent", post(ingest_agent)).layer(axum::middleware::from_fn(require_json_content_type))
}

/// 只接受 JSON 体（缺 Content-Type 或非 JSON ⇒ 400）。
async fn require_json_content_type(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let content_type = request
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.contains("json") {
        return ApiError::new(DomainError::Validation(format!(
            "本端点只接受 application/json 请求体（收到 Content-Type={content_type:?}）"
        )))
        .into_response();
    }
    next.run(request).await
}

/// 已通过认证的上行主体。
#[derive(Debug, Clone)]
pub struct AgentPrincipal {
    /// 租户（证书身份来自映射；Bearer/API Key 来自既有 `Principal`）。
    pub tenant: TenantId,
    /// 认证方式（`mtls-cert` / `bearer`）。
    pub auth_mode: &'static str,
    /// 证书身份（`None` = Bearer/API Key）。
    pub cert: Option<CertInfo>,
    /// 实际参与 RBAC 判定的角色列表。
    pub roles: Vec<String>,
    /// 是否超级管理员（**只看既有 RBAC，不接受请求自述**）。
    pub superadmin: bool,
}

impl AgentPrincipal {
    /// 权限判定：证书身份与 Bearer 走**同一条** RBAC 路径（由 [`delegated_principal`] 统一承载）。
    ///
    /// # Errors
    /// 权限不足（403）／首登未改密（412）／跨租户（403）。
    fn require(&self, state: &AppState, delegated: &Principal) -> ApiResult<()> {
        debug_assert_eq!(delegated.tenant, self.tenant, "委派主体的租户必须与上行主体一致");
        delegated.require(state, REQUIRED_GROUP, REQUIRED_ACTION)
    }

    /// 审计展示名（证书身份用 subject，Bearer 用既有 Principal 展示名）。
    #[must_use]
    fn identity_label(&self) -> String {
        self.cert.as_ref().map_or_else(|| "bearer".to_string(), |cert| cert.identity.clone())
    }
}

/// 由证书 subject 派生一个**确定性**主体 id（同一证书跨请求恒定，便于审计串联）。
fn cert_subject_id(label: &str) -> Id {
    let digest = agf_core::secret::content_hash(label);
    // 借 UUID v5 命名空间把 32 位 hex 映射成稳定 UUID（前 32 位足够，碰撞面等价于 SHA-256 前缀）
    let mut bytes = [0_u8; 16];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let hex_pair = digest.get(index * 2..index * 2 + 2).unwrap_or("00");
        *slot = u8::from_str_radix(hex_pair, 16).unwrap_or(0);
    }
    let uuid = uuid::Uuid::new_v5(&uuid::Uuid::parse_str(CERT_SUBJECT_NAMESPACE).unwrap_or(uuid::Uuid::nil()), &bytes);
    Id::from_uuid(uuid)
}

/// 认证结果：证书身份 / Bearer 主体 / 未认证。
enum AuthOutcome {
    Cert(Box<AgentPrincipal>),
    Bearer(Box<Principal>),
    None,
}

/// Replay uses exactly the collector's current certificate/JWT mapping and tenant checks.
pub(crate) async fn replay_principal(headers: &HeaderMap, state: &AppState) -> ApiResult<Principal> {
    let principal = match authenticate(headers, state).await? {
        AuthOutcome::Cert(agent) => delegated_principal(&agent),
        AuthOutcome::Bearer(principal) => *principal,
        AuthOutcome::None => return Err(DomainError::Unauthenticated("Collector credentials required".into()).into()),
    };
    principal.require(state, REQUIRED_GROUP, REQUIRED_ACTION)?;
    if !crate::tenant_directory::get(state, principal.tenant).await?.enabled {
        return Err(DomainError::Forbidden("Tenant is disabled".into()).into());
    }
    Ok(principal)
}

/// 采集器上行（`POST /api/v1/ingest/agent`）。
///
/// **刻意不用 `Principal` 提取器**：本端点要优先按 mTLS 证书识别主体，而提取器在缺凭据时
/// 会直接以 401 短路。这里手工调用同一套提取逻辑，以便"证书身份 → Bearer → 无凭据"依次尝试。
///
/// # Errors
/// 未认证（401）、证书无映射或权限不足（403）、载荷非法（400）。
pub async fn ingest_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<AgentUplinkBody>>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = authenticate(&headers, &state).await?;
    let (principal, delegated) = match &auth {
        AuthOutcome::Cert(agent) => (agent.as_ref().clone(), delegated_principal(agent)),
        AuthOutcome::Bearer(principal) => (
            AgentPrincipal {
                tenant: principal.tenant,
                auth_mode: "bearer",
                cert: None,
                roles: principal.roles.clone(),
                superadmin: principal.superadmin,
            },
            principal.as_ref().clone(),
        ),
        AuthOutcome::None => {
            return Err(ApiError::new(DomainError::Unauthenticated(format!(
                "缺少认证凭据：请出示 mTLS 客户端证书，或提供 `Authorization: Bearer <JWT>` / `X-AGF-Key`\
                 （本端点默认要求认证；证书身份需要 {ENV_HINT}）"
            ))));
        }
    };
    principal.require(&state, &delegated)?;
    if !crate::tenant_directory::get(&state, principal.tenant).await?.enabled {
        return Err(DomainError::Forbidden("租户已停用，采集器不能继续上报".into()).into());
    }

    let Some(Json(body)) = body else {
        return Err(ApiError::new(DomainError::Validation("请求体为空或不是合法 JSON".to_string())));
    };
    ingest_body(&state, &principal, body).await
}

/// 用既有 `Principal` 提取器解析 Bearer/API Key（复用同一套校验逻辑）。
async fn bearer_principal(headers: &HeaderMap, state: &AppState) -> ApiResult<Principal> {
    let request = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/api/v1/ingest/agent")
        .body(())
        .map_err(|e| ApiError::new(DomainError::Internal(format!("内部请求构造失败: {e}"))))?;
    let (mut parts, ()) = request.into_parts();
    parts.headers = headers.clone();
    // 直接调用 trait 实现，避免把请求体真正喂给提取器（证书路径不需要读体）
    <Principal as axum::extract::FromRequestParts<AppState>>::from_request_parts(&mut parts, state).await
}

/// 认证：证书优先（显式配置代理信任时），否则回落 Bearer/API Key。
async fn authenticate(headers: &HeaderMap, state: &AppState) -> ApiResult<AuthOutcome> {
    let has_credentials = headers.contains_key(axum::http::header::AUTHORIZATION) || headers.contains_key("x-agf-key");
    if trust_proxy_from_env() {
        if let Some(cert) = cert_from_headers(headers)? {
            let map = PrincipalMap::from_env();
            let Some((role, tenant)) = map.resolve(&cert) else {
                // **不默认全权**：证书可信但没有映射 ⇒ 如实拒绝
                return Err(ApiError::new(DomainError::Forbidden(format!(
                    "mTLS 客户端证书未映射到任何租户/角色（subject={}）：请配置 AGF_AGENT_MTLS_MAP 后重试",
                    cert.subject
                ))));
            };
            return Ok(AuthOutcome::Cert(Box::new(AgentPrincipal {
                tenant,
                auth_mode: "mtls-cert",
                cert: Some(cert),
                roles: vec![role],
                superadmin: false,
            })));
        }
    }
    if required_from_env() {
        return Err(ApiError::new(DomainError::Unauthenticated(format!(
            "本端点已配置只接受 mTLS 证书身份（AGF_AGENT_MTLS_REQUIRED=1）：Bearer/API Key 一律拒绝\
             （收到{}）",
            if has_credentials { " Bearer/API Key" } else { "无凭据" }
        ))));
    }
    match bearer_principal(headers, state).await {
        Ok(principal) => Ok(AuthOutcome::Bearer(Box::new(principal))),
        Err(error) => {
            if has_credentials {
                Err(error)
            } else {
                Ok(AuthOutcome::None)
            }
        }
    }
}

/// 证书身份 → 既有 `Principal`（供 `require` 与审计复用同一套路径）。
fn delegated_principal(agent: &AgentPrincipal) -> Principal {
    Principal {
        subject_id: Some(cert_subject_id(&agent.identity_label())),
        agent_id: None,
        subject_kind: SubjectKind::Service,
        tenant: agent.tenant,
        identity_tenant: agent.tenant,
        roles: agent.roles.clone(),
        superadmin: agent.superadmin,
        must_change_password: false,
        must_setup_mfa: false,
        session_id: None,
        scopes: Vec::new(),
        source_ip: None,
        user_agent: None,
        department: None,
    }
}

/// 环境变量提示串（错误文本里用，避免多处硬编码）。
const ENV_HINT: &str = "AGF_AGENT_MTLS_TRUST_PROXY=1 + AGF_AGENT_MTLS_MAP";

/// 把请求体送进既有接入流水线并组装响应。
async fn ingest_body(
    state: &AppState,
    principal: &AgentPrincipal,
    body: AgentUplinkBody,
) -> ApiResult<Json<serde_json::Value>> {
    let items = collect_items(&body)?;
    if items.is_empty() && body.report.is_none() {
        return Err(ApiError::new(DomainError::Validation(
            "请求体没有任何可接入载荷：请提供 raw_logs / logs（至少一条）或 report".to_string(),
        )));
    }
    // 先完整校验资产报告与扩展字段；坏数据不能留下已落库的半份上报。
    let prepared = if let Some(value) = &body.report {
        Some(super::agent_report_safety::prepare(principal.tenant, value, &body.extras)?)
    } else {
        if !body.extras.is_null() {
            return Err(DomainError::Validation("extras 必须与 report 一起提交".into()).into());
        }
        None
    };
    let handle = pipeline_for(state, principal.tenant).await?;
    let source = collector_source(principal.tenant, &body);
    let peer = agf_ingest::pipeline::TransportPeer { ip: None, mutual_tls: principal.cert.is_some() };

    // ① 原始日志：按协议分桶后交给既有流水线
    let mut outcomes: Vec<IngestOutcome> = Vec::new();
    let mut by_protocol: BTreeMap<&'static str, (IngestProtocol, Vec<(Vec<u8>, String)>)> = BTreeMap::new();
    for item in &items {
        let bytes = item.decode()?;
        let protocol = item.protocol();
        let origin = item.origin.clone().unwrap_or_else(|| body.origin_label());
        by_protocol.entry(protocol.as_str()).or_insert_with(|| (protocol, Vec::new())).1.push((bytes, origin));
    }
    for (_, (protocol, batch)) in by_protocol {
        let batch_outcomes =
            handle.pipeline.ingest_batch_from(&source, protocol, &batch, peer).await.map_err(ApiError::new)?;
        outcomes.extend(batch_outcomes);
    }

    // ② Agent 资产上报：同一条流水线（可见于回放/解析统计）+ 既有发现归并入资产台账
    let asset_stats: Option<agf_asset::service::IngestStats> = match prepared {
        Some((text, batch)) => {
            let report_outcomes = handle
                .pipeline
                .ingest_batch_from(
                    &source,
                    IngestProtocol::Mcp,
                    &[(text.into_bytes(), "agent-report".to_string())],
                    peer,
                )
                .await
                .map_err(ApiError::new)?;
            outcomes.extend(report_outcomes);
            Some(state.store.asset_ingest_durable(principal.tenant, &batch).await?)
        }
        None => None,
    };

    let response = summarize(principal, &outcomes, asset_stats.as_ref(), &handle).await?;
    state
        .audit(
            principal.tenant,
            agf_core::audit::AuditAction::Create,
            agf_core::audit::AuditOutcome::Success,
            audit_actor(principal),
            agf_core::audit::AuditTarget::new("collector-uplink", body.collector_key(), None),
            &format!(
                "采集器上行（{}）：载荷 {} 条、命中 {} 条、事件 {} 个、去重 {} 条；证书主体 {}",
                principal.auth_mode,
                response.get("total").and_then(serde_json::Value::as_u64).unwrap_or(0),
                response.get("matched").and_then(serde_json::Value::as_u64).unwrap_or(0),
                response.get("accepted").and_then(serde_json::Value::as_u64).unwrap_or(0),
                response.get("deduped").and_then(serde_json::Value::as_u64).unwrap_or(0),
                principal.identity_label()
            ),
        )
        .await?;
    Ok(Json(response))
}

/// 审计主体（证书身份用 service 类型 + subject 名）。
fn audit_actor(principal: &AgentPrincipal) -> agf_core::audit::AuditActor {
    agf_core::audit::AuditActor {
        id: Some(cert_subject_id(&principal.identity_label())),
        kind: if principal.cert.is_some() { "service".to_string() } else { "api-key".to_string() },
        name: format!("collector-uplink:{}", principal.identity_label()),
        source_ip: None,
        user_agent: None,
        session_id: None,
    }
}

/// 汇总响应（复用 webhook 的 `outcome_summary`，口径完全一致）。
async fn summarize(
    principal: &AgentPrincipal,
    outcomes: &[IngestOutcome],
    asset_stats: Option<&agf_asset::service::IngestStats>,
    handle: &Arc<PipelineHandle>,
) -> ApiResult<serde_json::Value> {
    let mut summary = WebhookReceiver::outcome_summary(outcomes);
    if let Some(map) = summary.as_object_mut() {
        map.insert("deduped".to_string(), serde_json::Value::from(outcomes.iter().filter(|o| o.deduped).count()));
        map.insert(
            "event_ids".to_string(),
            serde_json::Value::from(
                outcomes.iter().filter_map(|o| o.event_id).map(|id| id.to_string()).collect::<Vec<_>>(),
            ),
        );
        map.insert("tenant".to_string(), serde_json::Value::from(principal.tenant.to_string()));
        map.insert("auth_mode".to_string(), serde_json::Value::from(principal.auth_mode));
        map.insert("roles".to_string(), serde_json::Value::from(principal.roles.clone()));
        map.insert(
            "identity".to_string(),
            serde_json::json!({
                "subject": principal.cert.as_ref().map(|c| c.subject.clone()),
                "common_name": principal.cert.as_ref().and_then(|c| c.common_name.clone()),
                "organization": principal.cert.as_ref().and_then(|c| c.organization.clone()),
                "san": principal.cert.as_ref().map(|c| c.san.clone()).unwrap_or_default(),
                "fingerprint_sha256": principal.cert.as_ref().map(|c| c.fingerprint_sha256.clone()),
                "identity": principal.identity_label(),
            }),
        );
        map.insert(
            "sink".to_string(),
            serde_json::json!({
                "backend": handle.sink.backend(),
                "events_total": handle.sink.event_count(principal.tenant).await?,
                "raw_total": handle.sink.raw_count(principal.tenant).await?,
                "note": if handle.sink.backend() == "sql" { "数据库持久化，与日志回放共用仓储" } else { "离线内存模式，重启清空" },
            }),
        );
        if let Some(stats) = asset_stats {
            // 资产侧统计**平铺**进响应（`assets_created` / `assets_updated` / …），
            // 与 webhook 同口径的顶层字段保持并列，不嵌套一层。
            let value = serde_json::to_value(stats).unwrap_or(serde_json::Value::Null);
            if let Some(object) = value.as_object() {
                for (key, item) in object {
                    map.insert(format!("assets_{key}"), item.clone());
                }
            }
        }
    }
    Ok(summary)
}

/// 收集请求体里的载荷（`raw_logs` + `logs`，上限 [`MAX_RAW_LOGS`]）。
fn collect_items(body: &AgentUplinkBody) -> ApiResult<Vec<AgentUplinkItem>> {
    let mut items: Vec<AgentUplinkItem> = Vec::new();
    items.extend(body.raw_logs.iter().cloned());
    items.extend(body.logs.iter().cloned());
    if let Some(text) = body.source.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        items.push(AgentUplinkItem {
            text: Some(text.to_string()),
            origin: Some("agent-uplink".to_string()),
            ..Default::default()
        });
    }
    if items.len() > MAX_RAW_LOGS {
        return Err(ApiError::new(DomainError::Validation(format!(
            "单次上行载荷不能超过 {MAX_RAW_LOGS} 条（收到 {}）",
            items.len()
        ))));
    }
    Ok(items)
}

/// 本端点的 OpenAPI 描述（供 `platform::endpoint_specs()` 合并）。
#[must_use]
pub(crate) fn endpoint_specs() -> Vec<crate::routes::platform::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::Post;
    vec![crate::routes::platform::EndpointSpec {
        path: "/api/v1/ingest/agent",
        method: Post,
        id: "ingestAgentUplink",
        summary: "采集器上行（mTLS 证书身份 / Bearer；复用接入流水线）",
        tag: "sources",
        implemented: true,
    }]
}

/// 测试/排障用：本端点流水线的事件总数（**只读**，不改变任何状态）。
pub async fn pipeline_event_count(state: &AppState, tenant: TenantId) -> agf_core::error::DomainResult<u64> {
    state.ingest_sink.event_count(tenant).await
}
