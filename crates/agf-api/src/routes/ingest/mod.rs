//! Tenant-scoped persisted log sources, parser previews, replay and authenticated collector uplink.

use std::sync::Arc;

use agf_core::enums::IngestProtocol;
use agf_core::error::{DomainError, DomainResult};
use agf_core::event::{Event, RawLog};
use agf_core::ids::{Id, TenantId};
use agf_ingest::pipeline::{Sink, decode_payload};
use agf_ingest::receiver::{ReceiverDescriptor, receiver_capability_matrix};
use agf_ingest::registry::engine_support_matrix;
use agf_ingest::replay::{ReplayConfig, Replayer};
use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::routing::get;
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};
use crate::middleware::Principal;
use crate::query::ListQuery;
use crate::routes::parse_id;
use crate::state::AppState;

/// 接入源与解析器路由。
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/sources", get(list_sources).post(create_source))
        .route("/sources/capabilities", get(source_capabilities))
        .route("/sources/delivery", get(delivery::status))
        .route("/sources/broker/quarantine", get(broker_operations::list))
        .route("/sources/broker/quarantine/{id}", get(broker_operations::detail))
        .route("/sources/broker/quarantine/{id}/history", get(broker_operations::history))
        .route("/sources/broker/quarantine/{id}/{action}", axum::routing::post(broker_operations::act))
        .route("/sources/analysis/failures", get(analysis_operations::list))
        .route("/sources/analysis/failures/{id}/history", get(analysis_operations::history))
        .route("/sources/analysis/failures/{id}/{action}", axum::routing::post(analysis_operations::act))
        .route("/ingest/events/{id}", get(evidence::event))
        .route("/sources/{id}", get(get_source).put(update_source).patch(toggle_source).delete(delete_source))
        .route("/parsers", get(list_parsers).post(parser_config::create))
        .route("/parsers/validate", axum::routing::post(parser_config::validate))
        .route("/parsers/suggest", axum::routing::post(parser_inference::suggest))
        .route("/parsers/stats", get(parser_stats))
        .route("/parsers/engine-matrix", get(engine_matrix))
        .route("/parsers/{id}", get(get_parser).put(parser_config::update).delete(parser_config::delete))
        .route("/parsers/{id}/history", get(parser_config::history))
        .route("/parsers/{id}/restore", axum::routing::post(parser_config::restore))
        .route("/parsers/{id}/preview", get(parser_preview::preview))
        .route("/parsers/{id}/test", axum::routing::post(parser_preview::test_sample))
        // 采集器上行（`agent` 模块自带 router；这里合并以保持"接入面路由"集中在一处）
        .merge(agent::router())
}

/// 本资源组的端点清单（OpenAPI 用；`platform::endpoint_specs` 会合并进去）。
#[must_use]
pub fn endpoint_specs() -> Vec<crate::routes::platform::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod as Method;
    let mut specs = agent::endpoint_specs();
    for (path, method, operation_id, summary) in [
        ("/api/v1/parsers", Method::Post, "createParser", "保存租户解析模板"),
        ("/api/v1/parsers/validate", Method::Post, "validateParser", "校验待保存模板和样本"),
        ("/api/v1/parsers/suggest", Method::Post, "suggestParser", "依据脱敏样本生成解析草案"),
        ("/api/v1/parsers/{id}", Method::Put, "updateParser", "编辑租户解析模板"),
        ("/api/v1/parsers/{id}", Method::Delete, "deleteParser", "删除租户解析模板"),
        ("/api/v1/parsers/{id}/history", Method::Get, "parserHistory", "解析模板版本历史"),
        ("/api/v1/parsers/{id}/restore", Method::Post, "restoreParser", "恢复解析模板版本"),
        ("/api/v1/sources", Method::Post, "createSource", "保存日志源"),
        ("/api/v1/sources/delivery", Method::Get, "eventDeliveryStatus", "本租户事件投递与分析进度"),
        ("/api/v1/sources/broker/quarantine", Method::Get, "brokerQuarantine", "平台异常消息隔离队列"),
        ("/api/v1/sources/broker/quarantine/{id}", Method::Get, "brokerEvidence", "管理员查看加密原始消息"),
        ("/api/v1/sources/broker/quarantine/{id}/history", Method::Get, "brokerRecoveryHistory", "异常消息操作历史"),
        ("/api/v1/sources/broker/quarantine/{id}/retry", Method::Post, "retryBrokerMessage", "人工重试原始事件引用"),
        (
            "/api/v1/sources/broker/quarantine/{id}/dismiss",
            Method::Post,
            "dismissBrokerMessage",
            "保留证据并关闭异常消息",
        ),
        ("/api/v1/sources/analysis/failures", Method::Get, "analysisFailures", "事件失败队列与状态筛选"),
        ("/api/v1/sources/analysis/failures/{id}/retry", Method::Post, "retryAnalysis", "按版本重新排队分析"),
        ("/api/v1/sources/analysis/failures/{id}/pause", Method::Post, "pauseAnalysis", "按版本暂停后续分析重试"),
        (
            "/api/v1/sources/analysis/failures/{id}/history",
            Method::Get,
            "analysisRecoveryHistory",
            "持久化恢复操作历史",
        ),
        ("/api/v1/ingest/events/{id}", Method::Get, "eventEvidence", "归一化来源事件证据"),
        ("/api/v1/sources/{id}", Method::Put, "updateSource", "编辑日志源"),
        ("/api/v1/sources/{id}", Method::Patch, "toggleSource", "启停日志源"),
        ("/api/v1/sources/{id}", Method::Delete, "deleteSource", "删除日志源配置"),
        ("/api/v1/ingest/sources", Method::Post, "createIngestSource", "保存日志源"),
        ("/api/v1/ingest/sources/{id}", Method::Get, "getIngestSource", "日志源详情"),
        ("/api/v1/ingest/sources/{id}", Method::Put, "updateIngestSource", "编辑日志源"),
        ("/api/v1/ingest/sources/{id}", Method::Patch, "toggleIngestSource", "启停日志源"),
        ("/api/v1/ingest/sources/{id}", Method::Delete, "deleteIngestSource", "删除日志源配置"),
        ("/api/v1/ingest/sources/{id}/events", Method::Post, "pushSourceEvents", "认证推送日志"),
        ("/api/v1/ingest/sources/{id}/poll", Method::Post, "pollSource", "立即拉取日志"),
    ] {
        specs.push(crate::routes::platform::EndpointSpec {
            path,
            method,
            id: operation_id,
            summary,
            tag: if path.contains("/parsers") { "parsers" } else { "sources" },
            implemented: true,
        });
    }
    specs
}

// 采集器上行的对外可见面（显式列举而非 `pub use agent::*`：`unreachable_pub` 只在
// 显式重导出下才认得出"这个 pub 真的可达"）。`agent::router` / `agent::endpoint_specs`
// 由本模块内部使用，因此那两个保持 `pub(crate)`。
pub(crate) use agent::replay_principal as agent_replay_principal;
pub use agent::{AgentPrincipal, ingest_agent, pipeline_event_count};
// 上行请求体契约（信封与载荷项）——对外可见，便于控制台/脚本按同一份契约构造请求。
pub use agent_body::{AgentUplinkBody, AgentUplinkItem};
// 证书身份的纯函数（解析 / 主体映射 / 门禁）对外可见：既供集成测试断言，
// 也供运维按同一套规则复核"证书主体 → 角色/租户"的映射。
// `agent_mtls` 负责头部契约与主体映射，`agent_cert` 负责字节级解析（PEM/DER → subject/SAN）。
pub use agent_cert::*;
pub use agent_mtls::*;
pub use configured_sources::*;
pub use replay::*;
pub use sources::*;

mod agent;
mod agent_body;
mod agent_cert;
mod agent_extras;
mod agent_mtls;
mod agent_report_safety;
mod analysis_operations;
mod broker_operations;
mod configured_sources;
mod delivery;
mod parser_config;
mod parser_inference;
mod parser_preview;
mod pipeline_registry;
mod replay;
mod sources;

mod evidence;
