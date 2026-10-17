//! AI 资产只读投影：Agent、MCP、Skill 和模型端点共用持久化资产台账。
//!
//! 列表返回分页信封，按 name 默认升序，支持台账筛选、排序和 fields。
//! 前端传输层规范化 snake_case；字段的 null 必须保留。
//! /mcps 和 /mcp-servers 是同一组处理器，权限分别为 agents/mcps/skills/models:read。
//! 详情类型不匹配或跨租户不可见返回 404。
//!
//! 观察与测量语义：
//! - online 是兼容字段名，仅表示可用生命周期内的近期发现观察，不能证明运行时在线。
//!   未观察或未来时间为 null；窗口为有效心跳间隔的三倍，缺省 300 秒。
//! - lastHeartbeatAt 同样为兼容字段名，来自 last_seen_at，不回退资料编辑时间。
//! - 会话/工具/挂载数、单价、优先级和延迟缺少或类型无效时为 null，真实零保留。
//! - MCP 未知协议为 unknown；风险只来自保存的评估，不用暴露面评分代替。
//! - 台账投影不主动探测外部服务。MCP HTTP 发现、审批与路由策略分别使用专用写入口。

use agf_core::asset::Asset;
use agf_core::enums::{AssetKind, LifecycleState};
use agf_core::error::DomainError;
use agf_core::time::Timestamp;
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult};
use crate::middleware::Principal;
use crate::query::ListQuery;
use crate::routes::parse_id;
use crate::state::AppState;

/// 四组资源路由。
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/agents", get(list_agents))
        .route("/agents/{id}", get(get_agent))
        .route("/mcps", get(list_mcps))
        .route("/mcps/{id}", get(get_mcp))
        // 别名：控制台调的是 /mcp-servers（PV-024），与 /mcps 共用处理器
        .route("/mcp-servers", get(list_mcps))
        .route("/mcp-servers/{id}", get(get_mcp))
        .route("/skills", get(list_skills))
        .route("/skills/{id}", get(get_skill))
        .route("/models/endpoints", get(list_model_endpoints))
        .route("/models/endpoints/{id}", get(get_model_endpoint))
}

use group::*;
pub use handlers::*;
pub use views::*;

mod group;
mod handlers;
mod projections;
mod views;

use projections::*;
pub(crate) use projections::{skill_status, skill_view};
