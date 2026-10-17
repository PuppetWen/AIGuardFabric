//! 中间件与请求上下文：请求 id、tracing span、限流、幂等、认证主体提取。
//!
//! ## 三级限流
//!
//! 进程内令牌桶，三个维度独立计数（任一超限即 429）：
//! 1. `global` —— 整个进程；
//! 2. `tenant` —— 按租户；
//! 3. `identity` —— 按 API Key / JWT 主体（无凭据时退化为来源地址）。
//!
//! 响应始终带 `X-RateLimit-Limit` / `X-RateLimit-Remaining` / `X-RateLimit-Reset`
//! （取最紧的一级），超限时额外带 `Retry-After`。
//!
//! ## 幂等
//!
//! `Idempotency-Key` 绑定身份、租户、实际 URI、方法、请求字节和业务头。
//! 返回历史响应前重验认证、权限和 ABAC 上下文；并发/不确定状态返回 409。
//! 普通回执为有界进程内存，完成后 TTL 900 秒；红队提交使用独立持久化契约。
//! 流式/过大响应完整返回但不缓存；凭据与认证端点拒绝通用重放。见 docs/http-retry-guide.md。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use agf_core::constants::{
    HEADER_API_KEY, HEADER_IDEMPOTENCY_KEY, HEADER_RATE_LIMIT_LIMIT, HEADER_RATE_LIMIT_REMAINING,
    HEADER_RATE_LIMIT_RESET, HEADER_REQUEST_ID, HEADER_TENANT,
};
use agf_core::error::DomainError;
use agf_core::ids::{Id, TenantId};
use agf_core::rbac::{AccessRequest, Permission, SubjectKind};
use axum::body::Body;
use axum::extract::{FromRequestParts, MatchedPath, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use tracing::{Instrument, warn};

use crate::error::{ApiError, REQUEST_ID};
use crate::state::AppState;

/// 请求体缓冲上限（幂等与审计用；与 `AGF_MAX_BODY_BYTES` 独立）。
pub(super) const BODY_BUFFER_LIMIT: usize = 16 * 1024 * 1024;

pub use context::*;
pub use idempotency::*;
pub use idempotency_store::{IdempotencyStore, StoredResponse};
pub use principal::*;
pub use ratelimit::*;

pub(crate) mod client_address;
mod context;
mod idempotency;
mod idempotency_store;
mod principal;
mod ratelimit;
