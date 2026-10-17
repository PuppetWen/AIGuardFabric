//! 厂商适配器通用实现：`VendorSpec`（厂商差异）→ [`VendorAdapterImpl`]（契约落地）。
//!
//! 一个厂商模块只需实现 [`VendorSpec`]：元信息 + 载荷编码 + 响应解析（+ 必要时覆写真实调用）。
//! 契约行为——熔断、重试、健康、模式判定、Mock 确定性、幂等关闭、
//! `agf_core::adapter::Adapter` 的七个方法——全部在本模块统一实现，
//! 因此**不存在"某个厂商忘了包熔断"的可能**（对齐 spec §2.6 的三条硬约束）。
//!
//! `Live` 模式的真实传输默认由 [`crate::http::execute`] 统一完成（HTTP 往返 + 状态码分类），
//! 非 HTTP 通道（Syslog UDP/TCP）由厂商覆写 [`VendorSpec::invoke_live`]。
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | `send()` | `push()/pull()/sync()` |
//! |---|---|---|
//! | 未配置（缺凭据/必需设置） | `Err(Config)`，列出缺项清单，**不建连不发包** | `Err(Config)`，带缺项清单 |
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | `Ok(确定性回执)`，`mocked=true`，**绝不发起真实调用**（不依赖真实 endpoint/凭据；载荷缺字段仍报 `Validation`） | `Ok(确定性降级结果)`，`mocked=true`，warnings 说明未触达真实系统 |
//! | `Live` 且已登记该语义 | 真实 HTTP/UDP/TCP 往返；失败经熔断 + 重试后**如实报错**（5xx 可重试、4xx 不重试） | 同左（`push`/`pull`/`sync` 都走同一套熔断 + 重试） |
//! | `Live` 但**未登记**该语义（[`SemanticSupport::Unsupported`]） | —— | `Err(Validation)`，带**不适用原因**（**不可重试**：语义不适用，重试不会变好）。内置 12 个适配器**不得**留 `NotImplemented` 占位（有单测守住） |
//! | `Live` 且真实传输未实现（新增适配器脚手架） | `Err(NotImplemented)`，带 `TODO(<锚点>)` 锚点 | 同左（`SemanticProfile::undeclared`） |
//! | 已 `close()` | `Err(PreconditionFailed)` | 同左 |
//!
//! [`VendorSpec::REAL_TRANSPORT`] 为 `false` 的适配器在 `Live` 模式下健康状态是
//! `Unavailable`（如实标注不可用）；已实现真实传输的适配器按熔断态给出
//! `Available`/`Degraded`——这是**如实登记**，不是缺陷（见 `docs/adapter-spec.md` §5.3）。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::fmt;

pub(crate) use std::future::Future;

pub(crate) use std::marker::PhantomData;

pub(crate) use std::sync::Arc;

pub(crate) use std::sync::Mutex;
pub(crate) use std::sync::PoisonError;
pub(crate) use std::sync::atomic::AtomicU32;
pub(crate) use std::sync::atomic::Ordering;

pub(crate) use agf_core::adapter::Adapter as CoreAdapter;
pub(crate) use agf_core::adapter::AdapterCapability;
pub(crate) use agf_core::adapter::AdapterConfig;
pub(crate) use agf_core::adapter::AdapterDescriptor;
pub(crate) use agf_core::adapter::AdapterHealth;
pub(crate) use agf_core::adapter::CircuitSnapshot;
pub(crate) use agf_core::adapter::PullRequest;
pub(crate) use agf_core::adapter::PullResponse;
pub(crate) use agf_core::adapter::PushPayload;
pub(crate) use agf_core::adapter::SyncDirection;
pub(crate) use agf_core::adapter::SyncOutcome;
pub(crate) use agf_core::adapter::invoke_with_policy;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use crate::contract::AdapterMessage;
pub(crate) use crate::contract::AdapterMetadata;
pub(crate) use crate::contract::AdapterReceipt;
pub(crate) use crate::contract::ConflictPolicy;
pub(crate) use crate::contract::PullPage;
pub(crate) use crate::contract::PushOutcome;
pub(crate) use crate::contract::Semantic;
pub(crate) use crate::contract::SemanticProfile;
pub(crate) use crate::contract::SemanticSupport;
pub(crate) use crate::contract::SyncRequest;
pub(crate) use crate::contract::VendorAdapter;
pub(crate) use crate::contract::item_remote_id;
pub(crate) use crate::contract::item_state;
pub(crate) use crate::contract::item_updated_at;

pub(crate) use crate::health::AdapterHealthRecord;
pub(crate) use crate::health::MOCK_MESSAGE;
pub(crate) use crate::health::evaluate_status;

pub(crate) use crate::settings::AdapterMode;
pub(crate) use crate::settings::AdapterSettings;
pub(crate) use crate::settings::EnvSecrets;
pub(crate) use crate::settings::SecretLookup;

pub use crate::vendor::incremental::IncrementalWindow;
pub use crate::vendor::incremental::filter_since;
pub use crate::vendor::incremental::max_updated_at;
pub use crate::vendor::reconcile::ReconcileDecision;
pub use crate::vendor::reconcile::reconcile;

#[cfg(test)]
pub(crate) use crate::contract::AdapterCategory;
#[cfg(test)]
pub(crate) use crate::contract::MessageKind;

pub(crate) use crate::transport::VendorRequest;

#[cfg(test)]
pub(crate) use agf_core::adapter::CircuitBreakerConfig;
#[cfg(test)]
pub(crate) use agf_core::adapter::RetryConfig;

#[cfg(test)]
pub(crate) use agf_core::enums::Severity;

#[cfg(test)]
pub(crate) use agf_core::ids::Id;
#[cfg(test)]
pub(crate) use agf_core::ids::TenantId;

#[allow(unused_imports)]
pub use resolve_mode::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 厂商差异面（每个厂商模块实现一次）。
///
/// 所有编码/解析方法都是**纯函数**（无 I/O、无自持状态），因此可用临时数据完整单测；
/// 唯一的 I/O 点是 [`VendorSpec::invoke_live`]（`send` 主路径）、[`VendorSpec::invoke_push`] 与
/// [`VendorSpec::invoke_pull`]——默认都走 [`crate::http::execute`]，非 HTTP 通道由厂商覆写。
#[async_trait]
pub trait VendorSpec: Send + Sync + 'static {
    /// 注册名（kebab-case）。
    const NAME: &'static str;

    /// **尚未实现**真实传输的路径的 TODO 锚点（如 `adapter-edr`）。
    ///
    /// 11 个内置适配器均已实现真实传输，因此当前无人登记锚点（取默认空串）；
    /// 新增适配器的脚手架阶段才需要填。
    ///
    /// 已实现真实传输的适配器不再登记锚点（取默认空串），错误文本随之不再出现 TODO 字样。
    const TODO_ANCHOR: &'static str = "";

    /// 是否已有真实传输实现（`true` 时 `Live` 模式会真实发包）。
    const REAL_TRANSPORT: bool = false;

    /// `sync` 回写时使用的实体名（`PushPayload::entity`）。
    ///
    /// 未登记 `sync` 语义的适配器取不到该值（根本不会走到回写）。
    const SYNC_PUSH_ENTITY: &'static str = "ticket.status";

    /// 必需的非敏感设置键（缺失时判定为 `Unconfigured`）。
    const REQUIRED_SETTINGS: &'static [&'static str] = &[];

    /// 元信息。
    fn metadata() -> AdapterMetadata;

    /// 编码为厂商请求（纯函数；缺字段即报错，不触网）。
    ///
    /// # Errors
    /// 载荷缺少厂商必需字段（如 EDR 隔离缺少 host）时返回 `DomainError::Validation`。
    fn encode(msg: &AdapterMessage, settings: &AdapterSettings) -> DomainResult<crate::transport::VendorRequest>;

    /// 厂商特有的配置校验（只校验"存在但非法"的值）。
    ///
    /// # Errors
    /// 值非法时返回 `DomainError::Config`。
    fn validate_settings(_settings: &AdapterSettings) -> DomainResult<()> {
        Ok(())
    }

    /// 除凭据之外，厂商是否已具备可调用条件（如 endpoint / 必需设置）。
    #[must_use]
    fn is_configured(_settings: &AdapterSettings) -> bool {
        true
    }

    /// 是否订阅该载荷（路由与事件类型过滤）。
    #[must_use]
    fn subscribes(_msg: &AdapterMessage) -> bool {
        true
    }

    /// 解析远端响应（**纯函数**，可离线断言）。
    ///
    /// 默认实现直接提取通用 id 字段；厂商覆写以校验业务错误码
    /// （飞书/钉钉/企业微信的 `errcode != 0`、Slack 的 `ok` 体等）。
    ///
    /// 返回 `Ok(None)` 表示"上游接受但未返回 id"，属正常情形。
    ///
    /// # Errors
    /// 上游业务错误码非成功值时返回 `DomainError::Validation`。
    fn parse_response(_status: u16, body: &str) -> DomainResult<Option<String>> {
        Ok(crate::http::extract_id(body, crate::http::DEFAULT_ID_CANDIDATES))
    }

    /// 真实调用（默认实现：HTTP 往返）。
    ///
    /// 未实现真实传输（[`VendorSpec::REAL_TRANSPORT`] 为 `false`）时**明确失败**，绝不假装成功。
    /// 非 HTTP 通道的厂商覆写本方法（如 Syslog 走 UDP/TCP）。
    ///
    /// # Errors
    /// 未实现时返回 `NotImplemented`；网络/上游失败时返回 `Timeout`/`DependencyUnavailable` 等。
    async fn invoke_live(
        req: &crate::transport::VendorRequest,
        settings: &AdapterSettings,
    ) -> DomainResult<Option<String>> {
        if !Self::REAL_TRANSPORT {
            return Err(Self::pending_error("send"));
        }
        let response = crate::http::execute(Self::NAME, req, settings).await?;
        Self::parse_response(response.status, &response.body)
    }

    /// 尚未实现路径的统一"如实未实现"错误（已登记锚点的适配器会带上锚点文本）。
    ///
    /// 只用于**新增适配器的脚手架阶段**（`REAL_TRANSPORT=false` / 未登记语义）；
    /// 内置 12 个适配器的 `push`/`pull`/`sync` **一律不得**落到这里（有单测守住）。
    fn pending_error(operation: &str) -> DomainError {
        if Self::TODO_ANCHOR.is_empty() {
            DomainError::NotImplemented(format!(
                "{}：{operation} 的真实传输尚未实现（本适配器已实现 send 主路径，其余路径待接入），见 {}",
                Self::NAME,
                Self::metadata().doc_anchor
            ))
        } else {
            DomainError::NotImplemented(format!(
                "{}：{operation} 的真实传输尚未实现（TODO({})），见 {}",
                Self::NAME,
                Self::TODO_ANCHOR,
                Self::metadata().doc_anchor
            ))
        }
    }

    // -----------------------------------------------------------------------
    // 三条外部语义（push / pull / sync）的能力登记与编码面
    // -----------------------------------------------------------------------

    /// `push` / `pull` / `sync` 的能力登记（**唯一真源 = `metadata().semantics`**）。
    ///
    /// 厂商在 `metadata()` 里用 [`AdapterMetadata::with_semantics`] 声明；
    /// 未声明即 [`SemanticProfile::undeclared`]（不声称任何能力）。
    #[must_use]
    fn semantics() -> SemanticProfile {
        Self::metadata().semantics
    }

    /// `push` 档位。
    #[must_use]
    fn push_support() -> SemanticSupport {
        Self::semantics().push
    }

    /// `pull` 档位。
    #[must_use]
    fn pull_support() -> SemanticSupport {
        Self::semantics().pull
    }

    /// `sync` 档位。
    #[must_use]
    fn sync_support() -> SemanticSupport {
        Self::semantics().sync
    }

    /// 语义不适用的统一错误（**不可重试**：重试不会让语义变得可用）。
    ///
    /// 若档位是 `Implemented` 却走到本方法，说明实现漏覆盖 ⇒ 明确报 `Internal`（实现缺陷），
    /// 而不是伪装成"不支持"。
    #[must_use]
    fn unsupported_semantic_error(semantic: Semantic) -> DomainError {
        match Self::semantics().support(semantic).reason() {
            Some(reason) => DomainError::Validation(format!(
                "{}：不支持 {semantic}（Unsupported）——{reason}；见 {}",
                Self::NAME,
                Self::metadata().doc_anchor
            )),
            None => DomainError::Internal(format!(
                "{}：{semantic} 已登记为 Implemented 但未覆盖对应编码/解析（实现缺陷）",
                Self::NAME
            )),
        }
    }

    /// 语义不可用时**如实分类**的错误（`push`/`pull`/`sync` 的入口统一调用本方法）。
    ///
    /// 1. 档位 `Implemented` 却未覆盖编码/解析 ⇒ `Internal`（实现缺陷，不是"不支持"）；
    /// 2. 档位为"未登记"或适配器仍是脚手架（`REAL_TRANSPORT=false`）⇒ `NotImplemented` + TODO 锚点；
    /// 3. 已实现真实传输、但该语义协议上不适用 ⇒ `Validation` + 具体原因（**内置适配器的路径**）。
    #[must_use]
    fn semantic_error(semantic: Semantic) -> DomainError {
        let support = Self::semantics().support(semantic).clone();
        if support.is_implemented() {
            return DomainError::Internal(format!(
                "{}：{semantic} 已登记为 Implemented 但未覆盖对应编码/解析（实现缺陷）",
                Self::NAME
            ));
        }
        if support.reason() == Some(crate::contract::UNDECLARED_REASON) || !Self::REAL_TRANSPORT {
            return Self::pending_error(semantic.as_str());
        }
        Self::unsupported_semantic_error(semantic)
    }

    /// 编码**状态回写**请求序列（**纯函数**：不做网络，可离线断言）。
    ///
    /// 返回 `Vec` 而非单个请求：Jira 的"状态推进 + 评论"是一次回写两次调用；
    /// 顺序即执行顺序（最后一条响应用于提取回执 id）。
    ///
    /// # Errors
    /// 未登记 `push` ⇒ [`Self::unsupported_semantic_error`]；
    /// `payload.entity_id` 缺失（回写必须指向已存在的远端对象）⇒ `Validation`。
    fn encode_push(_payload: &PushPayload, _settings: &AdapterSettings) -> DomainResult<Vec<VendorRequest>> {
        Err(Self::unsupported_semantic_error(Semantic::Push))
    }

    /// 编码**增量拉取**请求（**纯函数**：不做网络，可离线断言）。
    ///
    /// # Errors
    /// 未登记 `pull` ⇒ [`Self::unsupported_semantic_error`]；`resource` 不受支持 ⇒ `Validation`。
    fn encode_pull(_req: &PullRequest, _settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        Err(Self::unsupported_semantic_error(Semantic::Pull))
    }

    /// 解析拉取响应为分页条目（**纯函数**：可离线断言）。
    ///
    /// 实现必须注入规范化字段（见 [`crate::contract::sync_types`] 模块文档），
    /// `sync` 的比对与冲突裁决才能跨厂商复用。
    ///
    /// # Errors
    /// 未登记 `pull` ⇒ [`Self::unsupported_semantic_error`]；响应体结构不符 ⇒ `Validation`。
    fn parse_pull(_status: u16, _body: &str, _req: &PullRequest) -> DomainResult<PullPage> {
        Err(Self::unsupported_semantic_error(Semantic::Pull))
    }

    /// 解析回写响应（**纯函数**）。
    ///
    /// 默认提取通用 id 字段；空响应体（如 Jira 状态推进返回 `204`）视为"已接受但无 id"。
    ///
    /// # Errors
    /// 上游业务错误码非成功值时返回 `DomainError::Validation`。
    fn parse_push_response(_status: u16, body: &str) -> DomainResult<Option<String>> {
        Ok(crate::http::extract_id(body, crate::http::DEFAULT_ID_CANDIDATES))
    }

    /// 真实回写（默认实现：**顺序**执行编码出的请求序列 + 解析末次响应）。
    ///
    /// # Errors
    /// 网络/上游失败时返回 `Timeout`/`DependencyUnavailable`（可重试）或 4xx 映射的错误（不重试）。
    async fn invoke_push(reqs: &[VendorRequest], settings: &AdapterSettings) -> DomainResult<Option<String>> {
        let mut remote_id = None;
        for req in reqs {
            let response = crate::http::execute(Self::NAME, req, settings).await?;
            remote_id = Self::parse_push_response(response.status, &response.body)?;
        }
        Ok(remote_id)
    }

    /// 真实拉取（默认实现：HTTP 往返 + [`Self::parse_pull`]）。
    ///
    /// # Errors
    /// 网络/上游失败时返回 `Timeout`/`DependencyUnavailable`（可重试）或 4xx 映射的错误（不重试）。
    async fn invoke_pull(
        req: &VendorRequest,
        pull: &PullRequest,
        settings: &AdapterSettings,
    ) -> DomainResult<PullPage> {
        let response = crate::http::execute(Self::NAME, req, settings).await?;
        Self::parse_pull(response.status, &response.body, pull)
    }

    /// Mock 回执的远端 id（确定性派生，便于断言与去重）。
    #[must_use]
    fn mock_remote_id(msg: &AdapterMessage) -> String {
        format!("mock-{}", crate::transport::deterministic_token(Self::NAME, &msg.idempotency_key))
    }

    /// 未配置形态的默认设置。
    #[must_use]
    fn default_settings() -> AdapterSettings {
        AdapterSettings::defaults(&Self::metadata()).with_required_settings(Self::REQUIRED_SETTINGS)
    }
}

/// 最近一次调用的观测值。
///
/// `send` 走 `&mut self`，而 `push`/`pull`/`sync` 必须能从 `&self` 调用
/// （`agf_core::adapter::Adapter` 的签名如此）⇒ 观测值放在 `Mutex` 里。
#[derive(Debug, Clone, Default)]
struct LastCall {
    error: Option<String>,
    latency_ms: Option<u64>,
    attempts: u32,
}

/// 适配器运行时内核。
struct AdapterCore {
    settings: AdapterSettings,
    mode: AdapterMode,
    /// 熔断快照。`&self` 路径（`push`/`pull`/`sync`）也要更新熔断态，
    /// 因此用 `Mutex` 承载：**锁不跨 `await`**（取副本 → 执行 → 写回），Future 保持 `Send`。
    circuit: Mutex<CircuitSnapshot>,
    closed: bool,
    mock_env: bool,
    /// 最近一次调用观测（错误/耗时/尝试次数）。
    last: Mutex<LastCall>,
    /// 增量拉取窗口（按 `resource` 维度隔离；`pull`/`sync` 由 `&self` 路径更新）。
    windows: Mutex<BTreeMap<String, IncrementalWindow>>,
}

/// 通用厂商适配器（[`VendorSpec`] 的契约实现）。
pub struct VendorAdapterImpl<V: VendorSpec> {
    core: AdapterCore,
    spec: PhantomData<fn() -> V>,
}

mod impl_semantics;
mod impl_vendor_adapter_impl;
mod incremental;
mod reconcile;
mod resolve_mode;
#[cfg(test)]
mod tests;
