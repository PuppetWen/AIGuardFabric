//! 内容安全前置/后置过滤：`ContentScreen` 契约 + 内置关键词实现。
//!
//! ## 定位
//!
//! 网关是**南北向流量的唯一收口**，因此内容安全必须在网关处做第一道闸：
//! 规则引擎（`agf-scan` / `rules/`）通过实现 [`ContentScreen`] 插进来，
//! 网关只负责"在正确的时机调用 + 按裁决执行"。
//!
//! ```text
//! 用户提示词 ──▶ screen_request ──┬─ Allow  ──▶ 路由/缓存/上游
//!                                ├─ Redact ──▶ 替换后继续（保留可逆映射）
//!                                └─ Block  ──▶ 直接拒绝（不触达厂商、不计费）
//! 上游回复  ──▶ screen_response ─┬─ Allow  ──▶ 返回
//!                                ├─ Redact ──▶ 打码后返回
//!                                └─ Block  ──▶ 以安全话术替换回复并标记
//! ```
//!
//! ## 内置 `KeywordScreen` 的规则范围（离线演示用）
//!
//! 三组**高置信度**模式，覆盖 §4.2 的"提示词攻击 / 凭证泄露"两个域：
//! 越狱与角色劫持、系统提示词泄露、凭证外传。刻意保守：宁可漏报也不制造
//! 满屏阻断（真实检测交给 `agf-scan` 的规则引擎与 LLM 二次研判）。
//!
//! ## 不可豁免的底线
//!
//! `Redact` 与 `Block` 的裁决**不受 `allow_cache` 等其他开关影响**；
//! 预筛 `Block` 时网关不会发起任何上游请求（审计里体现为"零成本拦截"）。

pub(crate) use std::sync::Arc;

pub(crate) use agf_core::enums::RiskDomain;

pub(crate) use agf_core::redact::Redaction;
pub(crate) use agf_core::redact::RedactionMap;
pub(crate) use agf_core::redact::RedactionMode;
pub(crate) use agf_core::redact::redact_text;

pub(crate) use agf_core::secret::scan_credentials;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::wire::ChatRequest;
pub(crate) use crate::wire::ChatResponse;
pub(crate) use crate::wire::MessageContent;
pub(crate) use crate::wire::Role;

#[cfg(test)]
pub(crate) use crate::wire::ChatMessage;
#[cfg(test)]
pub(crate) use crate::wire::Usage;

#[cfg(test)]
pub(crate) use pretty_assertions::assert_eq as eq;

#[allow(unused_imports)]
pub use mask_fragment::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 一条可解释的检测规则命中。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScreenRule {
    /// 规则标识（稳定，用于审计与统计）。
    pub id: String,
    /// 归属安全域。
    pub domain: RiskDomain,
    /// 中文说明。
    pub description: String,
    /// 命中的原文片段掩码（**不含明文**）。
    pub masked_hit: String,
}

/// 过滤裁决。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScreenVerdict {
    /// 放行。
    Allow,
    /// 修改后放行（脱敏）。
    Redact(Vec<Redaction>),
    /// 阻断。
    Block {
        /// 阻断原因（给人看）。
        reason: String,
        /// 命中的规则（给审计看）。
        rule: Box<ScreenRule>,
    },
}

/// 过滤结果（裁决 + 可能被改写的内容）。
#[derive(Debug, Clone)]
pub struct ScreenOutcome {
    /// 裁决。
    pub verdict: ScreenVerdict,
    /// 改写后的请求（`Redact` 时非 `None`）。
    pub request: Option<ChatRequest>,
    /// 改写后的响应（`Redact` 时非 `None`）。
    pub response: Option<ChatResponse>,
    /// 可逆脱敏映射（**仅在会话内存在，禁止落库明文**）。
    pub redaction_map: RedactionMap,
}

/// 内容安全过滤契约。
///
/// 实现者（如 `agf-scan` 的规则引擎桥接）必须：
/// 1. **纯函数式**：不改动入参，改写通过返回值传递；
/// 2. **不阻塞主流程的失败**：内部规则求值异常应降级为 `Allow` 并记日志，
///    而不是让网关报错（可用性与安全性在此处的取舍是"记录并放行 + 告警"）；
/// 3. 命中的规则必须给出稳定 `id`，供审计与策略闭环使用。
pub trait ContentScreen: Send + Sync + std::fmt::Debug {
    /// 请求前置过滤（送厂商之前）。
    fn screen_request(&self, req: &ChatRequest) -> ScreenOutcome;

    /// 响应后置过滤（返回给调用方之前）。
    fn screen_response(&self, resp: &ChatResponse) -> ScreenOutcome;

    /// 屏幕名称（审计标注）。
    fn name(&self) -> &str;

    /// 是否为无操作实现（网关据此跳过调用开销）。
    fn is_noop(&self) -> bool {
        false
    }
}

/// 不做任何过滤（用于排障或"仅审计"模式）。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopScreen;

/// 内置关键词模式的类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeywordCategory {
    /// 越狱 / 角色劫持（提示词攻击）。
    Jailbreak,
    /// 系统提示词泄露探测（提示词攻击）。
    SystemPromptLeak,
    /// 凭证外传（凭证泄露）。
    CredentialExfiltration,
}

/// 关键词模式的处置方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeywordAction {
    /// 阻断。
    Block,
    /// 脱敏后放行。
    Redact,
    /// 仅记录（放行）。
    Audit,
}

/// 关键词过滤（默认实现，离线可演示阻断与脱敏）。
#[derive(Debug, Clone)]
pub struct KeywordScreen {
    /// 是否在响应侧也做过滤。
    pub filter_responses: bool,
    /// 是否启用越狱检测。
    pub enable_jailbreak: bool,
    /// 是否启用系统提示词泄露检测。
    pub enable_system_prompt_leak: bool,
    /// 是否启用凭证外传检测。
    pub enable_credential_exfiltration: bool,
    /// 凭证命中的处置（默认脱敏而非阻断，避免误伤正常排障文本）。
    pub credential_action: KeywordAction,
    /// 阻断阈值：命中该类别即阻断（默认越狱与系统提示词泄露阻断）。
    pub block_categories: Vec<KeywordCategory>,
}

/// 内置关键词表：`(类别, 模式, 说明)`。
///
/// 全部为小写匹配（先对文本做 `to_lowercase`），中英文混合。
pub const KEYWORD_PATTERNS: [(&str, &str, &str); 20] = [
    // 越狱 / 角色劫持
    ("jailbreak", "ignore previous instructions", "英文指令覆盖"),
    ("jailbreak", "ignore all previous", "英文指令覆盖"),
    ("jailbreak", "disregard all previous", "英文指令覆盖"),
    ("jailbreak", "忽略之前的所有指令", "中文指令覆盖"),
    ("jailbreak", "忽略以上所有", "中文指令覆盖"),
    ("jailbreak", "你现在是", "中文角色劫持"),
    ("jailbreak", "you are now dan", "DAN 越狱"),
    ("jailbreak", "developer mode", "开发者模式越狱"),
    ("jailbreak", "越狱模式", "中文越狱模式"),
    ("jailbreak", "act as an unrestricted", "无限制角色扮演"),
    // 系统提示词泄露
    ("system-prompt-leak", "system prompt", "英文系统提示词探测"),
    ("system-prompt-leak", "系统提示词", "中文系统提示词探测"),
    ("system-prompt-leak", "系统指令原文", "中文系统指令索要"),
    ("system-prompt-leak", "repeat your instructions", "英文指令复述"),
    ("system-prompt-leak", "print your initial prompt", "英文初始提示词索取"),
    ("system-prompt-leak", "你的初始设定是什么", "中文初始设定探测"),
    // 凭证外传
    ("credential-exfiltration", "send the api key to", "要求外发密钥"),
    ("credential-exfiltration", "把密钥发送到", "中文要求外发密钥"),
    ("credential-exfiltration", "upload your credentials", "要求上传凭据"),
    ("credential-exfiltration", "curl http", "可疑外联命令"),
];

/// 组合多个过滤器：**任一阻断即阻断**，脱敏结果按顺序叠加。
#[derive(Debug)]
pub struct CompositeScreen {
    screens: Vec<Arc<dyn ContentScreen>>,
}

mod impl_screen_rule;
mod mask_fragment;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests;
