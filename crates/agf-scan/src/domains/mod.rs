//! 五大安全域专项检测器（§4.2）。
//!
//! 规则引擎（[`crate::detector`]）负责"模式匹配"，本模块负责**领域语义判定**：
//! 有些风险不是"文本里有某个词"就能判定的，需要结合上下文结构（例如
//! "工具调用的参数里出现了路径穿越序列 + 敏感文件路径"才是高危）。
//!
//! ## 五个域的分工
//!
//! | 域 | 判定输入 | 典型检出 |
//! |---|---|---|
//! | 提示词攻击 | 用户/系统提示词文本 | 直接/间接注入、越狱、角色劫持、系统提示词泄露、编码绕过、多轮诱导 |
//! | 凭证泄露 | 任意文本（多来源） | API Key / AK-SK / JWT / 私钥 / 连接串口令 / 明文 MCP 凭据 |
//! | RAG 投毒 | 知识库文档 + 检索片段 | 投毒指令、隐藏指令、上下文冲突、越权文档 |
//! | 工具与权限滥用 | 工具名 + 参数 + 能力画像 | 破坏性命令、命令注入、路径穿越、敏感文件、SSRF、能力组合 |
//! | 模型与数据安全 | 模型输出 + 数据分级 | 凭据回显、PII 回显、外传 URL、分级不匹配、供应链风险 |
//!
//! 所有判定都是**纯函数**，因此可以在离线环境下用单元测试穷举验证。

pub(crate) use std::collections::BTreeSet;

pub(crate) use agf_core::enums::DataClass;
pub(crate) use agf_core::enums::RiskDomain;
pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::mcp::ToolTraits;

pub(crate) use agf_core::risk::Finding;
pub(crate) use agf_core::risk::LlmJudgement;

pub(crate) use agf_core::secret::CredentialMatch;
pub(crate) use agf_core::secret::scan_credentials;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

#[cfg(test)]
pub(crate) use agf_core::time::Timestamp;

#[allow(unused_imports)]
pub use snippet::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests_2::*;

/// 领域判定结论。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DomainVerdict {
    /// 恶意/确认命中。
    Malicious,
    /// 疑似（需要人工确认或模型研判）。
    Suspicious,
    /// 良性。
    Benign,
}

/// 一条领域检出。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainHit {
    /// 稳定标识（形如 `prompt-attack:direct-injection`）。
    pub key: String,
    /// 标题。
    pub title: String,
    /// 所属安全域。
    pub domain: RiskDomain,
    /// 严重等级。
    pub severity: Severity,
    /// 判定。
    pub verdict: DomainVerdict,
    /// 置信度。
    pub confidence: f32,
    /// 说明。
    pub detail: String,
    /// 证据片段（已脱敏/截断）。
    pub evidence: Vec<String>,
    /// 修复建议。
    pub remediation: String,
    /// 关联资产。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<Id>,
}

/// 一个域的检测报告。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReport {
    /// 安全域。
    pub domain: RiskDomain,
    /// 检出列表。
    pub hits: Vec<DomainHit>,
    /// 该域的综合判定。
    pub verdict: DomainVerdict,
    /// 综合严重等级（取最高）。
    pub severity: Severity,
    /// 检查了哪些维度（可解释性）。
    pub checks_run: Vec<String>,
    /// 耗时（微秒）。
    pub elapsed_micros: u64,
}

/// 五大域检测器集合。
#[derive(Debug, Clone, Default)]
pub struct DomainDetector {
    /// 额外的凭据识别模式（来自规则包/客户自定义）。
    custom_credential_patterns: Vec<agf_core::secret::CredentialPattern>,
}

mod impl_domain_detector;
mod impl_domain_detector_2;
mod impl_domain_verdict;
mod snippet;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_2;
