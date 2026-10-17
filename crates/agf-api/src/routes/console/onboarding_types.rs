use super::*;

/// 纳管步骤（前端 `OnboardingStep`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OnboardingStepView {
    /// 顺序。
    pub order: i64,
    /// 标题。
    pub title: String,
    /// 命令。
    pub command: String,
    /// 回滚命令。
    pub rollback: String,
}

/// 纳管计划（前端 `OnboardingPlan`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OnboardingPlanView {
    /// Agent 资产 id（未指定参数时为空串）。
    pub agent_id: String,
    /// 纳管模式。
    pub mode: String,
    /// Exact connection mechanism; never silently replaced by another mode.
    pub target: String,
    /// A launch template is available. This does not attest deployment or execution.
    pub ready: bool,
    pub available_targets: Vec<String>,
    pub links: Vec<OnboardingLink>,
    pub sdk_sources: Vec<OnboardingSource>,
    /// Opaque SDK JSON text; UI adapters must not rename its keys.
    pub configuration_json: Option<String>,
    /// Secret environment variable name only; a value is never accepted or returned.
    pub key_env: Option<String>,
    /// 数据上报端点（由配置/请求 Host 推导）。
    pub endpoint: String,
    /// Published collector URL; None for SDK mode or unavailable builds.
    pub artifact_url: Option<String>,
    /// Published artifact digest, absent when no download exists.
    pub artifact_sha256: Option<String>,
    /// Target OS and architecture.
    pub platform: String,
    /// 环境变量片段。
    pub env_snippet: String,
    /// 步骤。
    pub steps: Vec<OnboardingStepView>,
    /// No application deployment measurement is available.
    pub estimated_downtime_sec: Option<i64>,
    /// Manual application rollout; plan generation does not deploy.
    pub rollout: String,
}

/// 纳管计划入参（GET query 与 POST body 共用）。
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OnboardingPlanRequest {
    /// Agent 资产 id（`agent_id` 的驼峰别名由控制台发送）。
    #[serde(default, alias = "agentId")]
    pub agent_id: Option<String>,
    /// 资产类型（不指定 id 时可用于生成通用计划）。
    #[serde(default)]
    pub kind: Option<String>,
    /// 纳管模式（缺省 `sidecar`）。
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub target: Option<OnboardingTarget>,
    /// Exact enabled platform model, never the special auto selector.
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub sdk: Option<OnboardingStartup>,
    /// windows-amd64 / linux-amd64 / macos-arm64.
    #[serde(default)]
    pub platform: Option<String>,
    /// zh-CN or en-US.
    #[serde(default)]
    pub locale: Option<String>,
    /// Client-visible platform origin, without path or credentials.
    #[serde(default, alias = "publicBase")]
    pub public_base: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OnboardingTarget {
    Collector,
    McpStdio,
    PythonStartup,
    NodeCjsStartup,
    ModelOpenai,
    ModelAnthropic,
    McpHttp,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OnboardingStartup {
    #[schema(value_type = String, format = Uuid)]
    pub source_id: agf_core::ids::Id,
    #[schema(value_type = String, format = Uuid)]
    pub binding_id: agf_core::ids::Id,
    pub worker: String,
    pub team: Option<String>,
    /// task or call. A call requires the explicit current callee.
    pub kind: String,
    pub callee_worker: Option<String>,
    pub callee_team: Option<String>,
    pub operation: String,
    /// Python qualified module; unused for CommonJS.
    pub module: String,
    /// Python attribute or CommonJS own-export path.
    pub callable: String,
    /// Python module entry or absolute CommonJS script path.
    pub entry: String,
    pub sdk_directory: String,
    pub spool_directory: String,
    pub configuration_file: String,
    pub target_file: Option<String>,
    pub async_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OnboardingLink {
    pub label: String,
    pub href: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OnboardingSource {
    #[schema(value_type = String, format = Uuid)]
    pub source_id: agf_core::ids::Id,
    #[schema(value_type = String, format = Uuid)]
    pub binding_id: agf_core::ids::Id,
    #[schema(value_type = String, format = Uuid)]
    pub scope_id: agf_core::ids::Id,
    pub mocked: bool,
    pub name: String,
    pub workers: Vec<OnboardingWorker>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OnboardingWorker {
    pub name: String,
    pub teams: Vec<String>,
}
