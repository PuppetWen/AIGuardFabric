# AIGuardFabric 适配器规范

> 本文件定义**统一适配器契约**、熔断/重试/死信规范、凭据获取优先级、配置驱动与热插拔机制，
> 并**逐适配器**写明「未配置时的降级行为」与「Mock 实现位置」（§12.4 强制要求）。
>
> 事实来源：`crates/agf-core/src/adapter.rs`（契约本体，930 行）、
> `crates/agf-alicloud/src/{lib,registry,mock,credential,http,selfcheck,deadletter,signer,endpoint}.rs`、
> `crates/agf-aigw/src/{provider,mock,gateway,lib}.rs`、
> `crates/agf-core/src/config.rs`（设备适配器开关）、`.env.example`、`deploy/sql/migration_parts/`
> （`adapter_configs` / `adapter_health` / `dead_letters` 表）。
>
> ⚠️ 状态图例：🟢 代码已验证 · 🟡 部分实现/修复中 · 🔴 未实现（空壳）。

---

## 1. 统一 `Adapter` trait 契约

**契约本体：`crates/agf-core/src/adapter.rs`。所有外部系统（大模型厂商、阿里云六服务、青藤云、各厂商 WAF、消息中间件）都实现同一个 trait。**

### 1.1 trait 定义（逐字）

```rust
/// 统一适配器契约。
///
/// 实现者注意：
/// - `init` **不应**在未配置时返回 `Err`，而是返回 `Ok(())` 并通过 `Self::health`
///   暴露 `HealthState::Unconfigured`，让上层决定是否切到 Mock；
/// - 所有网络调用必须走 `invoke` 包装（熔断 + 重试 + 死信），不要直接 `await` 底层客户端；
/// - `shutdown` 必须幂等，允许重复调用。
#[async_trait]
pub trait Adapter: Send + Sync {
    /// 适配器注册名。
    fn name(&self) -> &str;

    /// 适配器元信息。
    fn descriptor(&self) -> AdapterDescriptor;

    /// 初始化（建立连接、加载配置、预热）。未配置时返回 `Ok(())` 并标记未配置。
    ///
    /// # Errors
    /// 仅当**配置存在但非法**（如 URL 格式错误、凭据解密失败）时返回错误。
    async fn init(&mut self, config: &AdapterConfig) -> DomainResult<()>;

    /// 健康检查（同时更新熔断状态）。
    ///
    /// # Errors
    /// 探测过程本身的不可恢复错误（如配置损坏）；网络失败应映射为健康状态而非错误。
    async fn health(&self) -> DomainResult<AdapterHealth>;

    /// 同步：按 `direction` 拉取/推送台账与配置。
    ///
    /// # Errors
    /// 返回可重试错误，由调用方决定是否进死信队列。
    async fn sync(&self, direction: SyncDirection, req: &PullRequest) -> DomainResult<SyncOutcome>;

    /// 推送单个实体到远端。
    ///
    /// # Errors
    /// 远端拒绝或网络失败。
    async fn push(&self, payload: &PushPayload) -> DomainResult<()>;

    /// 从远端拉取。
    ///
    /// # Errors
    /// 远端拒绝或网络失败。
    async fn pull(&self, req: &PullRequest) -> DomainResult<PullResponse>;

    /// 自检（连通性 / 最小权限 / 配额余量），供"云环境自检"页调用。
    ///
    /// # Errors
    /// 自检本身无法执行时返回错误；单项检查不通过应体现在 `AdapterHealth` 中。
    async fn self_check(&self) -> DomainResult<AdapterHealth> {
        self.health().await
    }

    /// 关闭（幂等）。
    ///
    /// # Errors
    /// 关闭过程中的错误。
    async fn shutdown(&mut self) -> DomainResult<()>;
}
```

**关键语义**：

| 方法 | 约定 |
|---|---|
| `name()` | 注册名，与 `AdapterConfig::adapter` 一致（如 `alicloud-cms`、`llm-openai-compat`、`qingteng`） |
| `descriptor()` | 返回 `AdapterDescriptor`，**必须**填 `degradation` 与 `mock_location` 两个非空字段 |
| `init()` | **未配置 → `Ok(())` + `HealthState::Unconfigured`**，不是 `Err`；仅在"配置存在但非法"时才 `Err` |
| `health()` | **网络失败映射为健康状态，不映射为 `Err`**；只有探测本身不可执行才 `Err` |
| `sync()` | 返回可重试错误，由调用方决定是否进死信 |
| `self_check()` | 默认实现委托 `health()`；适配器可覆写以做连通性 + 最小权限 + 配额余量三项检查 |
| `shutdown()` | **必须幂等**，允许重复调用 |

### 1.2 `AdapterDescriptor`（§12.4 强制字段）

```rust
pub struct AdapterDescriptor {
    pub name: String,                       // 注册名
    pub display_name: String,               // 显示名
    pub category: String,                   // alicloud / llm / siem / waf / message / identity
    pub required_secrets: Vec<String>,      // 必需凭据键
    pub optional_secrets: Vec<String>,      // 可选凭据键
    pub capabilities: Vec<AdapterCapability>,
    pub degradation: String,                // ★ 未配置时的降级行为说明（非空）
    pub mock_location: String,              // ★ Mock 实现位置（文件路径或模块名，非空）
    pub real_implementation: bool,          // 是否有真实实现
    pub doc_anchor: String,                 // 本文档锚点，如 docs/adapter-spec.md#alicloud-cms
}
```

契约自带测试断言这两个字段非空（`adapter.rs:854-856`）：

```rust
assert!(!d.degradation.is_empty(), "必须写明降级行为");
assert!(!d.mock_location.is_empty(), "必须写明 Mock 实现位置");
```

`deploy/sql/migration_parts/` 提供持久化支撑：`adapter_configs`（`0001_init_04.sql:121`）、`adapter_health`（`:139`，索引 `ix_adapter_health_time`）、`dead_letters`（`:154`，索引 `ix_dead_letters_adapter`）。

### 1.3 `AdapterCapability`（11 个能力标签）

| 变体 | 文本 | 含义 |
|---|---|---|
| `PullInventory` | `pull-inventory` | 拉取远端台账/资源清单 |
| `PushConfig` | `push-config` | 推送平台配置/策略到远端 |
| `PushMetrics` | `push-metrics` | 上报指标 |
| `PushEvents` | `push-events` | 上报事件/告警 |
| `SubscribeEvents` | `subscribe-events` | 订阅远端事件流 |
| `QueryLogs` | `query-logs` | 查询远端日志 |
| `EnforcePolicy` | `enforce-policy` | 下发拦截/封禁策略 |
| `ScheduleTask` | `schedule-task` | 注册/触发任务调度 |
| `SelfCheck` | `self-check` | 健康与权限自检 |
| `AssumeRole` | `assume-role` | 跨账号 AssumeRole |
| `ProbePrivateLink` | `probe-private-link` | 私网连通性探测 |

### 1.4 数据载体类型

```rust
// 同步方向
pub enum SyncDirection { Pull, Push, Both }        // includes_pull() / includes_push()

// 推送载荷（平台 → 远端）
pub struct PushPayload {
    pub entity: String,                    // policy / metric / event / schedule
    pub entity_id: String,
    pub body: serde_json::Value,
    pub idempotency_key: Option<String>,   // 远端据此去重
}

// 拉取请求（平台 ← 远端）
pub struct PullRequest {
    pub resource: String,                  // agents / teams / services / alarms
    pub filter: BTreeMap<String, String>,  // 远端语法，透传
    pub cursor: Option<String>,            // 增量拉取游标
    pub limit: Option<u32>,
}

// 拉取结果
pub struct PullResponse {
    pub items: Vec<serde_json::Value>,
    pub next_cursor: Option<String>,
    pub mocked: bool,
    pub origin: String,                    // 真实 endpoint 或 fixture 路径（排障用）
}

// 同步结果
pub struct SyncOutcome {
    pub pulled: usize, pub pushed: usize, pub skipped: usize, pub failed: usize,
    pub mocked: bool, pub degraded: bool,
    pub changes: BTreeMap<String, usize>,  // 实体类型 → 变更数
    pub warnings: Vec<String>,
    pub elapsed_ms: u64, pub finished_at: Option<Timestamp>,
}

// 健康报告
pub struct AdapterHealth {
    pub adapter: String,
    pub state: HealthState,     // Healthy / Degraded / Unconfigured / CircuitOpen / ...
    pub configured: bool,
    pub mocked: bool,
    pub latency_ms: Option<u64>,
    pub circuit: CircuitSnapshot,
    pub capabilities: Vec<AdapterCapability>,
    pub message: Option<String>,
    pub checked_at: Timestamp,
}
```

两个便捷构造器把"降级而非失败"编码进类型：

| 构造器 | 产出 | 语义 |
|---|---|---|
| `AdapterHealth::unconfigured(adapter, reason)` | `state = Unconfigured`，`configured = false`，`mocked = false` | 未配置 |
| `AdapterHealth::mocked(adapter)` | `state = Degraded`，`mocked = true`，`latency_ms = Some(0)`，message 含 `AGF_MOCK_MODE=1：返回 fixtures 录制响应，未触达真实外部系统` | Mock 模式 |

---

## 2. 熔断 / 重试 / 死信规范

### 2.1 `CircuitBreakerConfig` 与 `CircuitSnapshot`

```rust
pub struct CircuitBreakerConfig {
    pub enabled: bool,              // 默认 true
    pub failure_threshold: u32,     // 默认 5（连续失败达到即开路）
    pub open_secs: i64,             // 默认 30（开路持续，之后进半开）
    pub half_open_probes: u32,      // 默认 1（半开允许的探测请求数）
}

pub enum CircuitState { Closed, Open, HalfOpen }

/// 可序列化的熔断器运行态（内存态，不落库）
pub struct CircuitSnapshot {
    pub state: CircuitState,
    pub consecutive_failures: u32,
    pub opened_at: Option<Timestamp>,
    pub probes_left: u32,
    pub total_success: u64,
    pub total_failure: u64,
    pub last_error: Option<String>,
}
```

### 2.2 状态机（逐字语义）

```rust
pub fn on_success(&mut self) {
    self.total_success += 1;
    self.consecutive_failures = 0;
    self.state = CircuitState::Closed;
    self.opened_at = None; self.probes_left = 0; self.last_error = None;
}

pub fn on_failure(&mut self, cfg: &CircuitBreakerConfig, error: impl Into<String>, now: Timestamp) {
    self.total_failure += 1;
    self.consecutive_failures += 1;
    self.last_error = Some(error.into());
    if cfg.enabled && self.consecutive_failures >= cfg.failure_threshold {
        self.state = CircuitState::Open;
        self.opened_at = Some(now);
    }
}

/// 是否允许本次调用（开路未到期则拒绝）。
/// 半开状态的探测额度在**进入半开时一次性发放**。
pub fn allows_call(&mut self, cfg: &CircuitBreakerConfig, now: Timestamp) -> bool { … }
```

| 状态迁移 | 条件 | 行为 |
|---|---|---|
| `Closed → Open` | `enabled && consecutive_failures >= failure_threshold` | 后续调用**快速失败**，不触达外部系统 |
| `Open → HalfOpen` | `now - opened_at >= open_secs` | 一次性发放 `half_open_probes` 个探测额度；**本次调用即消耗一个** |
| `HalfOpen → Closed` | 任一探测成功（`on_success`） | 计数清零，恢复 |
| `HalfOpen → HalfOpen` | 探测额度耗尽后继续调用 | 拒绝（返回 `false`），直到有成功把熔断器闭合 |
| `enabled == false` | — | `allows_call` 恒 `true` |

**健康状态映射**：

```rust
pub const fn health(&self) -> HealthState {
    match self.state {
        CircuitState::Closed   => HealthState::Healthy,
        CircuitState::HalfOpen => HealthState::Degraded,
        CircuitState::Open     => HealthState::CircuitOpen,
    }
}
```

### 2.3 `RetryConfig`（指数退避）

```rust
pub struct RetryConfig {
    pub max_attempts: u32,        // 默认 3（含首次）
    pub initial_backoff_ms: u64,  // 默认 200
    pub multiplier: f32,          // 默认 2.0
    pub max_backoff_ms: u64,      // 默认 10_000（上限截断）
    pub jitter: bool,             // 默认 true（避免惊群）
}

/// 第 `attempt` 次（从 0 开始）重试前的等待毫秒数（不含抖动）
pub fn backoff_ms(&self, attempt: u32) -> u64 {
    let base = self.initial_backoff_ms as f64 * f64::from(self.multiplier).powi(attempt as i32);
    base.min(self.max_backoff_ms as f64) as u64
}
```

### 2.4 `invoke_with_policy`（通用包装，契约的一部分）

```rust
pub async fn invoke_with_policy<T, F, Fut>(
    adapter: &str,
    snapshot: &mut CircuitSnapshot,
    cfg: &CircuitBreakerConfig,
    retry: &RetryConfig,
    now: Timestamp,
    mut op: F,
) -> DomainResult<T>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = DomainResult<T>>,
```

**执行流程**：

1. `snapshot.allows_call(cfg, now)` 为假 → **立即返回** `DomainError::DependencyUnavailable { cause: "熔断器处于 {state} 状态，快速失败" }`，**不执行 `op`**。
2. 循环 `0..retry.max_attempts.max(1)`：
   - `Ok(v)` → `snapshot.on_success()`，返回 `Ok(v)`；
   - `Err(e)` → 判定 `retryable = e.is_degradable() || matches!(e, DomainError::Timeout(_))`；
     **不可重试则立即 `break`**；可重试且还有剩余尝试则 `tokio::time::sleep(retry.backoff_ms(attempt))`。
3. 循环结束 → `snapshot.on_failure(cfg, msg, now)`，返回最后一次错误。

**可重试判定**（`agf-core/src/error.rs:189-191`）：

```rust
pub const fn is_degradable(&self) -> bool {
    matches!(self, Self::DependencyUnavailable { .. } | Self::Config(_) | Self::NotImplemented(_))
}
```

即：**只有"外部依赖不可用"、"配置问题"、"未实现"与"上游超时"会重试**；
`Validation` / `NotFound` / `Forbidden` / `TenantViolation` 等业务错误**一次都不重试**（测试 `invoke_with_policy_does_not_retry_non_retryable` 断言 `calls == 1`）。

### 2.5 死信队列

```rust
pub struct DeadLetterEntry {
    pub id: Id,
    pub tenant_id: TenantId,
    pub adapter: String,
    pub operation: String,          // sync / push / pull
    pub payload: serde_json::Value,
    pub error: String,              // 最后一次错误
    pub attempts: u32,
    pub replayed: bool,             // 是否已重放成功
    pub first_failed_at: Timestamp,
    pub last_failed_at: Timestamp,
}
```

**规范**：

| 规则 | 说明 |
|---|---|
| 落库时机 | 连续失败（重试耗尽）后落 `dead_letters` 表，**不阻塞主流程** |
| 隔离粒度 | 按 `(tenant_id, adapter, operation)` 记录；索引 `ix_dead_letters_adapter` |
| 重放 | `replayed` 标记；阿里云侧实现见 `crates/agf-alicloud/src/deadletter.rs`（离线缓存 + 死信 + 恢复重放） |
| 补传完成判定 | `deadletter.rs:211` —— "只要还有任一适配器的待补传条目，就说明'恢复补传'尚未完成" |
| 不落库场景 | 单次失败且仍在重试窗口内不落库；只在重试耗尽后落库 |

### 2.6 实现者的三条硬约束（契约文档原文）

1. **配置驱动 + 热插拔**：适配器由 `AdapterConfig` 描述，运行时可增删；
2. **未配置即降级**：`init` 返回 `HealthState::Unconfigured` 而不是错误，由 `MockAdapter`（各 crate 内 `mock` 模块）接管，保证平台永远可启动；
3. **熔断 + 重试 + 死信隔离**：`invoke` 必须经过 `CircuitBreakerConfig` 包裹，连续失败进死信队列，不阻塞主流程。

---

## 3. 凭据获取优先级

### 3.1 优先级（阿里云，规格 §5.3）

```
① RAM Role / 实例元数据（免密钥）
        ↓ 不可用时
② STS 临时凭据（含 AssumeRole 跨账号）
        ↓ 不可用时
③ 长期 AK（登记为一等风险，不推荐）
```

**禁止长期 AK 明文落盘**（`.env.example:213`）；生产凭据应通过 `agfctl secret set` 写入 `credentials` 表（AES-256-GCM 密文）。

### 3.2 凭据类型与推荐解析器

`agf-alicloud/src/credential.rs` 定义了 `CloudCredentialKind` 与推荐解析器映射：

```rust
pub fn recommended_resolver(kind: CloudCredentialKind) -> &'static str {
    match kind {
        CloudCredentialKind::InstanceRole     => "instance-role（元数据服务，无需密钥）",
        CloudCredentialKind::StsToken         => "sts",
        CloudCredentialKind::AssumeRole       => "assume-role",
        CloudCredentialKind::WorkloadIdentity => "workload-identity（OIDC 换取 STS）",
        CloudCredentialKind::LongTermAk       => "env / 静态（不推荐，请尽快迁移到 RAM Role）",
    }
}
```

### 3.3 解析器实现清单（`agf-alicloud`）

| 解析器 | 是否触网 | 状态 | 说明 |
|---|---|---|---|
| `StaticResolver` | ❌ 永不触网 | 🟢 | 凭据直接来自内存（**测试专用**，也是 Mock 模式的凭据来源） |
| `EnvResolver` | ❌ | 🟢 | 读 `AGF_ALIYUN_ACCESS_KEY_ID` / `..._SECRET` / `..._SECURITY_TOKEN`（前缀可覆盖，读取口可注入） |
| `StsResolver` | ✅ | 🔴 | **未实现**：`resolve` 返回 `DomainError::NotImplemented("STS 解析（账号 X）尚未实现，见 docs/pending-verification.md")`（`credential.rs:477-480`） |
| `AssumeRoleResolver` | ✅ | 🔴 | **未实现**：`resolve` 返回 `DomainError::NotImplemented("跨账号 AssumeRole（arn）尚未实现，…")`（`credential.rs:549-550`）；包装一个 `source: Arc<dyn CredentialResolver>` |

**未实现时的行为定义**（这是刻意的设计，不是缺陷）：

```rust
// credential.rs:452-456 —— STS / AssumeRole 的公共行为
/// STS / AssumeRole 解析器的公共行为：**没有网络就明确说不可用，绝不假装成功**。
```

| 场景 | 行为 |
|---|---|
| Mock 模式（`CredentialContext::mock == true`） | 直接返回 `DomainError::DependencyUnavailable`，**绝不发起真实 STS 调用** |
| 允许联网（`.allowing_network()`）但实现缺失 | 返回 `DomainError::NotImplemented`（同样是**明确失败，不假装成功**） |
| `AssumeRoleResolver::require_role_arn(integration)` | 缺少 `assume_role_arn` 时返回 `DomainError::Config` |

### 3.4 凭据的安全约定

```rust
/// 明文签名材料。
///
/// **安全约定**：本结构只在适配器内部短暂存活，不落库、不序列化、
/// `Debug`/日志输出一律掩码。
pub struct CloudCredential { … }
```

| 约定 | 实现 |
|---|---|
| `Debug` 掩码 | `impl std::fmt::Debug for CloudCredential`（`credential.rs:51`）只输出掩码，避免 `tracing` 的 `?cred` 把密钥打进日志 |
| 脱敏描述 | `CloudCredential::masked() -> String`（`:114`）——可安全写日志 |
| 齐全性校验 | `CloudCredential::validate()`：AK ID / Secret 为空 → `DomainError::Config` |
| 过期判定 | `is_expired(now)` / `is_expiring_soon(now)`（阈值 **15 分钟**，常量在 `credential.rs:27`，与 `CloudIntegration::sts_expiring_soon` 一致） |
| 长期 AK 风险登记 | `CredentialWarning::for_kind(kind) -> Option<Self>`；`to_check(now)` 产出 `PermissionCheck`，**长期 AK 是"已知风险"因此 `passed = false`（自检页标红）但 `required = false`（不阻断接入）** |
| 落库形态 | `agf_storage::crypto::FieldCipher`（AES-256-GCM，**AAD 绑定租户 + 凭据 id**）；本模块通过 `SecretLookup` trait 取明文，**不直接依赖数据库** |
| 自动刷新 | `RefreshableCredential::new(resolver)` + `cached()` + `should_refresh(now)` |

### 3.5 大模型厂商凭据（`agf-aigw`）

`ProviderAdapter` 的契约文档明确：**未配置凭据时不发起任何网络请求**，而是返回 `DomainError::NotImplemented`（可降级），由网关切换到 Mock。

| 解析器 | 读取来源 |
|---|---|
| `EnvCredentialResolver` | 约定名 `AGF_LLM_KEY_<CREDID>`（`credential_ref` 的 `-` 去掉后大写，`provider.rs:187`）；可被 `with_env` 覆盖 |
| `EnvCredentialResolver::resolve_aws_credentials` | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`（`provider.rs:1220-1225`） |
| `StaticCredentialResolver` | 内存注入 |
| `MockCredentialResolver` | 恒返回 `None`（用于强制走 Mock 路径） |

> **重要现状**：`.env.example` 第 146–209 行列出的 15 个上游变量（`AGF_OPENAI_API_KEY` 等）与 7 个 LLM 策略项
> 在 Rust 代码中**零引用**；`agf-core/src/config.rs` 的 `AppConfig` **没有 LLM/模型端点配置段**。
> `agf-aigw` 实际只读 3 类环境变量：`AGF_MOCK_MODE`、`AGF_LLM_KEY_<CREDID>`、`AWS_*`。
> 即：**把 `.env.example` 的 Key 变成可用的 `ModelEndpoint` 需要上层（`agf-api`）完成**。

---

## 4. 配置驱动与热插拔

### 4.1 `AdapterConfig`（DB 实体，`adapter_configs` 表）

```rust
pub struct AdapterConfig {
    pub id: Id,
    pub tenant_id: TenantId,
    pub adapter: String,                            // 注册名，如 alicloud-cms / llm-openai / qingteng
    pub display_name: String,
    pub enabled: bool,                              // ★ 热插拔开关
    pub settings: BTreeMap<String, serde_json::Value>,   // 非敏感参数（区域/endpoint/超时/开关）
    pub secret_refs: BTreeMap<String, Id>,          // ★ 凭据引用（键 = 用途名，如 access_key_id）
    pub circuit_breaker: CircuitBreakerConfig,
    pub retry: RetryConfig,
    pub timeout_secs: u64,                          // 默认 30
    pub mock: bool,                                 // 是否走 Mock（不触达真实外部系统）
    pub is_default: bool,                           // 是否为该适配器类型的默认实例
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}
```

**安全分工**：敏感值一律通过 `secret_refs` 指向 `credentials` 表（密文），`settings` 只放非敏感参数。辅助读取器：

| 方法 | 作用 |
|---|---|
| `get_str(key)` | 读取字符串设置 |
| `get_bool(key, default)` | 读取布尔设置 |
| `has_secrets(required: &[&str])` | 判断必需凭据键是否齐全 |

### 4.2 构建与热插拔（以阿里云 `AliCloudRegistry` 为参考实现）

```rust
impl AliCloudRegistry {
    /// 全部服务进入 Mock 模式（无云凭据环境的默认值，零配置可用）
    pub fn mock_only() -> Self;

    /// 按配置构建（每个服务可独立配置；缺失的服务回退 Mock）
    ///
    /// # Errors
    /// 某个服务的配置存在但非法（如地域非法）时返回 DomainError::Config
    pub async fn from_configs(configs: &[AdapterConfig]) -> DomainResult<Self>;

    /// 按注册名查适配器（返回 Arc<dyn Adapter>，供运行时统一调度）
    pub fn get(&self, name: &str) -> Option<Arc<dyn Adapter>>;

    /// 全部服务记录（控制台列表，按服务枚举顺序）
    pub fn records(&self) -> Vec<ServiceRecord>;

    /// 全部描述符
    pub fn descriptors(&self) -> Vec<AdapterDescriptor>;

    /// 健康汇总
    pub async fn health_all(&self) -> DomainResult<BTreeMap<String, AdapterHealth>>;

    /// 云环境自检：六个服务的报告 + 合并 RAM 策略
    pub fn self_check_suite(&self) -> CloudSelfCheckSuite;

    /// 未处于真实模式的服务（控制台"降级中"列表）
    pub fn degraded_services(&self) -> Vec<AliCloudService>;
}
```

**构建语义**（`registry.rs:114-190`）：

| 配置情况 | `mode` | `enabled` | `note` |
|---|---|---|---|
| 提供了配置且 `init` 成功、凭据齐全、非 Mock | `Live` | `config.enabled` | "已启用真实调用通道" |
| 提供了配置但 `config.mock == true` 或 `AGF_MOCK_MODE` | `Mocked` | `config.enabled` | "已启用 Mock（AGF_MOCK_MODE / config.mock）" |
| 提供了配置但缺少凭据引用 | `Unconfigured` | `config.enabled` | "配置存在但缺少凭据引用：已降级为不触达云 API" |
| **未提供配置** | `Mocked` | `true` | "未提供配置：自动回退 Mock 模式（不触达云 API）" |

**非法配置的处理**：`from_configs` 对"配置存在但非法"（如 `region_id` 含空格）返回 `DomainError::Config`（测试 `from_configs_rejects_invalid_region`）；
**缺凭据则降级为 `Unconfigured` 而非报错**（测试 `from_configs_without_credentials_degrades_not_fails`）。

**去重规则**：同一服务只允许一个实例；`index_configs` 遇到重复返回 `DomainError::Conflict`（测试 `index_configs_detects_duplicates`）。

**热插拔的控制台接口**：`ServiceRecord::is_serving() = enabled && mode.is_live()`；
`registry::console_row(&ServiceRecord) -> BTreeMap<String, String>` 产出 `service` / `display_name` / `mode` / `enabled` / `capabilities` / `degradation` / `mock_location` / `doc_anchor` 八个字段供"接入管理"页渲染。

**Mock 模式的环境变量判定**（`agf-alicloud/src/lib.rs:57-62`）：

```rust
pub const MOCK_MODE_ENV: &str = "AGF_MOCK_MODE";

pub fn mock_mode_from_env() -> bool {
    std::env::var(MOCK_MODE_ENV).is_ok_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        matches!(v.as_str(), "1" | "true" | "yes" | "on")
    })
}
```

**`AdapterMode` 三态**：`Unconfigured` / `Mocked` / `Live`；`is_mock()` / `is_live()`。

### 4.3 单一网络闸门（阿里云的关键不变量）

> **无凭据 / Mock 模式下绝不发起真实 HTTP。** 所有真实调用都必须先经过 `http::RpcClient::live` 这道闸门；
> `live` 在 `AdapterMode::Mocked` 或缺少 AK/SK 时返回错误，因此**不存在"忘了判断 mock 就打网络"的路径**。

这条不变量由 `crates/agf-alicloud/src/lib.rs:10-13` 明文声明，是"审计适配器是否偷跑网络"的检查入口。

### 4.4 适配器健康与自检的持久化

| 表 | 用途 | 关键字段 |
|---|---|---|
| `adapter_configs` | 适配器配置（含 `mock`、`enabled`、`circuit_breaker`、`retry`、`secret_refs`） | `0001_init_04.sql:121` |
| `adapter_health` | 健康快照历史（索引 `ix_adapter_health_time`） | `0001_init_04.sql:139` |
| `dead_letters` | 死信（索引 `ix_dead_letters_adapter`） | `0001_init_04.sql:154` |
| `cloud_integrations` / `alicloud_bindings` | 云账号绑定 | `0001_init_04.sql:22` / `:45` |
| `quota_sync_states` | 配额双向同步状态（冲突以平台为准） | `0001_init_04.sql:107` |
| `cross_team_calls` | AgentTeams 跨 Team 调用链 | `0001_init_04.sql:92` |
| `agent_teams` | AgentTeams 台账 | `0001_init_04.sql:75` |
| `cloud_resources` | 云资源清单 | `0001_init_04.sql:60` |

> **RLS 覆盖**：迁移的 RLS 表清单（`0001_init_04.sql:244-253`）包含 `cloud_integrations`、`cloud_resources`、`agent_teams`、`adapter_configs`，
> 但**不包含** `adapter_health`、`dead_letters`、`alicloud_bindings`、`cross_team_calls`、`quota_sync_states`
> —— 这几个表目前只有 `tenant_id` 列，无数据库层 RLS 兜底。

---

## 5. 适配器清单：降级行为与 Mock 实现位置

### 5.1 阿里云六适配器（`agf-alicloud`）🟢

**六个 `AdapterDescriptor` 均由 `mock::descriptor_of(service)` 统一产出**（保证"某个服务的降级行为没写"不可能发生），
`required_secrets` 恒为 `["access_key_id", "access_key_secret"]`，`optional_secrets` 恒为 `["sts_token", "assume_role_arn"]`，
`real_implementation` 恒为 `true`。

#### 5.1.1 `alicloud-cms`（阿里云云监控）

| 项 | 值 |
|---|---|
| 显示名 | 阿里云云监控（CMS） |
| Mock 实现位置 | `crates/agf-alicloud/src/mock.rs#mock_cms`（类型 `MockCmsAdapter`） |
| 文档锚点 | `docs/adapter-spec.md#alicloud-cms` |
| 能力 | 含 `PushMetrics`、`SelfCheck` |
| **未配置时的降级行为** | 未配置时不上报自定义事件与指标（本地事件照常落库），报警订阅回退为 ingest 侧本地轮询；平台主流程与已入库数据不受影响 |

#### 5.1.2 `alicloud-apig`（阿里云 AI 网关）

| 项 | 值 |
|---|---|
| 显示名 | 阿里云 AI 网关（APIG） |
| Mock 实现位置 | `crates/agf-alicloud/src/mock.rs#mock_apig`（类型 `MockApigAdapter`） |
| 文档锚点 | `docs/adapter-spec.md#alicloud-apig` |
| 能力 | 含 `EnforcePolicy`、`QueryLogs`；**不含** `SubscribeEvents`（有测试断言） |
| **未配置时的降级行为** | 未配置时不下发限流/Token 配额/内容安全/模型路由策略，`agf-aigw` 继续用本地策略兜底并记告警；访问日志改用本地采集通道 |

#### 5.1.3 `alicloud-mse`（阿里云微服务引擎）

| 项 | 值 |
|---|---|
| 显示名 | 阿里云微服务引擎（MSE） |
| Mock 实现位置 | `crates/agf-alicloud/src/mock.rs#mock_mse`（类型 `MockMseAdapter`） |
| 文档锚点 | `docs/adapter-spec.md#alicloud-mse` |
| 能力 | 含 `PullInventory` |
| **未配置时的降级行为** | 未配置时停止 Nacos 服务清单同步与配置热更新，资产发现回退为网段扫描 + 终端上报；已有资产标记 stale 但**绝不删除** |

#### 5.1.4 `alicloud-privatelink`（阿里云私网链接）

| 项 | 值 |
|---|---|
| 显示名 | 阿里云私网链接（PrivateLink） |
| Mock 实现位置 | `crates/agf-alicloud/src/mock.rs#mock_privatelink`（类型 `MockPrivatelinkAdapter`） |
| 文档锚点 | `docs/adapter-spec.md#alicloud-privatelink` |
| 能力 | 含 `ProbePrivateLink` |
| **未配置时的降级行为** | 未配置时私网探测不可用，连通性判定降级为「**未知**」而非「不通」；采集器继续本地缓存并在恢复后补传 |
| endpoint 支持 | `endpoint.rs` 支持私网形态 `https://<service>.<region>.privatelink.aliyuncs.com/` |

#### 5.1.5 `alicloud-schedulerx3`（阿里云分布式任务调度）

| 项 | 值 |
|---|---|
| 显示名 | 阿里云分布式任务调度（SchedulerX3） |
| Mock 实现位置 | `crates/agf-alicloud/src/mock.rs#mock_schedulerx3`（类型 `MockSchedulerX3Adapter`） |
| 文档锚点 | `docs/adapter-spec.md#alicloud-schedulerx3` |
| 能力 | 含 `ScheduleTask` |
| **未配置时的降级行为** | 未配置时全部云任务回退本地 tokio-cron（`ScheduleBackend::fallback`），无云环境**零配置可用**；分片退化为单实例串行 |
| 相关环境变量 | `AGF_SCHEDULER_BACKEND`（dev 默认 `local-cron`，prod 默认 `schedulerx3`）、`AGF_ALIYUN_SCHEDULERX3_NAMESPACE`、`AGF_ALIYUN_SCHEDULERX3_GROUP` |

#### 5.1.6 `alicloud-agentteams`（阿里云 AgentTeams 多智能体治理）

| 项 | 值 |
|---|---|
| 显示名 | 阿里云 AgentTeams 多智能体治理 |
| Mock 实现位置 | `crates/agf-alicloud/src/mock.rs#mock_agentteams`（类型 `MockAgentTeamsAdapter`） |
| 文档锚点 | `docs/adapter-spec.md#alicloud-agentteams` |
| 能力 | 含 `SubscribeEvents` |
| **未配置时的降级行为** | 未配置时台账只读：停止双向同步与配额下发，平台侧配置继续生效（**平台为准**）；审计事件缺失由网关侧流量审计补位 |
| Mock 语义示例 | `sync(Pull)` 返回 `changes["team"] == 3`（测试 `mock_only_smoke_sync_works_through_registry`） |

**六适配器的共同行为**：

| 行为 | 事实 |
|---|---|
| 未配置 = 降级不是错误 | `init` 永远返回 `Ok(())`；`health` 返回 `HealthState::Unconfigured`，由 `Mock*Adapter` 接管，**平台永远可启动** |
| Mock 与真实实现接口签名完全一致 | 每个服务定义 `*Api` trait，真实适配器与 `Mock*Adapter` **同时实现它**；差异只体现在 `AdapterMode` 字段上（`live()` 会拒绝 Mock 模式） |
| Mock 模式健康状态 | 全部六服务 `state == Degraded && mocked == true`，message 含 `AGF_MOCK_MODE`（测试 `health_all_reports_degraded_mock_for_every_service`） |
| 云环境自检 | `self_check_suite()` 产出六份 `CloudSelfCheckReport` + 合并 RAM 策略（`ram_policy_json()`，只含必需权限，不含可选权限如 `cms:ListAlarmHistories`）+ Markdown 报表（`to_markdown()`） |
| 自检结论 | Mock 模式下 `suite.overall() == Degraded`，`blocking_failures()` 为空（Mock 无阻断项） |

### 5.2 大模型厂商适配器（`agf-aigw`）🟢

**真实适配器 4 个 + Mock 适配器 1 个。** 四个真实适配器的 `ProviderDescriptor` 由同一个 `ProviderDescriptor::new(...)` 构造，因此
`category = "llm"`、`optional_secrets = ["base_url", "api_version"]`、
**`degradation` 与 `mock_location` 的文案完全一致**：

| 字段 | 值（逐字） |
|---|---|
| `category` | `llm` |
| `optional_secrets` | `["base_url", "api_version"]` |
| `degradation` | 未配置 API Key 时不发起任何上游请求，网关自动切换到 MockProvider（`src/mock.rs`）返回确定性回复，平台功能不中断 |
| `mock_location` | `crates/agf-aigw/src/mock.rs#MockProvider` |
| `adapter.doc_anchor` | `docs/roadmap.md`（注意：不是本文档） |

| # | 适配器注册名 | 类型 | 协议族 | 覆盖的 `LlmProvider` 变体 | 必需凭据 | 真实实现 |
|---|---|---|---|---|---|---|
| 1 | `llm-openai-compat` | `OpenAiCompatProvider` | `openai-compat` | **13 个**：`OpenAi`、`AzureOpenAi`、`DashScope`(百炼/通义)、`Ark`(火山方舟/豆包)、`Hunyuan`(腾讯混元)、`Qianfan`(百度文心)、`Moonshot`(Kimi)、`DeepSeek`、`Zhipu`(GLM)、`MiniMax`、`Ollama`、`Vllm`、`CustomOpenAiCompat` | API Key（Azure 走 `api-key` 头 + `api-version`） | 🟢 |
| 2 | `llm-anthropic` | `AnthropicProvider` | `anthropic` | `Anthropic` | API Key | 🟢（`x-api-key` + `anthropic-version`） |
| 3 | `llm-gemini` | `GeminiProvider` | `gemini` | `Gemini` | API Key | 🟢（流式用 `alt=sse`） |
| 4 | `llm-bedrock` | `BedrockProvider` | `bedrock` | `Bedrock` | `access_key_id` + `secret_access_key`（+ `session_token`） | 🟢（**自签 AWS SigV4**；流式用 Converse 私有二进制帧，**非 SSE**；不校验 CRC） |
| 5 | `llm-mock` | `MockProvider` | — | `Mock` | 无 | Mock 本体（`crates/agf-aigw/src/mock.rs`） |

**未识别厂商的处理**：`AiGateway::provider_for`（`gateway.rs:453-476`）按 Anthropic / Gemini / Bedrock / OpenAI 兼容四路分派；
**未识别厂商 warn 后按 OpenAI 兼容处理**。

**Mock 的三层触发条件**（在发出任何网络请求之前）：

1. `self.mock_mode == true`（显式 `.with_mock_mode(true)`，**覆盖环境变量**）；
2. `endpoint.provider == LlmProvider::Mock`；
3. `!self.credential_available(endpoint)`（`credential_ref` 为空或解析器返回 `None`）。

**Mock fixtures 位置**：`pub const FIXTURE_DIR: &str = "tests/fixtures/mock_responses"`（`mock.rs:149`，**相对进程当前工作目录**）；
`MockProvider::load_fixtures_from_dir(dir)` 遍历 `*.json`（数组或单对象，坏文件跳过并 warn）；`load_default_fixtures()` 用之。
匹配方式 = **按请求指纹精确查表**；未命中则按 `MockIntent::detect(prompt)` 渲染确定性回复。
⚠️ `crates/agf-aigw/tests/fixtures/mock_responses/` 目录**当前不存在**，因此实际只命中"合成"分支。

### 5.3 外部设备适配器（`agf-adapters`）🟢 send 全实现；push/pull/sync 按协议支持实现（3 工单类 + EDR + Slack push），其余如实 `Unsupported`

> **本节已按实现现状重写**（此前写的是"crate 5 行、全部开关背后无实现"，那在只有 Mock 时是对的，现已过时）。

| 事实 | 说明 |
|---|---|
| crate 状态 | `crates/agf-adapters` 已有完整实现：`contract/`（`Adapter`/`VendorAdapter` 契约 + 语义能力登记 + `sync_types`）、`registry/`（注册表 + 能力路由 + 配置热替换）、`vendor/`（`VendorAdapterImpl` + `push`/`pull`/`sync` 三个语义的实现与调度 + `incremental` 增量窗口 + `reconcile` 对账）、`health.rs`（可用/降级/不可用 + 连续失败数）、`transport.rs`、`settings/`、`http.rs`、`vendors/`（12 个厂商模块 + `capability_matrix` 能力矩阵渲染） |
| **真实传输** | 12 个适配器**全部**已实现真实传输：通知类 `feishu` / `dingtalk` / `wecom` / `slack` / `webhook` 走真实 HTTP POST，`email` 走**真实 SMTP 发送**（`lettre` 0.11.23）；工单类 `jira` / `servicenow` / `zentao` 走真实 REST 建单；安全平台类 `edr-isolation` 走 HTTP POST、`iam-scim` 走标准 SCIM 2.0 PATCH；`syslog-forwarder` 走真实 UDP/TCP（RFC 5424）。EDR/IAM 的真实写操作必须经持久化案件审批，集成中心只允许其 Mock 验证（EDR 另有只读拉取） |
| **email 的能力边界** | SMTP 的 TLS 信任锚是**编译内置的 webpki（Mozilla）根证书集**：公信证书的 SMTP 服务器可直接使用；**不支持内网自签 / 私有 CA 签发的 SMTP**（无 `smtp_ca_pem`，且**刻意不提供**"跳过证书校验"开关——把安全降级做成一行配置不是可接受的取舍）。需要私有 CA 时应在内网 SMTP 前置一个受信任证书的转发网关 |
| **push / pull / sync 的实现现状** | **接口类适配器（`jira` / `servicenow` / `zentao` / `edr`）已实现 push/pull/sync**（另：`slack` 有 `push` —— `chat.update`/`chat.delete`）；`pull` 按 `resource` 维护增量窗口去重，`sync` 按设置项 `sync_conflict_policy`（`external-wins` 默认 / `local-wins`）做本地 ↔ 外部双向对账并把每条裁决写进 `SyncOutcome.warnings`。**通知类与 `syslog`/`email` 因协议无读取/回写语义登记 `Unsupported` + 客观原因**（见 `crates/agf-adapters/CAPABILITY-MATRIX.md`——能力矩阵由代码同源渲染，是唯一事实源） |
| 测试证据 | `cargo test -p agf-adapters` = **290 项通过**（224 lib + 9 email_smtp + 49 http_vendors + 8 registry_routing）；其中 `tests/http_vendors/` 49 项用 **wiremock 本地假服务器**逐厂商断言**方法/路径/头/JSON 报文**（不是只看状态码），并覆盖超时、5xx 按 `RetryConfig` 重试、4xx/429 不重试、熔断开路与半开恢复、Mock 模式零网络请求、Syslog UDP/TCP 回环，以及 `push`/`pull`/`sync` 的增量游标、幂等键、冲突裁决；`tests/email_smtp/` 9 项用**假 SMTP 服务器**跑真实会话（`EHLO`/`STARTTLS`/`AUTH`/`DATA` 与报文原样投递） |
| 凭据纪律 | Webhook token 经 `redact_url` + `reqwest::Error::without_url()` 处理，**绝不进错误文本**；飞书/钉钉/企业微信/Slack 默认只允许厂商域名，私有化部署用 `allow_custom_host` 显式开关（默认 `false`） |
| 已解析的开关 | `agf-core/src/config.rs` 遍历 13 个名称，构造 `AGF_<VENDOR>_ENABLED` 键并解析为 bool（默认 `false`），存入 `AppConfig::device_adapters`；`AppConfig::adapter_enabled(name)` 查询 |
| 开关清单（13 个） | `qingteng`、`alicloud-waf`、`huawei-waf`、`huawei-hss`、`tencent`、`sangfor`、`qianxin`、`nsfocus`、`topsec`、`fortinet`、`paloalto`、`crowdstrike`、`wazuh` |
| **未配置时的降级行为** | `health_check` 返回 `Unconfigured`/`Degraded`（不报错、不 panic）；未配置时 `send` 返回**明确错误**（`Config`/`Validation`），绝不静默成功；**未登记语义返回不可重试的 `Validation` + 原因**（不是 `NotImplemented` 占位——只有新增适配器的脚手架阶段才会 `NotImplemented`）；`AGF_MOCK_MODE=1` 时全部走 Mock 且行为确定性 |
| 实现状态查询 | `GET /api/v1/integrations/adapters` 按 `agf_adapters::vendors::builtin()` 的 `descriptor()` **如实投影** `real_implementation` / `degradation`（`ecosystem.rs::device_adapter_views` 已不再硬编码 `false`） |
| Mock 实现位置 | 每个厂商模块内的 `Mock*Adapter`（`AdapterRegistry::mock_only()` 装配） |

> **设备事件接入有两条路**：**EDR 适配器已支持主机清单 / 设备事件增量拉取与对账**（`edr` 的 `pull`/`sync`，`GET /v1/hosts?updated_since=..`、`GET /v1/events?since=..`，见 `CAPABILITY-MATRIX.md`）；
> 其余没有可拉取设备 API 的设备仍建议走 Syslog/Webhook 转发接入 `agf-ingest`（已有厂商解析模板与样本，见 §5.4）——
> 平台主动下发（通知/建单/隔离）与主动拉取（EDR/工单类）现在都是真实可用的。

### 5.4 日志源适配（模板而非 `Adapter` trait）

设备与云平台的日志接入**不走 `Adapter` trait**，走 `agf-ingest` 的解析模板注册表。这是两类不同的扩展点：

| 维度 | `Adapter` trait | 解析模板（`ParserDefinition`） |
|---|---|---|
| 用途 | 双向集成（拉台账/推策略/上报指标/订阅事件） | 单向日志接入（原始文本 → AGF-ECS `Event`） |
| 实现载体 | Rust 结构体（`agf-alicloud` / `agf-aigw`） | YAML 模板（`agf-ingest/src/template.rs` 内置 + `AGF_RULES_DIR` 之外的模板目录） |
| 未配置降级 | `HealthState::Unconfigured` + Mock | 无匹配模板 → `ai_parser` 启发式推断（离线）+ 解析失败进 `raw_logs.parsed=false` |
| 内置数量 | 阿里云 6 + LLM 4（+1 Mock） | **18 个厂商模板** |
| 样本回归 | 无 | `manifest.json` 驱动的自动化测试（`manifest_covers_every_template_and_fixture_exists`、`every_manifest_fixture_parses_into_expected_event`） |

**18 个内置模板**（厂商 / 产品 / 引擎 / 样本）：

| # | key | 厂商 / 产品 | 引擎 | 样本文件 |
|---|---|---|---|---|
| 1 | `qingteng-hive-syslog` | 青藤云 / 蜂巢 | Grok | `qingteng-hive-1.log` |
| 2 | `aliyun-waf-webhook` | 阿里云 / Web应用防火墙 | JsonPath | `aliyun-waf-1.log` |
| 3 | `aliyun-sas-alert` | 阿里云 / 云安全中心 | JsonPath | `aliyun-sas-1.log` |
| 4 | `huawei-waf-webhook` | 华为云 / Web应用防火墙 | JsonPath | `huawei-waf-1.log` |
| 5 | `huawei-hss-alert` | 华为云 / 主机安全服务 | JsonPath | `huawei-hss-1.log` |
| 6 | `tencent-cfw-alert` | 腾讯云 / 云防火墙 | JsonPath | `tencent-cfw-1.log` |
| 7 | `sangfor-af-cef` | 深信服 / AF | Cef | `sangfor-af-1.log` |
| 8 | `qianxin-tianyan-cef` | 奇安信 / 天眼 | Cef | `qianxin-tianyan-1.log` |
| 9 | `nsfocus-ips-leef` | 绿盟 / IPS | Leef 2.0 | `nsfocus-ips-1.log` |
| 10 | `topsec-topsap-leef` | 天融信 / TopSAP | Leef 1.0（制表符） | `topsec-topsap-1.log` |
| 11 | `fortinet-fortigate-kv` | Fortinet / FortiGate | Kv | `fortinet-fortigate-1.log` |
| 12 | `paloalto-panos-csv` | Palo Alto / PAN-OS | Csv | `paloalto-panos-1.log` |
| 13 | `crowdstrike-falcon-webhook` | CrowdStrike / Falcon | JsonPath | `crowdstrike-falcon-1.log` |
| 14 | `wazuh-alert-json` | Wazuh / Wazuh Manager | JsonPath | `wazuh-alert-1.log` |
| 15 | `suricata-eve-json` | Suricata / eve.json | JsonPath | `suricata-eve-1.log`（**唯一真实样本**） |
| 16 | `zeek-conn-tsv` | Zeek / conn.log | Csv | `zeek-conn-1.log` |
| 17 | `linux-auditd-execve` | Linux / auditd | Regex | `linux-auditd-execve-1.log` |
| 18 | `syslog-generic` | generic / syslog | Syslog | `syslog-rfc3164-1.log` |

**未配置模板时的降级行为**（`agf-ingest` 的模板/引擎降级）：

| 情况 | 降级路径 |
|---|---|
| 无匹配模板 | `ai_parser` 的**离线启发式推断**（不打网络）；真实 LLM 推断 `RemoteAiParser` 返回 `NotImplemented`（`TODO ingest-ai-parser-remote`） |
| 解析失败 | 原始载荷仍落 `raw_logs`（`parsed = false` + `parse_error`），可经 `replay` 回放重解析；**绝不丢数据** |
| 模板正则非法 | 该模板进 `LoadReport.invalid`，不影响其它模板 |
| 语义引擎 | 不适用（解析引擎无语义类型） |

### 5.5 其他外部依赖的降级行为（非 `Adapter` trait，但同属"未配置即降级"）

| 依赖 | 未配置/不可用时的行为 | 证据 |
|---|---|---|
| **PostgreSQL** | **拒绝启动**（平台没有数据库无法工作），返回 `DependencyUnavailable` —— **唯一硬失败** | `agf-storage/src/lib.rs:14` |
| **Redis** | 启动继续；缓存走"未命中"；配额检查按调用方 `fail_closed` 决定（`true` = 拒绝）；分布式锁**返回错误**；网关缓存退化内存 | `lib.rs:112-118`、`redis_store.rs:224,318` |
| **对象存储** | 自动降级：S3 → 本地 `<data_dir>/objects` → 内存 | `objectstore.rs:1-9`、`select_object_store` / `build_object_store` |
| **NATS** | ⚠️ `AGF_NATS_ENABLED` / `AGF_NATS_URL` / `AGF_NATS_STREAM` 在 Rust 中**零引用**（`NatsConfig` 解析后无消费者）；`NatsEventBus` 无实例化调用方 ⇒ 当前实际无"总线降级"逻辑可触发 | `agf-core/src/config.rs:514-518` |
| **ClickHouse** | `AGF_CLICKHOUSE_ENABLED=0`（默认）；`events` 表在 TimescaleDB 不可用时退化为普通表 | `.env.example:87`、`0001_init_01.sql:18-29` |
| **大模型** | 缺 Key 或 `AGF_MOCK_MODE=1` → `MockProvider` 接管；`GatewayResponse.mocked = true` | `agf-aigw/src/lib.rs:47-57` |
| **Syslog TLS** | **已实现**：`SyslogTlsListener`（RFC5425，默认端口 6514），由 `apps/ingest` 按 `AGF_SYSLOG_TLS_PORT` + `AGF_SYSLOG_TLS_CERT/KEY` 装配，证书缺失只 `warn` 不监听 | `agf-ingest/src/syslog.rs` |
| **Kafka / Pulsar / MQTT / SNMP / JDBC / OTLP / OSS 拉取** | **全部已实现**（各带真实传输，`/readyz` 能力矩阵逐条 `ready` 且 `mock_replay: false`）：Kafka（`rskafka`）、Pulsar（**经 KoP 复用 Kafka 接收器**；原生协议未实现）、MQTT（`rumqttc`）、SNMP Trap（v1/v2c + v3 USM `noAuthNoPriv`/`authNoPriv`；`authPriv` 的 CBC-DES/CFB128-AES-128 **已实现**）、JDBC（**PostgreSQL / MySQL / MSSQL / Oracle 四种方言**，按 DSN scheme 自动选驱动；**MSSQL 与 Oracle 均已真机验证**——Oracle 证据：PG `events` 的 `source_name='sql-pull'` 70→75(+5)→77(仅 +2)、游标 `"5"`→`"7"`，见 `tools/simulators/out/oracle-e2e-evidence.txt`；OCI 运行库走仓库内 `tools/oracle/`，**构建期从此需要 C 编译器**，未覆盖项见 `TODO ingest-jdbc-oracle-extras`）、OTLP（HTTP + gRPC）、OSS-S3 拉取；**未配置即不启用**（不降级为 Mock） | `receiver.rs` 的 `receiver_capability_matrix()` |
| **通知渠道** | 未配置 → 不发送（模型与模板已就绪） | `.env.example` §14、`agf-core/src/notify.rs` |
| **Grafana** | `--profile grafana` 未启用时不启动；`AGF_GRAFANA_ADMIN_PASSWORD` 仅在启用时被 compose 强制校验 | `docker-compose.yml:353-373` |

---

## 6. 如何写一个新的适配器

### 6.1 检查清单（提交前必须全部满足）

| # | 要求 | 验证方式 |
|---|---|---|
| 1 | 实现 `agf_core::adapter::Adapter` 全部 7 个方法 | 编译（缺一个即报错） |
| 2 | `name()` 返回稳定的 kebab-case 注册名 | 单元测试断言 |
| 3 | `descriptor()` 的 `degradation` **非空且描述真实行为** | `assert!(!d.degradation.is_empty())` |
| 4 | `descriptor()` 的 `mock_location` **非空且指向真实路径** | `assert!(!d.mock_location.is_empty())` |
| 5 | `init()` 在未配置时返回 `Ok(())`，`health()` 暴露 `HealthState::Unconfigured` | 测试"未配置不得导致构建失败" |
| 6 | 同时提供 `Mock*` 实现，**接口签名与真实实现一致** | 统一 `*Api` trait 双实现 |
| 7 | 所有网络调用经 `invoke_with_policy` 包裹（熔断 + 重试 + 死信） | 代码评审 |
| 8 | Mock 模式下**绝不发起真实网络请求**（单一闸门） | 闸门函数测试 + 代码评审 |
| 9 | `shutdown()` 幂等，可重复调用 | 连续调用两次的测试 |
| 10 | 凭据走 `secret_refs` → `credentials` 表，**不落明文**；`Debug` 掩码 | `Debug` 输出断言 |
| 11 | 在本文件 §5 增加一节，写明显示名/能力/凭据键/**降级行为**/Mock 位置 | 文档评审 |
| 12 | 无 `unwrap()` / `expect()` / `panic!` / `unsafe` | `cargo clippy -- -D warnings` |
| 13 | 离线可测（不依赖真实外部系统） | `cargo test -p <crate>` 在无网络下通过 |

### 6.2 骨架代码

```rust
//! <厂商> 适配器：<一句话职责>
//!
//! 降级行为：<未配置时会发生什么——必须与 descriptor().degradation 一致>
//! Mock 实现：`crate::mock::Mock<Xxx>Adapter`

use std::sync::Arc;

use agf_core::adapter::{
    Adapter, AdapterCapability, AdapterConfig, AdapterDescriptor, AdapterHealth,
    CircuitBreakerConfig, CircuitSnapshot, PushPayload, PullRequest, PullResponse,
    SyncDirection, SyncOutcome, invoke_with_policy,
};
use agf_core::enums::HealthState;
use agf_core::error::{DomainError, DomainResult};
use agf_core::time::Timestamp;

/// 该厂商的能力面（真实实现与 Mock 共同实现，保证签名一致）。
#[async_trait::async_trait]
pub trait XxxApi: Send + Sync {
    /// 拉取远端台账。
    async fn list_things(&self, cursor: Option<&str>, limit: u32)
        -> DomainResult<(Vec<serde_json::Value>, Option<String>)>;
    /// 推送配置到远端。
    async fn put_config(&self, body: &serde_json::Value) -> DomainResult<()>;
}

/// 运行模式（与 `agf-alicloud::AdapterMode` 同构）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XxxMode { Unconfigured, Mocked, Live }

/// 真实适配器。
pub struct XxxAdapter {
    core: XxxCore,
    api: Option<Arc<dyn XxxApi>>,
}

struct XxxCore {
    tenant_id: agf_core::ids::TenantId,
    region: String,
    endpoint: String,
    circuit: CircuitSnapshot,
    breaker: CircuitBreakerConfig,
    retry: agf_core::adapter::RetryConfig,
    /// 明文只在内存短暂存活，`Debug` 必须掩码。
    credential: Option<crate::credential::CloudCredential>,
    mode: XxxMode,
}

impl std::fmt::Debug for XxxCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 绝不打印 credential 内容
        f.debug_struct("XxxCore")
            .field("tenant_id", &self.tenant_id)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("mode", &self.mode)
            .field("credential", &self.credential.as_ref().map(|c| c.masked()))
            .finish_non_exhaustive()
    }
}

impl XxxAdapter {
    /// 未配置形态（`init` 之前 / 无凭据）。
    #[must_use]
    pub fn unconfigured() -> Self { /* … */ }

    /// Mock 形态（**绝不联网**）。
    #[must_use]
    pub fn mocked() -> Self { /* … */ }

    #[must_use]
    pub const fn mode(&self) -> XxxMode { self.core.mode }

    /// 单一网络闸门：Mock 或缺凭据时返回错误。
    ///
    /// **所有**真实 HTTP 调用必须先过这里，杜绝"忘了判断 mock 就打网络"。
    fn live(&self) -> DomainResult<&dyn XxxApi> {
        match (self.core.mode, self.api.as_deref()) {
            (XxxMode::Live, Some(api)) => Ok(api),
            (XxxMode::Mocked, _) => Err(DomainError::DependencyUnavailable {
                dependency: "xxx".into(),
                cause: "Mock 模式：不发起真实请求".into(),
            }),
            _ => Err(DomainError::NotImplemented(
                "未配置凭据（见 docs/adapter-spec.md#xxx）".into(),
            )),
        }
    }

    /// 统一包装：熔断检查 → 重试 → 记录。
    async fn invoke<T, F, Fut>(&mut self, op: F) -> DomainResult<T>
    where
        F: FnMut(u32) -> Fut,
        Fut: std::future::Future<Output = DomainResult<T>>,
    {
        let name = self.name().to_string();
        let breaker = self.core.breaker;
        let retry = self.core.retry;
        invoke_with_policy(&name, &mut self.core.circuit, &breaker, &retry, Timestamp::now(), op).await
    }
}

#[async_trait::async_trait]
impl Adapter for XxxAdapter {
    fn name(&self) -> &str { "xxx" }

    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            name: "xxx".into(),
            display_name: "<厂商显示名>".into(),
            category: "waf".into(),                     // alicloud|llm|siem|waf|message|identity
            required_secrets: vec!["access_key_id".into(), "access_key_secret".into()],
            optional_secrets: vec!["sts_token".into()],
            capabilities: vec![AdapterCapability::PullInventory, AdapterCapability::SelfCheck],
            // ★ 必须写明：未配置时到底会发生什么
            degradation: "未配置时停止台账同步，资产发现回退为网段扫描 + 终端上报；\
                          已有资产标记 stale 但不删除；平台主流程不受影响".into(),
            // ★ 必须指向真实路径
            mock_location: "crates/agf-adapters/src/xxx/mock.rs#MockXxxAdapter".into(),
            real_implementation: true,
            doc_anchor: "docs/adapter-spec.md#xxx".into(),
        }
    }

    /// 未配置时返回 `Ok(())` 并标记 Unconfigured，**不是 Err**。
    async fn init(&mut self, config: &AdapterConfig) -> DomainResult<()> {
        // ① 读非敏感设置
        self.core.region = config.get_str("region").unwrap_or("cn-hangzhou").to_string();
        // ② 校验（仅"配置存在但非法"才报错）
        if self.core.region.contains(' ') {
            return Err(DomainError::Config(format!("非法地域: {}", self.core.region)));
        }
        // ③ 凭据未配置 → 走 Mock，不报错
        if !config.has_secrets(&["access_key_id", "access_key_secret"]) || config.mock {
            self.core.mode = XxxMode::Mocked;
            return Ok(());
        }
        // ④ 取明文（由 SecretLookup 从 credentials 表解密），失败也不 panic
        // self.core.credential = Some(resolver.resolve(...)?);
        self.core.mode = XxxMode::Live;
        Ok(())
    }

    async fn health(&self) -> DomainResult<AdapterHealth> {
        Ok(match self.core.mode {
            XxxMode::Unconfigured => AdapterHealth::unconfigured(self.name(), "未配置 AK/SK"),
            XxxMode::Mocked => AdapterHealth::mocked(self.name()),
            XxxMode::Live => AdapterHealth { /* 真实探测；网络失败映射为状态而非 Err */ ..Default::default() },
        })
    }

    async fn sync(&self, direction: SyncDirection, req: &PullRequest) -> DomainResult<SyncOutcome> {
        if self.core.mode != XxxMode::Live {
            return Ok(SyncOutcome::mock(0, 0));         // 降级：Mock 结果，不报错
        }
        let started = std::time::Instant::now();
        let mut out = SyncOutcome::default();
        if direction.includes_pull() {
            let (items, cursor) = self.live()?.list_things(req.cursor.as_deref(), req.limit.unwrap_or(100)).await?;
            out.pulled = items.len();
            out.changes.insert("thing".into(), items.len());
            let _ = cursor;
        }
        out.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        out.finished_at = Some(Timestamp::now());
        Ok(out)
    }

    async fn push(&self, payload: &PushPayload) -> DomainResult<()> {
        if self.core.mode != XxxMode::Live {
            return Ok(());                              // 降级：静默跳过并计数
        }
        self.live()?.put_config(&payload.body).await
    }

    async fn pull(&self, req: &PullRequest) -> DomainResult<PullResponse> {
        if self.core.mode != XxxMode::Live {
            return Ok(PullResponse {
                items: Vec::new(), next_cursor: None, mocked: true,
                origin: "mock://xxx".into(),
            });
        }
        let (items, next_cursor) = self.live()?.list_things(req.cursor.as_deref(), req.limit.unwrap_or(100)).await?;
        Ok(PullResponse { items, next_cursor, mocked: false, origin: self.core.endpoint.clone() })
    }

    async fn shutdown(&mut self) -> DomainResult<()> {
        // 幂等：重复调用必须成功
        self.api = None;
        Ok(())
    }
}

/// 确定性 Mock（与真实实现同签名，**绝不联网**）。
pub struct MockXxxAdapter { inner: XxxCore }

#[async_trait::async_trait]
impl XxxApi for MockXxxAdapter {
    async fn list_things(&self, _cursor: Option<&str>, _limit: u32)
        -> DomainResult<(Vec<serde_json::Value>, Option<String>)>
    {
        // 确定性：用 content_hash 派生，保证同一输入永远同一输出
        Ok((vec![serde_json::json!({ "id": "thing-1", "mock": true })], None))
    }
    async fn put_config(&self, _body: &serde_json::Value) -> DomainResult<()> { Ok(()) }
}
```

### 6.3 注册到注册表

```rust
// 参考 crates/agf-alicloud/src/registry.rs 的写法
pub struct MyRegistry {
    xxx: Arc<XxxAdapter>,
    records: BTreeMap<String, ServiceRecord>,
}

impl MyRegistry {
    /// 无凭据环境的默认值：全部 Mock，零配置可用。
    #[must_use]
    pub fn mock_only() -> Self { /* … */ }

    /// 按配置构建；缺失的服务回退 Mock，非法配置报 Config。
    ///
    /// # Errors
    /// 配置存在但非法时返回 `DomainError::Config`。
    pub async fn from_configs(configs: &[AdapterConfig]) -> DomainResult<Self> { /* … */ }

    /// 供运行时统一调度。
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<dyn Adapter>> { /* match name { "xxx" => Some(self.xxx.clone()), _ => None } */ }
}
```

### 6.4 必须补充的测试（离线，无需网络）

| # | 测试 | 断言 |
|---|---|---|
| 1 | `descriptor_is_complete` | `!degradation.is_empty()`、`!mock_location.is_empty()`、`!capabilities.is_empty()`、`real_implementation` |
| 2 | `mock_location_points_to_real_constructor` | `mock_location` 以 `#mock_xxx` 结尾 |
| 3 | `unconfigured_init_does_not_fail` | `init(&cfg_without_secrets).await.is_ok()`，且 `mode == Mocked` |
| 4 | `invalid_config_is_rejected` | 非法 `region` → `Err(DomainError::Config(_))` |
| 5 | `mock_never_opens_a_socket` | Mock 下 `live()` 返回 `Err`；`sync` / `push` / `pull` 均 `Ok` 且 `mocked == true` |
| 6 | `health_reports_degraded_not_failure` | `state == Degraded && mocked`，message 含 `AGF_MOCK_MODE` |
| 7 | `shutdown_is_idempotent` | `shutdown().await` 连续两次均 `Ok` |
| 8 | `circuit_opens_after_threshold`（复用 core 的测试思路） | 连续失败达阈值后 `allows_call == false` 且 `op` 不被执行 |
| 9 | `retry_does_not_retry_validation_errors` | `Validation` 错误只调用一次 `op` |
| 10 | `debug_does_not_leak_secrets` | `format!("{:?}", adapter)` 不含明文密钥 |

---

## 7. 相关文档

- 架构分层与数据流：[`docs/architecture.md`](architecture.md)
- 威胁模型（含适配器相关的 STRIDE 分析）：[`docs/threat-model.md`](threat-model.md)
- 部署与 `.env` 全量变量：[`docs/deployment.md`](deployment.md)
- 运维（熔断/死信/降级的日常处置）：[`docs/operations.md`](operations.md)
- 真实缺口清单：[`docs/pending-verification.docs.md`](pending-verification.docs.md)
