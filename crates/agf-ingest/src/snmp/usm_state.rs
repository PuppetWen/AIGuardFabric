//! USM 引擎时钟（RFC3414 §3.2 时间窗）与 `UsmConfig`（认证协议/口令/本地化密钥校验）。

use super::*;

/// 权威引擎时限状态（RFC3414 §3.2 步骤 7.1）。
///
/// Trap 接收侧的 engineID 由报文给出，因此**第一条报文总是被接受**（等价于引擎发现），
/// 之后按 `(boots, time)` 单调性 + 本地经过时间推算预期时间，超出 150s 窗口即判为超窗。
#[derive(Debug, Default)]
pub struct EngineClock {
    last: Mutex<Option<EngineSeen>>,
}

#[derive(Debug, Clone)]
struct EngineSeen {
    engine_id: Vec<u8>,
    boots: i64,
    time: i64,
    at: std::time::Instant,
}

impl EngineClock {
    /// 新建（空闲）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 校验并记录。返回 `false` 表示**超出时限窗口**（调用方计入 `usmStatsNotInTimeWindows` 并拒绝）。
    pub fn check(&self, engine_id: &[u8], boots: i64, time: i64) -> bool {
        let now = std::time::Instant::now();
        let mut guard = match self.last.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let accepted = match guard.as_ref() {
            Some(seen) if seen.engine_id == engine_id => match boots.cmp(&seen.boots) {
                // 引擎重启后 boots 前进 ⇒ 可信
                std::cmp::Ordering::Greater => true,
                // boots 回退 ⇒ 旧值不可信，按超窗处理（等对方重新上报）
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => {
                    let elapsed = i64::try_from(now.saturating_duration_since(seen.at).as_secs()).unwrap_or(0);
                    let expected = seen.time.saturating_add(elapsed);
                    (time.saturating_sub(expected)).abs() <= USM_TIME_WINDOW_SECS
                }
            },
            // 首次见到该引擎：接受（引擎发现语义）
            _ => true,
        };
        if accepted {
            *guard = Some(EngineSeen { engine_id: engine_id.to_vec(), boots, time, at: now });
        }
        accepted
    }
}

/// v3 USM 配置（用户名 / 安全级别 / 认证协议与口令 / 隐私协议与口令）。
///
/// **凭据纪律**：两个口令字段只进内存配置；`Debug` 是**手写**的（口令只输出"已设置/未配置"），
/// [`UsmConfig::describe`] 与所有错误文本同样**不含口令**——日志里 `?usm` 也不会泄漏。
#[derive(Clone, Serialize, Deserialize)]
pub struct UsmConfig {
    /// 期望的 `msgUserName`（空 = 不校验用户名）。
    pub user: Option<String>,
    /// 期望的安全级别。
    pub level: V3SecurityLevel,
    /// 认证协议（`noAuthNoPriv` 时无意义）。
    pub auth_protocol: AuthProtocol,
    /// 认证口令（`authNoPriv`/`authPriv` 必填，≥8 字符；**不落日志**）。
    pub auth_password: Option<String>,
    /// 隐私协议（`authPriv` 生效；DES 或 AES）。
    #[serde(default)]
    pub priv_protocol: PrivProtocol,
    /// 隐私口令（`authPriv` 必填，≥8 字符；**不落日志**）。
    #[serde(default)]
    pub priv_password: Option<String>,
}

impl std::fmt::Debug for UsmConfig {
    /// 手写 `Debug`：**口令一律脱敏**（只表明是否已配置），避免 `?usm` 把凭据写进日志。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsmConfig")
            .field("user", &self.user)
            .field("level", &self.level)
            .field("auth_protocol", &self.auth_protocol)
            .field("auth_password", &redacted(self.auth_password.as_deref()))
            .field("priv_protocol", &self.priv_protocol)
            .field("priv_password", &redacted(self.priv_password.as_deref()))
            .finish()
    }
}

/// 凭据脱敏文本（**只有"是否已配置"，没有长度也没有内容**——长度也会泄漏信息）。
fn redacted(secret: Option<&str>) -> &'static str {
    match secret {
        Some(value) if !value.is_empty() => "<已配置，值不回显>",
        _ => "<未配置>",
    }
}

impl Default for UsmConfig {
    fn default() -> Self {
        Self {
            user: None,
            level: V3SecurityLevel::NoAuthNoPriv,
            auth_protocol: AuthProtocol::Md5,
            auth_password: None,
            priv_protocol: PrivProtocol::default(),
            priv_password: None,
        }
    }
}

impl UsmConfig {
    /// 免认证（`noAuthNoPriv`）。
    #[must_use]
    pub fn no_auth() -> Self {
        Self::default()
    }

    /// 认证不加密（`authNoPriv`）。
    ///
    /// # Errors
    /// 口令缺失/过短（RFC3414 §A.2 要求 ≥8 字符）。
    pub fn auth_no_priv(
        user: impl Into<String>,
        protocol: AuthProtocol,
        password: impl Into<String>,
    ) -> DomainResult<Self> {
        let password = password.into();
        check_password_len("认证口令", "authNoPriv", &password)?;
        Ok(Self {
            user: Some(user.into()),
            level: V3SecurityLevel::AuthNoPriv,
            auth_protocol: protocol,
            auth_password: Some(password),
            priv_protocol: PrivProtocol::default(),
            priv_password: None,
        })
    }

    /// 认证且加密（`authPriv`，DES 或 AES）。
    ///
    /// # Errors
    /// 两个口令缺失/过短，或隐私协议不被支持。
    pub fn auth_priv(
        user: impl Into<String>,
        protocol: AuthProtocol,
        password: impl Into<String>,
        priv_protocol: PrivProtocol,
        priv_password: impl Into<String>,
    ) -> DomainResult<Self> {
        let password = password.into();
        let priv_password = priv_password.into();
        check_password_len("认证口令", "authPriv", &password)?;
        check_password_len("隐私口令", "authPriv", &priv_password)?;
        if !priv_protocol.is_implemented() {
            return Err(DomainError::NotImplemented(format!("SNMP v3 隐私协议 {} 未实现", priv_protocol.as_str())));
        }
        Ok(Self {
            user: Some(user.into()),
            level: V3SecurityLevel::AuthPriv,
            auth_protocol: protocol,
            auth_password: Some(password),
            priv_protocol,
            priv_password: Some(priv_password),
        })
    }

    /// 按安全级别构造。
    ///
    /// # Errors
    /// `authNoPriv`/`authPriv` 缺口令、`authPriv` 缺隐私协议或隐私口令、级别文本非法。
    pub fn from_parts(
        user: Option<String>,
        level: V3SecurityLevel,
        protocol: AuthProtocol,
        password: Option<String>,
        priv_protocol: PrivProtocol,
        priv_password: Option<String>,
    ) -> DomainResult<Self> {
        match level {
            V3SecurityLevel::NoAuthNoPriv => Ok(Self {
                user: user.filter(|u| !u.is_empty()),
                level,
                auth_protocol: protocol,
                auth_password: None,
                priv_protocol,
                priv_password: None,
            }),
            V3SecurityLevel::AuthNoPriv => {
                let Some(user) = user.filter(|u| !u.is_empty()) else {
                    return Err(DomainError::Config(
                        "SNMP v3 authNoPriv 需要用户名（AGF_INGEST_SNMP_V3_USER）".to_string(),
                    ));
                };
                let Some(password) = password.filter(|p| !p.is_empty()) else {
                    return Err(DomainError::Config(
                        "SNMP v3 authNoPriv 需要认证口令（AGF_INGEST_SNMP_V3_AUTH_PASSWORD）".to_string(),
                    ));
                };
                Self::auth_no_priv(user, protocol, password)
            }
            V3SecurityLevel::AuthPriv => {
                let Some(user) = user.filter(|u| !u.is_empty()) else {
                    return Err(DomainError::Config(
                        "SNMP v3 authPriv 需要用户名（AGF_INGEST_SNMP_V3_USER）".to_string(),
                    ));
                };
                let Some(password) = password.filter(|p| !p.is_empty()) else {
                    return Err(DomainError::Config(
                        "SNMP v3 authPriv 需要认证口令（AGF_INGEST_SNMP_V3_AUTH_PASSWORD）".to_string(),
                    ));
                };
                let Some(priv_password) = priv_password.filter(|p| !p.is_empty()) else {
                    return Err(DomainError::Config(
                        "SNMP v3 authPriv 需要隐私口令（AGF_INGEST_SNMP_V3_PRIV_PASSWORD）".to_string(),
                    ));
                };
                Self::auth_priv(user, protocol, password, priv_protocol, priv_password)
            }
        }
    }

    /// 按 engineID 本地化认证密钥（`authNoPriv` / `authPriv` 都有值）。
    #[must_use]
    pub fn localized_key(&self, engine_id: &[u8]) -> Option<Vec<u8>> {
        if self.level == V3SecurityLevel::NoAuthNoPriv {
            return None;
        }
        self.auth_protocol.localize_key(self.auth_password.as_deref()?, engine_id)
    }

    /// 按 engineID 本地化隐私密钥（`privKey = Kul 前 16 字节`；仅 `authPriv` 有值）。
    #[must_use]
    pub fn localized_priv_key(&self, engine_id: &[u8]) -> Option<Vec<u8>> {
        if self.level != V3SecurityLevel::AuthPriv {
            return None;
        }
        localized_priv_key(self.auth_protocol, self.priv_password.as_deref()?, engine_id)
    }

    /// 人读描述（**绝不包含口令**）。
    #[must_use]
    pub fn describe(&self) -> String {
        match self.level {
            V3SecurityLevel::NoAuthNoPriv => "v3/noAuthNoPriv".to_string(),
            V3SecurityLevel::AuthNoPriv => format!(
                "v3/authNoPriv(user={}, auth={})",
                self.user.as_deref().unwrap_or("<未配置>"),
                self.auth_protocol.as_str()
            ),
            V3SecurityLevel::AuthPriv => format!(
                "v3/authPriv(user={}, auth={}, priv={})",
                self.user.as_deref().unwrap_or("<未配置>"),
                self.auth_protocol.as_str(),
                self.priv_protocol.as_str()
            ),
        }
    }
}

/// 口令长度校验（RFC3414 §A.2：≥8 字符）。错误文本只含"哪一类口令 + 实际字符数"，不回显口令。
fn check_password_len(kind: &str, level: &str, password: &str) -> DomainResult<()> {
    if password.chars().count() < 8 {
        return Err(DomainError::Config(format!(
            "SNMP v3 {level} {kind}至少 8 字符（RFC3414 §A.2），当前 {} 字符",
            password.chars().count()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Trap 模型
// ---------------------------------------------------------------------------
