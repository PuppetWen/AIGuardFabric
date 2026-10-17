//! 由 `main.rs` 拆分：`impl_ListenerState`/`push_note` 等 16 项（纯搬移，逻辑不变）。
use super::*;

impl ListenerState {
    /// 追加一条降级说明（锁中毒时丢弃该条——指标不能反过来把进程搞挂）。
    pub(crate) fn note(&self, text: impl Into<String>) {
        if let Ok(mut notes) = self.notes.lock() {
            notes.push(text.into());
        }
    }

    /// 快照。
    pub(crate) fn note_snapshot(&self) -> Vec<String> {
        self.notes.lock().map(|notes| notes.clone()).unwrap_or_default()
    }
}

/// 后台任务里追加降级说明（同 [`ListenerState::note`]，但只持有 notes 句柄）。
pub(crate) fn push_note(notes: &std::sync::Arc<std::sync::Mutex<Vec<String>>>, text: impl Into<String>) {
    if let Ok(mut notes) = notes.lock() {
        notes.push(text.into());
    }
}

/// 拼装 SQL 拉取的最终语句（仅用于启动日志/排障；真正的执行在接收器内部）。
///
/// 按**方言**拼装：PostgreSQL 用 `row_to_json` + `$1`，MySQL 用 `?` + `CAST(... AS signed)`
/// （见 `agf_ingest::jdbc::build_pull_sql_for`）。
pub(crate) fn config_pull_sql(dialect: SqlDialect, config: &SqlPullConfig) -> agf_core::error::DomainResult<String> {
    let cursor_field = config.cursor_field.as_deref().map(str::trim).filter(|f| !f.is_empty());
    agf_ingest::jdbc::build_pull_sql_for(dialect, &config.sql, cursor_field, config.cursor_type, config.batch_limit)
}

/// 探测 `/healthz`。
pub(crate) async fn healthcheck(url: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .context("构造 HTTP 客户端失败")?;
    match client.get(url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let _ = writeln!(std::io::stdout(), "OK {}", resp.status().as_u16());
            Ok(())
        }
        Ok(resp) => {
            let _ = writeln!(std::io::stderr(), "FAIL {} {}", url, resp.status().as_u16());
            std::process::exit(1);
        }
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "FAIL {url} {e}");
            std::process::exit(1);
        }
    }
}

/// 读取环境变量（空值视为未设置）。
pub(crate) fn env_or(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => default.to_string(),
    }
}

/// 开关型环境变量。
pub(crate) fn env_flag(key: &str) -> bool {
    matches!(std::env::var(key).as_deref(), Ok("1" | "true" | "yes"))
}

/// 凭据型环境变量：读取 + 去首尾空白，**绝不打印**。
pub(crate) fn env_secret(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// 可选路径型环境变量。
pub(crate) fn env_path(key: &str) -> Option<PathBuf> {
    env_secret(key).map(PathBuf::from)
}

/// 由环境变量构造 Kafka SASL 配置（凭据只来自 env/settings）。
///
/// 机制非法或缺凭据 ⇒ `None` + warn（**绝不**把口令拼进任何日志/错误文本）。
pub(crate) fn kafka_sasl_from_env() -> Option<KafkaSaslConfig> {
    let raw = env_secret("AGF_INGEST_KAFKA_SASL_MECHANISM")?;
    let Some(mechanism) = KafkaSaslMechanism::parse(&raw) else {
        tracing::warn!(
            mechanism = %raw,
            "Kafka SASL 机制不认识（支持 PLAIN / SCRAM-SHA-256 / SCRAM-SHA-512）：SASL 未启用"
        );
        return None;
    };
    let Some(username) = env_secret("AGF_INGEST_KAFKA_SASL_USERNAME") else {
        tracing::warn!("Kafka SASL 未启用：缺少 AGF_INGEST_KAFKA_SASL_USERNAME");
        return None;
    };
    let Some(password) = env_secret("AGF_INGEST_KAFKA_SASL_PASSWORD") else {
        tracing::warn!("Kafka SASL 未启用：缺少 AGF_INGEST_KAFKA_SASL_PASSWORD");
        return None;
    };
    tracing::info!(mechanism = mechanism.as_str(), username = %username, "Kafka SASL 已启用（口令不落日志）");
    Some(KafkaSaslConfig::new(mechanism, username, password))
}

/// 由环境变量构造 Kafka TLS 配置（默认关闭；开启后默认**校验证书链**）。
///
/// 跳过校验只在 `AGF_INGEST_KAFKA_TLS_INSECURE_SKIP_VERIFY=1` 时生效，并立即 `warn!`。
pub(crate) fn kafka_tls_from_env() -> Option<KafkaTlsConfig> {
    if !env_flag("AGF_INGEST_KAFKA_TLS") {
        return None;
    }
    let insecure = env_flag("AGF_INGEST_KAFKA_TLS_INSECURE_SKIP_VERIFY");
    if insecure {
        tracing::warn!(
            "Kafka TLS：AGF_INGEST_KAFKA_TLS_INSECURE_SKIP_VERIFY=1 —— 证书链校验被关闭，仅可用于排障，生产环境必须关闭"
        );
    }
    let tls = KafkaTlsConfig {
        ca_pem: env_path("AGF_INGEST_KAFKA_TLS_CA"),
        client_cert_pem: env_path("AGF_INGEST_KAFKA_TLS_CERT"),
        client_key_pem: env_path("AGF_INGEST_KAFKA_TLS_KEY"),
        insecure_skip_verify: insecure,
    };
    tracing::info!(tls = %tls.describe(), "Kafka TLS 已启用");
    Some(tls)
}

/// 把 Kafka/KoP 共用的运维旋钮按 `<prefix>_*` 绑定到环境变量。
///
/// Kafka：`AGF_INGEST_KAFKA_*`；Pulsar（经 KoP 复用）：`AGF_INGEST_PULSAR_*`——
/// 两者共用同一份取数内核，因此旋钮命名也保持一致。
pub(crate) fn apply_kafka_tuning(config: &mut KafkaPullConfig, prefix: &str, default_cursor: &str) {
    if let Some(start_from) =
        env_secret(&format!("{prefix}_START_FROM")).and_then(|v| agf_ingest::kafka::KafkaStartFrom::parse(&v))
    {
        config.start_from = start_from;
    }
    config.max_records_per_partition =
        env_num(&format!("{prefix}_MAX_RECORDS"), config.max_records_per_partition).max(1);
    config.max_bytes = env_num(&format!("{prefix}_MAX_BYTES"), config.max_bytes).max(1);
    config.max_wait_ms = env_num(&format!("{prefix}_MAX_WAIT_MS"), config.max_wait_ms).max(0);
    config.interval_secs = env_num(&format!("{prefix}_INTERVAL_SECS"), config.interval_secs).max(1);
    config.reconnect_initial_ms =
        env_num(&format!("{prefix}_RECONNECT_INITIAL_MS"), config.reconnect_initial_ms).max(1);
    config.reconnect_max_ms = env_num(&format!("{prefix}_RECONNECT_MAX_MS"), config.reconnect_max_ms).max(1);
    config.reconnect_max_attempts = env_num(&format!("{prefix}_RECONNECT_MAX_ATTEMPTS"), config.reconnect_max_attempts);
    config.cursor_path =
        Some(env_path(&format!("{prefix}_CURSOR_PATH")).unwrap_or_else(|| PathBuf::from(default_cursor)));
}

/// 构造接入用的日志源（离线内存模式下的默认源）。
pub(crate) fn ingest_source(identity: &SourceIdentity, protocol: IngestProtocol, name: &str) -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: identity.source_id(protocol, name),
        tenant_id: identity.tenant,
        name: format!("{} / {name}", identity.instance),
        protocol,
        vendor: "generic".to_string(),
        product: name.to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: match protocol {
            IngestProtocol::Kafka | IngestProtocol::Pulsar | IngestProtocol::Nats | IngestProtocol::Mqtt => {
                CollectionMode::Subscribe
            }
            IngestProtocol::ObjectStorage => CollectionMode::Pull,
            IngestProtocol::Jdbc => CollectionMode::Poll,
            _ => CollectionMode::Push,
        },
        poll_interval_secs: None,
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes: 1_048_576,
        max_eps: 0,
        tags: vec!["ingest".to_string()],
        health: HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: now,
        updated_at: now,
    }
}

/// 解析路径：环境变量优先；容器里默认 `/app/<name>`，本机默认 `<项目根>/<name>`。
pub(crate) fn resolve_dir(key: &str, name: &str, fallback_root: &Path) -> PathBuf {
    let value = std::env::var(key).unwrap_or_default();
    if !value.trim().is_empty() {
        return PathBuf::from(value.trim());
    }
    let container = PathBuf::from(format!("/app/{name}"));
    if container.is_dir() {
        return container;
    }
    fallback_root.join(name)
}

/// 读整数型环境变量（非法值回退默认并 warn，绝不让进程起不来）。
pub(crate) fn env_num<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr,
{
    match std::env::var(key) {
        Ok(raw) if !raw.trim().is_empty() => match raw.trim().parse::<T>() {
            Ok(value) => value,
            Err(_) => {
                tracing::warn!(key, raw = %raw, "环境变量不是合法数字，使用默认值");
                default
            }
        },
        _ => default,
    }
}

/// 构造日志源（把连接参数放进 `SourceConnection`，由各接收器的 `from_source` 解析）。
pub(crate) fn source_with(
    identity: &SourceIdentity,
    protocol: IngestProtocol,
    name: &str,
    tune: impl FnOnce(&mut SourceConnection),
) -> LogSource {
    let mut source = ingest_source(identity, protocol, name);
    tune(&mut source.connection);
    source
}
