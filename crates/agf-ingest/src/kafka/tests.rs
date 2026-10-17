//! Kafka 单元测试：共用夹具（内存 Kafka 源、流水线、临时目录、自签 CA）+ 分组的用例子模块。

use super::*;
use crate::bus::NoopEventBus;
use crate::pipeline::{InMemorySink, IngestConfig, Sink};
use crate::registry::ParserRegistry;
use agf_core::enums::HealthState;
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, SourceConnection};
use agf_core::time::Timestamp;

const SYSLOG_A: &str =
    "<34>Feb 21 10:23:45 web-prod-01 sshd[2311]: Failed password for root from 203.0.113.77 port 51234 ssh2";
const SYSLOG_B: &str =
    "<34>Feb 21 10:23:46 web-prod-01 sshd[2311]: Failed password for root from 203.0.113.78 port 51235 ssh2";
/// 第三条（内容与 A/B 都不同：**避开流水线按内容哈希去重**，用于"新消息必须被消费"的断言）。
const SYSLOG_C: &str =
    "<34>Feb 21 10:24:07 web-prod-02 sshd[2312]: Accepted password for deploy from 203.0.113.79 port 51236 ssh2";

/// 内存 Kafka 源：模拟单/多分区日志（**接收器侧测试共用**，见 `receiver.rs` 的 KoP 测试）。
#[derive(Debug, Default)]
pub(crate) struct FakeKafkaSource {
    partitions: Mutex<Vec<i32>>,
    logs: Mutex<BTreeMap<i32, Vec<KafkaRecord>>>,
    failing_fetch: Mutex<Vec<i32>>,
    /// 为真时 `partitions()` 直接失败（模拟 broker 不可达）。
    broker_down: AtomicBool,
}

impl FakeKafkaSource {
    pub(crate) fn with_partitions(count: i32) -> Self {
        let source = Self::default();
        if let Ok(mut partitions) = source.partitions.lock() {
            *partitions = (0..count).collect();
        }
        source
    }

    pub(crate) fn append(&self, partition: i32, value: &str) {
        if let Ok(mut logs) = self.logs.lock() {
            let entries = logs.entry(partition).or_default();
            let offset = i64::try_from(entries.len()).unwrap_or(0);
            entries.push(KafkaRecord {
                offset,
                key: Some(format!("k{offset}").into_bytes()),
                value: Some(value.as_bytes().to_vec()),
                timestamp_millis: Some(1_770_985_425_000 + offset),
            });
        }
    }

    /// 追加墓碑（value 为空）。
    fn append_tombstone(&self, partition: i32) {
        if let Ok(mut logs) = self.logs.lock() {
            let entries = logs.entry(partition).or_default();
            let offset = i64::try_from(entries.len()).unwrap_or(0);
            entries.push(KafkaRecord { offset, key: Some(b"tomb".to_vec()), value: None, timestamp_millis: None });
        }
    }

    /// 新增一个分区（模拟 topic 扩分区）。
    fn add_partition(&self, partition: i32) {
        if let Ok(mut partitions) = self.partitions.lock() {
            partitions.push(partition);
            partitions.sort_unstable();
        }
    }

    fn fail_fetch(&self, partition: i32) {
        if let Ok(mut failing) = self.failing_fetch.lock() {
            failing.push(partition);
        }
    }

    fn set_broker_down(&self, down: bool) {
        self.broker_down.store(down, Ordering::Relaxed);
    }
}

#[async_trait]
impl KafkaSource for FakeKafkaSource {
    async fn partitions(&self, _topic: &str) -> DomainResult<Vec<i32>> {
        if self.broker_down.load(Ordering::Relaxed) {
            return Err(DomainError::DependencyUnavailable {
                dependency: "kafka".to_string(),
                cause: "注入的 broker 不可达".to_string(),
            });
        }
        Ok(self.partitions.lock().map(|p| p.clone()).unwrap_or_default())
    }

    async fn resolve_offset(&self, _topic: &str, _partition: i32, at: KafkaStartFrom) -> DomainResult<i64> {
        if at == KafkaStartFrom::Latest {
            let logs = self.logs.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
            return Ok(logs.values().map(|entries| i64::try_from(entries.len()).unwrap_or(0)).max().unwrap_or(0));
        }
        Ok(0)
    }

    async fn fetch(
        &self,
        _topic: &str,
        partition: i32,
        offset: i64,
        _max_bytes: i32,
        _max_wait_ms: i32,
    ) -> DomainResult<KafkaBatch> {
        if self.failing_fetch.lock().map(|f| f.contains(&partition)).unwrap_or(false) {
            return Err(DomainError::DependencyUnavailable {
                dependency: "kafka".to_string(),
                cause: format!("注入的拉取失败: partition {partition}"),
            });
        }
        let logs = self.logs.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        let entries = logs.get(&partition).cloned().unwrap_or_default();
        let high_watermark = i64::try_from(entries.len()).unwrap_or(0);
        Ok(KafkaBatch {
            records: entries.into_iter().filter(|record| record.offset >= offset).collect(),
            high_watermark,
        })
    }

    fn describe(&self) -> String {
        "kafka://memory:9092".to_string()
    }
}

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "kafka-test".to_string(),
        protocol: IngestProtocol::Kafka,
        vendor: "generic".to_string(),
        product: "syslog".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Pull,
        poll_interval_secs: Some(5),
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes: 1_048_576,
        max_eps: 0,
        tags: vec![],
        health: HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: now,
        updated_at: now,
    }
}

fn pipeline_and_sink() -> (Arc<IngestPipeline>, Arc<InMemorySink>) {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { emit_to_bus: false, ..IngestConfig::default() },
    );
    (Arc::new(pipeline), sink)
}

fn config(cursor_path: Option<PathBuf>, max_records: usize) -> KafkaPullConfig {
    KafkaPullConfig {
        brokers: vec!["127.0.0.1:9092".to_string()],
        topic: "agf-sec-logs".to_string(),
        max_records_per_partition: max_records,
        cursor_path,
        interval_secs: 1,
        ..KafkaPullConfig::default()
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("agf-kafka-{tag}-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// 测试用自签 CA（rcgen；**不落私钥**，只用于验证"私有 CA 能被装进信任库"）。
fn self_signed_ca_pem() -> String {
    let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap_or_default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name.push(rcgen::DnType::CommonName, "agf-test-kafka-ca");
    let key = rcgen::KeyPair::generate().ok();
    match key {
        Some(key) => params.self_signed(&key).map_or_else(|_| String::new(), |cert| cert.pem()),
        None => String::new(),
    }
}
/// 分配配置（测试用）：`instance_id/instance_count` + 可选租约目录。
///
/// `assign_settle_ms = 0`：多数用例想直接看到"认领/接管"，不想要启动静默期；
/// 静默期本身由 `settle_window_defers_claims_until_peers_are_visible` 单独覆盖。
fn assignment_config(instance_id: u32, instance_count: u32, lease_dir: Option<PathBuf>) -> KafkaPullConfig {
    KafkaPullConfig {
        instance_id: Some(instance_id),
        instance_count,
        lease_dir,
        lease_ttl_ms: 2_000,
        assign_settle_ms: 0,
        interval_secs: 1,
        ..config(None, 10)
    }
}

/// 写一份**指定时间戳**的租约心跳（模拟"某副本已经死了 ttl 那么久"）。
fn write_stale_heartbeat(dir: &Path, namespace: &str, instance_id: u32, age_ms: i64) {
    std::fs::create_dir_all(dir).unwrap_or_else(|e| panic!("创建租约目录失败: {e}"));
    let body = format!("{instance_id} {} 4242 test-host\n", now_millis() - age_ms);
    std::fs::write(lease_path(dir, namespace, instance_id), body).unwrap_or_else(|e| panic!("写心跳失败: {e}"));
}

mod assignment;
mod basic;
mod group;
mod poll;
