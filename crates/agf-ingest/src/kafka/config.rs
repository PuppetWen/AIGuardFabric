//! Kafka 数据模型与拉取配置：起始位置、单条记录/批量 DTO，以及 `KafkaPullConfig` 的解读与校验。

use super::*;

/// 起始消费位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KafkaStartFrom {
    /// 从最早可用记录开始（历史数据全量接入；首次启动可能量很大）。
    #[default]
    Earliest,
    /// 从最新位置开始（只接入启动之后的新数据）。
    Latest,
}

impl KafkaStartFrom {
    /// 解析文本（未知值 ⇒ `None`）。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "earliest" | "beginning" | "oldest" => Some(Self::Earliest),
            "latest" | "end" | "newest" => Some(Self::Latest),
            _ => None,
        }
    }

    /// 配置文本。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Earliest => "earliest",
            Self::Latest => "latest",
        }
    }
}

/// 一条 Kafka 记录（协议无关表示）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KafkaRecord {
    /// 记录 offset。
    pub offset: i64,
    /// key（原样保留；空表示无 key）。
    pub key: Option<Vec<u8>>,
    /// value（原样保留；空表示墓碑消息）。
    pub value: Option<Vec<u8>>,
    /// 记录时间（epoch 毫秒）。
    pub timestamp_millis: Option<i64>,
}

/// 一次拉取的结果。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KafkaBatch {
    /// 记录（按 offset 升序）。
    pub records: Vec<KafkaRecord>,
    /// 分区高水位（下一个将被写入的 offset）。
    pub high_watermark: i64,
}

// ---------------------------------------------------------------------------
// 鉴权 / TLS
// ---------------------------------------------------------------------------
/// 拉取配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaPullConfig {
    /// broker 列表。
    pub brokers: Vec<String>,
    /// topic。
    pub topic: String,
    /// 消费者标识（`rskafka` 无消费者组，仅用于客户端 id 与日志）。
    pub consumer_id: String,
    /// 起始位置。
    pub start_from: KafkaStartFrom,
    /// 单分区单轮最多消费记录数（背压阀）。
    pub max_records_per_partition: usize,
    /// 单次拉取字节上限。
    pub max_bytes: i32,
    /// 长轮询等待（毫秒）。
    pub max_wait_ms: i32,
    /// 轮询间隔（秒）。
    pub interval_secs: u64,
    /// 游标文件（`None` = 只存内存）。
    pub cursor_path: Option<PathBuf>,
    /// 落库协议标签（Kafka 自身 = `kafka`；**KoP 复用 = `pulsar`**）。
    pub protocol: IngestProtocol,
    /// 接收器名（`/metrics` 的 `receiver` 标签；`kafka` / `pulsar`）。
    pub receiver_name: String,
    /// 来源 scheme（origin 前缀；`kafka` / `pulsar`）。
    pub origin_scheme: String,
    /// 本地游标命名空间（Pulsar subscription / Kafka group.id）：rskafka 无消费者组，
    /// 这里只用于 client id、游标文件标注与日志/指标标注。
    pub namespace: Option<String>,
    /// SASL 配置（凭据只在建连瞬间取用；**序列化整体跳过**：凭据不落任何序列化产物）。
    #[serde(skip)]
    pub sasl: Option<KafkaSaslConfig>,
    /// TLS 配置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<KafkaTlsConfig>,
    /// 重连退避初始间隔（毫秒）。
    pub reconnect_initial_ms: u64,
    /// 重连退避**上限**（毫秒）。
    pub reconnect_max_ms: u64,
    /// 连续失败达到该次数即放弃并返回错误（`0` = 永不放弃，默认）。
    pub reconnect_max_attempts: u32,
    /// 多副本分区分配的**本副本序号**（0-based；`None` = 单副本，等价于 `0`）。
    ///
    /// `rskafka` 没有消费者组协议，多副本并行消费只能由**本接收器自己**做分片：
    /// 见 [`partition_owner`] 与 [`KafkaPullConfig::assignment_identity`]。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<u32>,
    /// 多副本分区分配的**副本总数**（`None`/`1` = 单副本消费全部分区）。
    pub instance_count: u32,
    /// 租约目录（**所有同订阅名副本必须看到同一个目录**）。
    ///
    /// * `None` = **纯静态取模**：`owner(p) = p % instance_count`，不接管、不心跳；
    /// * `Some(dir)` = **心跳租约 + 故障接管**：副本按 `lease_ttl_ms` 判活，
    ///   存活集合变化时全量重分片（见 [`partition_owner`]），接管时间上界 =
    ///   `lease_ttl_ms` + 一个轮询间隔（`interval_secs`）。
    ///
    /// 单机多进程可用普通目录（端到端测试即如此）；跨主机必须挂共享卷（RWX PVC / NFS），
    /// 否则每个副本只看得到自己，退化为"静态取模且永不接管"。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_dir: Option<PathBuf>,
    /// 租约判活时长（毫秒）。必须**大于**心跳间隔（= 轮询间隔）的 3 倍，
    /// 否则网络抖动会被误判为副本死亡并触发重复消费。
    pub lease_ttl_ms: u64,
    /// **启动静默期**（毫秒）：启用租约后，本副本启动后的这段时间内**不认领任何分区**
    /// （只写心跳、只观测存活集合）。
    ///
    /// 为什么必须有（实测踩过）：两个副本同时启动时，先起来的那一个在第一轮里
    /// 看不到同伴的心跳 ⇒ 它会把**全部分区**都认领并开始消费；等同伴的心跳到齐，
    /// 重分片才发生 —— 这中间有一个"两个副本都在消费同一个分区"的重叠窗口
    /// （实测：副本 0 认领 [0,1,2]，副本 1 也认领 [1]）。
    /// 静默期等价于 Kafka 消费者组的 `group.initial.rebalance.delay.ms`：
    /// 等同伴的心跳到齐、存活集合稳定下来再开始消费。
    ///
    /// 注意：静默期只影响**本副本启动之后**的头 `assign_settle_ms` 毫秒；
    /// 单副本部署（`instance_count=1`）不等待，也不受此影响（见
    /// [`PartitionOwnership::settling`]）。接管路径同样不受影响：接管是租约到期后才发生的
    /// （原副本已经真的死了），此时静默期早已结束。
    pub assign_settle_ms: u64,
}

impl Default for KafkaPullConfig {
    fn default() -> Self {
        Self {
            brokers: Vec::new(),
            topic: String::new(),
            consumer_id: "agf-ingest".to_string(),
            start_from: KafkaStartFrom::Earliest,
            max_records_per_partition: 500,
            max_bytes: 1024 * 1024,
            max_wait_ms: 500,
            interval_secs: 5,
            cursor_path: None,
            protocol: IngestProtocol::Kafka,
            receiver_name: "kafka".to_string(),
            origin_scheme: "kafka".to_string(),
            namespace: None,
            sasl: None,
            tls: None,
            reconnect_initial_ms: 500,
            reconnect_max_ms: 30_000,
            reconnect_max_attempts: 0,
            instance_id: None,
            instance_count: 1,
            lease_dir: None,
            lease_ttl_ms: 15_000,
            assign_settle_ms: 3_000,
        }
    }
}

impl KafkaPullConfig {
    /// 由日志源构造（`connection.endpoint` / `connection.topic` / `headers[group.id]`）。
    ///
    /// # Errors
    /// 缺 broker 或 topic。
    pub fn from_source(source: &LogSource) -> DomainResult<Self> {
        let endpoint = source
            .connection
            .endpoint
            .clone()
            .ok_or_else(|| DomainError::Config("Kafka 需要 connection.endpoint（broker 列表）".to_string()))?;
        let topic = source
            .connection
            .topic
            .clone()
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| DomainError::Config("Kafka 需要 connection.topic".to_string()))?;
        Ok(Self {
            brokers: parse_brokers(&endpoint)?,
            topic,
            consumer_id: source.connection.headers.get("group.id").cloned().unwrap_or_else(|| "agf-ingest".to_string()),
            ..Self::default()
        })
    }

    /// 客户端 id：命名空间（订阅/消费者组）+ 接收器名（便于 broker 侧排障）。
    #[must_use]
    pub fn client_id(&self) -> String {
        match &self.namespace {
            Some(namespace) => format!("{}@{}", self.receiver_name, namespace),
            None => format!("{}@{}", self.receiver_name, self.consumer_id),
        }
    }

    /// 重连退避的上下界（初始化用；`max` 不会小于 `initial`）。
    #[must_use]
    pub fn reconnect_bounds(&self) -> (Duration, Duration) {
        let initial = Duration::from_millis(self.reconnect_initial_ms.max(20));
        let max = Duration::from_millis(self.reconnect_max_ms.max(self.reconnect_initial_ms.max(20)));
        (initial, max)
    }

    /// 本副本的分配身份 `(instance_id, instance_count)`。
    ///
    /// 未配置时 = `(0, 1)`（单副本消费全部分区）；`instance_count` 至少为 1，
    /// 且 `instance_id` 会被规约到 `[0, instance_count)`（配置写错时不至于"谁也消费不到"）。
    #[must_use]
    pub fn assignment_identity(&self) -> (u32, u32) {
        let count = self.instance_count.max(1);
        (self.instance_id.unwrap_or(0) % count, count)
    }

    /// 是否启用多副本分区分配（配置了序号，或副本数 > 1）。
    ///
    /// 关闭时行为与历史版本**完全一致**：单副本消费 topic 全部分区。
    #[must_use]
    pub fn assignment_enabled(&self) -> bool {
        self.instance_id.is_some() || self.instance_count > 1
    }

    /// 是否启用**租约接管**（配置了共享租约目录 + 多副本分配）。
    #[must_use]
    pub fn lease_enabled(&self) -> bool {
        self.lease_dir.is_some() && self.assignment_enabled()
    }

    /// 分区分片游标文件的**公共前缀**（多副本模式；含订阅名 + topic，避免不同订阅/topic 互相串）。
    #[must_use]
    pub fn cursor_shard_prefix(&self) -> String {
        format!(
            "cursor-{}-{}-p",
            sanitize_component(self.namespace.as_deref().unwrap_or("agf-ingest")),
            sanitize_component(&self.topic)
        )
    }

    /// 某分区的**游标落盘路径**。
    ///
    /// * 未配租约目录（单副本 / 普通 Kafka）：沿用单个 `cursor_path`（全分区一个文件，历史行为不变）；
    /// * 配了租约目录（多副本）：`{lease_dir}/cursor-{订阅名}-{topic}-p{partition}.json`
    ///   —— **每个分区一个文件**。这样归属交接后新 owner 直接读原 owner 落盘的进度：
    ///   接管既**不丢**（不会退化成"从 latest 重来"），也不会因为两个副本同时改同一个文件而互相覆盖。
    #[must_use]
    pub fn cursor_path_for(&self, partition: i32) -> Option<PathBuf> {
        match &self.lease_dir {
            Some(dir) => {
                let prefix = self.cursor_shard_prefix();
                Some(dir.join(format!("{prefix}{partition}.json")))
            }
            None => self.cursor_path.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// 多副本分区分配（无消费者组时的并行消费语义）
// ---------------------------------------------------------------------------
