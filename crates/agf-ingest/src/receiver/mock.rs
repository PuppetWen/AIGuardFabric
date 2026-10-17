//! Mock 接收器：内置样本回放（演示/回归用），状态如实标 `Mock`。

use super::*;

/// 未实现协议的离线载荷回放通道。
#[derive(Debug, Clone)]
pub struct MockReceiver {
    /// 协议。
    pub protocol: IngestProtocol,
    /// 接收器名。
    pub name: &'static str,
    /// TODO 锚点。
    pub todo: &'static str,
    /// 离线样本（载荷 + 来源描述）。
    pub payloads: Vec<(Vec<u8>, String)>,
}

impl Default for MockReceiver {
    /// 默认实现：`IngestProtocol` 未实现 `Default`，因此显式指定一个中性协议
    /// （`File`）作为占位；实际使用时务必用 [`MockReceiver::new`] 指定真实协议。
    fn default() -> Self {
        Self { protocol: IngestProtocol::File, name: "mock", todo: "未指定", payloads: Vec::new() }
    }
}

impl MockReceiver {
    /// 构造。
    #[must_use]
    pub const fn new(protocol: IngestProtocol, name: &'static str, todo: &'static str) -> Self {
        Self { protocol, name, todo, payloads: Vec::new() }
    }

    /// 注入离线样本。
    #[must_use]
    pub fn with_payloads(mut self, payloads: Vec<(Vec<u8>, String)>) -> Self {
        self.payloads = payloads;
        self
    }

    /// 样本条数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.payloads.len()
    }

    /// 是否无样本。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.payloads.is_empty()
    }

    /// 能力描述。
    #[must_use]
    pub fn descriptor(&self) -> ReceiverDescriptor {
        ReceiverDescriptor {
            name: self.name.to_string(),
            protocol: self.protocol,
            status: ReceiverStatus::NotImplemented,
            note: format!("协议未实现：仅提供配置模型 + Mock 回放（{} 条离线样本）", self.payloads.len()),
            todo: Some(self.todo.to_string()),
            mock_replay: true,
        }
    }

    /// 把离线样本走一遍完整流水线（不做任何网络/协议交互）。
    ///
    /// # Errors
    /// 落库失败。
    pub async fn replay_all(&self, pipeline: &IngestPipeline, source: &LogSource, max: usize) -> DomainResult<usize> {
        let items: Vec<(Vec<u8>, String)> = self.payloads.iter().take(max).cloned().collect();
        if items.is_empty() {
            return Ok(0);
        }
        let outcomes = pipeline.ingest_batch(source, self.protocol, &items).await?;
        Ok(outcomes.iter().filter(|o| o.persisted).count())
    }
}

/// 生成"未实现协议"接收器的公共 `Receiver` 实现。
///
/// **当前无使用者**：Pulsar 已改为经 KoP 复用 Kafka 接收器（见 [`PulsarReceiver`]），
/// 未配置 KoP 地址时由 [`PulsarReceiver`] 自己回落到 [`MockReceiver`]。
/// 保留此宏供后续新增协议使用（避免每次重写 start/poll_once 的降级骨架）。
#[allow(unused_macros)]
macro_rules! impl_not_implemented_receiver {
    ($ty:ty, $protocol:expr, $mock_field:ident) => {
        #[async_trait]
        impl Receiver for $ty {
            fn protocol(&self) -> IngestProtocol {
                $protocol
            }

            fn describe(&self) -> ReceiverDescriptor {
                self.$mock_field.descriptor()
            }

            async fn start(&self, _pipeline: Arc<IngestPipeline>, _source: LogSource) -> DomainResult<()> {
                Err(DomainError::NotImplemented(self.$mock_field.todo.to_string()))
            }

            async fn poll_once(
                &self,
                pipeline: Arc<IngestPipeline>,
                source: LogSource,
                max: usize,
            ) -> DomainResult<usize> {
                // Mock 回放通道：链路可用，取数部分待真实 SDK 接入
                self.$mock_field.replay_all(&pipeline, &source, max).await
            }
        }
    };
}

/// **已实现的协议接收器**：各自的模块是唯一权威实现，这里只做**路径重导出**，
/// 保持 `agf_ingest::receiver::XxxReceiver` 这一既有引用路径不变。
///
/// | 协议 | 类型 | 实现模块 |
/// |---|---|---|
/// | OTLP/HTTP | [`OtlpLogsReceiver`] | [`crate::otlp`] |
/// | 对象存储拉取（S3/OSS/MinIO） | [`ObjectPullReceiver`] | [`crate::object_pull`] |
/// | SQL 拉取（"JDBC" 语义） | [`JdbcReceiver`] | [`crate::jdbc`] |
/// | MQTT | [`MqttReceiver`] | [`crate::mqtt`] |
/// | SNMP Trap | [`SnmpTrapReceiver`] | [`crate::snmp`] |
/// | Kafka | [`KafkaReceiver`] | [`crate::kafka`] |
pub use crate::jdbc::JdbcReceiver;
pub use crate::kafka::KafkaReceiver;
pub use crate::mqtt::MqttReceiver;
pub use crate::object_pull::ObjectPullReceiver;
pub use crate::otlp::OtlpLogsReceiver;
pub use crate::snmp::SnmpTrapReceiver;
