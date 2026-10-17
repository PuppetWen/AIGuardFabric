//! 接收器抽象：`Receiver` trait 与能力描述 `ReceiverDescriptor`（接入能力页渲染的口径）。

use super::*;

/// 接收器能力描述（接入能力页直接渲染）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverDescriptor {
    /// 接收器名。
    pub name: String,
    /// 协议。
    pub protocol: IngestProtocol,
    /// 状态。
    pub status: ReceiverStatus,
    /// 说明。
    pub note: String,
    /// TODO 锚点（未实现时必填）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub todo: Option<String>,
    /// 是否提供 Mock 回放通道。
    pub mock_replay: bool,
}

/// 接收器统一接口。
#[async_trait]
pub trait Receiver: Send + Sync + std::fmt::Debug {
    /// 协议。
    fn protocol(&self) -> IngestProtocol;

    /// 能力描述。
    fn describe(&self) -> ReceiverDescriptor;

    /// 启动接收（阻塞式长跑；Webhook 等服务型接收器由运行时挂载，这里返回 `Ok`）。
    ///
    /// # Errors
    /// 未实现或启动失败。
    async fn start(&self, pipeline: Arc<IngestPipeline>, source: LogSource) -> DomainResult<()>;

    /// 单次取数（拉取/轮询/回放模式）。
    ///
    /// # Errors
    /// 未实现、上游不可达或落库失败。
    async fn poll_once(&self, pipeline: Arc<IngestPipeline>, source: LogSource, max: usize) -> DomainResult<usize>;

    /// 停止接收（释放监听端口/连接）。
    ///
    /// # Errors
    /// 停止失败。
    async fn stop(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Webhook
// ---------------------------------------------------------------------------
