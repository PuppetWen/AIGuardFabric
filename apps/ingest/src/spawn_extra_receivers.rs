//! 由 `main.rs` 拆分：新增协议接收器的装配入口。
//!
//! 原 `spawn_extra_receivers` 是**单个 800+ 行函数**，现按"每个接收器一段"拆成私有
//! `async fn`（挂在 [`ExtraReceiverCtx`] 上），实现分散在 `spawn_extra_receivers/` 下的
//! 兄弟模块里（**纯搬移，逻辑不变**——同样的 env 名、默认值、warn/降级语义与日志文案）。
use super::*;

/// 装配过程的共享上下文 + 累计产出。
///
/// 为什么要有它：各接收器段之间要共享 `pipeline`/`metrics`/`listeners`/`shutdown`，
/// 并往 `kafka_series`/`kafka_tasks` 里塞东西。原先靠同一个函数体里的局部变量传递，
/// 抽成 `async fn` 后必须显式携带——但**绝不用全局可变状态**（那会让装配顺序变得不可推理）。
struct ExtraReceiverCtx<'a> {
    identity: SourceIdentity,
    /// 事件流水线（每个接收器都要克隆一份进后台任务）。
    pipeline: &'a Arc<IngestPipeline>,
    /// 各接收器的四类计数器注册表。
    metrics: &'a SharedMetrics,
    /// 监听器运行态（`/readyz` 的事实来源）。
    listeners: &'a mut ListenerState,
    /// Kafka/KoP 的停机广播句柄（SIGINT/SIGTERM 时先广播、再等刷新游标）。
    shutdown: &'a KafkaShutdown,
    /// Kafka/KoP 分区指标（`/metrics` 与 `/stats` 共用）。
    kafka_series: Vec<KafkaSeries>,
    /// 需要优雅停机的后台任务。
    kafka_tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl<'a> ExtraReceiverCtx<'a> {
    fn new(
        pipeline: &'a Arc<IngestPipeline>,
        metrics: &'a SharedMetrics,
        listeners: &'a mut ListenerState,
        shutdown: &'a KafkaShutdown,
        identity: &SourceIdentity,
    ) -> Self {
        Self {
            identity: identity.clone(),
            pipeline,
            metrics,
            listeners,
            shutdown,
            kafka_series: Vec::new(),
            kafka_tasks: Vec::new(),
        }
    }
}

mod archive;
mod cursor;
mod mqtt;
mod otlp;
mod pull;
mod snmp;
mod streaming;

/// 按 env 启动**新增协议接收器**（OTLP 之外的拉取/订阅型都走这里）。
///
/// 统一约定：
/// * **未配置 ⇒ 不启用**（并在 `/readyz` 的 notes 里写明原因，不静默）；
/// * 配置错误/连接失败 ⇒ **只 warn**，进程继续启动，其余接收器不受影响；
/// * 每个接收器都注册自己的四类计数（收到/命中/解析失败/丢弃）。
///
/// 返回挂到 HTTP 路由上的 OTLP 接收器（未启用时 `None`）。
pub(crate) async fn spawn_extra_receivers(
    pipeline: &Arc<IngestPipeline>,
    metrics: &SharedMetrics,
    listeners: &mut ListenerState,
    shutdown: &KafkaShutdown,
    identity: &SourceIdentity,
) -> ExtraReceivers {
    let mut ctx = ExtraReceiverCtx::new(pipeline, metrics, listeners, shutdown, identity);
    // ---- OTLP/HTTP 三信号（logs + traces + metrics）----
    let (otlp, otlp_traces, otlp_metrics) = ctx.otlp_http().await;
    // === OTLP/gRPC(4317)：官方 LogsService/Export 服务端（独立块）===
    ctx.otlp_grpc().await;
    // ---- 对象存储拉取（S3/OSS/MinIO） ----
    ctx.object_pull().await;
    // ---- SQL 拉取（"JDBC"） ----
    ctx.sql_pull().await;
    // === MySQL ===
    ctx.annotate_sql_dialect();
    // ---- MQTT ----
    let (broker, topic) = ctx.mqtt().await;
    // === MQTT 加固（TLS / 共享订阅 / 遗嘱）：独立块，只补运行态说明 ===
    ctx.annotate_mqtt_hardening(&broker, &topic);
    // ---- SNMP Trap ----
    ctx.snmp_trap().await;
    // === SNMP v3 ===
    ctx.annotate_snmp_v3();
    // === Parquet ===
    ctx.coldarchive_selfcheck().await;
    // ---- Kafka ----
    ctx.kafka().await;
    // ---- Pulsar（**经 KoP 复用 Kafka 接收器**；Pulsar 原生协议未实现） ----
    ctx.pulsar().await;
    // ---- Pulsar **原生二进制协议**（`AGF_INGEST_PULSAR_URL`；配了就优先于 KoP） ----
    ctx.pulsar_native().await;
    // ---- NATS JetStream 入向订阅（**与事件总线无关**） ----
    ctx.jetstream().await;
    // 游标文件只读校验：把"上次拉到哪里"如实写进 notes（运维排障用，缺失不报错）
    ctx.report_cursor_files();
    ExtraReceivers { otlp, otlp_traces, otlp_metrics, kafka_series: ctx.kafka_series, kafka_tasks: ctx.kafka_tasks }
}
