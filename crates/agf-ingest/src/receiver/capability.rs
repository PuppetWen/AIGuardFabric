//! 接入能力矩阵：逐协议/逐接收器如实呈现状态与 TODO（接入能力页直接渲染本表）。

use super::*;

/// 接收器能力清单（**逐条对应真实实现**；未实现协议也出现在清单里并带 TODO 锚点，
/// 前端"接入能力"页据此展示降级说明）。
#[must_use]
pub fn receiver_capability_matrix() -> Vec<ReceiverDescriptor> {
    let ready = |protocol: IngestProtocol, name: &str, note: String, todo: Option<&str>| ReceiverDescriptor {
        name: name.to_string(),
        protocol,
        status: ReceiverStatus::Ready,
        note,
        todo: todo.map(ToString::to_string),
        mock_replay: false,
    };
    vec![
        ReceiverDescriptor {
            name: "webhook".to_string(),
            protocol: IngestProtocol::Webhook,
            status: ReceiverStatus::Ready,
            note: "axum HTTP handler + Bearer 鉴权".to_string(),
            todo: None,
            mock_replay: false,
        },
        ReceiverDescriptor {
            name: "syslog-tcp".to_string(),
            protocol: IngestProtocol::Syslog,
            status: ReceiverStatus::Ready,
            note:
                "RFC3164/5424 + octet-counting / non-transparent 分帧；**连接生命周期内持续收帧**（无每连接帧数上限）"
                    .to_string(),
            todo: None,
            mock_replay: false,
        },
        ReceiverDescriptor {
            name: "syslog-tls".to_string(),
            protocol: IngestProtocol::Syslog,
            status: ReceiverStatus::Ready,
            note: "RFC5425：TLS over TCP 6514（RFC6587 分帧复用明文 TCP 实现）".to_string(),
            // 能力已实现，但默认不监听：需要 AGF_SYSLOG_TLS_CERT / AGF_SYSLOG_TLS_KEY 才启用
            // （证书缺失只 warn 不启用，绝不让进程起不来）；实际监听状态见 /readyz 的 listeners
            todo: Some(
                "运维动作：配置 AGF_SYSLOG_TLS_CERT/KEY 后才监听（AGF_SYSLOG_TLS_PORT=0 可显式关闭）".to_string(),
            ),
            mock_replay: false,
        },
        ReceiverDescriptor {
            name: "file-tail".to_string(),
            protocol: IngestProtocol::File,
            status: ReceiverStatus::Ready,
            note: "轮询式增量读取".to_string(),
            todo: Some("TODO ingest-notify-watch：事件驱动 watcher".to_string()),
            mock_replay: false,
        },
        ReceiverDescriptor {
            name: "http-pull".to_string(),
            protocol: IngestProtocol::HttpPull,
            status: ReceiverStatus::Ready,
            note: "增量游标 + reqwest 取数".to_string(),
            todo: None,
            mock_replay: false,
        },
        ReceiverDescriptor {
            name: "otlp".to_string(),
            protocol: IngestProtocol::Otlp,
            status: effective_status(ReceiverStatus::Ready, "otlp"),
            note: "OTLP/HTTP POST /v1/logs：JSON、Protobuf、gzip；日志归一化与持久入库；部分拒收准确计数，临时故障返回可重试错误".to_string(),
            todo: None,
            mock_replay: false,
        },
        ReceiverDescriptor {
            name: "otlp-traces".to_string(),
            protocol: IngestProtocol::Otlp,
            status: effective_status(ReceiverStatus::Ready, "otlp-traces"),
            note: "OTLP/HTTP POST /v1/traces：Span、trace.id、span.id、duration_nano 保真入库；部分拒收准确计数，临时故障返回可重试错误".to_string(),
            todo: None,
            mock_replay: false,
        },
        ReceiverDescriptor {
            name: "otlp-metrics".to_string(),
            protocol: IngestProtocol::Otlp,
            status: effective_status(ReceiverStatus::Ready, "otlp-metrics"),
            note: "OTLP/HTTP POST /v1/metrics：Gauge/Sum/Histogram/ExponentialHistogram/Summary 数据点入库；部分拒收准确计数，临时故障返回可重试错误".to_string(),
            todo: None,
            mock_replay: false,
        },
        ReceiverDescriptor {
            name: "otlp-grpc".to_string(),
            protocol: IngestProtocol::Otlp,
            status: effective_status(ReceiverStatus::Ready, "otlp-grpc"),
            note: "OTLP/gRPC LogsService/Export：gzip、TLS/mTLS；无效 TLS 配置拒绝启动；部分拒收准确计数，临时故障返回可重试错误".to_string(),
            todo: None,
            mock_replay: false,
        },
        ReceiverDescriptor {
            name: "otlp-grpc-traces".to_string(),
            protocol: IngestProtocol::Otlp,
            status: effective_status(ReceiverStatus::Ready, "otlp-grpc-traces"),
            note: "OTLP/gRPC TraceService/Export：gzip、TLS/mTLS；独立日志源、模板与统计；部分拒收准确计数，临时故障返回可重试错误".to_string(),
            todo: None,
            mock_replay: false,
        },
        ReceiverDescriptor {
            name: "otlp-grpc-metrics".to_string(),
            protocol: IngestProtocol::Otlp,
            status: effective_status(ReceiverStatus::Ready, "otlp-grpc-metrics"),
            note: "OTLP/gRPC MetricsService/Export：gzip、TLS/mTLS；独立日志源、模板与统计；部分拒收准确计数，临时故障返回可重试错误".to_string(),
            todo: None,
            mock_replay: false,
        },
        ready(
            IngestProtocol::ObjectStorage,
            "object-pull",
            "S3/OSS/MinIO 轮询拉取新对象（ETag+LastModified 幂等游标、游标落盘、NDJSON/JSON 拆包）".to_string(),
            None,
        ),
        ready(
            IngestProtocol::Jdbc,
            "jdbc",
            "增量拉取：**PostgreSQL / MySQL / MSSQL / Oracle 按 DSN scheme 自动选驱动**（postgres:// ⇒ sqlx/PostgreSQL，\
             mysql:// ⇒ sqlx/MySQL，mssql://|sqlserver:// ⇒ tiberius/MSSQL，oracle://|oracle+tcps:// ⇒ oracle/OCI）；\
             游标列 + 游标落盘 + 单轮上限（LIMIT / TOP(n) / OFFSET…FETCH）+ 方言化占位符/转型/引号\
             （游标逻辑只有一份）\
             + 指标 agf_ingest_jdbc_rows_pulled_total/_rows_dropped_total/_errors_total/_cursor_advanced_total\
             ；Oracle 行解码按列元数据（NUMBER 整数精确/小数 f64、DATE/TIMESTAMP 归一为 ISO-8601 毫秒 Z、\
             NULL 与解不出的列三态区分），OCI 运行库走仓库内 `tools/oracle/`（`AGF_ORACLE_CLIENT_LIB_DIR`，\
             **不写全局 PATH**）"
                .to_string(),
            Some(
                "TODO ingest-jdbc-oracle-extras：Oracle 已接线，**未覆盖**：REFCURSOR/对象/集合列按字符串兜底、\
                 钱包无专用 config_dir 环境变量（可用 `?descriptor=` 透传完整 TNS 描述符）、\
                 Oracle 未加引号的标识符折叠为大写（基础 SQL 需用 `AS \"col\"` 固定列名）；\
                 Oracle/MSSQL 的连接数是单连接句柄（连接池参数不适用）",
            ),
        ),
        ready(
            IngestProtocol::Mqtt,
            "mqtt",
            "rumqttc 订阅（QoS 0/1/2、通配主题、断线退避重连 + 链路错误按 TLS/鉴权/网络/协议分类计数）；\
             **TLS 已接线**（`mqtts://`/`wss://` 或 `AGF_INGEST_MQTT_TLS=1`，rustls：CA(PEM)/客户端证书(mTLS)/默认校验\
             证书链，跳过校验需显式开关并 `warn!`）；**WebSocket 已接线**（`ws://`/`wss://`，`rumqttc` 的\
             `websocket` 特性，完整 URL 含路径与 TCP/TLS 共用同一条解析落库路径）；**MQTT 5 已接线**\
             （`AGF_INGEST_MQTT_PROTOCOL_VERSION=5`：会话过期/Clean Start、Topic Alias 协商与入站别名解析、\
             Receive Maximum 流控、订阅选项 NoLocal/RetainAsPublished/RetainHandling 可配、CONNECT 用户属性；\
             3.1.1 上配 v5 专有项会**明确报错**而不是静默忽略）；**共享订阅已接线**\
             （`$share/<group>/<topic>`，组内竞争消费，适合多副本）；**遗嘱(LWT)已接线**（`AGF_INGEST_MQTT_WILL_*`）"
                .to_string(),
            Some(
                "TODO ingest-mqtt-v5-auth：MQTT 5 AUTH 增强认证未接线（只用 username/password）；\
                 TODO ingest-mqtt-v5-properties-extra：v5 用户属性随 origin 透传（事件 extra 的 log.origin），\
                 未写入独立的 Event::extra 键（IngestPipeline 无逐条元数据通道）",
            ),
        ),
        ready(
            IngestProtocol::SnmpTrap,
            "snmp-trap",
            "UDP 收 SNMP Trap：v1/v2c（community 校验）+ **v3 USM 三种安全级别全落地**\
             （noAuthNoPriv / authNoPriv（HMAC-MD5-96 / HMAC-SHA-96 摘要校验 + RFC3414 150s 时限窗口）/\
             **authPriv：CBC-DES(RFC3414 §8) 与 CFB128-AES-128(RFC3826 §3) 解密**），BER 手写解析；\
             认证/解密失败按 usmStats 分类计数（agf_ingest_snmp_usm_* 6 族 + priv 细分 4 族）"
                .to_string(),
            Some(
                "TODO ingest-snmp-inform-ack：Inform 只解析不回应答；GET/WALK 轮询请用 HTTP Pull/JDBC；\
                 SNMP v3 authPriv（DES/AES）已实现（crates/agf-ingest/src/snmp/privacy.rs）",
            ),
        ),
        ready(
            IngestProtocol::Kafka,
            "kafka",
            "rskafka（纯 Rust）消费 + 全分区独立 offset 游标 + SASL/PLAIN|SCRAM + TLS + 指数退避重连 + 优雅停机"
                .to_string(),
            Some(
                "TODO ingest-kafka-oauthbearer：SASL/OAUTHBEARER 未实现；消费者组协议已实现并在 apache/kafka:3.9.0 真机实测通过（需显式配 AGF_INGEST_KAFKA_GROUP_ID；粘性分配未实现）",
            ),
        ),
        // Pulsar：**经 KoP 复用 Kafka 接收器**；未配置 KoP 地址则显示 not-implemented（不假装 ready）。
        // 能力矩阵是"代码支持什么"，"本进程真的连上了 KoP 没有"见 /readyz 的 listeners/notes。
        pulsar_descriptor(std::env::var("AGF_INGEST_PULSAR_SERVICE_URL").ok().as_deref()),
        // Pulsar **原生二进制协议**（`AGF_INGEST_PULSAR_URL`）：与上面那行**分别列出**，
        // 两行写清差异（KoP = Kafka wire protocol 复用 Kafka 接收器；原生 = 手写 Pulsar binary protocol）。
        crate::pulsar::pulsar_native_descriptor(std::env::var("AGF_INGEST_PULSAR_URL").ok().as_deref()),
        // NATS JetStream **入向**订阅（与 `bus.rs` 的"事件总线发布"是两件事）。
        // 状态经 `effective_status` 折算：装配点没起订阅任务时如实显示 `not-wired`。
        ReceiverDescriptor {
            name: "nats-jetstream".to_string(),
            protocol: IngestProtocol::Nats,
            status: effective_status(ReceiverStatus::Ready, "nats-jetstream"),
            note: "NATS JetStream 入向订阅（`async-nats`）：durable stream/consumer 幂等 `provision`、\
                   显式应答（`ack_with(AckKind)`：ack/nak/term，落库成功才 ack）、pull 批量 + push 推送双模式；\
                   未配置 `AGF_INGEST_JETSTREAM_URL` ⇒ 不启用"
                .to_string(),
            todo: Some(
                "TODO ingest-jetstream-kv-object：JetStream KV/ObjectStore 未接线；\
                 事件总线发布已使用独立 SQL 事务队列与 JetStream 存储确认"
                    .to_string(),
            ),
            mock_replay: false,
        },
        ReceiverDescriptor {
            name: "collector-uplink".to_string(),
            protocol: IngestProtocol::Mcp,
            status: ReceiverStatus::Ready,
            note: "南向采集器 AgentReport + 原始日志上行（mTLS 指纹校验）".to_string(),
            todo: None,
            mock_replay: false,
        },
    ]
}

// ---------------------------------------------------------------------------
// 南向采集器上行
// ---------------------------------------------------------------------------
