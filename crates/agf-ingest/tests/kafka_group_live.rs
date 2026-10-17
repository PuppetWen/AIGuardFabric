//! Kafka **真消费者组协议**对**真 broker**（Apache Kafka / KoP）的端到端验证。
//!
//! 与 `jetstream_live.rs` 同一约定：**未设置 `AGF_E2E_KAFKA_BROKERS` 时直接跳过**
//! （`#[ignore]` + 早退），因此 `cargo test` 常规跑法**不依赖任何外部服务**。
//!
//! ## 为什么必须真机
//!
//! 离线单测覆盖的是分配器/编解码/rebalance 判据（纯函数），但组协议真正会出错的地方在
//! **协调器交互**：`JoinGroup` 的代际号、`SyncGroup` 的下发、心跳错误码、`OffsetCommit` 的
//! 代际栅栏。这些只有真 broker 才能证伪 —— 尤其是"`kafka-consumer-groups.sh --describe`
//! 能看到本组与该组的 offset/lag"这条，只能由 broker 侧的组元数据作证。
//!
//! ## 运行方式（由 `tools/simulators/run_kafka_group_e2e.ps1` 驱动）
//!
//! ```text
//! cargo test -p agf-ingest --test kafka_group_live --no-run
//! # 然后直接跑测试可执行文件（驱动脚本就是这么做的：这样才能"硬杀一个成员"）
//! set AGF_E2E_KAFKA_BROKERS=127.0.0.1:9092
//! set AGF_E2E_KAFKA_TOPIC=agf-e2e-group
//! set AGF_E2E_KAFKA_GROUP=agf-e2e-live
//! set AGF_E2E_GROUP_LABEL=member-A
//! set AGF_E2E_GROUP_RUN_SECS=30
//! kafka_group_live.exe --ignored --nocapture
//! ```
//!
//! 进程在 stdout 上按行输出三类机器可读事件（驱动脚本 grep 它们）：
//! `AGF_E2E_GROUP_READY`（**已入组**，含成员 id/代际/分配）、
//! `AGF_E2E_GROUP_STATE`（每次分配变化/心跳周期）、
//! `AGF_E2E_GROUP_SUMMARY`（退出前的最终账：消费条数、提交进度、rebalance 次数）。

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout, clippy::cast_precision_loss)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use agf_core::enums::{HealthState, IngestProtocol};
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, LogSource, SourceConnection};
use agf_core::time::Timestamp;
use agf_ingest::bus::NoopEventBus;
use agf_ingest::kafka::{
    KafkaGroupConfig, KafkaGroupSnapshot, KafkaGroupSource, KafkaPullConfig, KafkaReceiver, KafkaShutdown, KafkaSource,
    KafkaStartFrom, parse_brokers,
};
use agf_ingest::pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink};
use agf_ingest::receiver::Receiver as _;
use agf_ingest::registry::ParserRegistry;
use serde_json::json;

/// broker 列表（逗号分隔，`host:9092`）。
const ENV_BROKERS: &str = "AGF_E2E_KAFKA_BROKERS";
/// topic。
const ENV_TOPIC: &str = "AGF_E2E_KAFKA_TOPIC";
/// 消费者组 id。
const ENV_GROUP: &str = "AGF_E2E_KAFKA_GROUP";
/// 成员标签（日志/证据里区分 A/B）。
const ENV_LABEL: &str = "AGF_E2E_GROUP_LABEL";
/// 运行时长（秒）。
const ENV_RUN_SECS: &str = "AGF_E2E_GROUP_RUN_SECS";
/// 消费到该条数即主动停机（0 = 跑满 `RUN_SECS`）。
const ENV_STOP_AFTER: &str = "AGF_E2E_GROUP_STOP_AFTER";
/// 停机时是否发 `LeaveGroup`（1 = 优雅；0 = 只落盘，模拟"进程被杀"）。
const ENV_GRACEFUL: &str = "AGF_E2E_GROUP_LEAVE";
/// 是否打开 tracing（1 = DEBUG 级别打进 stdout）。
const ENV_LOG: &str = "AGF_E2E_LOG";
/// `session.timeout.ms` 覆盖（对照实验用）。
const ENV_SESSION_MS: &str = "AGF_E2E_GROUP_SESSION_MS";
/// `heartbeat.interval.ms` 覆盖。
const ENV_HEARTBEAT_MS: &str = "AGF_E2E_GROUP_HEARTBEAT_MS";
/// `rebalance.timeout.ms` 覆盖。
const ENV_REBALANCE_MS: &str = "AGF_E2E_GROUP_REBALANCE_MS";
/// 显式入组的重试总时长（秒）。
const ENV_JOIN_TIMEOUT_SECS: &str = "AGF_E2E_GROUP_JOIN_TIMEOUT_SECS";

fn env_or(name: &str, fallback: &str) -> String {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn env_num<T: std::str::FromStr>(name: &str, fallback: T) -> T {
    std::env::var(name).ok().and_then(|value| value.trim().parse::<T>().ok()).unwrap_or(fallback)
}

/// 组会话快照 → 一行 JSON（字段名与 PowerShell 侧的解析一一对应）。
fn snapshot_json(label: &str, topic: &str, snapshot: &KafkaGroupSnapshot, consumed: u64, sink_rows: usize) -> String {
    let committed: Vec<String> =
        snapshot.committed.iter().map(|((topic, partition), offset)| format!("{topic}/{partition}@{offset}")).collect();
    let assignment: Vec<String> =
        snapshot.assignment.iter().map(|(topic, partition)| format!("{topic}/{partition}")).collect();
    json!({
        "label": label,
        "topic": topic,
        "group": snapshot.group_id,
        "coordinator": snapshot.coordinator,
        "member_id": snapshot.member_id,
        "generation": snapshot.generation_id,
        "leader": snapshot.leader,
        "member_count": snapshot.member_count,
        "assignment": assignment,
        "assignment_size": snapshot.assignment.len(),
        "rebalances": snapshot.rebalances,
        "heartbeats": snapshot.heartbeats,
        "commits": snapshot.commits,
        "committed_partitions": snapshot.committed_partitions,
        "committed": committed,
        "records_consumed": consumed,
        "sink_rows": sink_rows,
    })
    .to_string()
}

fn log_source(topic: &str) -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "kafka-group-live".to_string(),
        protocol: IngestProtocol::Kafka,
        vendor: "generic".to_string(),
        product: "json".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection { topic: Some(topic.to_string()), ..SourceConnection::default() },
        mode: CollectionMode::Pull,
        poll_interval_secs: Some(1),
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

/// 组协议成员：入组 → 消费 → 提交；按 env 决定跑多久、是否优雅退组。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要真实 Kafka：设置 AGF_E2E_KAFKA_BROKERS 后用 --ignored 运行（见 tools/simulators/run_kafka_group_e2e.ps1）"]
async fn kafka_consumer_group_live() {
    let Some(brokers) = std::env::var(ENV_BROKERS).ok().filter(|value| !value.trim().is_empty()) else {
        println!("SKIP: 未设置 {ENV_BROKERS}（离线跑法不依赖 broker）");
        return;
    };
    // AGF_E2E_LOG=1：把组协议每一步的 info/warn 打进 stdout（"卡在哪一步"必须可见，不能靠猜）
    if env_num(ENV_LOG, 0_u8) == 1 {
        let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).with_test_writer().try_init();
    }
    let topic = env_or(ENV_TOPIC, "agf-e2e-group");
    let group_id = env_or(ENV_GROUP, "agf-e2e-live");
    let label = env_or(ENV_LABEL, "member");
    let run_secs = env_num(ENV_RUN_SECS, 20_u64).max(1);
    let stop_after = env_num(ENV_STOP_AFTER, 0_u64);
    let graceful = env_num(ENV_GRACEFUL, 1_u8) == 1;

    let config = KafkaPullConfig {
        brokers: parse_brokers(&brokers).expect("broker 列表非法"),
        topic: topic.clone(),
        start_from: KafkaStartFrom::Earliest,
        // 组协议下的轮询间隔：同时决定"心跳检查"与"rebalance 感知"的粒度
        interval_secs: 1,
        max_records_per_partition: 100,
        max_wait_ms: 500,
        // **不用本地游标文件**：证明进度确实来自 broker 侧已提交 offset
        cursor_path: None,
        ..KafkaPullConfig::default()
    };
    let group = KafkaGroupConfig {
        group_id: group_id.clone(),
        // session 10s / heartbeat 3s：硬杀一个成员后 ≤15s 就能观测到接管（可用 env 覆盖做对照实验）
        session_timeout_ms: env_num(ENV_SESSION_MS, 10_000_i32),
        heartbeat_interval_ms: env_num(ENV_HEARTBEAT_MS, 3_000_i32),
        max_poll_interval_ms: 60_000,
        rebalance_timeout_ms: env_num(ENV_REBALANCE_MS, 10_000_i32),
        ..KafkaGroupConfig::default()
    };
    let source = Arc::new(KafkaGroupSource::connect(config.clone(), group.clone()).expect("组数据源构造失败"));
    let sink = Arc::new(InMemorySink::new());
    let pipeline = Arc::new(IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { emit_to_bus: false, ..IngestConfig::default() },
    ));
    let shutdown = KafkaShutdown::new();
    let receiver = Arc::new(
        KafkaReceiver::new(Arc::clone(&source) as Arc<dyn KafkaSource>, config).with_shutdown(shutdown.handle()),
    );
    let task = tokio::spawn({
        let receiver = Arc::clone(&receiver);
        let pipeline = Arc::clone(&pipeline);
        let source = log_source(&topic);
        async move {
            if let Err(error) = receiver.start(pipeline, source).await {
                println!("AGF_E2E_GROUP_ERROR {error}");
            }
        }
    });

    println!("AGF_E2E_GROUP_BOOT {label} brokers={brokers} topic={topic} group={group_id}");
    // 先做一次**显式入组**（失败原因直接打在 stdout，脚本要能一眼看到卡在哪一步）。
    //
    // 为什么是重试循环而不是"一次失败就 panic"：组协议的入组天然是**可能被延后**的——
    // 协调器可能回 `MEMBER_ID_REQUIRED`（KIP-394 两步入组）、可能在 resettling 期间拒绝。
    // 真实客户端（Java）也是"每个 poll 周期重试一次"。这里按同一口径重试，并把每次失败原因打出来。
    let join_deadline = Instant::now() + Duration::from_secs(env_num(ENV_JOIN_TIMEOUT_SECS, 60_u64));
    loop {
        match source.partitions(&topic).await {
            Ok(partitions) => {
                println!("AGF_E2E_GROUP_ASSIGNED {partitions:?}");
                break;
            }
            Err(error) => {
                println!("AGF_E2E_GROUP_JOIN_RETRY {error}");
                if Instant::now() >= join_deadline {
                    println!("AGF_E2E_GROUP_JOIN_FAILED {error}");
                    panic!("JoinGroup/SyncGroup 在超时前未成功: {error}");
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    let started = Instant::now();
    let mut announced = false;
    let mut last_state = String::new();
    while started.elapsed() < Duration::from_secs(run_secs) {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let snapshot = source.snapshot().await;
        let consumed = receiver.stats().records_consumed_total();
        let rows = sink.events().map(|events| events.len()).unwrap_or(0);
        let state = snapshot_json(&label, &topic, &snapshot, consumed, rows);
        if !announced && snapshot.member_id.is_some() && snapshot.generation_id >= 0 {
            announced = true;
            println!("AGF_E2E_GROUP_READY {state}");
        }
        // 只在"实质变化"时打印，避免刷屏（分配/代际/成员 id/提交进度）
        let fingerprint = format!(
            "{}|{}|{:?}|{}|{}",
            snapshot.member_id.as_deref().unwrap_or("-"),
            snapshot.generation_id,
            snapshot.assignment,
            snapshot.commits,
            consumed
        );
        if announced && fingerprint != last_state {
            last_state = fingerprint;
            println!("AGF_E2E_GROUP_STATE {state}");
        }
        if stop_after > 0 && consumed >= stop_after {
            println!("AGF_E2E_GROUP_REACHED_TARGET consumed={consumed} target={stop_after}");
            break;
        }
    }

    // **入组快照必须在停机之前取**：优雅停机走 `LeaveGroup`，会把 `member_id`/`assignment` 清空
    // （那是"正常退组"的正确语义）。真机实测踩过这个坑：用停机后的快照去断言"是否入组过"，
    // 会把成功入组 + 正常退组误判成"未入组"。
    let joined = source.snapshot().await;

    if graceful {
        // 优雅停机：接收器会 close_session → 补提交 + LeaveGroup（同伴立即 rebalance）
        shutdown.trigger();
        let _ = receiver.stop().await;
        let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
    }
    let snapshot = source.snapshot().await;
    let consumed = receiver.stats().records_consumed_total();
    let rows = sink.events().map(|events| events.len()).unwrap_or(0);
    println!("AGF_E2E_GROUP_SUMMARY {}", snapshot_json(&label, &topic, &snapshot, consumed, rows));

    // 断言（真机路径）：入组成功、分配非空、代际有效、消费有条数、进度已提交到 broker
    assert!(joined.member_id.is_some(), "未入组：member_id 为空");
    assert!(joined.generation_id >= 0, "代际号无效：{}", joined.generation_id);
    assert!(!joined.assignment.is_empty(), "协调器未下发任何分区");
    if stop_after > 0 {
        assert!(consumed >= stop_after, "未达到目标消费条数：{consumed} < {stop_after}");
    }
    if consumed > 0 {
        assert!(snapshot.commits > 0, "消费了记录却没有任何 OffsetCommit");
        assert!(!snapshot.committed.is_empty(), "已提交进度镜像为空");
    }
}
