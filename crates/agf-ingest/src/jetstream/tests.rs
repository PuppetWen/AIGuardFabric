//! 离线单元测试：注入 [`FakeJetStream`] 内存实现，**不需要真实 NATS / docker**。

use std::sync::Arc;
use std::time::Duration;

use agf_core::enums::{HealthState, IngestProtocol};
use agf_core::error::DomainError;
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, LogSource, SourceConnection};
use agf_core::time::Timestamp;

use crate::bus::NoopEventBus;
use crate::pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink};
use crate::receiver::{Receiver, ReceiverStatus};
use crate::registry::ParserRegistry;

use super::JetIngestReport;
use super::plan::{
    ConsumerPlan, DEFAULT_STREAM_PREFIX, JetAckAction, JetMessage, JetMode, StreamPlan, parse_nats_urls, sanitize_token,
};
use super::receiver::JetStreamReceiver;
use super::source::{FakeJetStream, JetStreamSource};

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "jetstream-test".to_string(),
        protocol: IngestProtocol::Nats,
        vendor: "generic".to_string(),
        product: "json".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Pull,
        poll_interval_secs: None,
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

fn receiver(mode: JetMode, fake: Arc<FakeJetStream>) -> (JetStreamReceiver, Arc<InMemorySink>) {
    let (pipeline, sink) = pipeline_and_sink();
    let source = log_source();
    let stream = StreamPlan::for_source(&source, "agf.ingest");
    let consumer = ConsumerPlan::for_source(&source, mode, "", 8);
    (JetStreamReceiver::new(pipeline, source, stream, consumer, fake), sink)
}

#[test]
fn nats_url_parsing_is_strict() {
    assert_eq!(
        parse_nats_urls("nats://a:4222, nats://b:4222").ok(),
        Some(vec!["nats://a:4222".to_string(), "nats://b:4222".to_string()])
    );
    assert_eq!(parse_nats_urls("  ").ok(), None);
    assert!(matches!(parse_nats_urls(",,"), Err(DomainError::Config(_))));
}

#[test]
fn stream_plan_is_durable_and_sanitized() {
    let source = log_source();
    let plan = StreamPlan::for_source(&source, "agf.ingest");
    assert!(plan.name.starts_with(DEFAULT_STREAM_PREFIX), "durable 名带稳定前缀");
    assert_eq!(plan.subjects, vec![format!("agf.ingest.{}", source.id)]);
    assert_eq!(plan.retention, "limits");
    assert_eq!(plan.storage, "file");
    assert!(!plan.name.contains('.'), "stream 名不允许 `.`");
    assert_eq!(sanitize_token("a.b c*d>e"), "a-b-c-d-e");
}

#[test]
fn consumer_plan_modes_and_defaults() {
    let source = log_source();
    let pull = ConsumerPlan::for_source(&source, JetMode::Pull, "agf.ingest.>", 64);
    assert!(pull.durable_name.starts_with(super::plan::DEFAULT_CONSUMER_PREFIX));
    assert_eq!(pull.ack_policy, "explicit", "应答必须显式（非自动）");
    assert_eq!(pull.deliver_policy, "all");
    assert_eq!(pull.deliver_subject, "", "pull 模式无 deliver subject");
    assert_eq!(pull.batch_size, 64);
    assert_eq!(pull.max_deliver, 8);

    let push = ConsumerPlan::for_source(&source, JetMode::Push, "", 1);
    assert!(push.deliver_subject.starts_with("agf.deliver."), "push 模式必须有 deliver subject");
    assert_eq!(JetMode::Pull.as_str(), "pull");
    assert_eq!(JetMode::Push.as_str(), "push");
    assert_eq!(ConsumerPlan::for_source(&source, JetMode::Pull, "", 0).batch_size, 1, "batch_size 下限 1");
}

#[test]
fn plan_from_source_reads_connection() {
    let mut source = log_source();
    assert!(
        matches!(JetStreamReceiver::plan_from_source(&source), Err(DomainError::Config(_))),
        "缺 endpoint 必须报错"
    );
    // 一次性构造（`field_reassign_with_default` 要求不要在 `Default::default()` 之后逐字段赋值）
    let mut connection = SourceConnection {
        endpoint: Some("nats://127.0.0.1:4222".to_string()),
        topic: Some("agf.ingest.>".to_string()),
        ..SourceConnection::default()
    };
    connection.headers.insert("jetstream.mode".to_string(), "push".to_string());
    connection.headers.insert("jetstream.batch".to_string(), "32".to_string());
    source.connection = connection;
    let planned = JetStreamReceiver::plan_from_source(&source);
    assert!(planned.is_ok(), "plan_from_source 应成功: {planned:?}");
    let Some((stream, consumer)) = planned.ok() else { return };
    assert_eq!(stream.subjects, vec![format!("agf.ingest.{}", source.id)]);
    assert_eq!(consumer.mode, JetMode::Push);
    assert_eq!(consumer.filter_subject, "agf.ingest.>");
    assert_eq!(consumer.batch_size, 32);
}
#[test]
fn ack_decision_semantics() {
    let ok = JetIngestReport { records: 2, persisted: 2, persist_failed: false };
    assert_eq!(JetAckAction::decide(&ok, 1, 8), JetAckAction::Ack);
    let failed = JetIngestReport { records: 0, persisted: 0, persist_failed: true };
    assert_eq!(JetAckAction::decide(&failed, 1, 8), JetAckAction::Nak, "落库失败必须 nak 重投");
    assert_eq!(
        JetAckAction::decide(&JetIngestReport::default(), 1, 8),
        JetAckAction::Term,
        "空载荷 term（重投无意义）"
    );
    let poisoned = JetIngestReport { records: 1, persisted: 0, persist_failed: false };
    assert_eq!(JetAckAction::decide(&poisoned, 8, 8), JetAckAction::Term, "毒消息达 max_deliver 后 term");
    assert_eq!(JetAckAction::decide(&poisoned, 99, 0), JetAckAction::Ack, "max_deliver<=0 表示不限重投");
    assert_eq!(JetAckAction::Ack.as_str(), "ack");
    assert_eq!(JetAckAction::Nak.as_str(), "nak");
    assert_eq!(JetAckAction::Term.as_str(), "term");
}

#[tokio::test]
async fn provision_is_idempotent() {
    let fake = Arc::new(FakeJetStream::new());
    let (recv, _sink) = receiver(JetMode::Pull, Arc::clone(&fake));
    let first = recv.provision().await;
    let second = recv.provision().await;
    assert!(first.is_ok() && second.is_ok(), "{first:?} / {second:?}");
    assert_eq!(fake.consumer_count().ok(), Some(1), "durable consumer 幂等：重复声明不新增");
    let state = second.ok().unwrap_or_default();
    assert_eq!(state.consumer_count, 1);
}

#[tokio::test]
async fn pull_batch_ingests_and_acks() {
    let fake = Arc::new(FakeJetStream::new());
    for index in 0..3u8 {
        let payload = format!(
            "<34>Feb 21 10:23:4{index} web-prod-0{index} sshd[2311]: Failed password for root from 203.0.113.7{index} port 5123{index} ssh2"
        );
        let _ = fake.push("agf.ingest.site", payload.into_bytes());
    }
    let (recv, sink) = receiver(JetMode::Pull, Arc::clone(&fake));
    let provisioned = recv.provision().await;
    assert!(provisioned.is_ok(), "{provisioned:?}");
    let pulled = recv.poll_batch(8).await;
    assert_eq!(pulled.ok(), Some(3), "三条全部拉取并接入");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(3));
    assert_eq!(fake.pending().ok(), Some(0));
    let acked = fake.acked().unwrap_or_default();
    assert_eq!(acked.len(), 3);
    assert!(acked.iter().all(|(_, _, action)| *action == JetAckAction::Ack), "全部显式 ack：{acked:?}");
    assert_eq!(recv.counters().snapshot().received, 3);
}

#[tokio::test]
async fn pull_respects_batch_cap() {
    let fake = Arc::new(FakeJetStream::new());
    for index in 0..5u8 {
        let _ = fake.push("agf.ingest.site", format!("{{\"i\":{index}}}").into_bytes());
    }
    let (recv, _sink) = receiver(JetMode::Pull, Arc::clone(&fake));
    let _ = recv.provision().await;
    assert_eq!(recv.poll_batch(2).await.ok(), Some(2), "批次上限是背压阀");
    assert_eq!(fake.pending().ok(), Some(3), "未拉取的留在流内等下一轮");
    assert_eq!(recv.poll_batch(8).await.ok(), Some(3));
}

#[tokio::test]
async fn nak_redelivers_and_term_drops() {
    let fake = Arc::new(FakeJetStream::new());
    let _ = fake.push("agf.ingest.site", Vec::new());
    let (recv, _sink) = receiver(JetMode::Pull, Arc::clone(&fake));
    let _ = recv.provision().await;
    assert_eq!(recv.poll_batch(1).await.ok(), Some(1));
    let acked = fake.acked().unwrap_or_default();
    assert_eq!(acked.first().map(|entry| entry.2), Some(JetAckAction::Term), "空载荷 term");
    assert_eq!(recv.counters().snapshot().dropped, 1, "term 计入丢弃");
    assert_eq!(fake.pending().ok(), Some(0), "term 不重投");

    let msg = JetMessage {
        subject: "agf.ingest.site".to_string(),
        payload: b"{}".to_vec(),
        delivered: 2,
        stream_sequence: 9,
    };
    let ack = fake.ack("durable", &msg, JetAckAction::Nak).await;
    assert!(ack.is_ok());
    let redelivered = fake.fetch_batch("durable", 1, Duration::from_millis(1)).await.unwrap_or_default();
    assert_eq!(redelivered.first().map(|m| m.delivered), Some(3), "nak 后 delivered+1 重投");
}

#[tokio::test]
async fn push_consumes_until_channel_closed() {
    let fake = Arc::new(FakeJetStream::new());
    for index in 0..2u8 {
        let payload = format!(
            "<34>Feb 21 10:24:0{index} edge-0{index} sshd[42]: Accepted password for ops from 198.51.100.2{index} port 2222 ssh2"
        );
        let _ = fake.push("agf.ingest.site", payload.into_bytes());
    }
    let (recv, sink) = receiver(JetMode::Push, Arc::clone(&fake));
    let _ = recv.provision().await;
    let done = recv.run().await;
    assert!(done.is_ok(), "{done:?}");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(2));
    let acked = fake.acked().unwrap_or_default();
    assert_eq!(acked.len(), 2);
    assert!(acked.iter().all(|(_, _, action)| *action == JetAckAction::Ack));
}

#[tokio::test]
async fn push_poll_once_is_rejected_but_pull_works() {
    let (pipeline, _sink) = pipeline_and_sink();
    let source = log_source();
    let fake = Arc::new(FakeJetStream::new());
    let stream = StreamPlan::for_source(&source, "agf.ingest");
    let push = ConsumerPlan::for_source(&source, JetMode::Push, "", 8);
    let push_recv = JetStreamReceiver::new(
        Arc::clone(&pipeline),
        source.clone(),
        stream.clone(),
        push,
        Arc::clone(&fake) as Arc<dyn JetStreamSource>,
    );
    let poll = push_recv.poll_once(Arc::clone(&pipeline), source.clone(), 4).await;
    assert!(matches!(poll, Err(DomainError::NotImplemented(_))), "push 无轮询语义");

    let pull = ConsumerPlan::for_source(&source, JetMode::Pull, "", 8);
    let pull_recv = JetStreamReceiver::new(Arc::clone(&pipeline), source.clone(), stream, pull, fake);
    let _ = pull_recv.provision().await;
    assert_eq!(pull_recv.poll_once(pipeline, source, 4).await.ok(), Some(0), "空流拉取 0 条");
}

#[test]
fn descriptor_reports_wiring_aware_status_with_todo() {
    let fake = Arc::new(FakeJetStream::new());
    let (recv, _sink) = receiver(JetMode::Pull, fake);
    let descriptor = recv.describe();
    assert_eq!(descriptor.protocol, IngestProtocol::Nats);
    // 库测试进程里**没有装配点报到** ⇒ 按第四态如实显示 not-wired，绝不谎报 ready
    assert_eq!(
        descriptor.status,
        ReceiverStatus::NotWired,
        "订阅任务没被装配时必须显示 not-wired（修复前这里是 Ready——'口径不实'的原样）"
    );
    assert_eq!(
        crate::receiver::status_for(ReceiverStatus::Ready, Some(true)),
        ReceiverStatus::Ready,
        "装配点登记 wired=true 后同一模块才是 ready"
    );
    assert!(descriptor.note.contains("jetstream"), "能力矩阵行要如实呈现 JetStream 语义");
    assert!(descriptor.note.contains("ack_with"), "note 必须写明是真应答：{}", descriptor.note);
    assert!(descriptor.todo.as_deref().is_some_and(|t| t.contains("TODO ingest-jetstream")), "TODO 锚点必填");
    assert!(!descriptor.mock_replay);
    assert_eq!(descriptor.name, "nats-jetstream-pull");
}

/// **重启不丢的前提**：stream/consumer 名只由稳定标识决定（不用随机 `LogSource::id`）。
#[test]
fn identity_plans_are_stable_and_satisfy_the_stream_naming_convention() {
    let stream = StreamPlan::for_identity("site-a", "agf.ingest.site-a");
    let consumer = ConsumerPlan::for_identity("site-a", JetMode::Pull, "agf.ingest.site-a", 32);
    assert_eq!(stream.name, "AGF_INGEST-site-a");
    assert_eq!(stream.subjects, vec!["agf.ingest.site-a".to_string()]);
    assert_eq!(consumer.durable_name, "agf-ingest-site-a");
    assert_eq!(
        super::stream_name_for_durable(&consumer.durable_name),
        stream.name,
        "durable → stream 的命名约定必须与 for_identity 一致（否则 consumer 挂错 stream）"
    );
    // 同一标识重复构造 ⇒ 逐字节相同的名字（进程重启后复用同一 durable）
    assert_eq!(StreamPlan::for_identity("site-a", "agf.ingest.site-a"), stream);
    assert_eq!(ConsumerPlan::for_identity("site-a", JetMode::Pull, "agf.ingest.site-a", 32), consumer);
    // 非法字符被清洗（NATS token 不允许 `.`/空白/`*`/`>`）
    assert_eq!(StreamPlan::for_identity("a.b c", "s").name, "AGF_INGEST-a-b-c");
    // 与随机 id 版对比：for_source 的名字每次进程启动都不同（因此真机装配不能用它）
    let source = log_source();
    assert!(StreamPlan::for_source(&source, "agf.ingest").name.starts_with("AGF_INGEST-"));
    assert_ne!(
        StreamPlan::for_source(&source, "agf.ingest").name,
        StreamPlan::for_source(&log_source(), "agf.ingest").name
    );
}

/// 应答动作 → `AckKind` 的协议级映射（ack/nak/term 三态都要落到服务端语义上）。
#[cfg(feature = "nats")]
#[test]
fn ack_actions_map_to_real_ack_kinds() {
    use async_nats::jetstream::AckKind;
    assert!(matches!(super::ack_kind(JetAckAction::Ack), AckKind::Ack));
    assert!(matches!(super::ack_kind(JetAckAction::Nak), AckKind::Nak(None)), "nak 不额外延后，按 ack_wait 重投");
    assert!(matches!(super::ack_kind(JetAckAction::Term), AckKind::Term));
}
