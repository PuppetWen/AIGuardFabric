//! 对**真实 KoP（Kafka on Pulsar）** 的 Kafka 协议**写入路径**做端到端验证（默认 `#[ignore]`）。
//!
//! 为什么需要这个文件：本仓库的 Pulsar 接收器只做**消费**（`rskafka` 拉取），历史上
//! "Kafka 协议 produce 方向"从未被本仓库自己的代码验证过。这里用**本仓库同一份依赖**
//! （`rskafka` + `KafkaSaslConfig` + `KafkaTlsConfig`）写一版生产者，证明：
//!
//! * **写入路径可用**：`rskafka` 能把记录写进 KoP（纯 Rust，无 librdkafka）；
//! * **读回闭环**：写完再用**本仓库的源** [`RskafkaSource`]（= Pulsar 接收器的取数内核）
//!   把同一条记录读回来，值/分区/offset 完全一致；
//! * **鉴权真的生效**：错误 token（或已被授权模型拒绝的角色）必须**写不进去**；
//! * **TLS 真的握手**：带正确 CA 能写通，带**错 CA** 必须在握手阶段失败。
//!
//! 运行方式（KoP 已由 `docker compose -f docker-compose.ingest-test.yml --profile pulsar up -d` 拉起）：
//!
//! ```text
//! $env:AGF_E2E_KOP_BROKERS='127.0.0.1:19092'
//! $env:AGF_E2E_KOP_TOPIC='kop-probe'
//! $env:AGF_E2E_KOP_TOKEN=(Get-Content target\koprun\pulsar.token -Raw)
//! cargo test -p agf-ingest --test kop_produce -- --ignored --nocapture
//! ```
//!
//! 未设置 `AGF_E2E_KOP_BROKERS` 时全部用例跳过（且默认 `#[ignore]`，
//! 因此 `cargo test` / `cargo test --workspace` **不依赖 Docker**）。
//!
//! 可选环境变量：
//! * `AGF_E2E_KOP_SASL_USERNAME` —— KoP 的 SASL/PLAIN username（缺省按 token 的 `sub` 推导）；
//! * `AGF_E2E_KOP_TLS_CA` —— 客户端信任的 CA（PEM）；给了就启用 TLS（`SASL_SSL`）；
//! * `AGF_E2E_KOP_BAD_CA` —— **负例**：只信任这个 CA，TLS 握手必须失败；
//! * `AGF_E2E_KOP_DENIED_TOKEN` —— **负例**：这个 token 的角色未被授权，写入必须被拒；
//! * `AGF_E2E_KOP_PARTITIONS` —— 期望的分区数（默认 3）。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]
// 单测/集成测试里 panic 是断言手段；本文件不参与发布路径。

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use agf_ingest::kafka::{
    KafkaSaslConfig, KafkaSaslMechanism, KafkaSecurity, KafkaSource, KafkaStartFrom, KafkaTlsConfig, RskafkaSource,
};
use agf_ingest::receiver::{kop_plain_password, kop_plain_username};
use rskafka::client::partition::UnknownTopicHandling;
use rskafka::record::Record;

/// KoP 的 Kafka 协议地址（未设置 ⇒ 全部用例跳过）。
const ENV_BROKERS: &str = "AGF_E2E_KOP_BROKERS";
const ENV_TOPIC: &str = "AGF_E2E_KOP_TOPIC";
const ENV_TOKEN: &str = "AGF_E2E_KOP_TOKEN";
const ENV_USERNAME: &str = "AGF_E2E_KOP_SASL_USERNAME";
const ENV_TLS_CA: &str = "AGF_E2E_KOP_TLS_CA";
const ENV_BAD_CA: &str = "AGF_E2E_KOP_BAD_CA";
const ENV_DENIED_TOKEN: &str = "AGF_E2E_KOP_DENIED_TOKEN";
const ENV_PARTITIONS: &str = "AGF_E2E_KOP_PARTITIONS";

fn env_value(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

/// 一次"写入 + 读回"的完整上下文。
struct KopContext {
    brokers: Vec<String>,
    topic: String,
    username: String,
    password: String,
    tls: Option<KafkaTlsConfig>,
    partitions: i32,
}

impl KopContext {
    /// 由环境变量构造；`token_env` 选择用哪个 token（正常 / 被拒）。
    fn from_env(token_env: &str, ca_env: &str) -> Option<Self> {
        let brokers_raw = env_value(ENV_BROKERS)?;
        let token = env_value(token_env)?;
        let brokers: Vec<String> = brokers_raw.split(',').map(|item| item.trim().to_string()).collect();
        let username = env_value(ENV_USERNAME).unwrap_or_else(|| kop_plain_username(&token));
        let tls = env_value(ca_env).map(|ca| KafkaTlsConfig {
            ca_pem: Some(PathBuf::from(ca)),
            client_cert_pem: None,
            client_key_pem: None,
            insecure_skip_verify: false,
        });
        Some(Self {
            brokers,
            topic: env_value(ENV_TOPIC).unwrap_or_else(|| "kop-probe".to_string()),
            username,
            password: kop_plain_password(&token),
            tls,
            partitions: env_value(ENV_PARTITIONS).and_then(|value| value.parse().ok()).unwrap_or(3),
        })
    }

    fn security(&self) -> KafkaSecurity {
        KafkaSecurity {
            sasl: Some(KafkaSaslConfig::new(KafkaSaslMechanism::Plain, self.username.clone(), self.password.clone())),
            tls: self.tls.clone(),
        }
    }

    /// 建一个与接收器**同一套安全配置**的 rskafka 客户端。
    async fn client(&self) -> Result<rskafka::client::Client, String> {
        let mut builder = rskafka::client::ClientBuilder::new(self.brokers.clone())
            .client_id("agf-e2e-produce")
            .max_message_size(16 * 1024 * 1024)
            .backoff_config(rskafka::BackoffConfig {
                init_backoff: Duration::from_millis(50),
                max_backoff: Duration::from_secs(1),
                base: 2.0,
                deadline: Some(Duration::from_secs(20)),
            });
        if let Some(tls) = &self.tls {
            builder = builder.tls_config(tls.build_client_config().map_err(|e| e.to_string())?);
        }
        if let Some(sasl) = &self.security().sasl {
            builder = builder.sasl_config(sasl.to_rskafka());
        }
        builder.build().await.map_err(|e| format!("{e}"))
    }
}

/// 往每个分区各写一条唯一的记录，再用**本仓库的源**读回并核对。
///
/// 返回每个分区 `(offset, 期望值)`；任一步失败 ⇒ `Err(原因)`（负例断言用）。
async fn produce_then_read_back(ctx: &KopContext, tag: &str) -> Result<Vec<(i32, i64, String)>, String> {
    let client = ctx.client().await?;
    let mut written = Vec::new();
    for partition in 0..ctx.partitions {
        let value = format!(
            "<34>Feb 21 11:{:02}:00 {tag} sshd[2500]: Failed password for root from 203.0.113.{} port 52{:03} ssh2",
            partition,
            10 + partition,
            100 + partition
        );
        let partition_client = client
            .partition_client(ctx.topic.clone(), partition, UnknownTopicHandling::Error)
            .await
            .map_err(|e| format!("partition_client({partition}): {e}"))?;
        let offsets = partition_client
            .produce(
                vec![Record {
                    key: None,
                    value: Some(value.clone().into_bytes()),
                    headers: BTreeMap::new(),
                    timestamp: chrono::Utc::now(),
                }],
                rskafka::client::partition::Compression::NoCompression,
            )
            .await
            .map_err(|e| format!("produce({partition}): {e}"))?;
        let offset = *offsets.first().ok_or_else(|| format!("produce({partition}) 未返回 offset"))?;
        written.push((partition, offset, value));
    }

    // 读回：与 Pulsar 接收器**同一个**取数内核（RskafkaSource）
    let source = RskafkaSource::connect(ctx.brokers.clone(), "agf-e2e-verify", &ctx.security())
        .await
        .map_err(|e| format!("RskafkaSource::connect: {e}"))?;
    for (partition, offset, expected) in &written {
        let batch = source
            .fetch(&ctx.topic, *partition, *offset, 1024 * 1024, 0)
            .await
            .map_err(|e| format!("fetch({partition}): {e}"))?;
        let found = batch
            .records
            .iter()
            .find(|record| record.offset == *offset)
            .ok_or_else(|| format!("读回失败：分区 {partition} offset {offset} 不在返回批次里"))?;
        let actual = String::from_utf8_lossy(found.value.as_deref().unwrap_or_default()).to_string();
        if &actual != expected {
            return Err(format!("读回内容不一致：分区 {partition} 期望 {expected:?} 实际 {actual:?}"));
        }
    }
    // 顺带证明"分区发现"在 KoP 上也走通（KoP 不支持全量 topic 列表，靠 topic 级探测兜底）
    let partitions = source.partitions(&ctx.topic).await.map_err(|e| format!("partitions: {e}"))?;
    if partitions.len() < usize::try_from(ctx.partitions).unwrap_or(0) {
        return Err(format!("分区发现不足：期望 {} 个，实际 {partitions:?}", ctx.partitions));
    }
    Ok(written)
}

/// **(a) 正例：rskafka 写入 KoP → 本仓库源读回**（SASL/PLAIN token；带 `AGF_E2E_KOP_TLS_CA` 时走 SASL_SSL）。
#[tokio::test]
#[ignore = "需要真实 KoP（AGF_E2E_KOP_BROKERS）"]
async fn rskafka_produce_round_trips_through_the_repository_source() {
    let Some(ctx) = KopContext::from_env(ENV_TOKEN, ENV_TLS_CA) else {
        println!("[kop] {ENV_BROKERS}/{ENV_TOKEN} 未设置，跳过");
        return;
    };
    let tls = ctx.tls.is_some();
    let written = produce_then_read_back(&ctx, "kop-rskafka").await.unwrap_or_else(|e| panic!("{e}"));
    println!("[kop] brokers={:?} topic={} tls={tls} 写入并读回 {}", ctx.brokers, ctx.topic, written.len());
    for (partition, offset, value) in &written {
        println!("[kop]   p{partition}@{offset} {}", &value[..value.len().min(60)]);
    }
    assert_eq!(written.len(), usize::try_from(ctx.partitions).unwrap_or(0));
}

/// **(b) 负例：错误 token 必须写不进去**（KoP 在 SASL 阶段即拒绝）。
#[tokio::test]
#[ignore = "需要真实 KoP（AGF_E2E_KOP_BROKERS）"]
async fn rskafka_produce_with_a_bad_token_is_rejected() {
    let Some(mut ctx) = KopContext::from_env(ENV_TOKEN, ENV_TLS_CA) else {
        println!("[kop] {ENV_BROKERS}/{ENV_TOKEN} 未设置，跳过");
        return;
    };
    assert!(ctx.password.len() > 8, "token 过短，无法构造负例");
    let mut bad = ctx.password.clone();
    bad.replace_range(bad.len() - 6.., "AAAAAA");
    ctx.password = bad;
    let outcome = produce_then_read_back(&ctx, "kop-bad-token").await;
    let error = match outcome {
        Ok(_) => panic!("错误 token 竟然写入成功"),
        Err(e) => e,
    };
    println!("[kop] 错误 token 被拒（预期）：{error}");
}

/// **(c) 负例：未授权角色必须被拒**（`authorizationEnabled=true` 时用；token 有效但 ACL 不给）。
#[tokio::test]
#[ignore = "需要真实 KoP + authorizationEnabled=true（AGF_E2E_KOP_DENIED_TOKEN）"]
async fn rskafka_produce_with_an_unauthorized_role_is_rejected() {
    let Some(ctx) = KopContext::from_env(ENV_DENIED_TOKEN, ENV_TLS_CA) else {
        println!("[kop] {ENV_DENIED_TOKEN} 未设置，跳过");
        return;
    };
    let outcome = produce_then_read_back(&ctx, "kop-denied-role").await;
    let error = match outcome {
        Ok(_) => panic!("未授权角色竟然写入成功"),
        Err(e) => e,
    };
    println!("[kop] 未授权角色被拒（预期）：{error}");
}

/// **(d) 负例：错 CA 必须在 TLS 握手阶段失败**（服务端证书链校验不通过）。
#[tokio::test]
#[ignore = "需要真实 KoP + SASL_SSL（AGF_E2E_KOP_BAD_CA）"]
async fn rskafka_produce_with_a_wrong_ca_fails_the_handshake() {
    if env_value(ENV_BAD_CA).is_none() {
        println!("[kop] {ENV_BAD_CA} 未设置，跳过");
        return;
    }
    let Some(ctx) = KopContext::from_env(ENV_TOKEN, ENV_BAD_CA) else {
        println!("[kop] {ENV_BAD_CA} 未设置，跳过");
        return;
    };
    assert!(ctx.tls.is_some(), "{ENV_BAD_CA} 只用于 TLS 负例");
    let outcome = produce_then_read_back(&ctx, "kop-wrong-ca").await;
    let error = match outcome {
        Ok(_) => panic!("错 CA 竟然握手成功"),
        Err(e) => e,
    };
    println!("[kop] 错 CA 握手失败（预期）：{error}");
    assert!(
        error.to_lowercase().contains("certificate")
            || error.to_lowercase().contains("tls")
            || error.to_lowercase().contains("handshake")
            || error.to_lowercase().contains("unknown issuer")
            || error.to_lowercase().contains("invalid peer"),
        "失败原因必须指向证书/TLS：{error}"
    );
}

/// **(e) 正例：start_from 解析在 KoP 上也走通**（`earliest` / `latest` 都能定位）。
#[tokio::test]
#[ignore = "需要真实 KoP（AGF_E2E_KOP_BROKERS）"]
async fn rskafka_resolves_earliest_and_latest_offsets_on_kop() {
    let Some(ctx) = KopContext::from_env(ENV_TOKEN, ENV_TLS_CA) else {
        println!("[kop] {ENV_BROKERS}/{ENV_TOKEN} 未设置，跳过");
        return;
    };
    let source = RskafkaSource::connect(ctx.brokers.clone(), "agf-e2e-offsets", &ctx.security())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let earliest =
        source.resolve_offset(&ctx.topic, 0, KafkaStartFrom::Earliest).await.unwrap_or_else(|e| panic!("{e}"));
    let latest = source.resolve_offset(&ctx.topic, 0, KafkaStartFrom::Latest).await.unwrap_or_else(|e| panic!("{e}"));
    println!("[kop] topic={} p0 earliest={earliest} latest={latest}", ctx.topic);
    assert!(earliest >= 0 && latest >= earliest, "earliest/latest 必须单调：{earliest} / {latest}");
}
