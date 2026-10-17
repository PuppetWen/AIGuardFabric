//! 可直接部署的采集循环：真实上报、持久化重试队列、Ctrl+C 优雅退出。
use agf_agent::client::{AgentTransport, TlsTransport};
use agf_agent::queue::{LocalQueue, QueueConfig};
use agf_agent::{AgentIdentity, ClientConfig, CollectContext, PayloadKind, collect_all};
use clap::Args;
use secrecy::ExposeSecret;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub(super) struct RunArgs {
    /// 只采集并上报一次；失败返回非零退出码，载荷保留在队列中。
    #[arg(long)]
    once: bool,
    /// 服务端基址，例如 https://agf.example.com（凭据通过 AGF_AGENT_TOKEN 设置）。
    #[arg(long)]
    server: Option<String>,
    /// 要采集的用户目录；不指定时使用当前用户。
    #[arg(long)]
    home: Option<PathBuf>,
    /// 身份和断线队列存储目录。
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// 关闭进程与端口采集。
    #[arg(long)]
    no_system_probes: bool,
    /// 采集与上报间隔，至少 10 秒。
    #[arg(long, default_value_t = 60)]
    interval: u64,
}

pub(super) async fn run(args: RunArgs) -> anyhow::Result<()> {
    if args.interval < 10 {
        anyhow::bail!("--interval 至少为 10 秒");
    }
    agf_agent::selfupdate::arm_update_watchdog()?;
    let mut context = CollectContext::for_current_user();
    if let Some(home) = args.home {
        context = context.with_home(home);
    }
    if let Some(dir) = args.data_dir {
        context = context.with_data_dir(dir);
    }
    if args.no_system_probes {
        context = context.without_system_probes();
    }
    let identity = AgentIdentity::from_env(&context.data_dir)?;
    let mut config = ClientConfig::from_env();
    if let Some(server) = args.server {
        config.server_url = Some(server);
    }
    if config.mock {
        anyhow::bail!("run 执行真实上报，请将 AGF_MOCK_MODE 设置为 0；离线预览使用 collect");
    }
    let base = config
        .server_url
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("请提供 --server 或 AGF_AGENT_SERVER_URL"))?;
    let endpoint = format!("{}/api/v1/ingest/agent", base.trim_end_matches('/'));
    let authenticated_health = base.starts_with("https://")
        && !config.tls.insecure_skip_verify
        && (config.token.as_ref().is_some_and(|token| !token.expose_secret().is_empty())
            || config.tls.has_client_cert());
    if std::env::var_os("AGF_UPDATE_TRANSACTION").is_some() && !authenticated_health {
        anyhow::bail!("Supervised update health requires verified HTTPS and an enrolled token or mTLS identity");
    }
    let mut transport = TlsTransport::from_config(&config.tls, Some(base))?.with_agent_id(identity.agent_id.clone());
    if let Some(token) = config.token {
        transport = transport.with_token(token.expose_secret().to_owned());
    }
    let queue_config = QueueConfig::default().with_path(context.data_dir.join("uplink-queue.jsonl"));
    let mut queue = LocalQueue::load(queue_config)?;
    loop {
        let snapshot = collect_all(&identity, &context);
        let payload = serde_json::json!({
            "agent_id": identity.agent_id, "hostname": identity.hostname,
            "report": snapshot.payload.report,
            "extras": snapshot.payload.extras,
        });
        let body = serde_json::to_string(&payload)?;
        let id = identity.idempotency_key(PayloadKind::Snapshot, &body)?;
        let outcome = queue.push_payload(PayloadKind::Snapshot, &id, &body);
        queue.save()?;
        if matches!(outcome, agf_agent::queue::PushOutcome::Evicted(_)) {
            tracing::warn!("断线队列达到容量，旧快照已按容量策略淘汰");
        }
        let mut failure = None;
        // 大载荷可能被队列容量策略直接淘汰；空队列本身不能证明平台已接收新版本快照。
        let mut current_delivered = false;
        while let Some(entry) = queue.peek().cloned() {
            match transport.send(&endpoint, &entry.body) {
                Ok(()) => {
                    queue.mark_delivered(&entry.idempotency_key);
                    queue.save()?;
                    current_delivered |= entry.idempotency_key == id;
                }
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        if let Some(error) = failure {
            tracing::warn!(remaining = queue.len(), error = %error, "上报失败，队列已保留，下一周期重试");
            if args.once {
                return Err(error.into());
            }
        } else {
            if authenticated_health && current_delivered {
                agf_agent::selfupdate::acknowledge_platform_heartbeat()?;
            }
            println!("已上报：agent={} host={} queue={}", identity.agent_id, identity.hostname, queue.len());
        }
        if args.once {
            return Ok(());
        }
        tokio::select! {
            () = tokio::time::sleep(std::time::Duration::from_secs(args.interval)) => {}
            result = tokio::signal::ctrl_c() => {
                result?;
                queue.save()?;
                return Ok(());
            }
        }
    }
}
