//! 持久化本地 MCP 决策日志及已认证平台的检查点确认。
use agf_core::{
    audit::{
        AgentAuditAcknowledgement, AgentAuditBatch, AuditAction, AuditActor, AuditChainKind, AuditLog, AuditOutcome,
        AuditTarget, verify_agent_segment,
    },
    ids::Id,
    time::Timestamp,
};
use reqwest::{Client, header::HeaderValue};
use serde_json::{Value, json};
use std::path::Path;
use tokio::sync::Mutex;

#[cfg(test)]
use agf_core::audit::SignedAuditAnchor;

mod journal;
use journal::Journal;

/// 已认证的追加客户端；绝不接收或伪造平台签名密钥。
pub struct AgentAuditClient {
    client: Client,
    endpoint: String,
    token: HeaderValue,
    journal: Mutex<Journal>,
}
impl std::fmt::Debug for AgentAuditClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("AgentAuditClient").field("credentials", &"<redacted>").finish_non_exhaustive()
    }
}
impl AgentAuditClient {
    /// 打开持久日志，禁止第二个代理并发占用同一本地审计链。
    ///
    /// # Errors
    /// 目录归属、文件边界、系统锁或已保存链的校验失败。
    pub fn open(client: Client, endpoint: String, token: HeaderValue, data_dir: &Path) -> anyhow::Result<Self> {
        let url = reqwest::Url::parse(&endpoint)?;
        let loopback =
            url.host_str().and_then(|host| host.parse::<std::net::IpAddr>().ok()).is_some_and(|ip| ip.is_loopback());
        anyhow::ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && (url.scheme() == "https" || (url.scheme() == "http" && loopback)),
            "Audit ACK requires authenticated HTTPS, or a literal loopback test server"
        );
        // 每个数据目录及服务端仅绑定一个 Agent；更换凭据绑定时，依据
        // 保留的签名见证拒绝身份变化，不静默创建新链。
        let namespace = agf_core::secret::content_hash(&endpoint);
        Ok(Self { client, endpoint, token, journal: Mutex::new(Journal::open(data_dir, &namespace)?) })
    }

    /// 初始化实际身份，或先重放待确认记录，再接受新的 MCP 输入。
    ///
    /// # Errors
    /// 已认证平台不可用、拒绝该链，或无法给出持久化确认。
    pub async fn resume(&self) -> anyhow::Result<()> {
        let mut journal = self.journal.lock().await;
        self.flush(&mut journal).await
    }

    /// 将真实 HTTP、传输或协议失败记录为本地拒绝的门控结果。
    ///
    /// # Errors
    /// 本地日志或平台确认不可用，继续禁止转发。
    pub async fn record_failure(
        &self,
        frame: &Value,
        response: bool,
        session: &str,
        status: Option<u16>,
    ) -> anyhow::Result<()> {
        self.record(
            frame,
            response,
            session,
            &json!({"allowed":false,"frame":null,"local_transport_failure":true,"http_status":status}),
        )
        .await
    }

    /// 仅以帧摘要记录真实策略响应，然后取得并持久化确认。
    /// 审计记录不写入原始提示词、凭据、参数或响应正文。
    ///
    /// # Errors
    /// 本地持久化、策略结果校验或平台持久化确认失败。
    pub async fn record(&self, frame: &Value, response: bool, session: &str, decision: &Value) -> anyhow::Result<()> {
        let mut journal = self.journal.lock().await;
        self.flush(&mut journal).await?;
        let previous =
            journal.state.ack.as_ref().ok_or_else(|| anyhow::anyhow!("Audit identity was not bootstrapped"))?;
        let agent = previous.agent_id.ok_or_else(|| anyhow::anyhow!("Audit ACK is not Agent-bound"))?;
        let mut actor = AuditActor::system("agf-agent-mcp");
        actor.id = Some(agent);
        actor.kind = "agent".into();
        actor.session_id = Some(session.to_owned());
        let allowed = decision
            .get("allowed")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow::anyhow!("Policy response has no boolean decision"))?;
        let mut entry = AuditLog {
            id: Id::new(),
            tenant_id: previous.anchor.tenant_id,
            sequence: previous
                .anchor
                .up_to_sequence
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("Audit sequence exhausted"))?,
            action: AuditAction::Execute,
            outcome: if allowed { AuditOutcome::Success } else { AuditOutcome::Denied },
            actor,
            target: AuditTarget::new("mcp-gate-result", None, None),
            before: None,
            after: Some(
                json!({"input_sha256":agf_core::secret::content_hash(&serde_json::to_string(frame)?),"response":response,"allowed":allowed,
                "forwarded_sha256":decision.get("frame").map(|value|agf_core::secret::content_hash(&value.to_string())),
                "local_transport_failure":decision.get("local_transport_failure").and_then(Value::as_bool).unwrap_or(false),
                "http_status":decision.get("http_status").and_then(Value::as_u64).filter(|value|*value<=599)}),
            ),
            changed_fields: Vec::new(),
            request_id: None,
            error: None,
            note: "Local MCP gate result; forwarding is permitted only after a durable audit ACK".into(),
            prev_hash: previous.anchor.tail_hash.clone(),
            entry_hash: String::new(),
            at: Timestamp::now(),
        };
        entry.seal();
        journal.state.pending.push(entry);
        journal.save()?;
        self.flush(&mut journal).await
    }

    async fn flush(&self, journal: &mut Journal) -> anyhow::Result<()> {
        if journal.state.ack.is_some() && journal.state.pending.is_empty() {
            return Ok(());
        }
        let batch = AgentAuditBatch {
            chain_id: journal.state.chain,
            previous: journal.state.ack.clone(),
            entries: journal.state.pending.clone(),
        };
        let mut reply =
            self.client.post(&self.endpoint).header("X-AGF-Key", self.token.clone()).json(&batch).send().await?;
        anyhow::ensure!(
            reply.status().is_success(),
            "Audit checkpoint rejected with HTTP {}; MCP frame was not forwarded",
            reply.status().as_u16()
        );
        let content_length = reply.content_length();
        anyhow::ensure!(content_length.is_none_or(|size| size <= 16 * 1024), "Audit ACK exceeds limit");
        let mut bytes = Vec::new();
        while let Some(chunk) = reply.chunk().await? {
            anyhow::ensure!(bytes.len().saturating_add(chunk.len()) <= 16 * 1024, "Audit ACK exceeds limit");
            bytes.extend_from_slice(&chunk);
        }
        let ack: AgentAuditAcknowledgement = serde_json::from_slice(&bytes)?;
        verify_ack(&batch, &ack)?;
        // 已认证 HTTPS 响应是 Agent 的信任通道；HMAC 校验保留在平台，
        // Agent 自行构造的公钥不能建立信任。
        let previous = journal.state.ack.replace(ack.checkpoint);
        let pending = std::mem::take(&mut journal.state.pending);
        if let Err(error) = journal.save() {
            journal.state.ack = previous;
            journal.state.pending = pending;
            return Err(error);
        }
        Ok(())
    }
}

fn verify_ack(batch: &AgentAuditBatch, ack: &AgentAuditAcknowledgement) -> anyhow::Result<()> {
    let checkpoint = &ack.checkpoint;
    let agent = checkpoint.agent_id.ok_or_else(|| anyhow::anyhow!("Unbound audit ACK"))?;
    checkpoint.validate_identity(checkpoint.anchor.tenant_id, AuditChainKind::AgentRuntime, Some(agent))?;
    anyhow::ensure!(
        ack.durable
            && checkpoint.chain_id == batch.chain_id
            && agf_core::audit::valid_hash(&checkpoint.anchor.signature),
        "Non-durable or malformed audit ACK"
    );
    let (sequence, hash) = if let Some(previous) = &batch.previous {
        anyhow::ensure!(
            previous.anchor.tenant_id == checkpoint.anchor.tenant_id && previous.agent_id == Some(agent),
            "Audit ACK identity changed"
        );
        verify_agent_segment(
            &batch.entries,
            previous.anchor.tenant_id,
            agent,
            previous.anchor.up_to_sequence,
            &previous.anchor.tail_hash,
        )?
    } else {
        anyhow::ensure!(batch.entries.is_empty(), "Initial audit ACK must bootstrap an empty chain");
        (0, agf_core::audit::GENESIS_HASH.to_owned())
    };
    anyhow::ensure!(
        checkpoint.anchor.up_to_sequence == sequence && checkpoint.anchor.tail_hash == hash,
        "Audit ACK covers different records"
    );
    checkpoint.follows(batch.previous.as_ref())?;
    Ok(())
}

#[cfg(test)]
mod tests;
