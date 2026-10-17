//! MCP stdio 代理：逐帧执行服务端策略，服务不可达时拒绝转发。
use clap::Args;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use std::{collections::BTreeMap, process::Stdio, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    sync::Mutex,
};

const MAX_FRAME: u64 = 4 * 1024 * 1024;

#[cfg(test)]
mod tests;
#[derive(Debug, Args)]
pub(super) struct ProxyArgs {
    /// AIGuardFabric 服务端基址；也可用 AGF_AGENT_SERVER_URL。
    #[arg(long)]
    server: Option<String>,
    /// 上游 MCP 的可执行文件及参数，例如 -- node server.js。
    #[arg(last = true, required = true)]
    command: Vec<String>,
}
struct Guard {
    client: reqwest::Client,
    endpoint: String,
    token: reqwest::header::HeaderValue,
    session: String,
    leases: Mutex<BTreeMap<String, Value>>,
    audit: agf_agent::audit_anchor::AgentAuditClient,
}
impl Guard {
    fn new(server: Option<String>) -> anyhow::Result<Self> {
        let config = agf_agent::ClientConfig::from_env();
        let base =
            server.or(config.server_url).ok_or_else(|| anyhow::anyhow!("请设置 AGF_AGENT_SERVER_URL 或 --server"))?;
        let url = reqwest::Url::parse(&base)?;
        anyhow::ensure!(
            ["https", "http"].contains(&url.scheme()) && url.username().is_empty() && url.password().is_none(),
            "服务端基址必须为无凭据的 HTTP(S) URL"
        );
        let token = config.token.ok_or_else(|| anyhow::anyhow!("请设置具有 policies:read 权限的 AGF_AGENT_TOKEN"))?;
        let mut header = reqwest::header::HeaderValue::from_str(token.expose_secret())?;
        header.set_sensitive(true);
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(20));
        if let Some(path) = config.tls.ca_pem {
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(path)?)?);
        }
        anyhow::ensure!(
            config.tls.client_cert_pem.is_some() == config.tls.client_key_pem.is_some(),
            "客户端 TLS 证书和私钥必须同时配置"
        );
        if let (Some(cert), Some(key)) = (config.tls.client_cert_pem, config.tls.client_key_pem) {
            let mut pem = std::fs::read(cert)?;
            pem.push(b'\n');
            pem.extend(std::fs::read(key)?);
            builder = builder.identity(reqwest::Identity::from_pem(&pem)?);
        }
        let client = builder.build()?;
        let data_dir =
            std::env::var_os("AGF_DATA_DIR").map_or_else(|| std::path::PathBuf::from("data"), std::path::PathBuf::from);
        let audit = agf_agent::audit_anchor::AgentAuditClient::open(
            client.clone(),
            format!("{}/api/v1/runtime/audit/anchors", base.trim_end_matches('/')),
            header.clone(),
            &data_dir,
        )?;
        Ok(Self {
            client,
            endpoint: format!("{}/api/v1/runtime/mcp/check", base.trim_end_matches('/')),
            token: header,
            session: agf_core::ids::Id::new().to_string(),
            leases: Mutex::new(BTreeMap::new()),
            audit,
        })
    }
    async fn check(&self, frame: &Value, response: bool) -> anyhow::Result<Value> {
        let response_frame = response && frame.get("method").is_none();
        let key = frame.get("id").filter(|id| !id.is_null()).map(Value::to_string);
        if !response && frame["method"] == "tools/call" {
            let key = key.as_ref().ok_or_else(|| anyhow::anyhow!("tools/call 必须包含非空请求 id"))?;
            anyhow::ensure!(!self.leases.lock().await.contains_key(key), "请求 id 正在使用，请等待上次调用完成");
        }
        let mut body = json!({"frame":frame,"session_id":self.session,"response":response});
        if response_frame {
            if let Some(key) = &key {
                body["lease_id"] = self.leases.lock().await.get(key).cloned().unwrap_or(Value::Null);
            }
        }
        let reply =
            match self.client.post(&self.endpoint).header("X-AGF-Key", self.token.clone()).json(&body).send().await {
                Ok(reply) => reply,
                Err(error) => {
                    let _ = self.audit.record_failure(frame, response, &self.session, None).await;
                    return Err(error.into());
                }
            };
        if !reply.status().is_success() {
            let status = reply.status().as_u16();
            self.audit.record_failure(frame, response, &self.session, Some(status)).await?;
            anyhow::bail!("策略服务返回 HTTP {status}，当前帧未转发");
        }
        let value: Value = match reply.json().await {
            Ok(value) => value,
            Err(error) => {
                let _ = self.audit.record_failure(frame, response, &self.session, Some(200)).await;
                return Err(error.into());
            }
        };
        if !value.get("allowed").is_some_and(Value::is_boolean) {
            self.audit.record_failure(frame, response, &self.session, Some(200)).await?;
            anyhow::bail!("策略服务返回无效决策，当前帧未转发");
        }
        if let Err(error) = self.audit.record(frame, response, &self.session, &value).await {
            if let Some(lease) = value.get("lease_id").filter(|lease| !lease.is_null()) {
                if !self.settle_lease(lease).await {
                    if let Some(key) = &key {
                        self.leases.lock().await.insert(key.clone(), lease.clone());
                    }
                }
            }
            return Err(error);
        }
        let valid_frame = value.get("frame").filter(|frame| frame.is_object() && frame["jsonrpc"] == "2.0");
        if value["allowed"] != true || valid_frame.is_none() {
            // 服务端可能已经为 tools/call 预留并发配额；即使响应损坏也要尽快归还。
            if !response && frame["method"] == "tools/call" {
                if let (Some(key), Some(lease)) = (key.as_ref(), value.get("lease_id").filter(|lease| !lease.is_null()))
                {
                    if !self.settle_lease(lease).await {
                        self.leases.lock().await.insert(key.clone(), lease.clone());
                    }
                }
            }
        }
        anyhow::ensure!(value["allowed"] == true, "{}", value["reason"].as_str().unwrap_or("策略拒绝该请求"));
        let forwarded = valid_frame.cloned().ok_or_else(|| anyhow::anyhow!("策略服务未返回有效 JSON-RPC 帧"))?;
        if let Some(key) = key {
            if response_frame {
                self.leases.lock().await.remove(&key);
            } else if !response && frame["method"] == "tools/call" {
                if let Some(lease) = value.get("lease_id").filter(|lease| !lease.is_null()) {
                    self.leases.lock().await.insert(key, lease.clone());
                }
            }
        }
        Ok(forwarded)
    }
    async fn settle_lease(&self, lease: &Value) -> bool {
        let result = self
            .client
            .post(&self.endpoint)
            .header("X-AGF-Key", self.token.clone())
            .json(&json!({"frame":null,"session_id":self.session,"lease_id":lease,"finished":true}))
            .send()
            .await;
        matches!(result, Ok(reply) if reply.status().is_success())
    }
    async fn finish(&self) {
        let pending = std::mem::take(&mut *self.leases.lock().await);
        for (_, lease) in pending {
            if !self.settle_lease(&lease).await {
                tracing::warn!("MCP 调用结算未确认，服务端将在租约到期后回收并发额度");
            }
        }
    }
}
async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> anyhow::Result<Option<Value>> {
    let mut buffer = Vec::new();
    let count = reader.take(MAX_FRAME + 1).read_until(b'\n', &mut buffer).await?;
    if count == 0 {
        return Ok(None);
    }
    anyhow::ensure!(count as u64 <= MAX_FRAME, "MCP 帧超过 4 MiB");
    let value: Value = serde_json::from_slice(&buffer)?;
    anyhow::ensure!(value["jsonrpc"] == "2.0", "仅支持 JSON-RPC 2.0");
    Ok(Some(value))
}
async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, value: &Value) -> anyhow::Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}
fn rejected(frame: &Value, error: &anyhow::Error) -> Option<Value> {
    frame
        .get("id")
        .map(|id| json!({"jsonrpc":"2.0","id":id,"error":{"code":-32003,"message":format!("AIGuardFabric: {error}")}}))
}
pub(super) async fn run(args: ProxyArgs) -> anyhow::Result<()> {
    let guard = Arc::new(Guard::new(args.server)?);
    guard.audit.resume().await?;
    let program = args.command.first().ok_or_else(|| anyhow::anyhow!("缺少上游 MCP 命令"))?;
    let mut command = tokio::process::Command::new(program);
    command
        .args(&args.command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .env_remove("AGF_AGENT_TOKEN");
    #[cfg(windows)]
    command.creation_flags(0x0800_0000);
    let mut child = command.spawn()?;
    let mut upstream = child.stdin.take().ok_or_else(|| anyhow::anyhow!("无法打开 MCP 标准输入"))?;
    let child_stdout = child.stdout.take().ok_or_else(|| anyhow::anyhow!("无法打开 MCP 标准输出"))?;
    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));
    let output_guard = guard.clone();
    let output = stdout.clone();
    let mut reader_task = tokio::spawn(async move {
        let mut reader = BufReader::new(child_stdout);
        while let Some(frame) = read_frame(&mut reader).await? {
            let result = match output_guard.check(&frame, true).await {
                Ok(value) => Some(value),
                Err(error) => rejected(&frame, &error),
            };
            if let Some(value) = result {
                write_frame(&mut *output.lock().await, &value).await?;
            }
        }
        Ok::<(), anyhow::Error>(())
    });
    let input_loop = async {
        let mut reader = BufReader::new(tokio::io::stdin());
        while let Some(frame) = read_frame(&mut reader).await? {
            match guard.check(&frame, false).await {
                Ok(value) => write_frame(&mut upstream, &value).await?,
                Err(error) => {
                    tracing::warn!(error = %error, "MCP 请求被拒绝");
                    if let Some(value) = rejected(&frame, &error) {
                        write_frame(&mut *stdout.lock().await, &value).await?;
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let result = tokio::select! {
        result = input_loop => {
            // 关闭输入后让上游完成待处理响应，避免短生命周期客户端丢失最后一帧。
            drop(upstream);
            match result {
                Err(error) => Err(error),
                Ok(()) => match tokio::time::timeout(std::time::Duration::from_secs(30), &mut reader_task).await {
                    Ok(joined) => joined?,
                    Err(_) => Err(anyhow::anyhow!("上游未在关闭输入后 30 秒内退出")),
                },
            }
        },
        result = &mut reader_task => result?,
        result = tokio::signal::ctrl_c() => result.map_err(Into::into),
    };
    reader_task.abort();
    let _ = child.kill().await;
    guard.finish().await;
    result
}
