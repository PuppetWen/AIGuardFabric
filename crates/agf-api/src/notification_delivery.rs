//! 连接通知策略派发器与已实现的厂商协议，并将回执持久化。
use crate::{
    config_store::ConfigStore,
    notification_config::{self as config, PrivateConfig, StoredChannel},
    state::AppState,
};
use agf_adapters::contract::{AdapterMessage, VendorAdapter};
use agf_core::{
    enums::Severity,
    error::DomainResult,
    ids::{Id, TenantId, deterministic_id},
    notify::ChannelKind,
    time::Timestamp,
};
use agf_correlate::notify::{ChannelReceipt, NotificationChannel, OutboundMessage};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;

struct Channel {
    kind: ChannelKind,
    adapter: Option<Mutex<Box<dyn VendorAdapter>>>,
    private: PrivateConfig,
    mock: bool,
    store: Arc<ConfigStore>,
}
impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel").field("kind", &self.kind).field("mocked", &self.mock).finish_non_exhaustive()
    }
}
#[async_trait::async_trait]
impl NotificationChannel for Channel {
    fn kind(&self) -> ChannelKind {
        self.kind
    }
    async fn send(&self, msg: &OutboundMessage) -> Result<ChannelReceipt, String> {
        if self.kind == ChannelKind::InApp {
            self.store
                .put(
                    msg.tenant_id,
                    "notification-inbox",
                    deterministic_id("agf.notification-inbox", &msg.dedup_key),
                    msg,
                )
                .await
                .map_err(|e| e.to_string())?;
            return Ok(receipt("站内消息已保存", None));
        }
        if let Some(adapter) = &self.adapter {
            let mut payload = AdapterMessage::notification(&msg.title, &msg.body).with_severity(msg.severity);
            payload.idempotency_key.clone_from(&msg.dedup_key);
            payload.occurred_at = msg.at;
            let reply = adapter
                .lock()
                .await
                .send(&payload)
                .await
                .map_err(|_| "通知服务拒绝请求或无法连接；请检查渠道参数、凭据及网络".to_string())?;
            if !reply.accepted {
                return Err("通知服务未接受消息".into());
            }
            return Ok(receipt(
                if reply.mocked { "模拟投递，未发送到外部系统" } else { "通知服务已接受" },
                reply.remote_id,
            ));
        }
        if self.mock {
            return Ok(receipt("模拟投递，未发送到外部系统", Some(format!("mock-{}", msg.channel_id))));
        }
        let endpoint = self
            .private
            .settings
            .get("endpoint")
            .and_then(Value::as_str)
            .unwrap_or("https://events.pagerduty.com/v2/enqueue");
        let payload = if self.kind == ChannelKind::PagerDuty {
            json!({"routing_key":self.private.secrets.get("routing_key"),"event_action":"trigger","dedup_key":msg.dedup_key,
                "payload":{"summary":msg.title,"source":"AIGuardFabric","severity":match msg.severity {
                    Severity::Critical => "critical", Severity::High => "error", Severity::Medium => "warning", _ => "info" },
                    "custom_details":{"body":msg.body,"tenant":msg.tenant_id}}})
        } else {
            // 企业 HTTP 短信网关协议，原生云短信厂商可由内部网关转换。
            json!({"to":self.private.target.split([',',';']).map(str::trim).filter(|v| !v.is_empty()).collect::<Vec<_>>(),
                "text":format!("{}\n{}", msg.title, msg.body),"idempotency_key":msg.dedup_key})
        };
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|_| "无法初始化通知 HTTP 客户端".to_string())?;
        let mut request = client.post(endpoint).json(&payload);
        if let Some(token) = self.private.secrets.get("token") {
            request = request.bearer_auth(token);
        }
        let mut response = request.send().await.map_err(|_| "通知 HTTP 服务不可达或 TLS 验证失败".to_string())?;
        if !response.status().is_success() {
            return Err(format!("通知服务返回 HTTP {}", response.status().as_u16()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "读取通知回执失败".to_string())? {
            if bytes.len() + chunk.len() > 65536 {
                return Err("通知回执超过 64 KiB".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| "通知服务必须返回 JSON 回执".to_string())?;
        let accepted =
            if self.kind == ChannelKind::PagerDuty { value["status"] == "success" } else { value["accepted"] == true };
        if !accepted {
            return Err("通知服务业务回执未确认成功".into());
        }
        Ok(receipt(
            "通知服务已接受",
            value.get("dedup_key").or_else(|| value.get("id")).and_then(Value::as_str).map(str::to_string),
        ))
    }
}
fn receipt(detail: &str, external_id: Option<String>) -> ChannelReceipt {
    ChannelReceipt { external_id, detail: detail.into(), accepted_at: Timestamp::now() }
}
pub async fn dispatch(
    state: &AppState,
    tenant: TenantId,
    rows: Vec<StoredChannel>,
    subject: &str,
    subject_id: Id,
    title: &str,
    body: &str,
    severity: Severity,
) -> DomainResult<Value> {
    let ids =
        crate::notification_outbox::enqueue(state, tenant, rows, subject, subject_id, title, body, severity).await?;
    let mut deliveries = Vec::new();
    for id in ids {
        deliveries.push(crate::notification_outbox::attempt(state, tenant, id, Timestamp::now()).await?);
    }
    let delivered = deliveries.iter().filter(|row| row["outcome"] == "delivered").count();
    Ok(json!({"delivered_count":delivered,"any_delivered":delivered > 0,"deliveries":deliveries,
        "mocked":state.config.mock_mode,"note":if state.config.mock_mode {"外部渠道为模拟投递；站内消息已保存"} else {"以各渠道实际回执为准"}}))
}

/// One bounded network attempt. Persistent retry and concurrency are owned by the outbox.
pub(crate) async fn send_one(
    state: &AppState,
    tenant: TenantId,
    row: &StoredChannel,
    message: &OutboundMessage,
) -> Result<ChannelReceipt, String> {
    let private = config::decrypt(state, tenant, row).map_err(|_| "无法解密通知渠道配置".to_string())?;
    let adapter = if matches!(row.channel, ChannelKind::Sms | ChannelKind::PagerDuty | ChannelKind::InApp) {
        None
    } else {
        Some(Mutex::new(
            config::adapter(state, tenant, row.channel, &private).map_err(|_| "通知渠道配置无效".to_string())?,
        ))
    };
    let channel = Channel {
        kind: row.channel,
        adapter,
        private,
        mock: state.config.mock_mode,
        store: state.configurations.clone(),
    };
    channel.send(message).await
}
