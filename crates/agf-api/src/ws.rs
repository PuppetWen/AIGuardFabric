//! WebSocket 事件推送（`GET /ws`）。
//!
//! - 订阅事件面（[`AppState::events`]：NATS 订阅回灌的帧，或进程内广播），按租户过滤后推送；
//! - 每 30 秒发一次心跳，客户端可回 `ping` 拿 `pong`；
//! - 事件源是**统一事件面**：`POST /scans`、发现导入、战役发起、策略热重载都会投递事件。
//!
//! ## 事件面：NATS 还是进程内广播（`AGF_NATS_ENABLED`）
//!
//! | `AGF_NATS_ENABLED` | 连接结果 | 发布路径 | `/ws` 收到事件的路径 | 多副本 |
//! |---|---|---|---|---|
//! | `0` | 不尝试连接 | 进程内广播 | 进程内广播 | 不互通（单机部署的既有行为） |
//! | `1` | 成功 | NATS 主题 `agf.ws.<tenant>.<kind>` | NATS 订阅 `agf.ws.>` → 回灌进程内广播 | **互通** |
//! | `1` | 失败 | 进程内广播 | 进程内广播 | 不互通（已在 `/readyz` 的 `notes` 里标注） |
//!
//! 装配顺序（[`NatsEventPlane::connect`]）：**先** `SUB agf.ws.>`，**再**启动发布泵，
//! 订阅到的帧按原样写回 [`AppState::events`] 广播，因此 `/ws` 的推送逻辑（心跳、`lagged`
//! 通知、租户过滤、superadmin 跨租户）与单机部署**完全一致**，只是事件的来源不同：
//! 本副本发布的事件也必须经 NATS 回到本副本，才会推给本地客户端——**事件真的过了 NATS**，
//! 不是"本地直发 + NATS 旁路"。可用 `agf_ws_nats_published_total`（发布入 NATS 的条数）
//! 与 `agf_ws_nats_received_total`（从 NATS 订阅回灌的条数）在 `/metrics` 上核对。
//!
//! ## 降级铁律（`TODO(api-ws-nats)` 的落地约定）
//!
//! 1. `AGF_NATS_ENABLED=1` 但 NATS 不可达/URL 非法/订阅失败：只 `warn` + 写 `notes`
//!    （`GET /readyz` 的 `notes` 字段可见），**自动退回进程内广播**：
//!    **不阻断启动、不让 `/ws` 不可用、不返回错误**；
//! 2. 运行期单条事件投递失败（连接抖动、发布队列满、序列化失败）：该条事件**立即退回
//!    进程内广播**（本副本的客户端照常收到，只是跨副本不可见），计入
//!    `agf_ws_local_fallback_total`；
//! 3. 订阅流结束（NATS 客户端关闭/不可恢复）：置降级位并 `warn`，此后所有事件走进程内广播。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::TenantId;
use agf_core::time::Timestamp;
use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::get;
use futures::{SinkExt, StreamExt};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::metrics::Metrics;
use crate::middleware::Principal;
use crate::state::{AppState, WsEvent};

/// 心跳间隔（秒）。
pub const HEARTBEAT_SECS: u64 = 30;

/// `/ws` 事件的 NATS 主题命名空间前缀（与接入侧 `agf.events.*` 分开，避免互相误解析）。
pub const NATS_SUBJECT_PREFIX: &str = "agf.ws";

/// NATS 发布队列容量（有界：满了就退回进程内广播，不做无界缓冲）。
pub const NATS_QUEUE_CAPACITY: usize = 1024;

/// NATS 连接超时（秒）：连不上时快速降级，不让启动卡在握手或重连上。
pub const NATS_CONNECT_TIMEOUT_SECS: u64 = 3;

/// WebSocket 路由。
pub fn router() -> Router<AppState> {
    Router::new().route("/ws", get(upgrade))
}

/// `/ws` 事件主题：`agf.ws.<tenant>.<kind>`（如 `agf.ws.<租户 UUID>.alert`）。
///
/// 租户名归一化**复用** [`agf_ingest::bus::subject_for`] 的既有规则（租户 id 里的 `.` 换成 `-`），
/// 只把命名空间由 `agf.events.` 换成 `agf.ws.`。为什么不直接复用返回的主题：
/// `NatsEventBus` 的主题是 `<租户>.<严重度>`，而 `/ws` 事件没有严重度、只有 `kind`，
/// 且必须与接入事件分流——否则订阅泵会把接入事件当成 WebSocket 事件解析。
#[must_use]
pub fn subject_for(tenant: TenantId, kind: &str) -> String {
    let base = agf_ingest::bus::subject_for(&tenant.to_string(), kind);
    match base.strip_prefix("agf.events.") {
        Some(rest) => format!("{NATS_SUBJECT_PREFIX}.{rest}"),
        // 上游命名规则变化时的自保分支：仍用同一条归一化规则自己拼主题。
        None => format!("{NATS_SUBJECT_PREFIX}.{}.{kind}", tenant.to_string().replace('.', "-")),
    }
}

/// `/ws` 订阅通配主题（`agf.ws.>`）：所有租户、所有 `kind`，租户过滤在推送侧做。
#[must_use]
pub fn wildcard_subject() -> String {
    format!("{NATS_SUBJECT_PREFIX}.>")
}

/// 待发布的一帧：主题 + 序列化载荷 + 原始事件（发布失败时退回进程内广播）。
#[derive(Debug)]
struct PendingFrame {
    /// NATS 主题。
    subject: String,
    /// 序列化后的 JSON 载荷。
    payload: bytes::Bytes,
    /// 原始事件（本地兜底投递用）。
    event: WsEvent,
}

/// NATS 事件面（`AGF_NATS_ENABLED=1` 且连接成功时装配）。
///
/// 一个副本只有一个 NATS 订阅（`agf.ws.>`）与一个发布泵：订阅到的帧统一回灌本副本的
/// 进程内广播，再由各 `/ws` 连接按租户过滤推送。这样 `/ws` 的连接数不影响 NATS 订阅数，
/// 也不会让"升级 WebSocket 时 NATS 抖动"变成"`/ws` 不可用"。
pub struct NatsEventPlane {
    /// 主题前缀（`agf.ws`）。
    prefix: String,
    /// 发布队列（有界；入队失败即退回进程内广播）。
    queue: mpsc::Sender<PendingFrame>,
    /// 降级位（订阅流结束、或订阅队列不可用时置位）。
    degraded: Arc<AtomicBool>,
    /// 成功交给 NATS 的条数。
    published: Arc<AtomicU64>,
    /// 从 NATS 订阅回灌进进程内广播的条数。
    received: Arc<AtomicU64>,
    /// 退回进程内广播的条数。
    fallback: Arc<AtomicU64>,
    /// 指标（`agf_ws_*` 计数与这里同一份）。
    metrics: Arc<Metrics>,
}

impl std::fmt::Debug for NatsEventPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatsEventPlane")
            .field("prefix", &self.prefix)
            .field("degraded", &self.is_degraded())
            .field("published", &self.published())
            .field("received", &self.received())
            .field("fallback", &self.fallback())
            .finish_non_exhaustive()
    }
}

impl NatsEventPlane {
    /// 连接 NATS，装配「订阅回灌 + 发布泵」。
    ///
    /// 调用方**必须**把错误当作可降级项：`warn` + 写 `notes` 后继续用进程内广播。
    ///
    /// # Errors
    /// URL 非法、服务器不可达、或订阅 `agf.ws.>` 失败（均返回
    /// [`DomainError::DependencyUnavailable`]）。
    pub async fn connect(
        url: &str,
        local: broadcast::Sender<WsEvent>,
        metrics: Arc<Metrics>,
    ) -> DomainResult<Arc<Self>> {
        // Shared URL authentication and redaction, retaining this plane's three-second bound.
        let client = agf_ingest::bus::connect_nats(&[url.to_string()], Duration::from_secs(NATS_CONNECT_TIMEOUT_SECS)).await?;
        let wildcard = wildcard_subject();
        let mut subscriber =
            client.subscribe(wildcard.clone()).await.map_err(|e| DomainError::DependencyUnavailable {
                dependency: "nats".to_string(),
                cause: format!("订阅 {wildcard} 失败: {e}"),
            })?;

        let (queue, mut pending) = mpsc::channel::<PendingFrame>(NATS_QUEUE_CAPACITY);
        let degraded = Arc::new(AtomicBool::new(false));
        let published = Arc::new(AtomicU64::new(0));
        let received = Arc::new(AtomicU64::new(0));
        let fallback = Arc::new(AtomicU64::new(0));

        // ---- 订阅回灌：NATS 帧 → 进程内广播（/ws 的推送逻辑一字未改）----
        let sub_local = local.clone();
        let sub_metrics = Arc::clone(&metrics);
        let sub_received = Arc::clone(&received);
        let sub_degraded = Arc::clone(&degraded);
        tokio::spawn(async move {
            while let Some(message) = subscriber.next().await {
                match serde_json::from_slice::<WsEvent>(&message.payload) {
                    Ok(event) => {
                        sub_received.fetch_add(1, Ordering::Relaxed);
                        sub_metrics.record_ws_nats_received();
                        // 没有 /ws 连接时广播无接收者：静默丢弃（与进程内广播语义一致）。
                        let _ = sub_local.send(event);
                    }
                    Err(error) => {
                        warn!(error = %error, subject = %message.subject, "NATS 上的 /ws 事件解析失败（已跳过该帧）");
                    }
                }
            }
            sub_degraded.store(true, Ordering::Relaxed);
            warn!("NATS 订阅流已结束：/ws 退回进程内广播（跨副本互通失效，请检查 NATS 可用性）");
        });

        // ---- 发布泵：进程内队列 → NATS（失败即本地兜底，绝不丢事件）----
        let pump_client = client.clone();
        let pump_local = local;
        let pump_metrics = Arc::clone(&metrics);
        let pump_published = Arc::clone(&published);
        let pump_fallback = Arc::clone(&fallback);
        let pump_degraded = Arc::clone(&degraded);
        tokio::spawn(async move {
            while let Some(frame) = pending.recv().await {
                let PendingFrame { subject, payload, event } = frame;
                if pump_degraded.load(Ordering::Relaxed) {
                    pump_fallback.fetch_add(1, Ordering::Relaxed);
                    pump_metrics.record_ws_local_fallback();
                    let _ = pump_local.send(event);
                    continue;
                }
                match pump_client.publish(subject.clone(), payload).await {
                    Ok(()) => {
                        pump_published.fetch_add(1, Ordering::Relaxed);
                        pump_metrics.record_ws_nats_published();
                    }
                    Err(error) => {
                        warn!(error = %error, subject = %subject, "NATS 发布失败：该事件退回进程内广播（跨副本不可见）");
                        pump_fallback.fetch_add(1, Ordering::Relaxed);
                        pump_metrics.record_ws_local_fallback();
                        let _ = pump_local.send(event);
                    }
                }
            }
            debug!("NATS 发布泵已退出（事件面关闭）");
        });

        info!(url, subject = %wildcard, "NATS /ws 事件面已连接：事件经 NATS 跨副本分发");
        Ok(Arc::new(Self {
            prefix: NATS_SUBJECT_PREFIX.to_string(),
            queue,
            degraded,
            published,
            received,
            fallback,
            metrics,
        }))
    }

    /// 事件面的主题前缀（`agf.ws`）。
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// 是否已降级（订阅流结束/发布队列不可用）。
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    /// 成功交给 NATS 的条数。
    #[must_use]
    pub fn published(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }

    /// 从 NATS 订阅回灌的条数（>0 即证明事件真的过了 NATS）。
    #[must_use]
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }

    /// 退回进程内广播的条数。
    #[must_use]
    pub fn fallback(&self) -> u64 {
        self.fallback.load(Ordering::Relaxed)
    }

    /// 同步入队（**非阻塞**）。
    ///
    /// 返回 `false` 表示本次**没有**交给 NATS（已降级 / 发布队列满 / 序列化失败），
    /// 调用方（[`AppState::publish`]）必须退回进程内广播，保证事件不丢。
    #[must_use]
    pub fn try_publish(&self, event: &WsEvent) -> bool {
        if self.is_degraded() {
            self.count_fallback();
            return false;
        }
        let payload = match serde_json::to_vec(event) {
            Ok(payload) => payload,
            Err(error) => {
                warn!(error = %error, "WsEvent 序列化失败：退回进程内广播");
                self.count_fallback();
                return false;
            }
        };
        let frame = PendingFrame {
            subject: subject_for(event.tenant_id, &event.kind),
            payload: payload.into(),
            event: event.clone(),
        };
        match self.queue.try_send(frame) {
            Ok(()) => true,
            Err(error) => {
                // 队列满属背压信号：只记 debug（避免刷屏），但计数与本地兜底必须做。
                debug!(error = %error, "NATS 发布队列已满：事件退回进程内广播");
                self.count_fallback();
                false
            }
        }
    }

    /// 记一次"退回进程内广播"（计数 + 指标），供 `try_publish` 与发布泵共用。
    fn count_fallback(&self) {
        self.fallback.fetch_add(1, Ordering::Relaxed);
        self.metrics.record_ws_local_fallback();
    }
}

async fn upgrade(State(state): State<AppState>, principal: Principal, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| serve(socket, state, principal))
}

async fn serve(socket: WebSocket, state: AppState, principal: Principal) {
    let tenant = principal.tenant;
    let superadmin = principal.superadmin;
    let (mut sender, mut receiver) = socket.split();
    let mut subscription = state.events.subscribe();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT_SECS));

    let hello = serde_json::json!({
        "kind": "hello",
        "tenant_id": tenant,
        "at": Timestamp::now(),
        "plane": state.event_plane_name(),
        "message": "已订阅事件流；30 秒心跳，发送 ping 可获 pong",
    });
    if sender.send(Message::Text(hello.to_string().into())).await.is_err() {
        return;
    }

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                let beat = serde_json::json!({
                    "kind": "heartbeat",
                    "tenant_id": tenant,
                    "at": Timestamp::now(),
                });
                if sender.send(Message::Text(beat.to_string().into())).await.is_err() {
                    break;
                }
            }
            received = subscription.recv() => match received {
                Ok(event) => {
                    if event.tenant_id != tenant && !superadmin {
                        continue;
                    }
                    let text = serde_json::to_string(&event).unwrap_or_else(|_| "{\"kind\":\"error\"}".to_string());
                    if sender.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Lagged(skipped)) => {
                    let notice = serde_json::json!({
                        "kind": "lagged",
                        "tenant_id": tenant,
                        "at": Timestamp::now(),
                        "skipped": skipped,
                    });
                    if sender.send(Message::Text(notice.to_string().into())).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Closed) => break,
            },
            incoming = receiver.next() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    if text.as_str().trim().eq_ignore_ascii_case("ping") {
                        let pong = serde_json::json!({"kind": "pong", "at": Timestamp::now()});
                        if sender.send(Message::Text(pong.to_string().into())).await.is_err() {
                            break;
                        }
                    }
                }
                Some(Ok(Message::Ping(payload))) => {
                    if sender.send(Message::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
            },
        }
    }
}
