//! OTLP/HTTP 导出层装配（原 `metrics.rs` 内联 `pub mod otel`，拆为独立文件，逻辑未变）。

//! OTLP 链路导出装配（`TODO(server-otlp)`）。
//!
//! **门控**：`AGF_OTLP_ENDPOINT` 非空即启用；未设置时，仅当 `AGF_OTEL_ENABLED=1`
//! 且 `AGF_OTEL_ENDPOINT` 非空才启用；两者都不满足 → [`resolve_otlp_endpoint`] 返回 `None`，
//! 调用方按既有方式初始化 `tracing`（**零开销、无副作用**：不建导出器、不起后台线程、
//! 不发任何网络请求）。
//!
//! **降级**：端点非法、导出器构建失败只由调用方 `warn` 并继续本地输出；
//! 运行期导出失败由 OTLP SDK 在后台吞掉（批处理 + 超时），**不影响任何请求路径**。
//!
//! 为什么装配放在 `agf-api` 而不是 `apps/server`：`opentelemetry*` 依赖声明在本 crate，
//! 二进制入口只通过 [`build`] / [`resolve_otlp_endpoint`] 使用，避免二进制被迫了解
//! exporter 类型与版本细节。

use std::time::Duration;

use agf_core::config::AppConfig;
use agf_core::error::{DomainError, DomainResult};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{SpanExporter, WithExportConfig as _, WithHttpConfig as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::Registry;
use tracing_subscriber::registry::LookupSpan;

/// OTLP 导出超时（秒）：collector 不可达时不拖住导出线程。
pub const EXPORT_TIMEOUT_SECS: u64 = 5;

/// OTLP/HTTP 的 traces 信号路径（端点只给 host:port 时必须补上）。
pub const TRACES_SIGNAL_PATH: &str = "/v1/traces";

/// 装配好的 tracing 层类型（`S` 是它要挂载到的订阅者栈，交给 `with(...)` 时自动对齐）。
///
/// `OpenTelemetryLayer<S, T>` 的 `Layer<S>` 实现要求**同一个 `S`**：
/// 它只能挂到类型参数与之相同的订阅者上，因此这里是泛型别名而不是固定 `Registry`
/// （固定 `Registry` 时无法挂到 `Layered<EnvFilter, Registry>` 上）。
pub type OtlpLayer<S> = OpenTelemetryLayer<S, SdkTracer>;

/// provider 保活句柄：**必须活到进程退出**，并在退出前 [`Self::shutdown`] 以冲刷批次。
///
/// 丢弃句柄会停止导出线程；`std::process::exit` 不会跑析构，所以调用方要显式关闭。
#[derive(Debug)]
pub struct OtlpKeepAlive {
    provider: SdkTracerProvider,
}

impl OtlpKeepAlive {
    /// 冲刷未发送的 span 并关闭 provider（失败只记 `warn`，不影响退出码）。
    pub fn shutdown(&self) {
        if let Err(error) = self.provider.shutdown() {
            tracing::warn!(error = %error, "OTLP provider 关闭失败（进程退出码不受影响）");
        }
    }

    /// 冲刷未发送的 span（不关闭）。
    ///
    /// # Errors
    /// 导出器仍在推进或冲刷超时。
    pub fn force_flush(&self) -> DomainResult<()> {
        self.provider
            .force_flush()
            .map_err(|e| DomainError::DependencyUnavailable { dependency: "otlp".to_string(), cause: format!("{e}") })
    }
}

/// 纯函数门控：给定"环境变量显式端点"与进程配置，判定是否启用 OTLP，并归一化 traces 端点。
///
/// 抽成纯函数是为了可测：测试不必改进程环境变量（`std::env::set_var` 在 edition 2024
/// 里是 `unsafe`，且会污染同进程的其它测试）。
#[must_use]
pub fn resolve_otlp_endpoint_from(env_endpoint: Option<&str>, config: &AppConfig) -> Option<String> {
    let explicit = env_endpoint.map(str::trim).filter(|value| !value.is_empty());
    let raw = match explicit {
        Some(value) => value,
        None if config.observability.otel_enabled => config.observability.otel_endpoint.trim(),
        None => return None,
    };
    if raw.is_empty() {
        return None;
    }
    Some(traces_endpoint(raw))
}

/// 从进程环境解析 OTLP 门控（`AGF_OTLP_ENDPOINT` 优先，其次 `AGF_OTEL_ENABLED` + `AGF_OTEL_ENDPOINT`）。
#[must_use]
pub fn resolve_otlp_endpoint(config: &AppConfig) -> Option<String> {
    let env_endpoint = std::env::var("AGF_OTLP_ENDPOINT").ok();
    resolve_otlp_endpoint_from(env_endpoint.as_deref(), config)
}

/// 归一化 OTLP/HTTP traces 端点：只给了主机/根路径时补 [`TRACES_SIGNAL_PATH`]。
///
/// 为什么必须自己补：`opentelemetry-otlp` 只在读 `OTEL_EXPORTER_OTLP_ENDPOINT` 环境变量时
/// 追加信号路径，**程序化 `with_endpoint` 是"按原样使用"**，直接传 `http://host:4318`
/// 会 POST 到根路径而 404。
#[must_use]
pub fn traces_endpoint(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    let has_path =
        url::Url::parse(trimmed).map(|parsed| !parsed.path().is_empty() && parsed.path() != "/").unwrap_or(true);
    if has_path { trimmed.to_string() } else { format!("{trimmed}{TRACES_SIGNAL_PATH}") }
}

/// 装配 OTLP span exporter + provider + `tracing-opentelemetry` 层。
///
/// 返回的层交给 `tracing_subscriber::registry().with(filter).with(layer).with(fmt)...`；
/// `S` 与实际订阅者栈相同（`Registry` 或 `Layered<EnvFilter, Registry>`），
/// 句柄由调用方保活到进程退出。
///
/// **为什么显式注入 HTTP 客户端，且是 `blocking` 客户端**：
///
/// 1. workspace 对 `opentelemetry-otlp` 声明的特性同时打开了 `reqwest-client` 与默认特性里的
///    `reqwest-blocking-client`，而上游 `build_client` 的三条 `cfg` 分支两两互斥
///    （`not(reqwest-client)` / `not(reqwest-blocking-client)`），**没有任何分支命中**
///    ⇒ 构建期报 `no http client specified`。这里显式注入以绕开该 cfg 组合。
/// 2. SDK 的批量导出线程（`OpenTelemetry.Traces.BatchProcessor`）用
///    `futures_executor::block_on` 轮询导出 future，该线程**没有 tokio reactor**；
///    注入**异步** `reqwest::Client` 会在首个批次导出时 panic
///    （`there is no reactor running, must be called from the context of a Tokio 1.x runtime`，
///    已实测复现）。`reqwest::blocking::Client` 自带内部运行时线程，正好匹配这个模型。
/// 3. 但 `reqwest::blocking::Client::build()` **不能在 tokio 运行时内调用**（实测
///    `Cannot drop a runtime in a context where blocking is not allowed`），
///    因此这里在**独立线程**里构造再把句柄搬回来（`Client` 是 `Send`）。
///
/// 根治办法在工作区 `Cargo.toml` 给该依赖加 `default-features = false`（并只保留一个客户端特性），
/// 不在本次可改范围；以上三条都写在代码里，换环境也不会踩。
///
/// # Errors
/// 端点非法、HTTP 客户端或导出器构建失败（调用方**只 `warn` 并继续本地输出**，不得中断启动）。
pub fn build<S>(endpoint: &str, service_name: &str) -> DomainResult<(OtlpLayer<S>, OtlpKeepAlive)>
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
    // 独立线程构造：见上文第 3 条（在异步上下文里构造 blocking 客户端会 panic）。
    let timeout = Duration::from_secs(EXPORT_TIMEOUT_SECS);
    let http_client = std::thread::Builder::new()
        .name("agf-otlp-http-client".to_string())
        .spawn(move || reqwest::blocking::Client::builder().timeout(timeout).build())
        .map_err(|e| DomainError::Internal(format!("OTLP HTTP 客户端线程创建失败: {e}")))?
        .join()
        .map_err(|_| DomainError::Internal("OTLP HTTP 客户端构造线程 panic".to_string()))?
        .map_err(|e| DomainError::Internal(format!("OTLP HTTP 客户端构建失败: {e}")))?;
    let exporter = SpanExporter::builder()
        .with_http()
        .with_http_client(http_client)
        .with_endpoint(endpoint.to_string())
        .with_timeout(Duration::from_secs(EXPORT_TIMEOUT_SECS))
        .build()
        .map_err(|e| DomainError::Internal(format!("OTLP span exporter 构建失败: {e}")))?;
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(Resource::builder().with_service_name(service_name.to_string()).build())
        .build();
    let tracer = provider.tracer(service_name.to_string());
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    Ok((layer, OtlpKeepAlive { provider }))
}

/// 便于调用方命名的默认栈类型（`registry().with(filter)` 之后的类型）。
pub type FilteredRegistry = tracing_subscriber::layer::Layered<tracing_subscriber::EnvFilter, Registry>;
