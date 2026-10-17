//! OTLP/gRPC three-signal receiver using official tonic service definitions.
//!
//! `LogsService`, `TraceService` and `MetricsService` reuse the OTLP/HTTP decoders,
//! native source controls and durable ingest pipeline. The server accepts uncompressed
//! and gzip requests. Trace and metric receivers are attached with `with_signals`;
//! the production collector attaches all three with distinct stable source IDs.
//!
//! Full success omits `partial_success`. Per-record rejections include their true count;
//! exporters must not retry a partial-success batch. Malformed requests return
//! `InvalidArgument`; transient storage/control failures return `Unavailable`.
//! See the [OTLP specification](https://opentelemetry.io/docs/specs/otlp/).
//!
//! | Environment variable | Default | Meaning |
//! |---|---|---|
//! | `AGF_INGEST_OTLP_GRPC_ENABLED` | `1` | Disable with `0`/`false`/`no`/`off` |
//! | `AGF_INGEST_OTLP_GRPC_LISTEN` | `0.0.0.0:4317` | Listener IP and port |
//! | `AGF_INGEST_OTLP_GRPC_MAX_RECORDS` | `10000` | Per-export signal record limit |
//! | `AGF_INGEST_OTLP_GRPC_MAX_MESSAGE_BYTES` | `16777216` | Decoded message byte limit |
//! | `AGF_INGEST_OTLP_GRPC_TLS` | `0` | Enable native server TLS |
//! | `AGF_INGEST_OTLP_GRPC_TLS_CERT` / `..._TLS_KEY` | empty | PEM certificate/key paths |
//! | `AGF_INGEST_OTLP_GRPC_TLS_CLIENT_CA` | empty | Require a trusted client certificate |
//!
//! Incomplete or invalid TLS material prevents this listener from starting and appears
//! in `/readyz` notes. It never silently opens an unencrypted fallback port.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agf_core::error::{DomainError, DomainResult};
use axum::http::HeaderMap;
use axum::http::header::{CONTENT_TYPE, HeaderValue};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsPartialSuccess, ExportLogsServiceRequest, ExportLogsServiceResponse,
    logs_service_server::{LogsService, LogsServiceServer},
};
use tokio::net::{TcpListener, TcpStream};
use tonic::codec::CompressionEncoding;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use crate::otlp::{OtlpIngestReport, OtlpLogRecord, OtlpLogsReceiver};

mod config;
mod mapping;
mod server;
mod signals;
mod tls;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_tls;

pub use config::*;
pub use mapping::*;
pub use server::*;
pub use tls::*;
