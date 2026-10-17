//! Trace and metric services share the HTTP decoders, tenant controls and durable pipeline.
use std::sync::Arc;

use opentelemetry_proto::tonic::collector::{metrics::v1 as metrics, trace::v1 as traces};
use tonic::{Request, Response, Status};

use crate::otlp::{OtlpMetricsReceiver, OtlpTracesReceiver, http_response::grpc_error};

#[derive(Debug)]
pub(super) struct TraceService(pub Option<Arc<OtlpTracesReceiver>>);

#[derive(Debug)]
pub(super) struct MetricsService(pub Option<Arc<OtlpMetricsReceiver>>);

pub(super) fn transport_peer<T>(request: &Request<T>) -> crate::pipeline::TransportPeer {
    crate::pipeline::TransportPeer {
        ip: request.remote_addr().map(|address| address.ip()),
        mutual_tls: request.peer_certs().is_some_and(|certificates| !certificates.is_empty()),
    }
}

fn json_body(value: &impl serde::Serialize) -> Result<Vec<u8>, Status> {
    serde_json::to_vec(value).map_err(|_| Status::invalid_argument("Invalid OTLP export request"))
}

#[tonic::async_trait]
impl traces::trace_service_server::TraceService for TraceService {
    async fn export(
        &self,
        request: Request<traces::ExportTraceServiceRequest>,
    ) -> Result<Response<traces::ExportTraceServiceResponse>, Status> {
        let receiver = self.0.as_ref().ok_or_else(|| Status::unimplemented("Trace receiver is not configured"))?;
        let peer = transport_peer(&request);
        let body = json_body(&request.into_inner())?;
        let report = receiver
            .ingest_traces_from(&super::mapping::json_headers(), &body, peer)
            .await
            .map_err(|e| grpc_error(&e))?;
        Ok(Response::new(traces::ExportTraceServiceResponse {
            partial_success: (report.rejected > 0).then(|| traces::ExportTracePartialSuccess {
                rejected_spans: i64::try_from(report.rejected).unwrap_or(i64::MAX),
                error_message: report.error_message.unwrap_or_else(|| "Some spans were rejected".into()),
            }),
        }))
    }
}

#[tonic::async_trait]
impl metrics::metrics_service_server::MetricsService for MetricsService {
    async fn export(
        &self,
        request: Request<metrics::ExportMetricsServiceRequest>,
    ) -> Result<Response<metrics::ExportMetricsServiceResponse>, Status> {
        let receiver = self.0.as_ref().ok_or_else(|| Status::unimplemented("Metric receiver is not configured"))?;
        let peer = transport_peer(&request);
        let body = json_body(&request.into_inner())?;
        let report = receiver
            .ingest_metrics_from(&super::mapping::json_headers(), &body, peer)
            .await
            .map_err(|e| grpc_error(&e))?;
        Ok(Response::new(metrics::ExportMetricsServiceResponse {
            partial_success: (report.rejected > 0).then(|| metrics::ExportMetricsPartialSuccess {
                rejected_data_points: i64::try_from(report.rejected).unwrap_or(i64::MAX),
                error_message: report.error_message.unwrap_or_else(|| "Some data points were rejected".into()),
            }),
        }))
    }
}
