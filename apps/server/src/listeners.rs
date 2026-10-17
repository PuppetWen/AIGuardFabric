//! Bind the optional dedicated MCP port before declaring the HTTP service ready.
use agf_api::AppState;
use axum::Router;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

pub(super) async fn serve(state: AppState, api: TcpListener, app: Router) -> anyhow::Result<()> {
    let port = std::env::var("AGF_MCP_PROXY_PORT").unwrap_or_else(|_| "0".into());
    let port: u16 = port.parse().map_err(|_| anyhow::anyhow!("AGF_MCP_PROXY_PORT must be 0..65535"))?;
    let mcp = if port == 0 {
        None
    } else {
        let host = std::env::var("AGF_MCP_PROXY_HOST").unwrap_or_else(|_| state.config.server.host.clone());
        let listener = TcpListener::bind((host.as_str(), port)).await?;
        tracing::info!(address = %listener.local_addr()?, "Authenticated MCP HTTP listener ready");
        Some(listener)
    };
    let metrics = if state.config.server.metrics_port == 0 {
        None
    } else {
        let listener = TcpListener::bind((state.config.server.host.as_str(), state.config.server.metrics_port)).await?;
        tracing::info!(address = %listener.local_addr()?, "Prometheus metrics listener ready");
        Some(listener)
    };

    let mut servers = JoinSet::new();
    servers.spawn(async move {
        axum::serve(api, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(super::shutdown_signal())
            .await
    });
    if let Some(listener) = mcp {
        let mcp_state = state.clone();
        servers.spawn(async move {
            axum::serve(
                listener,
                agf_api::build_mcp_router(mcp_state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(super::shutdown_signal())
            .await
        });
    }
    if let Some(listener) = metrics {
        servers.spawn(async move {
            axum::serve(
                listener,
                agf_api::build_metrics_router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(super::shutdown_signal())
            .await
        });
    }

    // The first listener error or shutdown ends the process. Stop the other listeners too.
    let first = servers.join_next().await.ok_or_else(|| anyhow::anyhow!("no HTTP listener started"))?;
    servers.abort_all();
    while servers.join_next().await.is_some() {}
    first??;
    Ok(())
}
