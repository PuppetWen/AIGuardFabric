//! Public, revision-bound OAuth Client ID Metadata Documents for MCP authorization servers.
use super::{Configuration, Registration, get};
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use serde_json::{Value, json};
use url::Url;

pub(super) fn client_id(
    state: &AppState,
    tenant: TenantId,
    endpoint_id: Id,
    revision: Id,
    redirect_uri: &Url,
) -> DomainResult<String> {
    if redirect_uri.scheme() != "https" {
        return Err(super::invalid("托管 Client ID 元数据需要公开可访问的 HTTPS 控制台回调地址"));
    }
    let prefix = state.config.server.api_prefix.trim_end_matches('/');
    Ok(format!(
        "{}{prefix}/mcp/oauth/client-metadata/{tenant}/{endpoint_id}/{revision}",
        redirect_uri.origin().ascii_serialization()
    ))
}

pub(crate) async fn document(state: &AppState, tenant: TenantId, endpoint_id: Id, revision: Id) -> DomainResult<Value> {
    let endpoint = super::super::config::get(state, tenant, endpoint_id).await?;
    let row: Configuration = get(state, tenant, endpoint_id)
        .await?
        .filter(|row| {
            row.registration == Registration::ClientIdMetadata
                && row.revision == revision
                && row.endpoint_url == endpoint.url
                && endpoint.enabled
        })
        .ok_or_else(|| missing(revision))?;
    let redirect_uri = Url::parse(&row.redirect_uri).map_err(|_| missing(revision))?;
    if row.client_id != client_id(state, tenant, endpoint_id, revision, &redirect_uri)? {
        return Err(missing(revision));
    }
    Ok(json!({
        "client_id":row.client_id,
        "client_name":"AIGuardFabric MCP Gateway",
        "redirect_uris":[row.redirect_uri],
        "grant_types":["authorization_code","refresh_token"],
        "response_types":["code"],
        "token_endpoint_auth_method":"none",
        "application_type":"web"
    }))
}

fn missing(id: Id) -> DomainError {
    DomainError::NotFound { entity: "mcp-oauth-client-metadata", id: id.to_string() }
}
