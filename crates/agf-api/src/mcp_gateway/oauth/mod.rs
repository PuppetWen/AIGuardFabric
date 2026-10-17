//! Tenant-bound authorization-code OAuth for administrator-registered MCP resources.
mod client_metadata;
mod discovery;
mod dynamic_registration;
mod flow;
mod store;
mod token;

pub(crate) use client_metadata::document as client_metadata_document;
pub(crate) use flow::{Complete, complete, start};
pub(crate) use store::{Configuration, Input, Registration, get, public, save};
pub(crate) use token::{connected, credential, disconnect};

use crate::{model_gateway, state::AppState};
use agf_core::credential::SecretMaterial;
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;

pub(super) const CONFIG_KIND: &str = "mcp-oauth-client";
const FLOW_KIND: &str = "mcp-oauth-flow";
const TOKEN_KIND: &str = "mcp-oauth-token";

fn invalid(message: &str) -> DomainError {
    DomainError::Validation(message.into())
}

fn denied() -> DomainError {
    DomainError::Unauthenticated("MCP OAuth 授权状态无效或已使用，请重新连接".into())
}

fn unavailable() -> DomainError {
    DomainError::DependencyUnavailable {
        dependency: "mcp-oauth".into(),
        cause: "MCP 授权服务不可用或响应无效；请检查发现文档、客户端注册及服务端日志".into(),
    }
}

fn unseal(state: &AppState, tenant: TenantId, id: Id, value: &SecretMaterial) -> DomainResult<String> {
    if value.aad.as_deref() != Some(&FieldCipher::make_aad(&tenant, &id)) {
        return Err(DomainError::Crypto("MCP OAuth 密文租户或端点绑定不匹配".into()));
    }
    Ok(model_gateway::cipher(state)?.decrypt(value)?.expose_secret().to_owned())
}
