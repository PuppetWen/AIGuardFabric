//! Explicit protocol selection. A session is private, scoped to this original run and never persisted.
use super::{mcp_frames::invalid, mcp_headers, transport};
use agf_core::error::DomainResult;
use reqwest::{
    Client, Url,
    header::{HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Revision {
    #[default]
    #[serde(rename = "2026-07-28")]
    Modern,
    #[serde(rename = "2025-11-25")]
    Legacy,
}
impl Revision {
    pub(super) const fn value(self) -> &'static str {
        match self {
            Self::Modern => "2026-07-28",
            Self::Legacy => "2025-11-25",
        }
    }
}
pub(super) struct Session {
    revision: Revision,
    id: Option<HeaderValue>,
}
impl Session {
    pub(super) fn modern() -> Self {
        Self { revision: Revision::Modern, id: None }
    }
    pub(super) async fn initialize(client: &Client, url: &Url, bearer: Option<&str>) -> DomainResult<Self> {
        let body = json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25",
            "capabilities":{},"clientInfo":{"name":"AIGuardFabric bounded redteam","version":env!("CARGO_PKG_VERSION")}}});
        let wire = transport::mcp_exchange(client, url, bearer, &body, &HeaderMap::new(), Some(0)).await?;
        if wire.content["result"]["protocolVersion"] != "2025-11-25"
            || !wire.content["result"]["capabilities"].is_object()
            || ["name", "version"].iter().any(|field| {
                wire.content["result"]["serverInfo"][*field]
                    .as_str()
                    .is_none_or(|value| value.is_empty() || value.len() > 160)
            })
        {
            return Err(invalid());
        }
        let id = wire
            .session
            .map(|id| -> DomainResult<HeaderValue> {
                let mut value = HeaderValue::from_str(&id).map_err(|_| invalid())?;
                value.set_sensitive(true);
                Ok(value)
            })
            .transpose()?;
        Ok(Self { revision: Revision::Legacy, id })
    }
    fn headers(&self, method: &str, name: Option<&str>) -> DomainResult<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert("mcp-protocol-version", HeaderValue::from_static(self.revision.value()));
        if let Some(id) = &self.id {
            headers.insert("mcp-session-id", id.clone());
        }
        if self.revision == Revision::Modern {
            headers.insert("mcp-method", HeaderValue::from_str(method).map_err(|_| invalid())?);
            if let Some(name) = name {
                headers.insert("mcp-name", mcp_headers::encoded(name)?);
            }
        }
        Ok(headers)
    }
    pub(super) async fn initialized(&self, client: &Client, url: &Url, bearer: Option<&str>) -> DomainResult<()> {
        if self.revision != Revision::Legacy {
            return Err(invalid());
        }
        let wire = transport::mcp_exchange(
            client,
            url,
            bearer,
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            &self.headers("notifications/initialized", None)?,
            None,
        )
        .await?;
        self.check_session(&wire)?;
        Ok(())
    }
    fn check_session(&self, wire: &transport::Wire) -> DomainResult<()> {
        if self.revision == Revision::Legacy
            && wire
                .session
                .as_deref()
                .is_some_and(|value| self.id.as_ref().is_none_or(|id| id.as_bytes() != value.as_bytes()))
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn body(&self, method: &str, mut params: Value) -> DomainResult<Value> {
        if !params.is_object() {
            return Err(invalid());
        }
        if self.revision == Revision::Modern {
            params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":self.revision.value(),
                "io.modelcontextprotocol/clientInfo":{"name":"AIGuardFabric bounded redteam","version":env!("CARGO_PKG_VERSION")},
                "io.modelcontextprotocol/clientCapabilities":{}});
        }
        Ok(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
    }
    pub(super) async fn request(
        &self,
        client: &Client,
        url: &Url,
        bearer: Option<&str>,
        body: &Value,
        extra: HeaderMap,
    ) -> DomainResult<transport::Wire> {
        let method = body["method"].as_str().ok_or_else(invalid)?;
        let name = body["params"]["name"].as_str();
        let mut headers = self.headers(method, name)?;
        headers.extend(extra);
        let wire = transport::mcp_exchange(client, url, bearer, body, &headers, Some(1)).await?;
        self.check_session(&wire)?;
        Ok(wire)
    }
}
