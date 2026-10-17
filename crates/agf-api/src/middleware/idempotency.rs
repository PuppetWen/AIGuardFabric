//! Authenticated, request-bound replay; business-owned durable protocols take precedence.
use super::idempotency_store::REPLAY_PERMISSIONS;
use super::*;
use axum::body::HttpBody as _;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const RESPONSE_LIMIT: u64 = 2 * 1024 * 1024;

#[cfg(test)]
#[path = "idempotency/deadline_tests.rs"]
mod deadline_tests;

async fn within_gateway_window<T>(
    window: Option<(agf_core::time::Timestamp, tokio::time::Instant)>,
    future: impl std::future::Future<Output = T>,
) -> Result<T, DomainError> {
    if let Some((_, deadline)) = window {
        tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| DomainError::Timeout("Original gateway admission request budget expired".into()))
    } else {
        Ok(future.await)
    }
}

#[derive(Clone)]
pub struct IdempotencyContext {
    pub key: String,
    gateway_fingerprint: Option<String>,
    gateway_owner: Option<String>,
    gateway_window: Option<(agf_core::time::Timestamp, tokio::time::Instant)>,
}
impl IdempotencyContext {
    pub(crate) fn gateway_fingerprint(&self, principal: &Principal) -> Result<Option<&str>, DomainError> {
        if self.gateway_fingerprint.is_some()
            && self.gateway_owner.as_deref() != Some(gateway_owner(principal).as_str())
        {
            return Err(DomainError::Forbidden(
                "Gateway request witness belongs to another authenticated identity or Agent".into(),
            ));
        }
        Ok(self.gateway_fingerprint.as_deref())
    }
    pub(crate) fn gateway_window(
        &self,
        principal: &Principal,
    ) -> Result<Option<(agf_core::time::Timestamp, tokio::time::Instant)>, DomainError> {
        self.gateway_fingerprint(principal)?;
        Ok(self.gateway_window)
    }
}

fn gateway_owner(principal: &Principal) -> String {
    let value = serde_json::json!([
        principal.tenant,
        principal.identity_tenant,
        principal.subject_kind,
        principal.subject_id,
        principal.agent_id
    ]);
    format!("{:x}", Sha256::digest(value.to_string().as_bytes()))
}
impl std::fmt::Debug for IdempotencyContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("IdempotencyContext").finish_non_exhaustive()
    }
}

fn fingerprint(parts: &Parts, bytes: &Bytes) -> String {
    let mut hash = Sha256::new();
    let mut headers: Vec<_> = parts
        .headers
        .iter()
        .filter(|(name, _)| {
            matches!(name.as_str(), "content-type" | "content-encoding" | "accept")
                || name.as_str().starts_with("x-agf-")
                || name.as_str().starts_with("x-ssl-client-")
        })
        .filter(|(name, _)| !matches!(name.as_str(), "x-agf-key" | "x-agf-tenant"))
        .collect();
    headers.sort_by(|(a, av), (b, bv)| a.as_str().cmp(b.as_str()).then(av.as_bytes().cmp(bv.as_bytes())));
    for (name, value) in headers {
        hash.update((name.as_str().len() as u64).to_le_bytes());
        hash.update(name.as_str());
        hash.update((value.as_bytes().len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    format!("{:x}", hash.finalize())
}

fn authorization(principal: &Principal) -> String {
    // A token refresh does not change this context; role/scope, bound Agent or ABAC context changes do.
    let value = serde_json::json!({"roles":principal.roles,"scopes":principal.scopes,"superadmin":principal.superadmin,
        "agent":principal.agent_id,"department":principal.department,"source_ip":principal.source_ip,
        "must_change_password":principal.must_change_password,"must_setup_mfa":principal.must_setup_mfa});
    format!("{:x}", Sha256::digest(value.to_string().as_bytes()))
}

/// The same actor, tenant, concrete URI, method and key identify one local receipt.
pub async fn idempotency(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let prefix = &state.config.server.api_prefix;
    let path = req.uri().path();
    let gateway = req.method() == Method::POST
        && (path == format!("{prefix}/chat/completions") || path == "/v1/chat/completions");
    let gateway_window = gateway
        .then(|| (agf_core::time::Timestamp::now(), tokio::time::Instant::now() + std::time::Duration::from_secs(110)));
    // Do not intercept protocol streams or the campaign's durable, cross-instance submission contract.
    if path.starts_with(&format!("{prefix}/mcp/proxy/"))
        || path.starts_with(&format!("{prefix}/mcp/legacy/"))
        || (req.method() == Method::POST && path == format!("{prefix}/redteam/campaigns"))
    {
        return next.run(req).await;
    }
    if !matches!(*req.method(), Method::POST | Method::PUT | Method::PATCH | Method::DELETE)
        || !req.headers().contains_key(HEADER_IDEMPOTENCY_KEY)
    {
        return next.run(req).await;
    }
    // Credentials, authentication and gateway streams use their own retry protocol, never shared replay.
    if (!gateway && !path.starts_with(&format!("{prefix}/")))
        || ["auth/", "sso/", "mfa/", "settings/api-keys"]
            .iter()
            .any(|segment| path.starts_with(&format!("{prefix}/{segment}")))
    {
        return ApiError::new(DomainError::Validation(
            "Idempotency-Key is not supported for credential, authentication or streaming endpoints".into(),
        ))
        .into_response();
    }
    let Some(key) = req
        .headers()
        .get(HEADER_IDEMPOTENCY_KEY)
        .and_then(|v| v.to_str().ok())
        .filter(|key| !key.is_empty() && key.len() <= 200 && key.bytes().all(|b| b.is_ascii_graphic()))
        .map(str::to_owned)
    else {
        return ApiError::new(DomainError::Validation("Idempotency-Key requires 1–200 printable ASCII bytes".into()))
            .into_response();
    };
    let (mut parts, body) = req.into_parts();
    let authentication = async {
        if parts.uri.path() == format!("{prefix}/ingest/agent") {
            crate::routes::ingest::agent_replay_principal(&parts.headers, &state).await
        } else {
            Principal::from_request_parts(&mut parts, &state).await
        }
    };
    let authenticated = match within_gateway_window(gateway_window, authentication).await {
        Ok(result) => result,
        Err(error) => return ApiError::new(error).into_response(),
    };
    let principal = match authenticated {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let buffered = match within_gateway_window(gateway_window, axum::body::to_bytes(body, BODY_BUFFER_LIMIT)).await {
        Ok(result) => result,
        Err(error) => return ApiError::new(error).into_response(),
    };
    let bytes = match buffered {
        Ok(bytes) => bytes,
        Err(_) => {
            return ApiError::new(DomainError::Validation("Request body exceeds replay buffer limit".into()))
                .into_response();
        }
    };
    let fingerprint = fingerprint(&parts, &bytes);
    let gateway_fingerprint = if gateway {
        // Concrete aliases/query/body/business headers are input, not a fresh key namespace.
        let input = serde_json::json!([parts.method.as_str(), parts.uri.to_string(), fingerprint]);
        Some(format!("{:x}", Sha256::digest(input.to_string().as_bytes())))
    } else {
        None
    };
    if let Some(input) = &gateway_fingerprint {
        let Some(window) = gateway_window else {
            return ApiError::new(DomainError::Internal("Gateway admission window is unavailable".into()))
                .into_response();
        };
        match crate::gateway_settlement::admission_key_prelookup(
            &state,
            &principal,
            &parts.headers,
            &key,
            input,
            window,
        )
        .await
        {
            Ok(Some(original)) => return original.response(),
            Err(error) => return ApiError::new(error).into_response(),
            Ok(None) => {}
        }
    }
    let authorization = authorization(&principal);
    let scope =
        serde_json::json!([principal.tenant, principal.display(), parts.method.as_str(), parts.uri.to_string(), key])
            .to_string();
    let store_key = format!("{:x}", Sha256::digest(scope.as_bytes()));
    match state.idempotency.begin(&store_key, &fingerprint) {
        Ok(Some(stored)) => {
            for (group, action) in &stored.permissions {
                if let Err(error) = principal.require(&state, group, action) {
                    return error.into_response();
                }
            }
            if stored.authorization != authorization {
                return ApiError::new(DomainError::Conflict(
                    "Authorization context changed; inspect the original operation before retrying".into(),
                ))
                .into_response();
            }
            state.metrics.record_idempotent_replay();
            return replay_response(stored);
        }
        Err(error) => return error.into_response(),
        Ok(None) => {}
    }
    let gateway_owner = gateway_fingerprint.as_ref().map(|_| gateway_owner(&principal));
    parts.extensions.insert(IdempotencyContext {
        key: store_key.clone(),
        gateway_fingerprint,
        gateway_owner,
        gateway_window,
    });
    let _lease =
        super::idempotency_store::ReceiptLease { store: Arc::clone(&state.idempotency), key: store_key.clone() };
    let trace = Arc::new(Mutex::new(Vec::new()));
    let response =
        REPLAY_PERMISSIONS.scope(Arc::clone(&trace), next.run(Request::from_parts(parts, Body::from(bytes)))).await;
    let permissions = trace.lock().map(|trace| trace.clone()).unwrap_or_default();
    let content_type = response.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    // A stream/large or uncertain result is returned untouched. A retry must reconcile it instead of rerunning.
    if !response.status().is_success()
        || permissions.is_empty()
        || response.headers().contains_key(header::SET_COOKIE)
        || !content_type.starts_with("application/json")
        || response.body().size_hint().upper().is_none_or(|size| size > RESPONSE_LIMIT)
    {
        return response;
    }
    let (parts, body) = response.into_parts();
    let bytes = match axum::body::to_bytes(body, RESPONSE_LIMIT as usize).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return ApiError::new(DomainError::Internal(
                "Operation response was interrupted; inspect the resource before retrying".into(),
            ))
            .into_response();
        }
    };
    state.idempotency.complete(
        &store_key,
        StoredResponse {
            status: parts.status,
            headers: parts.headers.clone(),
            body: bytes.clone(),
            permissions,
            authorization,
        },
    );
    Response::from_parts(parts, Body::from(bytes))
}

fn replay_response(stored: StoredResponse) -> Response {
    let mut response = Response::new(Body::from(stored.body));
    *response.status_mut() = stored.status;
    *response.headers_mut() = stored.headers;
    insert_header(response.headers_mut(), "Idempotency-Replayed", "true");
    response
}
