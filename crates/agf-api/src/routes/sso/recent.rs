//! Short-lived server-side proof of a fresh external login, used only for MFA management.
use super::*;
use agf_core::ids::deterministic_id;
const KIND: &str = "oidc-recent-login";

#[derive(Serialize, Deserialize)]
struct Proof {
    user_id: Id,
    expires_at: i64,
}

pub(super) async fn record(state: &AppState, tenant: TenantId, user: Id, session: &str) -> DomainResult<()> {
    let now = Timestamp::now().unix_secs();
    state.configurations.purge_expired(tenant, KIND, now).await?;
    state
        .configurations
        .put(tenant, KIND, deterministic_id(KIND, session), &Proof { user_id: user, expires_at: now + 300 })
        .await
}

pub(crate) async fn verify(state: &AppState, principal: &Principal, user: Id) -> DomainResult<()> {
    let session = principal.session_id.as_deref().ok_or_else(denied)?;
    let proof: Option<Proof> =
        state.configurations.get(principal.identity_tenant, KIND, deterministic_id(KIND, session)).await?;
    if !proof.is_some_and(|p| p.user_id == user && p.expires_at > Timestamp::now().unix_secs()) {
        return Err(DomainError::PreconditionFailed("请重新通过企业 SSO 登录，并在 5 分钟内管理 MFA".into()));
    }
    Ok(())
}
