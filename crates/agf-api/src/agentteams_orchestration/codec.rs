use super::*;
use agf_storage::crypto::FieldCipher;
use secrecy::{ExposeSecret, SecretString};

fn aad(tenant: TenantId) -> String {
    format!("{}:{KIND}:application-owned:v1", FieldCipher::make_aad(&tenant, &record_id(tenant)))
}
fn validate(tenant: TenantId, rows: &model::Registry) -> DomainResult<()> {
    if rows.tenant != Some(tenant)
        || rows.records.len() > MAX_RECORDS
        || rows.intents.len() > MAX_INTENTS
        || rows
            .records
            .iter()
            .any(|(name, row)| name != &row.team_name || row.version == 0 || row.source.tenant != tenant)
        || rows.intents.iter().any(|(id, row)| {
            *id != row.request_id
                || id.is_nil()
                || row.tenant != tenant
                || row.source.tenant != tenant
                || row.actor_id.is_nil()
                || row.version == 0
        })
    {
        return Err(DomainError::Crypto("编排声明身份或永久请求事实无效".into()));
    }
    Ok(())
}
pub(super) fn open(state: &AppState, tenant: TenantId, row: Option<&model::Envelope>) -> DomainResult<model::Registry> {
    let Some(row) = row else {
        return Ok(model::Registry { tenant: Some(tenant), ..Default::default() });
    };
    if row.secret.aad.as_deref() != Some(aad(tenant).as_str()) || row.secret.plaintext_len > MAX_BYTES {
        return Err(DomainError::Crypto("编排声明的租户、用途或长度绑定无效".into()));
    }
    let raw = crate::model_gateway::cipher(state)?.decrypt(&row.secret)?;
    if raw.expose_secret().len() > MAX_BYTES {
        return Err(DomainError::Crypto("编排声明超过容量上限".into()));
    }
    let rows = serde_json::from_str(raw.expose_secret()).map_err(|_| DomainError::Crypto("编排声明正文无效".into()))?;
    validate(tenant, &rows)?;
    Ok(rows)
}
pub(super) fn seal(state: &AppState, tenant: TenantId, rows: &model::Registry) -> DomainResult<model::Envelope> {
    validate(tenant, rows)?;
    let raw = serde_json::to_string(rows)?;
    if raw.len() > MAX_BYTES {
        return Err(DomainError::Validation("本租户编排声明与永久回执容量已满；旧编号不会删除或重新派发".into()));
    }
    let secret = crate::model_gateway::cipher(state)?.encrypt(&SecretString::from(raw), &aad(tenant))?;
    let envelope = model::Envelope { secret };
    if serde_json::to_vec(&envelope)?.len() > 4 * 1024 * 1024 {
        return Err(invalid());
    }
    Ok(envelope)
}
pub(super) async fn load(state: &AppState, tenant: TenantId) -> DomainResult<model::Registry> {
    let row = state.configurations.get::<model::Envelope>(tenant, KIND, record_id(tenant)).await?;
    open(state, tenant, row.as_ref())
}
