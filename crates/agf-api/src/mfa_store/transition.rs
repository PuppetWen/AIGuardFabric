//! MFA enrollment and account state commit in one tenant transaction.
use super::{Enrollment, KIND, decrypt, verify_record};
use agf_auth::mfa::TotpService;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
    user::User,
};
use agf_storage::{Store, crypto::FieldCipher, db::TenantTransaction};
use serde_json::Value;

fn db_error(error: sqlx::Error) -> DomainError {
    agf_storage::db::map_sqlx_err("mfa_transition", &error)
}

async fn locked_enrollment(tx: &mut TenantTransaction<'_>, tenant: TenantId, id: Id) -> DomainResult<Enrollment> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("{tenant}:{KIND}:{id}"))
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    let payload: Option<Value> = sqlx::query_scalar(
        "SELECT payload FROM console_configurations
         WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL",
    )
    .bind(tenant.as_uuid())
    .bind(KIND)
    .bind(id.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;
    payload
        .ok_or_else(|| DomainError::PreconditionFailed("请先发起 MFA 绑定".into()))
        .and_then(|value| serde_json::from_value(value).map_err(Into::into))
}

async fn save_enrollment(
    tx: &mut TenantTransaction<'_>,
    tenant: TenantId,
    id: Id,
    record: &Enrollment,
) -> DomainResult<()> {
    let changed = sqlx::query(
        "UPDATE console_configurations SET payload=$4, updated_at=now()
         WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL",
    )
    .bind(tenant.as_uuid())
    .bind(KIND)
    .bind(id.as_uuid())
    .bind(serde_json::to_value(record)?)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    if changed.rows_affected() != 1 {
        return Err(DomainError::Conflict("MFA 绑定状态已变化，请重新加载".into()));
    }
    Ok(())
}

fn user_version(user: &User) -> DomainResult<i64> {
    i64::try_from(user.version).map_err(|_| DomainError::Validation("账号版本无效".into()))
}

pub async fn confirm_sql(
    db: &Store,
    cipher: &FieldCipher,
    tenant: TenantId,
    user: &User,
    code: &str,
) -> DomainResult<Vec<String>> {
    if user.tenant_id != tenant {
        return Err(DomainError::Forbidden("用户不属于当前租户".into()));
    }
    let mut tx = db.db().begin_tenant(tenant).await?;
    let mut record = locked_enrollment(&mut tx, tenant, user.id).await?;
    if record.confirmed {
        return Err(DomainError::Conflict("MFA 已确认，请重新登录".into()));
    }
    if Timestamp::now().unix_secs() - record.created_at > 600 {
        return Err(DomainError::PreconditionFailed("绑定已过期，请重新生成二维码".into()));
    }
    let secret = decrypt(cipher, tenant, user.id, &record)?;
    if !TotpService::default().verify(&user.username, &secret, code)? {
        return Err(DomainError::Validation("验证码错误".into()));
    }
    let (recovery, hashes) = TotpService::default().generate_recovery_codes(10, &user.id.to_string());
    record.confirmed = true;
    record.confirmed_at = Timestamp::now().unix_millis();
    record.recovery_hashes = hashes;
    let changed = sqlx::query(
        "UPDATE users SET mfa_enabled=true, mfa_secret_ref=$2, updated_at=now(), version=version+1
         WHERE tenant_id=$1 AND id=$2 AND version=$3 AND state='active'
           AND deleted_at IS NULL AND NOT mfa_enabled",
    )
    .bind(tenant.as_uuid())
    .bind(user.id.as_uuid())
    .bind(user_version(user)?)
    .execute(&mut *tx)
    .await
    .map_err(db_error)?;
    if changed.rows_affected() != 1 {
        return Err(DomainError::Conflict("账号状态已变化，请重新确认 MFA 绑定".into()));
    }
    save_enrollment(&mut tx, tenant, user.id, &record).await?;
    tx.commit().await?;
    Ok(recovery)
}

pub async fn disable_sql(
    db: &Store,
    cipher: &FieldCipher,
    tenant: TenantId,
    user: &User,
    code: Option<&str>,
) -> DomainResult<()> {
    if user.tenant_id != tenant {
        return Err(DomainError::Forbidden("用户不属于当前租户".into()));
    }
    let mut tx = db.db().begin_tenant(tenant).await?;
    let mut record = locked_enrollment(&mut tx, tenant, user.id).await?;
    let Some(code) = code.filter(|value| !value.trim().is_empty()) else {
        return Err(DomainError::Unauthenticated("验证码或恢复码错误，已使用的码不可重用".into()));
    };
    if !verify_record(&mut record, cipher, tenant, user, code)? {
        return Err(DomainError::Unauthenticated("验证码或恢复码错误，已使用的码不可重用".into()));
    }
    let changed = sqlx::query(
        "UPDATE users SET mfa_enabled=false, mfa_secret_ref=NULL, updated_at=now(), version=version+1
         WHERE tenant_id=$1 AND id=$2 AND version=$3 AND state='active'
           AND deleted_at IS NULL AND mfa_enabled",
    )
    .bind(tenant.as_uuid())
    .bind(user.id.as_uuid())
    .bind(user_version(user)?)
    .execute(&mut *tx)
    .await
    .map_err(db_error)?;
    if changed.rows_affected() != 1 {
        return Err(DomainError::Conflict("账号状态已变化，请重新验证后关闭 MFA".into()));
    }
    save_enrollment(
        &mut tx,
        tenant,
        user.id,
        &Enrollment { confirmed_at: Timestamp::now().unix_millis(), ..Enrollment::default() },
    )
    .await?;
    tx.commit().await
}
