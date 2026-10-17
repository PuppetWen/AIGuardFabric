//! 同一事务保存账号和角色绑定，避免创建半成品账号。
use super::*;
use agf_storage::db::TenantTransaction;

pub(super) async fn save(tx: &mut TenantTransaction<'_>, user: &User, password: Option<&str>) -> DomainResult<()> {
    let mut value = serde_json::to_value(user).map_err(|e| DomainError::Internal(e.to_string()))?;
    value["password_hash"] = serde_json::to_value(password).map_err(|e| DomainError::Internal(e.to_string()))?;
    let next_version = i64::try_from(user.version)
        .ok()
        .and_then(|version| version.checked_add(1))
        .ok_or_else(|| DomainError::Validation("账号版本无效".into()))?;
    value["version"] = Value::from(next_version);
    if user.last_login_ip.as_deref().is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_err()) {
        value["last_login_ip"] = Value::Null;
    }
    let result = sqlx::query(
        "INSERT INTO users (id, tenant_id, username, email, password_hash, display_name, phone, department,
         idp, external_subject, state, is_superadmin, must_change_password, mfa_enabled, mfa_secret_ref,
         failed_logins, locked_until, last_login_at, last_login_ip, password_changed_at, created_at, updated_at, deleted_at, version)
         SELECT id, tenant_id, username, email, password_hash, display_name, phone, department,
         idp, external_subject, state, is_superadmin, must_change_password, mfa_enabled, mfa_secret_ref,
         failed_logins, locked_until, last_login_at, last_login_ip, password_changed_at, created_at, updated_at, deleted_at, version
         FROM jsonb_populate_record(NULL::users, $1)
         ON CONFLICT (id) DO UPDATE SET
         username=excluded.username, email=excluded.email, display_name=excluded.display_name,
         password_history=CASE WHEN excluded.password_hash IS NOT NULL AND users.password_hash IS NOT NULL
             AND excluded.password_hash <> users.password_hash THEN
             jsonb_path_query_array(jsonb_build_array(users.password_hash) || users.password_history, '$[0 to 23]')
             ELSE users.password_history END,
         password_hash=COALESCE(excluded.password_hash, users.password_hash),
         phone=excluded.phone, department=excluded.department, state=excluded.state,
         is_superadmin=excluded.is_superadmin, must_change_password=excluded.must_change_password,
         mfa_enabled=excluded.mfa_enabled, mfa_secret_ref=excluded.mfa_secret_ref,
         failed_logins=excluded.failed_logins, locked_until=excluded.locked_until,
         last_login_at=excluded.last_login_at, last_login_ip=excluded.last_login_ip,
         password_changed_at=excluded.password_changed_at, updated_at=excluded.updated_at,
         deleted_at=excluded.deleted_at, version=excluded.version
         WHERE users.tenant_id=excluded.tenant_id AND users.deleted_at IS NULL
           AND users.version=excluded.version-1")
        .bind(value).execute(&mut **tx).await.map_err(db_error)?;
    if result.rows_affected() == 0 {
        return Err(DomainError::Conflict("账号已被其他操作修改，请刷新后重试".into()));
    }
    Ok(())
}

pub(super) async fn assign_roles(tx: &mut TenantTransaction<'_>, user: &User, names: &[String]) -> DomainResult<()> {
    sqlx::query("UPDATE role_bindings SET deleted_at=now() WHERE tenant_id=$1 AND subject_id=$2 AND subject_kind='user' AND deleted_at IS NULL")
        .bind(user.tenant_id.as_uuid()).bind(user.id.as_uuid()).execute(&mut **tx).await.map_err(db_error)?;
    let definitions = agf_core::rbac::Role::builtin_definitions();
    for name in names {
        let Some((_, display, description, permissions)) = definitions.iter().find(|(n, _, _, _)| *n == name) else {
            return Err(DomainError::Validation(format!("未知角色: {name}")));
        };
        let role: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO roles (id,tenant_id,name,display_name,description,permissions,builtin)
             VALUES ($1,$2,$3,$4,$5,$6,true)
             ON CONFLICT (tenant_id,name) WHERE deleted_at IS NULL
             DO UPDATE SET display_name=excluded.display_name, permissions=excluded.permissions RETURNING id",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(user.tenant_id.as_uuid())
        .bind(name)
        .bind(display)
        .bind(description)
        .bind(serde_json::json!(permissions))
        .fetch_one(&mut **tx)
        .await
        .map_err(db_error)?;
        sqlx::query(
            "INSERT INTO role_bindings (id,tenant_id,subject_id,subject_kind,role_id)
             VALUES ($1,$2,$3,'user',$4)",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(user.tenant_id.as_uuid())
        .bind(user.id.as_uuid())
        .bind(role)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    }
    Ok(())
}
