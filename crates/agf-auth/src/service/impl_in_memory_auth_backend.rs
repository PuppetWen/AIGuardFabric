//! 由 `service.rs` 拆分：`InMemoryAuthBackend` 的实现（纯搬移，逻辑不变）。
use super::*;

use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId};
use agf_core::user::{LoginAttempt, RefreshTokenRecord, User, UserWithSecret};
use async_trait::async_trait;

impl InMemoryAuthBackend {
    /// 新建空后端。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 插入用户。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn insert_user(&self, user: User, password_hash: Option<String>) -> DomainResult<()> {
        let mut map = self.users.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        map.insert(user.id, (user, password_hash));
        Ok(())
    }

    /// 设置用户角色。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn set_roles(&self, user_id: Id, roles: Vec<String>) -> DomainResult<()> {
        let mut map = self.role_assignments.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        map.insert(user_id, roles);
        Ok(())
    }

    /// 预设 MFA 验证码（测试用）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn set_mfa_code(&self, user_id: Id, code: &str) -> DomainResult<()> {
        let mut map = self.mfa_codes.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        map.insert(user_id, code.to_string());
        Ok(())
    }

    /// 登录尝试记录数。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn attempt_count(&self) -> DomainResult<usize> {
        self.attempts.lock().map(|v| v.len()).map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))
    }

    /// 最后一次尝试是否成功。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn last_attempt_success(&self) -> DomainResult<Option<bool>> {
        self.attempts
            .lock()
            .map(|v| v.last().map(|a| a.success))
            .map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))
    }

    /// 活跃刷新令牌数。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn active_refresh_count(&self) -> DomainResult<usize> {
        self.refreshes
            .lock()
            .map(|v| v.iter().filter(|r| !r.revoked).count())
            .map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))
    }

    fn save_record(&self, user: &User, password_hash: Option<&str>, roles: Option<&[String]>) -> DomainResult<()> {
        let mut users = self.users.lock().map_err(|e| DomainError::Internal(e.to_string()))?;
        let mut assignments = roles
            .map(|_| self.role_assignments.lock().map_err(|e| DomainError::Internal(e.to_string())))
            .transpose()?;
        let previous = users.get(&user.id);
        if previous.is_some_and(|(saved, _)| saved.tenant_id != user.tenant_id) {
            return Err(DomainError::Forbidden("用户不属于当前租户".into()));
        }
        if previous.map_or(user.version != 0, |(saved, _)| saved.version != user.version) {
            return Err(DomainError::Conflict("账号已被其他操作修改，请刷新后重试".into()));
        }
        let next_version = user.version.checked_add(1).ok_or_else(|| DomainError::Validation("账号版本无效".into()))?;
        let old_hash = previous.and_then(|(_, hash)| hash.clone());
        if let Some(new_hash) = password_hash.filter(|hash| Some(*hash) != old_hash.as_deref()) {
            if let Some(old_hash) = &old_hash {
                let mut histories = self.password_histories.lock().map_err(|e| DomainError::Internal(e.to_string()))?;
                let hashes = histories.entry((user.tenant_id, user.id)).or_default();
                hashes.insert(0, old_hash.clone());
                hashes.truncate(24);
            }
            let mut saved = user.clone();
            saved.version = next_version;
            users.insert(user.id, (saved, Some(new_hash.to_string())));
        } else {
            let mut saved = user.clone();
            saved.version = next_version;
            users.insert(user.id, (saved, old_hash));
        }
        if let (Some(names), Some(assignments)) = (roles, assignments.as_mut()) {
            assignments.insert(user.id, names.to_vec());
        }
        Ok(())
    }
}

#[async_trait]
impl AuthBackend for InMemoryAuthBackend {
    fn current_user_authority(&self, tenant: TenantId, id: Id) -> DomainResult<CurrentUserAuthority> {
        // 与 save_record/provision_federated 一致：先账号、后角色，避免两个快照之间撤权。
        let users = self.users.lock().map_err(|error| DomainError::Internal(error.to_string()))?;
        let roles = self.role_assignments.lock().map_err(|error| DomainError::Internal(error.to_string()))?;
        let user = users.get(&id).filter(|(user, _)| user.tenant_id == tenant).map(|(user, _)| user.clone());
        Ok(CurrentUserAuthority::Synchronous {
            user: user.map(Box::new),
            roles: roles.get(&id).cloned().unwrap_or_default(),
            mfa_configuration_identity: None,
        })
    }

    async fn provision_federated(&self, user: &User, roles: &[String]) -> DomainResult<()> {
        let mut users = self.users.lock().map_err(|e| DomainError::Internal(e.to_string()))?;
        if users.contains_key(&user.id) {
            return Ok(());
        }
        let mut assignments = self.role_assignments.lock().map_err(|e| DomainError::Internal(e.to_string()))?;
        assignments.insert(user.id, roles.to_vec());
        users.insert(user.id, (user.clone(), None));
        Ok(())
    }
    async fn list_users(&self, tenant: TenantId) -> DomainResult<Vec<User>> {
        let map = self.users.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(map
            .values()
            .filter(|(u, _)| u.tenant_id == tenant && u.deleted_at.is_none())
            .map(|(u, _)| u.clone())
            .collect())
    }

    async fn save_account(&self, user: &User, password_hash: Option<&str>, roles: &[String]) -> DomainResult<()> {
        self.save_record(user, password_hash, Some(roles))
    }

    async fn find_user_with_secret(&self, tenant: TenantId, username: &str) -> DomainResult<Option<UserWithSecret>> {
        let map = self.users.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(map
            .values()
            .find(|(u, _)| u.tenant_id == tenant && u.deleted_at.is_none() && u.username.eq_ignore_ascii_case(username))
            .map(|(u, p)| UserWithSecret { user: u.clone(), password_hash: p.clone() }))
    }

    async fn find_user(&self, tenant: TenantId, user_id: Id) -> DomainResult<Option<User>> {
        let map = self.users.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(map.get(&user_id).filter(|(u, _)| u.tenant_id == tenant && u.deleted_at.is_none()).map(|(u, _)| u.clone()))
    }

    async fn save_user(&self, user: &User, password_hash: Option<&str>) -> DomainResult<()> {
        self.save_record(user, password_hash, None)
    }

    async fn password_history(&self, tenant: TenantId, user_id: Id) -> DomainResult<Vec<String>> {
        Ok(self
            .password_histories
            .lock()
            .map_err(|e| DomainError::Internal(e.to_string()))?
            .get(&(tenant, user_id))
            .cloned()
            .unwrap_or_default())
    }

    async fn store_refresh(&self, record: &RefreshTokenRecord) -> DomainResult<()> {
        let mut v = self.refreshes.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        v.push(record.clone());
        Ok(())
    }

    async fn find_refresh(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<Option<RefreshTokenRecord>> {
        let v = self.refreshes.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(v.iter().rev().find(|r| r.tenant_id == tenant && r.token_fingerprint == fingerprint).cloned())
    }

    async fn revoke_refresh(&self, tenant: TenantId, id: Id, reason: &str) -> DomainResult<bool> {
        let mut v = self.refreshes.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        let mut changed = false;
        for r in v.iter_mut().filter(|r| r.tenant_id == tenant && r.id == id && !r.revoked) {
            r.revoked = true;
            r.revoked_reason = Some(reason.to_string());
            changed = true;
        }
        Ok(changed)
    }

    async fn record_attempt(&self, attempt: &LoginAttempt) -> DomainResult<()> {
        let mut v = self.attempts.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        v.push(attempt.clone());
        Ok(())
    }

    async fn roles_of(&self, tenant: TenantId, user_id: Id) -> DomainResult<Vec<String>> {
        if self.find_user(tenant, user_id).await?.is_none() {
            return Ok(Vec::new());
        }
        let map = self.role_assignments.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(map.get(&user_id).cloned().unwrap_or_default())
    }

    async fn verify_mfa(&self, tenant: TenantId, user: &User, code: Option<&str>) -> DomainResult<bool> {
        if user.tenant_id != tenant {
            return Ok(false);
        }
        if !user.mfa_enabled {
            return Ok(true);
        }
        let map = self.mfa_codes.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        match (map.get(&user.id), code) {
            (Some(expected), Some(given)) => Ok(expected == given),
            _ => Ok(false),
        }
    }
}
