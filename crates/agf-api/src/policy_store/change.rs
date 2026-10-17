//! Management mutations use CAS; trusted internal upserts retain their existing contract.
use super::*;
use agf_core::audit::{AuditAction, AuditActor, AuditLog, AuditOutcome, AuditTarget};
use serde_json::json;

#[derive(Debug)]
pub(super) enum Change {
    Create(Box<Policy>),
    Update { policy: Box<Policy>, expected: u64 },
    Restore { policy: Box<Policy>, version: u32, expected: u64 },
    Save(Box<Policy>),
    Delete { id: Id, expected: Option<u64> },
}

impl Change {
    pub(super) fn candidate(&self) -> Option<&Policy> {
        match self {
            Self::Create(policy) | Self::Update { policy, .. } | Self::Restore { policy, .. } | Self::Save(policy) => {
                Some(policy)
            }
            Self::Delete { .. } => None,
        }
    }

    pub(super) fn action(&self) -> &'static str {
        if matches!(self, Self::Delete { .. }) { "delete" } else { "write" }
    }

    pub(super) fn apply(
        self,
        rows: &mut registry::Registry,
        tenant: TenantId,
        signer: &PolicySigner,
        actor: AuditActor,
    ) -> DomainResult<(Policy, AuditLog)> {
        rows.validate(tenant, signer)?;
        let (mut candidate, before, action, note) = match self {
            Self::Create(policy) => {
                if rows.entries.contains_key(&policy.id)
                    || rows.entries.values().any(|row| row.name == policy.name && row.deleted_at.is_none())
                {
                    return Err(DomainError::Conflict("策略名称已存在；请读取原策略后使用带版本的更新".into()));
                }
                (*policy, None, AuditAction::Create, "创建并签名发布平台策略")
            }
            Self::Update { policy, expected } => {
                let current = rows.previous(policy.id)?.clone();
                check_version(&current, expected)?;
                if current.deleted_at.is_some() {
                    return Err(not_found(current.id));
                }
                (*policy, Some(current), AuditAction::Update, "更新并签名发布平台策略")
            }
            Self::Restore { policy, version, expected } => {
                let current = rows.previous(policy.id)?.clone();
                check_version(&current, expected)?;
                let target = rows
                    .history
                    .get(&policy.id)
                    .into_iter()
                    .flatten()
                    .chain(std::iter::once(&current))
                    .find(|row| row.version == version)
                    .ok_or_else(|| DomainError::NotFound {
                        entity: "policy-version",
                        id: format!("{}/{version}", policy.id),
                    })?;
                if (target.content_hash.as_str(), target.signature.as_str())
                    != (policy.content_hash.as_str(), policy.signature.as_str())
                {
                    return Err(DomainError::Conflict("所选历史快照已变化；请重新读取后确认".into()));
                }
                (*policy, Some(current), AuditAction::Update, "从可信历史生成并签名发布新的平台策略版本")
            }
            Self::Save(policy) => {
                let current = rows
                    .entries
                    .get(&policy.id)
                    .or_else(|| rows.entries.values().find(|row| row.name == policy.name && row.deleted_at.is_none()))
                    .cloned();
                let action = if current.is_some() { AuditAction::Update } else { AuditAction::Create };
                (*policy, current, action, "可信内部流程发布签名平台策略")
            }
            Self::Delete { id, expected } => {
                let current = rows.previous(id)?.clone();
                if let Some(expected) = expected {
                    check_version(&current, expected)?;
                }
                if current.deleted_at.is_some() {
                    return Err(not_found(id));
                }
                (current.clone(), Some(current), AuditAction::Delete, "软删除平台策略；保留可信签名历史")
            }
        };
        if let Some(previous) = &before {
            candidate.id = previous.id;
            candidate.name = previous.name.clone();
            candidate.created_at = previous.created_at;
            candidate.version =
                previous.version.checked_add(1).ok_or_else(|| DomainError::Conflict("策略版本已达上限".into()))?;
            rows.remember(previous.clone());
        } else {
            candidate.version = 1;
        }
        candidate.tenant_id = tenant;
        candidate.updated_at = Timestamp::now();
        candidate.deleted_at = if action == AuditAction::Delete { Some(candidate.updated_at) } else { None };
        if candidate.deleted_at.is_none() {
            let name_owner = rows.entries.values().find(|row| row.deleted_at.is_none() && row.name == candidate.name);
            if name_owner.is_some_and(|row| row.id != candidate.id) {
                return Err(DomainError::Conflict("已有另一条有效策略使用该名称；请保留草稿并重新选择策略".into()));
            }
        }
        if action == AuditAction::Delete {
            candidate.enabled = false;
        }
        candidate.content_hash = candidate.compute_hash();
        candidate.signature = signer.sign(&candidate);
        rows.entries.insert(candidate.id, candidate.clone());
        rows.validate(tenant, signer)?;
        let mut audit = AppState::audit_entry(
            tenant,
            action,
            AuditOutcome::Success,
            actor,
            AuditTarget::new("policy", Some(candidate.id.to_string()), Some(candidate.name.clone())),
            note,
        );
        audit.before = before.as_ref().map(summary);
        audit.after = Some(summary(&candidate));
        Ok((candidate, audit))
    }
}

fn summary(row: &Policy) -> serde_json::Value {
    json!({"version":row.version,"content_hash":row.content_hash,"enabled":row.enabled,
        "deleted":row.deleted_at.is_some(),"language":row.language.as_str(),"action":row.action.as_str()})
}
fn check_version(row: &Policy, expected: u64) -> DomainResult<()> {
    if expected == 0 {
        return Err(DomainError::Validation("expected_version 必须是当前策略的正整数版本".into()));
    }
    if u64::from(row.version) != expected {
        return Err(DomainError::Conflict("策略已被其他人修改；请保留草稿，重新读取和比较后明确提交".into()));
    }
    Ok(())
}
fn not_found(id: Id) -> DomainError {
    DomainError::NotFound { entity: "policy", id: id.to_string() }
}
