//! Case IDs, state transitions and timelines are committed before the API reports success.
use super::*;
use agf_core::audit::{AuditAction, AuditOutcome};
use agf_core::case::CaseEventKind;
use agf_storage::{AuditRepo, CaseRepo, TenantTransaction, map_sqlx_err};

async fn required(tx: &mut TenantTransaction<'_>, id: Id, lock: bool) -> DomainResult<Case> {
    CaseRepo::get(tx, id, lock).await?.ok_or_else(|| DomainError::NotFound { entity: "case", id: id.to_string() })
}

fn event(tenant: TenantId, case_id: Id, kind: CaseEventKind, actor: &str, note: &str) -> CaseEvent {
    CaseEvent {
        id: Id::new(),
        tenant_id: tenant,
        case_id,
        kind,
        actor: actor.into(),
        note: note.into(),
        detail: serde_json::Value::Null,
        automated: false,
        at: Timestamp::now(),
    }
}

impl ApiStore {
    /// Persist a supplied event identity so a retried workflow projection cannot duplicate it.
    pub async fn case_insert_event_durable(&self, event: &CaseEvent) -> DomainResult<()> {
        if let Some(database) = &self.database {
            let event = event.clone();
            database
                .with_tenant(event.tenant_id, move |tx| {
                    Box::pin(async move { CaseRepo::insert_event(tx, &event).await })
                })
                .await?;
        } else if self.case_get(event.tenant_id, event.case_id)?.is_none() {
            return Err(DomainError::NotFound { entity: "case", id: event.case_id.to_string() });
        }
        self.hydrate_case_event(event)
    }
    pub async fn case_get_durable(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Case>> {
        let Some(database) = &self.database else { return self.case_get(tenant, id) };
        let case =
            database.with_tenant(tenant, move |tx| Box::pin(async move { CaseRepo::get(tx, id, false).await })).await?;
        if let Some(case) = &case {
            self.hydrate_case(case)?;
        } else {
            self.lock()?.cases.remove(&(tenant, id));
        }
        Ok(case)
    }

    pub async fn case_list_durable(&self, tenant: TenantId) -> DomainResult<Vec<Case>> {
        let Some(database) = &self.database else { return self.case_list(tenant) };
        let rows: Vec<serde_json::Value> = database
            .with_tenant(tenant, |tx| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT to_jsonb(c) FROM cases c ORDER BY created_at DESC,id")
                        .fetch_all(&mut **tx)
                        .await
                        .map_err(|e| map_sqlx_err("case_list_all", &e))
                })
            })
            .await?;
        let cases: Vec<Case> = rows.into_iter().map(serde_json::from_value).collect::<Result<_, _>>()?;
        let mut mem = self.lock()?;
        mem.cases.retain(|(owner, _), _| *owner != tenant);
        for case in &cases {
            mem.cases.insert((tenant, case.id), case.clone());
        }
        Ok(cases)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn case_create_durable(
        &self,
        tenant: TenantId,
        title: &str,
        summary: &str,
        severity: Severity,
        alert_ids: &[Id],
        finding_ids: &[Id],
        asset_ids: &[Id],
        owner: Option<&str>,
        actor: &str,
        mut audit: Option<AuditLog>,
    ) -> DomainResult<Case> {
        if audit.as_ref().is_some_and(|entry| {
            entry.tenant_id != tenant
                || entry.action != AuditAction::Create
                || entry.outcome != AuditOutcome::Success
                || entry.target.kind != "case"
                || entry.target.id.is_some()
        }) {
            return Err(DomainError::Validation("Case creation audit does not match the request".into()));
        }
        let Some(database) = &self.database else {
            let case = self.case_create(tenant, title, summary, severity, alert_ids, finding_ids, asset_ids, owner)?;
            self.case_add_event(tenant, case.id, CaseEventKind::Created, actor, "案件创建")?;
            if let Some(mut entry) = audit.take() {
                entry.target.id = Some(case.id.to_string());
                entry.target.name = Some(case.code.clone());
                self.audit_append_durable(entry).await?;
            }
            return Ok(case);
        };
        let (title, summary, owner, actor) =
            (title.to_owned(), summary.to_owned(), owner.map(str::to_owned), actor.to_owned());
        let (alert_ids, finding_ids, asset_ids) = (alert_ids.to_vec(), finding_ids.to_vec(), asset_ids.to_vec());
        let (case, created, sealed) = database
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    let (id, _) = CaseRepo::create(
                        tx,
                        &title,
                        &summary,
                        severity,
                        &alert_ids,
                        &finding_ids,
                        &asset_ids,
                        owner.as_deref(),
                    )
                    .await?;
                    let case = required(tx, id, false).await?;
                    CaseRepo::link_alerts(tx, &case).await?;
                    let created = event(tenant, id, CaseEventKind::Created, &actor, "案件创建");
                    CaseRepo::insert_event(tx, &created).await?;
                    let sealed = if let Some(mut entry) = audit {
                        entry.target.id = Some(id.to_string());
                        entry.target.name = Some(case.code.clone());
                        Some(AuditRepo::append_log(tx, entry).await?)
                    } else {
                        None
                    };
                    Ok((case, created, sealed))
                })
            })
            .await?;
        if let Err(error) = self.hydrate_case(&case) {
            tracing::warn!(case_id=%case.id,%error,"Committed case projection failed");
        }
        if let Err(error) = self.hydrate_case_event(&created) {
            tracing::warn!(case_id=%case.id,%error,"Committed case event projection failed");
        }
        if let Some(sealed) = sealed {
            if let Err(error) = self.hydrate_audit(&sealed) {
                tracing::warn!(case_id=%case.id,%error,"Committed case audit projection failed");
            }
        }
        for id in &case.alert_ids {
            if let Err(error) = self.alert_get_durable(tenant, *id).await {
                tracing::warn!(case_id=%case.id,alert_id=%id,%error,"Committed case alert projection failed");
            }
        }
        Ok(case)
    }

    pub async fn case_set_state_durable(
        &self,
        tenant: TenantId,
        id: Id,
        target: CaseState,
        resolution: Option<String>,
        actor: &str,
    ) -> DomainResult<Case> {
        self.case_set_state_audited_durable(tenant, id, target, resolution, actor, None).await
    }

    pub async fn case_set_state_audited_durable(
        &self,
        tenant: TenantId,
        id: Id,
        target: CaseState,
        resolution: Option<String>,
        actor: &str,
        mut audit: Option<AuditLog>,
    ) -> DomainResult<Case> {
        let expected_id = id.to_string();
        if audit.as_ref().is_some_and(|entry| {
            entry.tenant_id != tenant
                || entry.action != AuditAction::Update
                || entry.outcome != AuditOutcome::Success
                || entry.target.kind != "case"
                || entry.target.id.as_deref() != Some(expected_id.as_str())
                || entry.target.name.is_some()
        }) {
            return Err(DomainError::Validation("Case state audit does not match the request".into()));
        }
        let Some(database) = &self.database else {
            let case = self.case_set_state_as(tenant, id, target, resolution, actor)?;
            if let Some(mut entry) = audit.take() {
                entry.target.name = Some(case.code.clone());
                self.audit_append_durable(entry).await?;
            }
            return Ok(case);
        };
        let actor = actor.to_owned();
        let (case, changed, sealed) = database
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    let current = required(tx, id, true).await?;
                    if current.state != target && !current.can_transition_to(target) {
                        return Err(DomainError::Conflict(format!(
                            "非法案件流转: {} → {}",
                            current.state.as_str(),
                            target.as_str()
                        )));
                    }
                    if current.state == target
                        && resolution.as_ref().is_none_or(|value| Some(value) == current.resolution.as_ref())
                    {
                        return Ok((current, None, None));
                    }
                    CaseRepo::set_state(tx, id, target, resolution.as_deref()).await?;
                    let changed = event(
                        tenant,
                        id,
                        CaseEventKind::StateChanged,
                        &actor,
                        &format!("状态流转到 {}", target.as_str()),
                    );
                    CaseRepo::insert_event(tx, &changed).await?;
                    let case = required(tx, id, false).await?;
                    let sealed = if let Some(mut entry) = audit {
                        entry.target.name = Some(case.code.clone());
                        Some(AuditRepo::append_log(tx, entry).await?)
                    } else {
                        None
                    };
                    Ok((case, Some(changed), sealed))
                })
            })
            .await?;
        if let Err(error) = self.hydrate_case(&case) {
            tracing::warn!(case_id=%case.id,%error,"Committed case projection failed");
        }
        if let Some(changed) = changed {
            if let Err(error) = self.hydrate_case_event(&changed) {
                tracing::warn!(case_id=%case.id,%error,"Committed case event projection failed");
            }
        }
        if let Some(sealed) = sealed {
            if let Err(error) = self.hydrate_audit(&sealed) {
                tracing::warn!(case_id=%case.id,%error,"Committed case audit projection failed");
            }
        }
        Ok(case)
    }

    pub async fn case_add_event_durable(
        &self,
        tenant: TenantId,
        id: Id,
        kind: CaseEventKind,
        actor: &str,
        note: &str,
    ) -> DomainResult<CaseEvent> {
        let Some(database) = &self.database else { return self.case_add_event(tenant, id, kind, actor, note) };
        let row = event(tenant, id, kind, actor, note);
        let write = row.clone();
        database
            .with_tenant(tenant, move |tx| Box::pin(async move { CaseRepo::insert_event(tx, &write).await }))
            .await?;
        self.hydrate_case_event(&row)?;
        Ok(row)
    }

    pub async fn case_events_durable(&self, tenant: TenantId, id: Id) -> DomainResult<Vec<CaseEvent>> {
        let Some(database) = &self.database else { return self.case_events(tenant, id) };
        let rows: Vec<serde_json::Value> = database
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    required(tx, id, false).await?;
                    sqlx::query_scalar("SELECT to_jsonb(e) FROM case_events e WHERE case_id=$1 ORDER BY at,id")
                        .bind(id.as_uuid())
                        .fetch_all(&mut **tx)
                        .await
                        .map_err(|e| map_sqlx_err("case_timeline_all", &e))
                })
            })
            .await?;
        rows.into_iter().map(serde_json::from_value).collect::<Result<_, _>>().map_err(Into::into)
    }

    pub async fn case_set_sla_durable(
        &self,
        tenant: TenantId,
        id: Id,
        due_at: Option<Timestamp>,
        breached: bool,
    ) -> DomainResult<Case> {
        let Some(database) = &self.database else { return self.case_set_sla(tenant, id, due_at, breached) };
        let case = database
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    sqlx::query("UPDATE cases SET sla_due_at=$2,sla_breached=$3 WHERE id=$1")
                        .bind(id.as_uuid())
                        .bind(due_at.map(|at| at.as_datetime()))
                        .bind(breached)
                        .execute(&mut **tx)
                        .await
                        .map_err(|e| map_sqlx_err("case_sla_write", &e))?;
                    required(tx, id, false).await
                })
            })
            .await?;
        self.hydrate_case(&case)?;
        Ok(case)
    }
}
