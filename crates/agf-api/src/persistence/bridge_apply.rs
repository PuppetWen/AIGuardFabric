//! 写意图执行：消费者循环与唯一触达 PostgreSQL 的写路径 `apply`。

use super::*;

impl PersistenceBridge {
    /// 消费循环：串行执行写意图（串行保证同一资源的先后顺序与内存层一致）。
    pub(super) async fn consume(self: Arc<Self>, mut receiver: UnboundedReceiver<PgWrite>) {
        while let Some(intent) = receiver.recv().await {
            self.queue.stats.depth.fetch_sub(1, Ordering::Relaxed);
            let label = intent.label();
            match self.apply(&intent).await {
                Ok(()) => {
                    self.queue.stats.applied.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => {
                    self.queue.stats.record_failure(label, &error);
                    warn!(
                        intent = label,
                        error = %error,
                        "写后持久化失败：内存已改、PG 未落（最终一致窗口内的不一致，已计入 failed）"
                    );
                }
            }
        }
        debug!("写后持久化消费者退出（通道已关闭）");
    }

    /// 解析内存 id → PG 行 id（未发生重映射时就是原 id）。
    fn resolve(&self, tenant: TenantId, id: Id) -> Id {
        self.remap.lock().ok().and_then(|map| map.get(&(tenant, id)).copied()).unwrap_or(id)
    }

    /// 记录一次 id 重映射（内存 id ≠ PG 行 id）。
    fn remember_remap(&self, tenant: TenantId, memory_id: Id, pg_id: Id) {
        if memory_id == pg_id {
            return;
        }
        if let Ok(mut map) = self.remap.lock() {
            map.insert((tenant, memory_id), pg_id);
        }
        self.queue.stats.id_remapped.fetch_add(1, Ordering::Relaxed);
        debug!(memory_id = %memory_id, pg_id = %pg_id, "告警/案件 id 重映射（仓储不接受调用方 id）");
    }

    /// 执行一条写意图（唯一触达 PG 的写路径）。
    async fn apply(&self, intent: &PgWrite) -> DomainResult<()> {
        match intent {
            PgWrite::AssetUpsert { asset } => {
                let asset = asset.clone();
                let tenant = asset.tenant_id;
                self.store
                    .with_tenant(tenant, move |tx| {
                        Box::pin(async move { AssetRepo::upsert(tx, &asset).await.map(|_| ()) })
                    })
                    .await
            }
            PgWrite::AssetLifecycle { tenant, id, state } => {
                let (tenant, id, state) = (*tenant, *id, *state);
                self.store
                    .with_tenant(tenant, move |tx| {
                        Box::pin(async move { AssetRepo::set_lifecycle(tx, id, state).await })
                    })
                    .await
            }
            PgWrite::AssetChange { change } => {
                let change = change.clone();
                let tenant = change.tenant_id;
                self.store
                    .with_tenant(tenant, move |tx| Box::pin(async move { AssetRepo::insert_change(tx, &change).await }))
                    .await
            }
            PgWrite::AssetSnapshot { tenant, date, asset } => {
                let (tenant, date, asset) = (*tenant, date.clone(), asset.clone());
                self.store
                    .with_tenant(tenant, move |tx| {
                        Box::pin(async move { AssetRepo::snapshot(tx, &date, &asset).await })
                    })
                    .await
            }
            PgWrite::FindingInsert { finding } => {
                let finding = finding.clone();
                let tenant = finding.tenant_id;
                self.store
                    .with_tenant(tenant, move |tx| {
                        Box::pin(async move { FindingRepo::insert(tx, &finding).await.map(|_| ()) })
                    })
                    .await
            }
            PgWrite::FindingSetState { tenant, id, state, verify_note, evidence_level } => {
                let (tenant, id, state) = (*tenant, *id, *state);
                let note = verify_note.clone();
                let level = evidence_level.map(|l| l.as_str().to_string());
                self.store
                    .with_tenant(tenant, move |tx| {
                        Box::pin(async move {
                            FindingRepo::set_state(tx, id, state.as_str(), note.as_deref(), level.as_deref()).await
                        })
                    })
                    .await
            }
            PgWrite::PolicyUpsert { policy } => {
                let policy = policy.clone();
                let tenant = policy.tenant_id;
                self.store
                    .with_tenant(tenant, move |tx| {
                        Box::pin(async move { PolicyRepo::upsert(tx, &policy).await.map(|_| ()) })
                    })
                    .await
            }
            PgWrite::AlertDedup { write } => {
                let write = write.clone();
                let tenant = write.tenant;
                let memory_id = write.memory_id;
                let (pg_id, _created) = self
                    .store
                    .with_tenant(tenant, move |tx| {
                        Box::pin(async move {
                            AlertRepo::upsert_dedup(
                                tx,
                                &write.dedup_key,
                                &write.title,
                                &write.description,
                                write.severity,
                                write.domain,
                                &write.asset_ids,
                                &write.finding_ids,
                                write.sla_due_at,
                            )
                            .await
                        })
                    })
                    .await?;
                self.remember_remap(tenant, memory_id, pg_id);
                Ok(())
            }
            PgWrite::AlertSetState { tenant, id, state, assignee } => {
                let (tenant, id, state) = (*tenant, self.resolve(*tenant, *id), *state);
                let assignee = assignee.clone();
                self.store
                    .with_tenant(tenant, move |tx| {
                        Box::pin(async move { AlertRepo::set_state(tx, id, state, assignee.as_deref()).await })
                    })
                    .await
            }
            PgWrite::CaseCreate { case } => {
                let mut case = (**case).clone();
                let tenant = case.tenant_id;
                let memory_id = case.id;
                case.alert_ids = case.alert_ids.iter().map(|id| self.resolve(tenant, *id)).collect();
                case.finding_ids = case.finding_ids.iter().map(|id| self.resolve(tenant, *id)).collect();
                case.asset_ids = case.asset_ids.iter().map(|id| self.resolve(tenant, *id)).collect();
                let saved = self
                    .store
                    .with_tenant(tenant, move |tx| Box::pin(async move { CaseRepo::insert_identity(tx, &case).await }))
                    .await?;
                self.remember_remap(tenant, memory_id, saved.id);
                Ok(())
            }
            PgWrite::CaseSetState { tenant, id, state, resolution } => {
                let (tenant, id, state) = (*tenant, self.resolve(*tenant, *id), *state);
                let resolution = resolution.clone();
                self.store
                    .with_tenant(tenant, move |tx| {
                        Box::pin(async move { CaseRepo::set_state(tx, id, state, resolution.as_deref()).await })
                    })
                    .await
            }
            PgWrite::CaseAddEvent { event } => {
                let mut event = (**event).clone();
                let tenant = event.tenant_id;
                event.case_id = self.resolve(tenant, event.case_id);
                self.store
                    .with_tenant(tenant, move |tx| Box::pin(async move { CaseRepo::insert_event(tx, &event).await }))
                    .await
            }
            PgWrite::ApiKeyInsert { key } => {
                let key = key.clone();
                let tenant = key.tenant_id;
                self.store
                    .with_tenant(tenant, move |tx| Box::pin(async move { ApiKeyRepo::insert(tx, &key).await }))
                    .await
            }
            PgWrite::ApiKeyRevoke { tenant, id } => {
                let (tenant, id) = (*tenant, *id);
                self.store
                    .with_tenant(tenant, move |tx| Box::pin(async move { ApiKeyRepo::revoke(tx, id).await }))
                    .await
            }
        }
    }
}
