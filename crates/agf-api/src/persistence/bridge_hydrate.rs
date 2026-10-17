//! 启动水合：从 PostgreSQL 把各资源读进内存缓存（同步包装 `hydrate_blocking` 与异步主体 `hydrate`）。

use super::*;

impl PersistenceBridge {
    /// **同步**水合包装（`AppState::build` 是同步函数）。
    ///
    /// - multi-thread 运行时：`block_in_place` + `Handle::block_on` 做**启动期同步水合**
    ///   （返回时缓存已就绪，请求不会看到空列表）；
    /// - 其它运行时（如 `#[tokio::test]` 默认的 current-thread）：`block_in_place` 会 panic，
    ///   阻塞 IO 驱动又会挂死，因此**推迟到后台任务**并在报告里标注 `deferred`；
    /// - 完全没有运行时：记 `errors`，不 panic（此时也不会有请求进来）。
    pub fn hydrate_blocking(self: &Arc<Self>, target: &Arc<ApiStore>) {
        let report = match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(self.hydrate(target)))
            }
            Ok(handle) => {
                let bridge = Arc::clone(self);
                let target = Arc::clone(target);
                handle.spawn(async move {
                    let report = bridge.hydrate(&target).await;
                    info!(loaded = report.total_loaded(), errors = report.errors.len(), "启动水合（后台任务）完成");
                    bridge.set_hydration(report);
                });
                HydrationReport::deferred()
            }
            Err(_) => {
                let mut report = HydrationReport::default();
                report.errors.push("没有 tokio 运行时：跳过启动水合（进程内缓存为空）".to_string());
                report
            }
        };
        if !report.deferred && report.errors.is_empty() {
            info!(
                loaded = report.total_loaded(),
                resources = report.loaded.len(),
                "启动水合完成：PG 资源已读入内存缓存"
            );
        }
        for error in &report.errors {
            warn!(error = %error, "启动水合失败（该资源重启后可能为空；PG 数据未受影响）");
        }
        self.set_hydration(report);
    }

    /// 从 PG 把各资源读进内存缓存（`ApiStore` 的内存层即"PG 的读缓存"）。
    ///
    /// **失败不阻断启动**：没有任何仓储的资源记进 `skipped`，查询/反序列化失败记进 `errors`。
    pub async fn hydrate(&self, target: &ApiStore) -> HydrationReport {
        let mut report = HydrationReport::default();
        let tenant = TenantId::default_tenant();

        // ---- 资产（仓储已有强类型映射）----
        let assets = self
            .store
            .with_tenant(tenant, |tx| Box::pin(async move { AssetRepo::list_all(tx, HYDRATE_LIMIT).await }))
            .await;
        match assets {
            Ok(assets) => {
                let mut loaded = 0_usize;
                for asset in &assets {
                    if let Err(error) = target.hydrate_asset(asset) {
                        report.errors.push(format!("assets 写入缓存失败: {error}"));
                    } else {
                        loaded = loaded.saturating_add(1);
                    }
                }
                report.loaded.insert("assets".to_string(), loaded);
            }
            Err(error) => report.errors.push(format!("assets 水合失败: {error}")),
        }

        // ---- 发现（分页：仓储 list 受 MAX_PAGE_SIZE 限制）----
        let mut loaded_findings = 0_usize;
        for page_number in 1..=MAX_FINDING_PAGES {
            let request = PageRequest { page: page_number, page_size: FINDING_PAGE_SIZE, ..PageRequest::default() };
            let page = self
                .store
                .with_tenant(tenant, move |tx| {
                    Box::pin(async move { FindingRepo::list(tx, &request, None, None).await })
                })
                .await;
            match page {
                Ok(page) => {
                    let total = page.total.unwrap_or(0);
                    let empty = page.items.is_empty();
                    for finding in &page.items {
                        if let Err(error) = target.hydrate_finding(finding) {
                            report.errors.push(format!("findings 写入缓存失败: {error}"));
                        } else {
                            loaded_findings = loaded_findings.saturating_add(1);
                        }
                    }
                    if empty || i64::try_from(loaded_findings).unwrap_or(i64::MAX) >= total {
                        break;
                    }
                }
                Err(error) => {
                    report.errors.push(format!("findings 水合失败（第 {page_number} 页）: {error}"));
                    break;
                }
            }
        }
        report.loaded.insert("findings".to_string(), loaded_findings);

        // ---- 策略（仓储 list_all 返回 JSON 投影，反序列化失败逐条记录）----
        let policies =
            self.store.with_tenant(tenant, |tx| Box::pin(async move { PolicyRepo::list_all(tx).await })).await;
        match policies {
            Ok(rows) => {
                let mut loaded = 0_usize;
                let mut invalid = 0_usize;
                for row in rows {
                    match serde_json::from_value::<Policy>(row) {
                        Ok(policy) => {
                            if let Err(error) = target.hydrate_policy(&policy) {
                                report.errors.push(format!("policies 写入缓存失败: {error}"));
                            } else {
                                loaded = loaded.saturating_add(1);
                            }
                        }
                        Err(error) => {
                            invalid = invalid.saturating_add(1);
                            report.errors.push(format!("policies 行反序列化失败: {error}"));
                        }
                    }
                }
                if invalid > 0 {
                    report.skipped.push(format!("policies：{invalid} 行无法映射回领域对象，未进缓存"));
                }
                report.loaded.insert("policies".to_string(), loaded);
            }
            Err(error) => report.errors.push(format!("policies 水合失败: {error}")),
        }

        // ---- 告警（仓储只有 list_active：已关闭/已抑制的告警不回读，如实记录）----
        let alerts = self
            .store
            .with_tenant(tenant, |tx| Box::pin(async move { AlertRepo::list_active(tx, HYDRATE_LIMIT).await }))
            .await;
        match alerts {
            Ok(rows) => {
                let mut loaded = 0_usize;
                for row in rows {
                    match serde_json::from_value::<agf_core::alert::Alert>(row) {
                        Ok(alert) => {
                            if let Err(error) = target.hydrate_alert(&alert) {
                                report.errors.push(format!("alerts 写入缓存失败: {error}"));
                            } else {
                                loaded = loaded.saturating_add(1);
                            }
                        }
                        Err(error) => report.errors.push(format!("alerts 行反序列化失败: {error}")),
                    }
                }
                report.loaded.insert("alerts".to_string(), loaded);
                report
                    .skipped
                    .push("alerts：仓储只有 list_active，非活动态（closed/suppressed）告警不从 PG 回读".to_string());
            }
            Err(error) => report.errors.push(format!("alerts 水合失败: {error}")),
        }

        // ---- 案件 + 时间线（仓储 create 自生成 id/code，见"已知身份漂移"）----
        let cases =
            self.store.with_tenant(tenant, |tx| Box::pin(async move { CaseRepo::list(tx, HYDRATE_LIMIT).await })).await;
        match cases {
            Ok(rows) => {
                let mut loaded = 0_usize;
                let mut events_loaded = 0_usize;
                let mut case_ids: Vec<Id> = Vec::new();
                for row in rows {
                    match serde_json::from_value::<Case>(row) {
                        Ok(case) => {
                            case_ids.push(case.id);
                            if let Err(error) = target.hydrate_case(&case) {
                                report.errors.push(format!("cases 写入缓存失败: {error}"));
                            } else {
                                loaded = loaded.saturating_add(1);
                            }
                        }
                        Err(error) => report.errors.push(format!("cases 行反序列化失败: {error}")),
                    }
                }
                report.loaded.insert("cases".to_string(), loaded);
                for case_id in case_ids {
                    let timeline = self
                        .store
                        .with_tenant(tenant, move |tx| Box::pin(async move { CaseRepo::timeline(tx, case_id).await }))
                        .await;
                    match timeline {
                        Ok(rows) => {
                            for row in rows {
                                match serde_json::from_value::<CaseEvent>(row) {
                                    Ok(event) => {
                                        if let Err(error) = target.hydrate_case_event(&event) {
                                            report.errors.push(format!("case_events 写入缓存失败: {error}"));
                                        } else {
                                            events_loaded = events_loaded.saturating_add(1);
                                        }
                                    }
                                    Err(error) => {
                                        report.errors.push(format!("case_events 行反序列化失败: {error}"));
                                    }
                                }
                            }
                        }
                        Err(error) => report.errors.push(format!("case_events 水合失败: {error}")),
                    }
                }
                report.loaded.insert("case_events".to_string(), events_loaded);
            }
            Err(error) => report.errors.push(format!("cases 水合失败: {error}")),
        }

        // ---- 已提交 PostgreSQL 审计链的启动期本地投影 ----
        let audits = self
            .store
            .with_tenant(tenant, |tx| Box::pin(async move { AuditRepo::load_chain(tx, 0, HYDRATE_LIMIT).await }))
            .await;
        match audits {
            Ok(entries) => {
                let mut loaded = 0_usize;
                for entry in &entries {
                    if let Err(error) = target.hydrate_audit(entry) {
                        report.errors.push(format!("audit_logs 写入缓存失败: {error}"));
                    } else {
                        loaded = loaded.saturating_add(1);
                    }
                }
                report.loaded.insert("audit_logs".to_string(), loaded);
            }
            Err(error) => report.errors.push(format!("audit_logs 水合失败: {error}")),
        }

        // ---- API Key（身份凭据：只回读指纹/前缀/scope/租户/吊销状态，**明文从不落库**）----
        //
        // 这一段是"重启后服务凭据仍可用"的关键：`agf-scheduler` 的 `asset-inventory` /
        // `rule-hot-reload` 用 `.env` 的 `AGF_SCHEDULER_API_KEY` 调 agf-api，若 Key 不水合，
        // 重启后必然 401（`API Key 无效`）且 /tasks 的 failures 永久 > 0。
        let api_keys = self
            .store
            .with_tenant(tenant, |tx| Box::pin(async move { ApiKeyRepo::list_all(tx, HYDRATE_LIMIT).await }))
            .await;
        match api_keys {
            Ok(keys) => {
                let mut loaded = 0_usize;
                for key in &keys {
                    if let Err(error) = target.hydrate_api_key(key) {
                        report.errors.push(format!("api_keys 写入缓存失败: {error}"));
                    } else {
                        loaded = loaded.saturating_add(1);
                    }
                }
                report.loaded.insert("api_keys".to_string(), loaded);
            }
            Err(error) => report.errors.push(format!("api_keys 水合失败: {error}")),
        }

        // ---- 没有仓储的面：如实登记（不是"忘了接"，是仓储层没有）----
        for resource in MEMORY_ONLY_RESOURCES {
            report.skipped.push(format!("{resource}：agf_storage 无对应仓储，仍仅内存（重启即丢）"));
        }
        report.skipped.push(
            "assets.changes / assets.snapshots：写入已落 PG，但启动水合不回读（按资产逐条查询会放大启动成本）"
                .to_string(),
        );
        report.skipped.push(
            "findings.evidence：证据明细在插入时落 finding_evidence，水合只回读主表（仓储 list 不加载证据）"
                .to_string(),
        );

        report
    }
}
