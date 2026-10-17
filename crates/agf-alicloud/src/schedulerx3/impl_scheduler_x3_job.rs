//! 由 `schedulerx3.rs` 拆分：`JobRegistrationReport`/`SchedulerX3Adapter`/`SchedulerX3Job` 的实现（纯搬移，逻辑不变）。
use super::*;

impl SchedulerX3Job {
    /// 平台六个任务的权威定义。
    ///
    /// `tenant_id` 参与 id 生成，保证多租户下互不冲突。
    #[must_use]
    pub fn platform_defaults(tenant_id: TenantId) -> Vec<Self> {
        let id_of = |kind: &str| deterministic_id(NS_SCHEDULE, &format!("{tenant_id}/{kind}"));
        // 依赖表：把 job_kind 转成确定性 id
        let depends = |kinds: &[&str]| kinds.iter().map(|k| id_of(k)).collect::<Vec<Id>>();
        let job =
            |kind: &str, name: &str, cron: &str, shard_count: u32, max_retries: u32, deps: &[&str], handler: &str| {
                Self {
                    cloud_parameters: BTreeMap::new(),
                    id: id_of(kind),
                    name: name.to_string(),
                    job_kind: kind.to_string(),
                    cron: cron.to_string(),
                    shard_count,
                    max_retries,
                    depends_on: depends(deps),
                    enabled: true,
                    backend: ScheduleBackend::SchedulerX3,
                    cloud_job_id: None,
                    handler: handler.to_string(),
                }
            };
        vec![
            job("asset-inventory", "资产盘点", "0 2 * * *", 1, 3, &[], "/api/v1/internal/jobs/asset-inventory"),
            job("log-pull", "日志拉取", "*/10 * * * *", 8, 5, &["asset-inventory"], "/api/v1/internal/jobs/log-pull"),
            job(
                "redteam-cruise",
                "红队巡航",
                "0 3 * * 1",
                2,
                2,
                &["asset-inventory"],
                "/api/v1/internal/jobs/redteam-cruise",
            ),
            job("rule-hot-reload", "规则热更新", "*/5 * * * *", 1, 2, &[], "/api/v1/internal/jobs/rule-hot-reload"),
            job(
                "report",
                "安全报表",
                "0 7 * * *",
                1,
                3,
                &["asset-inventory", "log-pull"],
                "/api/v1/internal/jobs/report",
            ),
            job("archive", "数据归档", "0 4 1 * *", 2, 1, &["report"], "/api/v1/internal/jobs/archive"),
        ]
    }

    /// 转平台调度登记实体（`ScheduleRegistration`）。
    #[must_use]
    pub fn to_registration(&self, tenant_id: TenantId) -> ScheduleRegistration {
        ScheduleRegistration {
            id: self.id,
            tenant_id,
            name: self.name.clone(),
            job_kind: self.job_kind.clone(),
            cron: self.cron.clone(),
            backend: self.backend,
            cloud_job_id: self.cloud_job_id.clone(),
            shard_count: self.shard_count,
            max_retries: self.max_retries,
            depends_on: self.depends_on.clone(),
            enabled: self.enabled,
            last_run_at: None,
            last_result: None,
            created_at: Timestamp::now(),
        }
    }

    /// Explicit public API parameters; cloud-specific HTTP/script configuration is preserved.
    pub fn parameters(&self, cluster_id: &str, app_name: &str) -> DomainResult<serde_json::Value> {
        let mut body = serde_json::to_value(&self.cloud_parameters)?;
        body["ClusterId"] = cluster_id.into();
        body["AppName"] = app_name.into();
        body["Name"] = self.name.clone().into();
        body["TimeExpression"] = self.cron.clone().into();
        body["MaxAttempt"] = self.max_retries.into();
        if body.get("TimeType").is_none() {
            body["TimeType"] = 1.into();
        }
        let action = if let Some(id) = &self.cloud_job_id {
            body["JobId"] = live::job_id(id)?.into();
            if let Some(object) = body.as_object_mut() {
                object.remove("JobType");
                object.remove("Status");
                object.remove("Coordinate");
            }
            "UpdateJob"
        } else {
            if body.get("JobType").is_none() {
                return Err(DomainError::Config(
                    "创建云任务需要 cloud_parameters.JobType 及该任务类型的执行器配置；不能直接发布本地演示入口".into(),
                ));
            }
            body["Status"] = i32::from(self.enabled).into();
            "CreateJob"
        };
        crate::openapi::contract(AliCloudService::SchedulerX3, action)?.validate(&body)?;
        Ok(body)
    }

    /// 依赖是否已在本批次内全部满足（依赖编排自检）。
    #[must_use]
    pub fn dependencies_satisfied(&self, batch: &[Self]) -> bool {
        self.depends_on.iter().all(|dep| batch.iter().any(|j| j.id == *dep))
    }

    /// 是否处于降级后端。
    #[must_use]
    pub fn is_degraded_backend(&self) -> bool {
        self.backend != ScheduleBackend::SchedulerX3
    }
}

impl JobRegistrationReport {
    /// 总数。
    #[must_use]
    pub const fn total(&self) -> usize {
        self.created + self.updated + self.skipped + self.failed
    }
}

impl std::fmt::Debug for SchedulerX3Adapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchedulerX3Adapter")
            .field("core", &self.core)
            .field("namespace", &self.namespace)
            .field("has_client", &self.client.is_some())
            .field("transport", &"<transport-double>")
            .finish_non_exhaustive()
    }
}

impl Default for SchedulerX3Adapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedulerX3Adapter {
    /// 未配置态构造。
    #[must_use]
    pub fn new() -> Self {
        Self {
            core: AdapterCore::new(AliCloudService::SchedulerX3),
            client: None,
            transport: null_transport(),
            namespace: "agf-default".to_string(),
            cluster_id: String::new(),
            registration_jobs: Vec::new(),
        }
    }

    /// Mock 模式构造。
    #[must_use]
    pub fn mocked() -> Self {
        let mut adapter = Self::new();
        adapter.core.mode = AdapterMode::Mocked;
        adapter.core.unconfigured_reason = None;
        adapter
    }

    /// 注入录制替身（测试用）。
    ///
    /// # Errors
    /// 缺少凭据或未初始化。
    pub fn with_recording_transport(&mut self, transport: Arc<dyn crate::http::Transport>) -> DomainResult<()> {
        self.client = Some(self.core.build_test_client(transport)?);
        Ok(())
    }

    /// 当前模式。
    #[must_use]
    pub const fn mode(&self) -> AdapterMode {
        self.core.mode()
    }

    /// 只读核心。
    #[must_use]
    pub const fn core(&self) -> &AdapterCore {
        &self.core
    }

    /// 可变核心。
    pub const fn core_mut(&mut self) -> &mut AdapterCore {
        &mut self.core
    }

    /// 传输替身句柄（Mock 模式下恒不被调用；测试用它断言"零网络"）。
    #[must_use]
    pub fn transport(&self) -> Arc<crate::http::RecordingTransport> {
        self.transport.clone()
    }

    /// 云侧命名空间。
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// 当前生效的调度后端（未配置/降级时为本地 cron）。
    #[must_use]
    pub fn effective_backend(&self) -> ScheduleBackend {
        if self.core.is_live() { ScheduleBackend::SchedulerX3 } else { ScheduleBackend::SchedulerX3.fallback() }
    }

    /// 平台六个任务的 [ScheduleRegistration] 列表（**双模统一出口**：云后端与本地 cron 共用）。
    #[must_use]
    pub fn platform_registrations(&self, tenant_id: TenantId) -> Vec<ScheduleRegistration> {
        let backend = self.effective_backend();
        SchedulerX3Job::platform_defaults(tenant_id)
            .into_iter()
            .map(|mut job| {
                job.backend = backend;
                job.to_registration(tenant_id)
            })
            .collect()
    }

    pub(crate) fn live_client(&self) -> DomainResult<&RpcClient> {
        if self.core.is_mock() {
            return Err(mock::mock_blocked(AliCloudService::SchedulerX3));
        }
        self.client.as_deref().ok_or_else(|| {
            mock::unavailable(AliCloudService::SchedulerX3, "适配器未初始化或凭据未就绪（无真实调用通道）")
        })
    }
}

#[async_trait]
impl Adapter for SchedulerX3Adapter {
    fn name(&self) -> &str {
        AliCloudService::SchedulerX3.as_str()
    }

    fn descriptor(&self) -> AdapterDescriptor {
        mock::descriptor_of(AliCloudService::SchedulerX3)
    }

    async fn init(&mut self, config: &AdapterConfig) -> DomainResult<()> {
        self.core.load_from_config(config)?;
        self.namespace = config
            .get_str("app_name")
            .or_else(|| config.get_str("namespace"))
            .map_or_else(|| "agf-default".to_string(), ToString::to_string);
        self.cluster_id = config.get_str("cluster_id").unwrap_or_default().into();
        self.registration_jobs =
            config.settings.get("platform_jobs").cloned().map(serde_json::from_value).transpose()?.unwrap_or_default();
        self.client = self.core.build_live_client();
        mock::log_init(AliCloudService::SchedulerX3, self.core.mode());
        Ok(())
    }

    async fn health(&self) -> DomainResult<AdapterHealth> {
        let mut health = self.core.health_of();
        if !self.core.is_live() {
            health.message = Some(format!(
                "{}；调度回退后端 {}（本地 tokio-cron 双模）",
                health.message.unwrap_or_default(),
                self.effective_backend().as_str()
            ));
        }
        Ok(health)
    }

    async fn sync(&self, direction: SyncDirection, req: &PullRequest) -> DomainResult<SyncOutcome> {
        let started = std::time::Instant::now();
        let mut outcome = SyncOutcome {
            mocked: self.core.is_mock(),
            degraded: !self.core.is_live(),
            finished_at: Some(Timestamp::now()),
            ..SyncOutcome::default()
        };
        if direction.includes_pull() {
            let jobs = self.pull_jobs().await?;
            let executions = self.pull_executions(None).await?;
            outcome.pulled = jobs.len() + executions.len();
            outcome.changes.insert("schedule_job".to_string(), jobs.len());
            outcome.changes.insert("execution".to_string(), executions.len());
            outcome
                .changes
                .insert("execution_failed".to_string(), executions.iter().filter(|e| e.status == "FAILED").count());
        }
        if direction.includes_push() {
            // 平台 → 云：注册六个任务（依赖编排按序下发）
            let report = self.register_platform_jobs(self.core.tenant_id).await?;
            outcome.pushed = report.created + report.updated;
            outcome.failed = report.failed;
            outcome.skipped = report.skipped;
            outcome.changes.insert("job_created".to_string(), report.created);
            outcome.changes.insert("job_updated".to_string(), report.updated);
            if report.failed > 0 {
                outcome
                    .warnings
                    .push(format!("{} 个任务注册失败；请核对回执后重试，尚未自动加入补传队列", report.failed));
            }
        }
        if !self.core.is_live() {
            outcome.warnings.push(format!(
                "调度后端降级为 {}：云任务定义仍可下发/登记，但由本地 tokio-cron 实际执行",
                self.effective_backend().as_str()
            ));
        }
        if self.core.is_mock() {
            outcome
                .warnings
                .push("Mock 模式：返回确定性 fixtures，未触达真实 SchedulerX3（AGF_MOCK_MODE）".to_string());
        }
        if !req.resource.is_empty() {
            outcome.changes.insert("requested_resource".to_string(), 1);
        }
        outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(outcome)
    }

    async fn push(&self, payload: &PushPayload) -> DomainResult<()> {
        match payload.entity.as_str() {
            "schedule" | "job" => {
                let job: SchedulerX3Job = serde_json::from_value(payload.body.clone())?;
                self.create_job(&job, &self.namespace).await?;
                Ok(())
            }
            other => {
                Err(DomainError::Validation(format!("SchedulerX3 适配器只接受 schedule / job 载荷，收到 {other}")))
            }
        }
    }

    async fn pull(&self, req: &PullRequest) -> DomainResult<PullResponse> {
        let resource = if req.resource.is_empty() { "jobs".to_string() } else { req.resource.clone() };
        let items = match resource.as_str() {
            "jobs" | "schedules" => self
                .pull_jobs()
                .await?
                .into_iter()
                .map(|j| serde_json::to_value(j).unwrap_or(serde_json::Value::Null))
                .collect(),
            "executions" => {
                let job_id = req.filter.get("job_id").map(String::as_str);
                self.pull_executions(job_id)
                    .await?
                    .into_iter()
                    .map(|e| serde_json::to_value(e).unwrap_or(serde_json::Value::Null))
                    .collect()
            }
            "registrations" => self
                .platform_registrations(self.core.tenant_id)
                .into_iter()
                .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
                .collect(),
            other => return Err(DomainError::Validation(format!("SchedulerX3 不支持拉取资源类型 {other}"))),
        };
        Ok(PullResponse {
            items,
            next_cursor: None,
            mocked: self.core.is_mock(),
            origin: if self.core.is_mock() {
                format!("fixture:crates/agf-alicloud/src/mock.rs#{resource}")
            } else {
                format!("https://{}", self.core.endpoint_host().unwrap_or_default())
            },
        })
    }

    async fn self_check(&self) -> DomainResult<AdapterHealth> {
        let mut health = self.core.health_of();
        let checks = crate::selfcheck::service_checks(AliCloudService::SchedulerX3, &self.core, None);
        health.message = Some(crate::selfcheck::summarize_checks(&checks, self.core.mode()));
        Ok(health)
    }

    async fn shutdown(&mut self) -> DomainResult<()> {
        self.core.shutdown_common();
        self.client = None;
        Ok(())
    }
}
