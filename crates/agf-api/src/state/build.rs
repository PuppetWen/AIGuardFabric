//! `AppState::build` / `offline` / `with_database`：装配全部依赖（自 `state.rs` 拆出）。

use super::*;

impl AppState {
    pub fn offline(config: AppConfig) -> DomainResult<Self> {
        Self::build(config, None)
    }

    /// 构造状态（带 PostgreSQL 连接）。
    ///
    /// # Errors
    /// 同 [`Self::offline`]。
    pub fn with_database(config: AppConfig, store: Arc<agf_storage::Store>) -> DomainResult<Self> {
        Self::build(config, Some(store))
    }

    /// 构造状态。
    ///
    /// # Errors
    /// 规则包/红队用例库加载失败到无法降级时返回错误。
    pub fn build(config: AppConfig, database: Option<Arc<agf_storage::Store>>) -> DomainResult<Self> {
        let mut notes: Vec<String> = Vec::new();

        // ---- 令牌签发者：密钥过弱时降级为进程内临时密钥（生产由 enforce_safety 拦截）----
        let issuer = if config.security.jwt_secret_strong_enough() {
            TokenIssuer::new(
                &config.security.jwt_secret,
                config.security.jwt_issuer.clone(),
                JWT_AUDIENCE,
                config.security.jwt_access_ttl_secs,
                config.security.jwt_refresh_ttl_secs,
            )?
        } else {
            let ephemeral = agf_core::secret::generate_token();
            notes.push("AGF_JWT_SECRET 未配置或强度不足：已生成进程内临时 JWT 密钥（重启后令牌全部失效）".to_string());
            warn!("AGF_JWT_SECRET 缺失或过弱，使用进程内临时密钥");
            TokenIssuer::new(
                &ephemeral,
                config.security.jwt_issuer.clone(),
                JWT_AUDIENCE,
                config.security.jwt_access_ttl_secs,
                config.security.jwt_refresh_ttl_secs,
            )?
        };

        // ---- 口令策略 ----
        let policy = PasswordPolicy {
            min_length: config.security.password_min_length,
            max_failures: config.security.login_max_failures,
            lockout_secs: config.security.login_lockout_secs,
            deny_list: agf_core::auth::default_weak_passwords(),
            ..PasswordPolicy::default()
        };
        if !config.security.force_password_change {
            notes.push("AGF_FORCE_PASSWORD_CHANGE 已关闭：首登不再强制改密（不满足安全基线）".to_string());
        }
        let auth = AuthService::new(issuer, policy, config.security.fingerprint_salt.clone());

        // ---- 授权器：内置角色 ----
        let now = Timestamp::now();
        let roles: Vec<Role> = Role::builtin_definitions()
            .into_iter()
            .map(|(name, display, desc, perms)| Role {
                id: Id::new(),
                tenant_id: TenantId::default_tenant(),
                name: name.to_string(),
                display_name: display.to_string(),
                description: desc.to_string(),
                permissions: perms.iter().map(|p| agf_core::rbac::Permission::from_raw(*p)).collect(),
                builtin: true,
                created_at: now,
                updated_at: now,
            })
            .collect();
        let authorizer = Authorizer::from_parts(roles, Vec::new());

        // ---- 规则包（缺失时降级为内置最小集合）----
        let rules = Arc::new(load_rules(&config, &mut notes)?);

        // ---- 红队用例库（目录缺失/加载失败只降级，不阻断启动）----
        let redteam_cases = Arc::new(load_redteam_cases(&config, &mut notes));

        // ---- 解析器注册表（内置模板恒可用，目录模板按需叠加）----
        let parsers = Arc::new(load_parsers(&config, &mut notes));

        // ---- 回放用解析器注册表（同一加载来源的第二份实例；回放需要 &mut self）----
        //
        // 这里刻意**再加载一次**而不是改 `parsers` 的类型：`state.parsers` 被多个模块
        // （`routes::ingest`、`routes::console`、`routes::platform`）以只读方式使用，
        // 改成 `Arc<Mutex<_>>` 会波及不在本轮范围内的文件。第二份实例的告警/说明写进
        // 丢弃的 notes（避免 `/readyz` 的 notes 重复一行）。
        let mut replay_notes: Vec<String> = Vec::new();
        let replay_parsers = Arc::new(std::sync::Mutex::new(load_parsers(&config, &mut replay_notes)));

        // ---- 原始日志仓储（回放）+ 通知派发器（Mock 渠道）----
        let ingest_sink: Arc<dyn Sink> = match &database {
            Some(db) => Arc::new(agf_ingest::pipeline::SqlSink::new(db.clone()).with_event_outbox(config.nats.enabled)),
            None => Arc::new(InMemorySink::new()),
        };
        let notifier = Arc::new(tokio::sync::Mutex::new(
            NotificationDispatcher::new(DispatchConfig::default())
                .map_err(|e| DomainError::Config(format!("通知派发器装配失败: {e}")))?,
        ));

        // ---- 阿里云适配器注册表（无凭据 → 全部 Mock）----
        let alicloud = Arc::new(AliCloudRegistry::mock_only());
        let mock_modes: Vec<String> = alicloud
            .records()
            .into_iter()
            .filter(|r| r.mode.is_mock())
            .map(|r| r.service.as_str().to_string())
            .collect();
        if !mock_modes.is_empty() {
            notes.push(format!(
                "阿里云 {} 个服务适配器运行在 Mock 模式（无云凭据）：{}",
                mock_modes.len(),
                mock_modes.join(", ")
            ));
        }

        // ---- 运行时引擎 ----
        //
        // `RuntimeEngine::in_memory` 装配的**不是空黑名单**：它走 `in_memory_with(..., Blocklist::with_defaults(), ...)`，
        // 即 `agf_runtime::blocklist::default_rules()` 的 35+ 条内置最低防线（命令/域名/敏感路径/工具/哈希）。
        // 演示环境下策略集为空（0 条）是有意的：fixtures 的策略是 `Structured` 条件，
        // 其效果（提示注入拦截/审批/PII 脱敏）需要上游给出的 `risk_domains` 才能命中，
        // 灌进引擎只会造成"看着有策略其实不生效"；拦截演示统一由内置黑名单承担。
        let runtime = Arc::new(RuntimeEngine::in_memory(Vec::new(), Vec::new(), EngineConfig::default())?);

        // ---- 模型计量（真实计量链；见 `meter` 字段文档）----
        let meter = Arc::new(Meter::new());

        // ---- 数据层（PG 持久层 + 内存读缓存）----
        //
        // 装配顺序（有数据库时）：
        //   1. `PersistenceBridge::spawn`：建写后队列 + 启动消费者任务；
        //   2. 建 `ApiStore` 并挂上队列（写方法此后会产生写意图）；
        //   3. `hydrate_blocking`：**同步**把 PG 各资源读进内存缓存（重启不丢的关键）。
        //      水合走 `hydrate_*` 专用方法**只写内存、不入队**，因此不会把读回来的行再写回 PG
        //      （结构上排除了"启动即回写"的放大效应，见 `crate::persistence`）；
        //   4. 之后的写（含演示灌库）才真正经队列落 PG。
        let auth_backend: Arc<dyn AuthBackend> = match &database {
            Some(db) => Arc::new(crate::auth_store::SqlAuthBackend::new(Arc::clone(db))),
            None => Arc::new(InMemoryAuthBackend::new()),
        };
        let configurations = Arc::new(crate::config_store::ConfigStore::new(database.clone()));
        let auth_backend = Arc::new(crate::auth_store::protected::ProtectedBackend::new(
            auth_backend,
            configurations.clone(),
            &config.security.master_key_b64,
        )) as Arc<dyn AuthBackend>;
        let (store, persistence) = match database {
            Some(db) => {
                let bridge = PersistenceBridge::spawn(db);
                let base = Arc::new(ApiStore::with_database(Arc::clone(bridge.store())).with_journal(bridge.queue()));
                bridge.hydrate_blocking(&base);
                (base, Some(bridge))
            }
            None => (Arc::new(ApiStore::offline()), None),
        };
        store.quota_ensure_defaults(TenantId::default_tenant(), &config.quota)?;

        // ---- 演示数据灌库（`AGF_SEED_FIXTURES=1`，默认关闭；见 `crate::seed`）----
        //
        // PG 模式与离线内存模式下**都生效**：水合**之后**灌入，因此在已有数据之上叠加演示数据；
        // 有数据库时灌库同样经写后队列落 PG（`TODO(api-persistence)` 已由写后桥承接，
        // 事务性直写见 `TODO(api-persistence-tx)`）。任何失败都只降级告警，绝不阻断启动。
        if crate::seed::seed_enabled() {
            let seed_root = crate::seed::seed_dir(&config.project_root);
            match crate::seed::seed_demo_data(
                &store,
                &seed_root,
                TenantId::default_tenant(),
                &config.quota,
                &redteam_cases,
            ) {
                Ok(mut report) => {
                    // 驱动**真实组件**产出控制台上"接口通但恒为空"的两类数据：
                    // 运行时拦截审计（引擎自己的哈希链）与模型计量（`agf-aigw` 的 Meter）。
                    // 与 fixtures 灌库同一条降级铁律：失败只告警，不阻断启动、不返回 500。
                    if let Err(error) =
                        crate::seed::seed_runtime_interceptions(&runtime, TenantId::default_tenant(), &mut report)
                    {
                        warn!(error = %error, "演示运行时拦截灌入失败（服务继续启动，/runtime/events 可能为空）");
                        notes.push(format!("演示运行时拦截灌入失败（{error}），/runtime/events 可能为空"));
                    }
                    if let Err(error) =
                        crate::seed::seed_model_usage(&store, &meter, TenantId::default_tenant(), &mut report)
                    {
                        warn!(error = %error, "演示模型计量灌入失败（服务继续启动，/models/usage 可能为空）");
                        notes.push(format!("演示模型计量灌入失败（{error}），/models/usage 可能为空"));
                    }
                    for warning in &report.warnings {
                        warn!(warning = %warning, "演示数据灌库降级说明");
                    }
                    info!(
                        dir = %report.root,
                        inserted = report.total_inserted(),
                        errors = report.total_errors(),
                        runtime_events = report.inserted(crate::seed::DATASET_RUNTIME_EVENTS),
                        model_usage = report.inserted(crate::seed::DATASET_MODEL_USAGE),
                        summary = %report.summary(),
                        "演示数据灌库完成（AGF_SEED_FIXTURES=1；合成数据仅供演示，禁止用于生产）"
                    );
                    notes.push(format!("已灌入演示数据（AGF_SEED_FIXTURES=1）：{}", report.summary()));
                    // 原始日志（回放用）：`agf-ingest` 的 Replayer 只处理**未解析**的原始日志，
                    // 因此这里灌入的是 parsed=false 的合成样例；不灌则 `/ingest/replay` 恒为 0 条
                    // （那是"诚实的 0"，但面板看不到链路）。失败同样只降级。
                    match seed_replay_raw_logs(&ingest_sink, TenantId::default_tenant()) {
                        Ok(count) => {
                            info!(raw_logs = count, "演示原始日志已确保存在于回放仓储（供 /ingest/replay 使用）");
                            notes.push(format!(
                                "已处理 {count} 条演示原始日志样例（AGF_SEED_FIXTURES=1），供 /ingest/replay 真实回放"
                            ));
                        }
                        Err(error) => {
                            warn!(error = %error, "演示原始日志灌入失败（服务继续启动，/ingest/replay 可能为 0 条）");
                            notes.push(format!("演示原始日志灌入失败（{error}），/ingest/replay 可能为 0 条"));
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, dir = %seed_root.display(), "演示数据灌库失败（服务继续启动，列表页可能为空）");
                    notes.push(format!("演示数据灌库失败（{e}），相关列表页可能为空"));
                }
            }
        }

        let mode = if store.has_database() { ServiceMode::Database } else { ServiceMode::Offline };
        if mode.is_offline() {
            notes.push(
                "以离线内存模式启动：未配置数据库或数据库不可达，资产/发现/策略/告警/案件/报表等资源保存在进程内存中（重启即清空）"
                    .to_string(),
            );
        }
        // 有数据库时把写后持久化的**一致性口径、覆盖面与水合结果**如实写进 notes
        // （/readyz 与 /settings 直接引用 state.notes；routes/** 本轮不改，因此这是启动期快照）。
        match &persistence {
            Some(bridge) => notes.extend(bridge.report().notes()),
            None => notes.push("离线内存模式：无写后持久化桥（PersistenceBridge），所有写入只落进程内存".to_string()),
        }

        let cors_origins = Arc::new(resolve_cors_origins(&config));
        let (events, _rx) = tokio::sync::broadcast::channel(256);
        let started_at = Timestamp::now();
        // 恢复真实小时观测；历史文件异常时停用本次进程的自动写入，保留原始数据。
        //
        // **跨重启持久化**：启动时从 `history::default_path()`（`AGF_RISK_HISTORY_PATH` 可覆盖，
        // 默认 `<AGF_DATA_DIR>/state/risk-history.json`）把历史采样读回来回填；此后由一个后台任务
        // **周期性原子落盘**（见文件末尾 `spawn_risk_history_persister`）。读失败只 warn（损坏文件
        // 不会被删除，便于人工取证），绝不阻断启动——这是 `TODO(api-console-history)` 的长期面
        // （真正长期序列应由 Prometheus 承载）之外的本地兜底。
        let history_override = std::env::var_os(crate::history::ENV_RISK_HISTORY_PATH);
        let risk_history_path =
            crate::history::path_for(Some(std::ffi::OsStr::new(&config.data_dir)), history_override.as_deref());
        let risk_history = Arc::new(RiskHistory::new(started_at));
        let mut history_writable = true;
        match crate::history::load_from(&risk_history_path) {
            Ok(samples) if !samples.is_empty() => {
                let grouped = crate::history::group_by_tenant(&samples);
                let total: usize = grouped.values().map(Vec::len).sum();
                for (tenant, points) in grouped {
                    for sample in points {
                        risk_history.record(tenant, sample.ts, sample.value);
                    }
                }
                info!(
                    path = %risk_history_path.display(),
                    samples = total,
                    "风险趋势历史已从本地恢复（跨重启延续；长期序列仍应由 Prometheus 承载）"
                );
            }
            Ok(_) => {}
            Err(e) => {
                history_writable = false;
                warn!(
                    path = %risk_history_path.display(),
                    error = %e,
                    "风险趋势历史读取失败（按空历史继续；原文件保留以便人工排查）"
                );
            }
        }
        // 指标与运行时拦截链**同源**装配：`agf_runtime_interceptions_total{point,action}`
        // 在抓取时按链上条目增量同步（没有流量则为 0，但序列存在）。
        let metrics = Arc::new(Metrics::with_runtime(crate::VERSION, Arc::clone(&runtime))?);

        // 周期落盘（默认 5 分钟，可由 AGF_RISK_HISTORY_SAVE_SECS 覆盖；<5s 会被夹到 5s 防抖）。
        if history_writable {
            spawn_risk_history_persister(Arc::clone(&risk_history), risk_history_path);
        }

        let state = Self {
            #[cfg(feature = "test-loopback-transport")]
            gateway_test_transport: None,
            #[cfg(feature = "test-loopback-transport")]
            redteam_multi_test_transport: None,
            config: Arc::new(config),
            store,
            persistence,
            mode,
            notes: Arc::new(notes),
            auth: Arc::new(auth),
            auth_backend,
            configurations,
            model_asset_lock: Arc::new(tokio::sync::Mutex::new(())),
            soar_automation_lock: Arc::new(tokio::sync::Mutex::new(())),
            model_gateway: Arc::new(crate::model_gateway::GatewayRegistry::default()),
            integration_runtime: Arc::new(crate::integration_runtime::Registry::default()),
            privatelink_provisioning: std::sync::Arc::new(crate::privatelink_provisioning::Registry::default()),
            cloud_runtime: Arc::new(crate::cloud_runtime::Registry::default()),
            mse_config_publication: Arc::new(crate::mse_config_publication::Registry::default()),
            apig_policy_publication: Arc::new(crate::apig_policy_publication::Registry::default()),
            apig_configuration_publication: Arc::new(crate::apig_configuration_publication::Registry::default()),
            scheduler_native_observation: Arc::new(crate::scheduler_native_observation::Registry::default()),
            cms_queue: Arc::new(crate::cms_queue::Registry::default()),
            authorizer: Arc::new(authorizer),
            api_keys: Arc::new(ApiKeyService::new("agf-api-key-salt", API_KEY_PREFIX_LIVE)),
            rules,
            rule_cache: Arc::new(crate::rule_store::RuleCache::default()),
            redteam_cases,
            parsers,
            alicloud,
            runtime,
            meter,
            ingest_sink,
            runtime_registry: Arc::new(crate::runtime_registry::Registry::default()),
            ingest_pipelines: Arc::new(crate::ingest_pipelines::Registry::default()),
            replay_parsers,
            notifier,
            schedules: Arc::new(ScheduleStore::new()),
            scan_engine: Arc::new(ScanEngine::new()),
            metrics,
            limiter: Arc::new(RateLimiter::new(RateLimitTiers::default())),
            shared_rate_limit_required: std::env::var("AGF_SHARED_RATELIMIT_REQUIRED")
                .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true")),
            idempotency: Arc::new(IdempotencyStore::new(900)),
            events,
            nats: None,
            risk_history,
            started_at,
            default_tenant: TenantId::default_tenant(),
            cors_origins,
        };
        info!(
            mode = state.mode.as_str(),
            rules = state.rules.len(),
            redteam_cases = state.redteam_cases.cases().len(),
            parsers = state.parsers.all().len(),
            parsers_loaded = state.parsers.stats().loaded,
            parsers_builtin = state.parsers.stats().builtin,
            parsers_invalid = state.parsers.stats().invalid,
            "API 状态装配完成"
        );
        Ok(state)
    }
}
