);

CREATE TABLE IF NOT EXISTS schedules (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    job_kind              text NOT NULL,
    cron                  text NOT NULL,
    backend               text NOT NULL DEFAULT 'local-cron'
                          CHECK (backend IN ('schedulerx3','local-cron','k8s-cronjob','interval')),
    cloud_job_id          text,
    shard_count           integer NOT NULL DEFAULT 1,
    max_retries           integer NOT NULL DEFAULT 3,
    depends_on            jsonb NOT NULL DEFAULT '[]'::jsonb,
    enabled               boolean NOT NULL DEFAULT true,
    last_run_at           timestamptz,
    last_result           text,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_schedules_name ON schedules (tenant_id, name);

CREATE TABLE IF NOT EXISTS cloud_integrations (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider              text NOT NULL,
    name                  text NOT NULL,
    account_id            text NOT NULL DEFAULT '',
    region_id             text NOT NULL DEFAULT '',
    credential_kind       text NOT NULL DEFAULT 'instance-role',
    credential_ref        uuid,
    assume_role_arn       text,
    role_session_name     text,
    sts_expires_at        timestamptz,
    endpoints             jsonb NOT NULL DEFAULT '{}'::jsonb,
    enabled               boolean NOT NULL DEFAULT false,
    health                text NOT NULL DEFAULT 'unconfigured',
    last_sync_at          timestamptz,
    last_error            text,
    permission_checks     jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cloud_integrations_name ON cloud_integrations (tenant_id, provider, name);

CREATE TABLE IF NOT EXISTS alicloud_bindings (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    integration_id        uuid NOT NULL REFERENCES cloud_integrations(id) ON DELETE CASCADE,
    service               text NOT NULL,
    endpoint              text,
    region_id             text NOT NULL DEFAULT '',
    settings              jsonb NOT NULL DEFAULT '{}'::jsonb,
    enabled               boolean NOT NULL DEFAULT false,
    health                text NOT NULL DEFAULT 'unconfigured',
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_alicloud_bindings ON alicloud_bindings (integration_id, service);

CREATE TABLE IF NOT EXISTS cloud_resources (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    integration_id        uuid NOT NULL REFERENCES cloud_integrations(id) ON DELETE CASCADE,
    service               text NOT NULL,
    resource_id           text NOT NULL,
    resource_kind         text NOT NULL DEFAULT '',
    asset_id              uuid,
    attributes            jsonb NOT NULL DEFAULT '{}'::jsonb,
    stale                 boolean NOT NULL DEFAULT false,
    discovered_at         timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cloud_resources ON cloud_resources (integration_id, service, resource_id);

CREATE TABLE IF NOT EXISTS agent_teams (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cloud_team_id         text NOT NULL,
    name                  text NOT NULL,
    description           text NOT NULL DEFAULT '',
    agents                jsonb NOT NULL DEFAULT '[]'::jsonb,
    roles                 jsonb NOT NULL DEFAULT '[]'::jsonb,
    orchestration         jsonb NOT NULL DEFAULT '[]'::jsonb,
    onboarding            text NOT NULL DEFAULT 'sidecar',
    synced                boolean NOT NULL DEFAULT false,
    cloud_updated_at      timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_agent_teams_cloud_id ON agent_teams (tenant_id, cloud_team_id);

CREATE TABLE IF NOT EXISTS cross_team_calls (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    from_team_id          text NOT NULL,
    from_agent_id         text NOT NULL,
    to_team_id            text NOT NULL,
    to_agent_id           text NOT NULL,
    call_kind             text NOT NULL DEFAULT 'a2a',
    cross_account         boolean NOT NULL DEFAULT false,
    blocked               boolean NOT NULL DEFAULT false,
    latency_ms            bigint NOT NULL DEFAULT 0,
    at                    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_cross_team_calls_time ON cross_team_calls (tenant_id, at DESC);

CREATE TABLE IF NOT EXISTS quota_sync_states (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    integration_id        uuid NOT NULL REFERENCES cloud_integrations(id) ON DELETE CASCADE,
    dimension             text NOT NULL,
    platform_value        bigint NOT NULL DEFAULT 0,
    cloud_value           bigint NOT NULL DEFAULT 0,
    conflict              boolean NOT NULL DEFAULT false,
    effective_value       bigint NOT NULL DEFAULT 0,
    conflict_alerted      boolean NOT NULL DEFAULT false,
    synced_at             timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_quota_sync_states ON quota_sync_states (integration_id, dimension);

CREATE TABLE IF NOT EXISTS adapter_configs (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    adapter               text NOT NULL,
    display_name          text NOT NULL DEFAULT '',
    enabled               boolean NOT NULL DEFAULT false,
    settings              jsonb NOT NULL DEFAULT '{}'::jsonb,
    secret_refs           jsonb NOT NULL DEFAULT '{}'::jsonb,
    circuit_breaker       jsonb NOT NULL DEFAULT '{}'::jsonb,
    retry                 jsonb NOT NULL DEFAULT '{}'::jsonb,
    timeout_secs          integer NOT NULL DEFAULT 30,
    mock                  boolean NOT NULL DEFAULT false,
    is_default            boolean NOT NULL DEFAULT false,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_adapter_configs ON adapter_configs (tenant_id, adapter, display_name);

CREATE TABLE IF NOT EXISTS adapter_health (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    adapter               text NOT NULL,
    state                 text NOT NULL DEFAULT 'unconfigured',
    configured            boolean NOT NULL DEFAULT false,
    mocked                boolean NOT NULL DEFAULT false,
    latency_ms            bigint,
    circuit               jsonb NOT NULL DEFAULT '{}'::jsonb,
    capabilities          jsonb NOT NULL DEFAULT '[]'::jsonb,
    message               text,
    checked_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_adapter_health_time ON adapter_health (tenant_id, adapter, checked_at DESC);

CREATE TABLE IF NOT EXISTS dead_letters (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    adapter               text NOT NULL,
    operation             text NOT NULL,
    payload               jsonb NOT NULL DEFAULT '{}'::jsonb,
    error                 text NOT NULL DEFAULT '',
    attempts              integer NOT NULL DEFAULT 0,
    replayed              boolean NOT NULL DEFAULT false,
    first_failed_at       timestamptz NOT NULL DEFAULT now(),
    last_failed_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_dead_letters_adapter ON dead_letters (tenant_id, adapter, last_failed_at DESC);

CREATE TABLE IF NOT EXISTS usage_records (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    session_id            text NOT NULL DEFAULT '',
    agent_id              uuid,
    endpoint_id           uuid NOT NULL,
    provider              text NOT NULL,
    model                 text NOT NULL,
    prompt_tokens         bigint NOT NULL DEFAULT 0,
    completion_tokens     bigint NOT NULL DEFAULT 0,
    cached_tokens         bigint NOT NULL DEFAULT 0,
    cache_hit             boolean NOT NULL DEFAULT false,
    cost_micro            bigint NOT NULL DEFAULT 0,
    mocked                boolean NOT NULL DEFAULT false,
    latency_ms            bigint NOT NULL DEFAULT 0,
    at                    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_usage_records_time ON usage_records (tenant_id, at DESC);
CREATE INDEX IF NOT EXISTS ix_usage_records_billing ON usage_records (tenant_id, provider, model, at);

CREATE TABLE IF NOT EXISTS semantic_cache (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_fingerprint   text NOT NULL,
    embedding             jsonb,
    response              jsonb NOT NULL,
    endpoint_id           uuid NOT NULL,
    saved_prompt_tokens   bigint NOT NULL DEFAULT 0,
    saved_micro           bigint NOT NULL DEFAULT 0,
    hits                  bigint NOT NULL DEFAULT 0,
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_semantic_cache ON semantic_cache (tenant_id, request_fingerprint);

CREATE TABLE IF NOT EXISTS tenant_settings (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key                   text NOT NULL,
    value                 jsonb NOT NULL DEFAULT '{}'::jsonb,
    encrypted             boolean NOT NULL DEFAULT false,
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_tenant_settings ON tenant_settings (tenant_id, key);

-- ===========================================================================
-- 8. updated_at 触发器
-- ===========================================================================
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'tenants','users','roles','assets','asset_types','agents','mcps','skills',
        'model_endpoints','credentials','findings','risk_rules','policies','quotas',
        'log_sources','parsers','alerts','cases','notification_channels','reports',
        'cloud_integrations','alicloud_bindings','agent_teams','adapter_configs',
        'redteam_cases','scan_jobs','prompt_templates','playbooks'
    ]
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS trg_%1$s_touch ON %1$s', t);
        EXECUTE format(
            'CREATE TRIGGER trg_%1$s_touch BEFORE UPDATE ON %1$s FOR EACH ROW EXECUTE FUNCTION agf_touch_updated_at()',
            t
        );
    END LOOP;
END
$$;

-- ===========================================================================
-- 9. RLS：为多租户表启用行级隔离
--    应用层每个连接以 SET LOCAL agf.tenant_id = '<uuid>' 声明身份
-- ===========================================================================
DO $$
DECLARE
    t text;
    rls_tables text[] := ARRAY[
        'users','roles','role_bindings','api_keys','assets','asset_relations','asset_snapshots',
        'asset_changes','agents','mcps','skills','model_endpoints','credentials','credential_leaks',
        'findings','finding_evidence','risk_rules','rule_versions','scan_jobs','redteam_campaigns',
        'redteam_cases','redteam_results','redteam_reports','policies','policy_versions','policy_hits',
        'quotas','quota_usage','log_sources','parsers','raw_logs','collector_registrations','alerts',
        'aggregation_policies','escalation_rules','cases','case_events','notification_channels',
        'notifications','playbooks','playbook_runs','audit_logs','reports','cloud_integrations',
        'cloud_resources','agent_teams','adapter_configs','usage_records','semantic_cache','tenant_settings'
    ];
BEGIN
    FOREACH t IN ARRAY rls_tables LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS p_%1$s_tenant ON %1$s', t);
        EXECUTE format(
            'CREATE POLICY p_%1$s_tenant ON %1$s USING (tenant_id = agf_current_tenant()) WITH CHECK (tenant_id = agf_current_tenant())',
            t
        );
    END LOOP;
END
$$;

-- events 表策略单独处理（复合主键，无 tenant_id 外键约束）
DO $$
BEGIN
    EXECUTE 'ALTER TABLE events ENABLE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS p_events_tenant ON events';
    EXECUTE 'CREATE POLICY p_events_tenant ON events USING (tenant_id = agf_current_tenant()) WITH CHECK (tenant_id = agf_current_tenant())';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'events RLS 配置跳过：%', SQLERRM;
END
$$;

-- 超级管理员旁路角色（平台运维用；应用正常连接不使用该角色）
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agf_platform_admin') THEN
        CREATE ROLE agf_platform_admin NOLOGIN BYPASSRLS;
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE '创建 agf_platform_admin 角色跳过：%', SQLERRM;
END
$$;

-- ===========================================================================
-- 10. 种子数据：默认租户 + 权限点字典
-- ===========================================================================
INSERT INTO tenants (id, slug, name, isolation, default_data_class, enabled, branding)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'default',
    '默认租户',
    'logical',
    'internal',
    true,
    '{"product_name":"AIGuardFabric 智御矩阵","primary_color":"#1677ff","default_locale":"zh-CN"}'::jsonb
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO permissions (id, resource_group, action, code, description) VALUES
    (gen_random_uuid(), 'assets', 'read', 'assets:read', '查看资产台账'),
    (gen_random_uuid(), 'assets', 'write', 'assets:write', '创建/修改资产'),
    (gen_random_uuid(), 'assets', 'delete', 'assets:delete', '删除资产'),
    (gen_random_uuid(), 'agents', 'read', 'agents:read', '查看 Agent'),
    (gen_random_uuid(), 'agents', 'write', 'agents:write', '管理 Agent'),
    (gen_random_uuid(), 'mcps', 'read', 'mcps:read', '查看 MCP'),
    (gen_random_uuid(), 'mcps', 'write', 'mcps:write', '管理 MCP'),
    (gen_random_uuid(), 'skills', 'read', 'skills:read', '查看 Skill'),
    (gen_random_uuid(), 'skills', 'write', 'skills:write', '管理 Skill'),
    (gen_random_uuid(), 'models', 'read', 'models:read', '查看模型端点'),
    (gen_random_uuid(), 'models', 'write', 'models:write', '管理模型端点'),
    (gen_random_uuid(), 'findings', 'read', 'findings:read', '查看风险发现'),
    (gen_random_uuid(), 'findings', 'write', 'findings:write', '修改风险发现'),
    (gen_random_uuid(), 'rules', 'read', 'rules:read', '查看检测规则'),
    (gen_random_uuid(), 'rules', 'write', 'rules:write', '编辑检测规则'),
    (gen_random_uuid(), 'scans', 'read', 'scans:read', '查看扫描任务'),
    (gen_random_uuid(), 'scans', 'execute', 'scans:execute', '执行扫描'),
    (gen_random_uuid(), 'redteam', 'read', 'redteam:read', '查看红队结果'),
    (gen_random_uuid(), 'redteam', 'execute', 'redteam:execute', '执行红队'),
    (gen_random_uuid(), 'policies', 'read', 'policies:read', '查看策略'),
    (gen_random_uuid(), 'policies', 'write', 'policies:write', '编辑策略'),
    (gen_random_uuid(), 'quotas', 'read', 'quotas:read', '查看配额'),
    (gen_random_uuid(), 'quotas', 'write', 'quotas:write', '管理配额'),
    (gen_random_uuid(), 'alerts', 'read', 'alerts:read', '查看告警'),
    (gen_random_uuid(), 'alerts', 'write', 'alerts:write', '处置告警'),
    (gen_random_uuid(), 'cases', 'read', 'cases:read', '查看案件'),
    (gen_random_uuid(), 'cases', 'write', 'cases:write', '处置案件'),
    (gen_random_uuid(), 'sources', 'read', 'sources:read', '查看日志源'),
    (gen_random_uuid(), 'sources', 'write', 'sources:write', '管理日志源'),
    (gen_random_uuid(), 'parsers', 'read', 'parsers:read', '查看解析器'),
    (gen_random_uuid(), 'parsers', 'write', 'parsers:write', '管理解析器'),
    (gen_random_uuid(), 'integrations', 'read', 'integrations:read', '查看集成'),
    (gen_random_uuid(), 'integrations', 'write', 'integrations:write', '管理集成'),
    (gen_random_uuid(), 'alicloud', 'read', 'alicloud:read', '查看阿里云集成'),
    (gen_random_uuid(), 'alicloud', 'write', 'alicloud:write', '管理阿里云集成'),
    (gen_random_uuid(), 'audit', 'read', 'audit:read', '查看审计日志'),
    (gen_random_uuid(), 'audit', 'export', 'audit:export', '导出审计日志'),
    (gen_random_uuid(), 'reports', 'read', 'reports:read', '查看报表'),
    (gen_random_uuid(), 'reports', 'write', 'reports:write', '生成报表'),
    (gen_random_uuid(), 'settings', 'read', 'settings:read', '查看设置'),
    (gen_random_uuid(), 'settings', 'write', 'settings:write', '修改设置'),
    (gen_random_uuid(), 'platform', 'admin', 'platform:admin', '平台管理（租户/用户/角色）')
ON CONFLICT (code) DO NOTHING;

INSERT INTO roles (id, tenant_id, name, display_name, description, permissions, builtin) VALUES
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'superadmin', '平台超级管理员',
     '跨租户平台运维', '["*"]'::jsonb, true),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'tenant-admin', '租户管理员',
     '本租户内全部管理权限',
     '["assets:*","agents:*","mcps:*","skills:*","models:*","findings:*","rules:*","scans:*","redteam:*","policies:*","quotas:*","alerts:*","cases:*","sources:*","parsers:*","integrations:*","alicloud:*","audit:read","audit:export","reports:*","settings:*","platform:admin"]'::jsonb,
     true),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'soc-analyst', '安全运营',
     '告警研判与案件处置',
     '["assets:read","findings:read","alerts:read","alerts:write","cases:read","cases:write","reports:read","reports:write","scans:read","redteam:read"]'::jsonb,
     true),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'redteam-engineer', '红队工程师',
     '红队用例编排与执行',
     '["assets:read","findings:read","findings:write","redteam:*","scans:read","scans:execute","rules:read","reports:read"]'::jsonb,
     true),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'auditor', '审计员',
     '只读与审计导出',
     '["audit:read","audit:export","reports:read","assets:read","findings:read","cases:read"]'::jsonb,
     true),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'viewer', '只读观察者',
     '控制台只读',
     '["assets:read","findings:read","alerts:read","cases:read","reports:read"]'::jsonb,
     true),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'asset-owner', '资产负责人',
     '仅本部门资产（ABAC 生效）',
     '["assets:read","assets:write","agents:read","mcps:read","findings:read"]'::jsonb,
     true)
ON CONFLICT DO NOTHING;

-- 资产类型字典
INSERT INTO asset_types (id, code, display_name, category) VALUES
    (gen_random_uuid(), 'agent', 'AI Agent', 'ai'),
    (gen_random_uuid(), 'mcp-server', 'MCP Server', 'ai'),
    (gen_random_uuid(), 'mcp-client', 'MCP Client', 'ai'),
    (gen_random_uuid(), 'skill', 'Skill / Tool', 'ai'),
    (gen_random_uuid(), 'prompt-template', 'Prompt 模板', 'ai'),
    (gen_random_uuid(), 'rag-kb', 'RAG 知识库', 'data'),
    (gen_random_uuid(), 'vector-store', '向量库', 'data'),
    (gen_random_uuid(), 'model-endpoint', '模型端点', 'ai'),
    (gen_random_uuid(), 'credential', '凭据', 'security'),
    (gen_random_uuid(), 'compute-node', '算力节点', 'infra'),
    (gen_random_uuid(), 'ide-plugin', 'IDE 插件', 'ai'),
    (gen_random_uuid(), 'collector', '南向采集器', 'infra'),
    (gen_random_uuid(), 'data-source', '数据源', 'data'),
    (gen_random_uuid(), 'other', '其他', 'other')
ON CONFLICT (code) DO NOTHING;

-- ===========================================================================
-- 11. 默认配额（三级）
-- ===========================================================================
INSERT INTO quotas (id, tenant_id, name, scope, dimension, "window", limit_, soft_threshold, on_exceed, enabled, target_id) VALUES
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'tenant-default-tokens', 'tenant', 'tokens', 'day', 5000000, 4000000, 'deny', true, NULL),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'tenant-default-requests', 'tenant', 'requests', 'minute', 6000, 4800, 'throttle', true, NULL),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'agent-default-tokens', 'agent', 'tokens', 'day', 500000, 400000, 'throttle', true, NULL),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'session-default-tokens', 'session', 'tokens', 'session', 100000, 80000, 'degrade', true, NULL)
ON CONFLICT DO NOTHING;
