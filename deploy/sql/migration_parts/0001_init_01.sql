-- =============================================================================
-- AIGuardFabric 初始迁移 0001_init.sql
-- 目标：PostgreSQL 16 + TimescaleDB
--
-- 约定（§7 数据库核心表）：
--   * 所有业务表带 tenant_id、created_at、updated_at、deleted_at（软删除）
--   * 主键统一 uuid（应用层生成 UUID v7，故无 DEFAULT，避免双写不一致）
--   * 关键表启用 RLS，策略基于 current_setting('agf.tenant_id')
--   * 迁移仅向前：本文件一经发布不再修改，变更走新文件
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 扩展
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";
-- TimescaleDB 为可选（无该扩展时 events 退化为普通表，功能不受影响）
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb') THEN
        CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
    ELSE
        RAISE NOTICE 'timescaledb 扩展不可用，events 将创建为普通表（功能降级但可用）';
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'timescaledb 扩展加载失败：%，events 退化普通表', SQLERRM;
END
$$;

-- ---------------------------------------------------------------------------
-- 通用触发器函数：自动维护 updated_at
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION agf_touch_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 会话变量取当前租户（RLS 用）
CREATE OR REPLACE FUNCTION agf_current_tenant() RETURNS uuid AS $$
BEGIN
    RETURN NULLIF(current_setting('agf.tenant_id', true), '')::uuid;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

-- ===========================================================================
-- 1. 租户、身份与权限
-- ===========================================================================

CREATE TABLE IF NOT EXISTS tenants (
    id                    uuid PRIMARY KEY,
    slug                  citext NOT NULL UNIQUE,
    name                  text NOT NULL,
    isolation             text NOT NULL DEFAULT 'logical' CHECK (isolation IN ('logical','physical')),
    physical_dsn_ref      text,
    default_data_class    text NOT NULL DEFAULT 'internal'
                          CHECK (default_data_class IN ('public','internal','confidential','restricted')),
    enabled               boolean NOT NULL DEFAULT true,
    branding              jsonb NOT NULL DEFAULT '{}'::jsonb,
    billing_enabled       boolean NOT NULL DEFAULT true,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);
COMMENT ON TABLE tenants IS '租户。支持逻辑隔离（同库 + RLS）与物理隔离（独立库/schema）';

CREATE TABLE IF NOT EXISTS users (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username              citext NOT NULL,
    email                 citext NOT NULL,
    password_hash         text,
    display_name          text NOT NULL DEFAULT '',
    phone                 text,
    department            text,
    idp                   text NOT NULL DEFAULT 'local'
                          CHECK (idp IN ('local','oidc','saml','ldap','qr-code')),
    external_subject      text,
    state                 text NOT NULL DEFAULT 'active'
                          CHECK (state IN ('invited','active','locked','disabled')),
    is_superadmin         boolean NOT NULL DEFAULT false,
    must_change_password  boolean NOT NULL DEFAULT true,
    mfa_enabled           boolean NOT NULL DEFAULT false,
    mfa_secret_ref        uuid,
    failed_logins         integer NOT NULL DEFAULT 0,
    locked_until          timestamptz,
    last_login_at         timestamptz,
    last_login_ip         inet,
    password_changed_at   timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_tenant_username ON users (tenant_id, lower(username)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_tenant_email ON users (tenant_id, lower(email)) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_users_tenant_state ON users (tenant_id, state);
COMMENT ON COLUMN users.password_hash IS 'Argon2id PHC 字符串；绝不通过 API 序列化';

CREATE TABLE IF NOT EXISTS roles (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    display_name          text NOT NULL DEFAULT '',
    description           text NOT NULL DEFAULT '',
    permissions           jsonb NOT NULL DEFAULT '[]'::jsonb,
    builtin               boolean NOT NULL DEFAULT false,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_roles_tenant_name ON roles (tenant_id, name) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS permissions (
    id                    uuid PRIMARY KEY,
    resource_group        text NOT NULL,
    action                text NOT NULL,
    code                  text NOT NULL UNIQUE,
    description           text NOT NULL DEFAULT '',
    created_at            timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE permissions IS '权限点字典（<资源组>:<动作>），由平台内置维护';

CREATE TABLE IF NOT EXISTS role_bindings (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_id            uuid NOT NULL,
    subject_kind          text NOT NULL CHECK (subject_kind IN ('user','api-key','agent','service')),
    role_id               uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    abac_condition        jsonb NOT NULL DEFAULT '{}'::jsonb,
    granted_at            timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz,
    granted_by            uuid,
    deleted_at            timestamptz
);
CREATE INDEX IF NOT EXISTS ix_role_bindings_subject ON role_bindings (tenant_id, subject_id, subject_kind);
CREATE UNIQUE INDEX IF NOT EXISTS ux_role_bindings ON role_bindings (tenant_id, subject_id, role_id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS api_keys (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    prefix                text NOT NULL,
    key_fingerprint       text NOT NULL UNIQUE,
    scopes                jsonb NOT NULL DEFAULT '[]'::jsonb,
    bound_agent_id        uuid,
    expires_at            timestamptz,
    last_used_at          timestamptz,
    allowed_cidrs         jsonb NOT NULL DEFAULT '[]'::jsonb,
    revoked               boolean NOT NULL DEFAULT false,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);
CREATE INDEX IF NOT EXISTS ix_api_keys_prefix ON api_keys (prefix);
COMMENT ON COLUMN api_keys.key_fingerprint IS 'SHA-256(盐||明文) hex；明文仅在创建响应中返回一次';

CREATE TABLE IF NOT EXISTS login_attempts (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid,
    username              text NOT NULL,
    source_ip             inet,
    user_agent            text,
    success               boolean NOT NULL,
    failure_code          text,
    at                    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_login_attempts_at ON login_attempts (at DESC);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id               uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_fingerprint     text NOT NULL UNIQUE,
    device                text,
    expires_at            timestamptz NOT NULL,
    revoked               boolean NOT NULL DEFAULT false,
    revoked_reason        text,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_user ON refresh_tokens (user_id, revoked);

CREATE TABLE IF NOT EXISTS mfa_enrollments (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id               uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method                text NOT NULL CHECK (method IN ('totp','webauthn','sms','email','recovery-code')),
    confirmed             boolean NOT NULL DEFAULT false,
    secret_ref            uuid,
    recovery_hashes       jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    last_used_at          timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_mfa_user_method ON mfa_enrollments (user_id, method);

CREATE TABLE IF NOT EXISTS idp_configs (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider              text NOT NULL CHECK (provider IN ('oidc','saml','ldap','qr-code')),
    display_name          text NOT NULL,
    enabled               boolean NOT NULL DEFAULT false,
    issuer                text,
    client_id             text,
    client_secret_ref     uuid,
    scopes                jsonb NOT NULL DEFAULT '[]'::jsonb,
    username_claim        text,
    department_claim      text,
    auto_provision        boolean NOT NULL DEFAULT false,
    default_roles         jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS approval_requests (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    requester_id          uuid NOT NULL,
    target                text NOT NULL,
    action                text NOT NULL,
    reason                text NOT NULL DEFAULT '',
    ttl_secs              bigint NOT NULL DEFAULT 3600,
    state                 text NOT NULL DEFAULT 'pending'
                          CHECK (state IN ('pending','approved','rejected','expired','revoked')),
    approver_id           uuid,
    decision_note         text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    decided_at            timestamptz
);
CREATE INDEX IF NOT EXISTS ix_approval_requests_state ON approval_requests (tenant_id, state);

-- ===========================================================================
-- 2. 资产域
-- ===========================================================================

CREATE TABLE IF NOT EXISTS asset_types (
    id                    uuid PRIMARY KEY,
    code                  text NOT NULL UNIQUE,
    display_name          text NOT NULL,
    category              text NOT NULL DEFAULT '',
    schema                jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS assets (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind                  text NOT NULL,
    name                  text NOT NULL,
    fingerprint           text NOT NULL,
    vendor                text,
    version               text,
    protocol              text,
    endpoint              text,
    owner                 text,
    department            text,
    data_class            text NOT NULL DEFAULT 'internal'
                          CHECK (data_class IN ('public','internal','confidential','restricted')),
    lifecycle             text NOT NULL DEFAULT 'trial'
                          CHECK (lifecycle IN ('requested','under-review','trial','production','changing','archived','rejected')),
    discovery_source      text NOT NULL DEFAULT 'manual',
    exposure_score        smallint NOT NULL DEFAULT 0 CHECK (exposure_score BETWEEN 0 AND 100),
    risk_score            smallint CHECK (risk_score BETWEEN 0 AND 100),
    runtime               text,
    network_zone          text,
    cloud_resource_id     text,
    tags                  jsonb NOT NULL DEFAULT '[]'::jsonb,
    attributes            jsonb NOT NULL DEFAULT '{}'::jsonb,
    dependencies          jsonb NOT NULL DEFAULT '[]'::jsonb,
    last_seen_at          timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_assets_fingerprint ON assets (tenant_id, fingerprint) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_assets_kind ON assets (tenant_id, kind) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_assets_exposure ON assets (tenant_id, exposure_score DESC) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_assets_attributes ON assets USING gin (attributes);

CREATE TABLE IF NOT EXISTS asset_relations (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    from_asset_id         uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    to_asset_id           uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    edge_kind             text NOT NULL,
    note                  text,
    discovered_at         timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_asset_relations ON asset_relations (from_asset_id, to_asset_id, edge_kind);
CREATE INDEX IF NOT EXISTS ix_asset_relations_to ON asset_relations (to_asset_id);

CREATE TABLE IF NOT EXISTS asset_snapshots (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    snapshot_date         date NOT NULL,
    asset_id              uuid NOT NULL,
    kind                  text NOT NULL,
    payload               jsonb NOT NULL,
    content_hash          text NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_asset_snapshots ON asset_snapshots (tenant_id, snapshot_date, asset_id);
CREATE INDEX IF NOT EXISTS ix_asset_snapshots_hash ON asset_snapshots (tenant_id, snapshot_date, content_hash);

CREATE TABLE IF NOT EXISTS asset_changes (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id              uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    kind                  text NOT NULL,
    change_kind           text NOT NULL CHECK (change_kind IN ('added','removed','modified')),
    field                 text,
    old_value             jsonb,
    new_value             jsonb,
    risky                 boolean NOT NULL DEFAULT false,
    risk_note             text,
    domain                text,
    detected_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_asset_changes_time ON asset_changes (tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS ix_asset_changes_risky ON asset_changes (tenant_id, risky) WHERE risky;

CREATE TABLE IF NOT EXISTS asset_onboardings (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind                  text NOT NULL,
    name                  text NOT NULL,
    requester             text NOT NULL,
    department            text,
    purpose               text NOT NULL DEFAULT '',
    data_class            text NOT NULL DEFAULT 'internal',
    state                 text NOT NULL DEFAULT 'requested',
    reviewer              text,
    review_note           text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    decided_at            timestamptz
);
CREATE INDEX IF NOT EXISTS ix_asset_onboardings_state ON asset_onboardings (tenant_id, state);

CREATE TABLE IF NOT EXISTS agents (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id              uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    flavor                text NOT NULL DEFAULT 'unknown',
    version               text,
    host                  text NOT NULL DEFAULT '',
    os                    text,
    os_user               text,
    owner                 text,
    department            text,
    onboarding_mode       text NOT NULL DEFAULT 'observe-only'
                          CHECK (onboarding_mode IN ('sidecar','sdk-injection','gateway-registration','observe-only')),
    lifecycle             text NOT NULL DEFAULT 'trial',
    data_class            text NOT NULL DEFAULT 'internal',
    mcp_servers           jsonb NOT NULL DEFAULT '[]'::jsonb,
    model_endpoints       jsonb NOT NULL DEFAULT '[]'::jsonb,
    config_hash           text,
    collector_id          text,
    last_heartbeat_at     timestamptz,
    heartbeat_interval_secs bigint NOT NULL DEFAULT 60,
    discovery_source      text NOT NULL DEFAULT 'agent-report',
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);
CREATE INDEX IF NOT EXISTS ix_agents_flavor ON agents (tenant_id, flavor);
CREATE INDEX IF NOT EXISTS ix_agents_heartbeat ON agents (tenant_id, last_heartbeat_at DESC);
CREATE INDEX IF NOT EXISTS ix_agents_collector ON agents (collector_id);

CREATE TABLE IF NOT EXISTS mcps (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id              uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    transport             text NOT NULL CHECK (transport IN ('stdio','sse','http','websocket')),
    command               text,
    args                  jsonb NOT NULL DEFAULT '[]'::jsonb,
    url                   text,
    protocol_version      text,
    server_info           jsonb,
    capabilities          jsonb NOT NULL DEFAULT '{}'::jsonb,
    tools                 jsonb NOT NULL DEFAULT '[]'::jsonb,
    resources             jsonb NOT NULL DEFAULT '[]'::jsonb,
    prompts               jsonb NOT NULL DEFAULT '[]'::jsonb,
    env_keys              jsonb NOT NULL DEFAULT '[]'::jsonb,
    has_plaintext_secret  boolean NOT NULL DEFAULT false,
    requires_auth         boolean NOT NULL DEFAULT false,
    owner                 text,
    department            text,
    registered            boolean NOT NULL DEFAULT false,
    last_handshake_at     timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_mcps_asset_name ON mcps (tenant_id, asset_id, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_mcps_shadow ON mcps (tenant_id) WHERE NOT registered;

CREATE TABLE IF NOT EXISTS skills (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id              uuid NOT NULL,
    name                  text NOT NULL,
    display_name          text NOT NULL DEFAULT '',
    description           text NOT NULL DEFAULT '',
    origin                text NOT NULL DEFAULT 'mcp-tool',
    provider_asset_id     uuid,
    input_schema          jsonb NOT NULL DEFAULT '{}'::jsonb,
    traits                jsonb NOT NULL DEFAULT '{}'::jsonb,
    sensitive_params      jsonb NOT NULL DEFAULT '[]'::jsonb,
    authz                 text NOT NULL DEFAULT 'pending'
                          CHECK (authz IN ('approved','pending','denied','revoked')),
    allowed_subjects      jsonb NOT NULL DEFAULT '[]'::jsonb,
    network_allowed       boolean NOT NULL DEFAULT false,
    domain_allowlist      jsonb NOT NULL DEFAULT '[]'::jsonb,
    path_allowlist        jsonb NOT NULL DEFAULT '[]'::jsonb,
    max_data_class        text NOT NULL DEFAULT 'internal',
    content_hash          text,
    risk_score            smallint NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
