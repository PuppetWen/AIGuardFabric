    first_seen_at         timestamptz NOT NULL DEFAULT now(),
    last_changed_at       timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_skills_name ON skills (tenant_id, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_skills_authz ON skills (tenant_id, authz);

CREATE TABLE IF NOT EXISTS skill_changes (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    skill_id              uuid NOT NULL REFERENCES skills(id) ON DELETE CASCADE,
    old_hash              text NOT NULL,
    new_hash              text NOT NULL,
    changed_fields        jsonb NOT NULL DEFAULT '[]'::jsonb,
    tampered              boolean NOT NULL DEFAULT false,
    note                  text,
    detected_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS prompt_templates (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    version               integer NOT NULL DEFAULT 1,
    content               text NOT NULL DEFAULT '',
    variables             jsonb NOT NULL DEFAULT '[]'::jsonb,
    tags                  jsonb NOT NULL DEFAULT '[]'::jsonb,
    enabled               boolean NOT NULL DEFAULT true,
    content_hash          text NOT NULL,
    scanned               boolean NOT NULL DEFAULT false,
    created_by            uuid,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_prompt_templates ON prompt_templates (tenant_id, name, version);

CREATE TABLE IF NOT EXISTS models (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider              text NOT NULL,
    model                 text NOT NULL,
    display_name          text NOT NULL DEFAULT '',
    modalities            jsonb NOT NULL DEFAULT '[]'::jsonb,
    context_window        integer,
    supports_tools        boolean NOT NULL DEFAULT false,
    supports_streaming    boolean NOT NULL DEFAULT true,
    pricing               jsonb NOT NULL DEFAULT '{}'::jsonb,
    known_jailbreak_prone boolean NOT NULL DEFAULT false,
    self_hostable         boolean NOT NULL DEFAULT false,
    regions               jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_models_provider_model ON models (provider, model);
COMMENT ON TABLE models IS '跨租户共享的模型目录（能力/价格/风险画像）';

CREATE TABLE IF NOT EXISTS model_endpoints (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id              uuid NOT NULL,
    name                  text NOT NULL,
    provider              text NOT NULL,
    base_url              text NOT NULL,
    model                 text NOT NULL,
    modalities            jsonb NOT NULL DEFAULT '[]'::jsonb,
    context_window        integer,
    max_output_tokens     integer,
    supports_streaming    boolean NOT NULL DEFAULT true,
    supports_tools        boolean NOT NULL DEFAULT false,
    credential_ref        uuid,
    local_deployment      boolean NOT NULL DEFAULT false,
    max_data_class        text NOT NULL DEFAULT 'internal',
    pricing               jsonb NOT NULL DEFAULT '{}'::jsonb,
    enabled               boolean NOT NULL DEFAULT true,
    fallback              boolean NOT NULL DEFAULT false,
    priority              integer NOT NULL DEFAULT 100,
    extra_headers         jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_model_endpoints_name ON model_endpoints (tenant_id, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_model_endpoints_route ON model_endpoints (tenant_id, enabled, priority);

CREATE TABLE IF NOT EXISTS credentials (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    kind                  text NOT NULL,
    purpose               text NOT NULL DEFAULT '',
    owner                 text,
    department            text,
    backend               text NOT NULL DEFAULT 'local-file',
    key_id                text NOT NULL,
    ciphertext_b64        text NOT NULL,
    nonce_b64             text NOT NULL,
    tag_b64               text,
    plaintext_len         integer NOT NULL DEFAULT 0,
    aad                   text,
    encrypted_at          timestamptz NOT NULL DEFAULT now(),
    masked                text NOT NULL DEFAULT '',
    fingerprint           text NOT NULL,
    used_by_assets        jsonb NOT NULL DEFAULT '[]'::jsonb,
    rotation_days         integer NOT NULL DEFAULT 0,
    last_rotated_at       timestamptz,
    next_rotation_at      timestamptz,
    expires_at            timestamptz,
    revoked               boolean NOT NULL DEFAULT false,
    revoked_at            timestamptz,
    platform_generated    boolean NOT NULL DEFAULT false,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);
CREATE INDEX IF NOT EXISTS ix_credentials_fingerprint ON credentials (tenant_id, fingerprint);
CREATE INDEX IF NOT EXISTS ix_credentials_rotation ON credentials (tenant_id, next_rotation_at) WHERE revoked = false;
COMMENT ON TABLE credentials IS '凭据仅以密文落库：ciphertext+nonce(+tag)，明文永不入库';

CREATE TABLE IF NOT EXISTS credential_leaks (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind                  text NOT NULL,
    context               text NOT NULL,
    source_ref            text NOT NULL,
    masked                text NOT NULL,
    fingerprint           text NOT NULL,
    confidence            real NOT NULL DEFAULT 0,
    severity              text NOT NULL DEFAULT 'medium',
    known_credential      boolean NOT NULL DEFAULT false,
    detected_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_credential_leaks_time ON credential_leaks (tenant_id, detected_at DESC);

-- ===========================================================================
-- 3. 风险、规则、红队
-- ===========================================================================

CREATE TABLE IF NOT EXISTS findings (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title                 text NOT NULL,
    severity              text NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    domain                text NOT NULL,
    category              text NOT NULL DEFAULT '',
    cwe                   text,
    cvss                  text,
    target                text NOT NULL,
    asset_id              uuid,
    summary               text NOT NULL DEFAULT '',
    description           text NOT NULL DEFAULT '',
    poc                   text NOT NULL DEFAULT '',
    fix                   text NOT NULL DEFAULT '',
    patch                 text,
    state                 text NOT NULL DEFAULT 'pending'
                          CHECK (state IN ('pending','code-reviewed','verified','false-positive','fixed')),
    evidence_level        text NOT NULL DEFAULT 'unknown'
                          CHECK (evidence_level IN ('unknown','partial','confirmed','impact')),
    evidence_refs         jsonb NOT NULL DEFAULT '[]'::jsonb,
    rule_ids              jsonb NOT NULL DEFAULT '[]'::jsonb,
    rule_keys             jsonb NOT NULL DEFAULT '[]'::jsonb,
    llm_verdict           jsonb,
    confidence            real NOT NULL DEFAULT 0,
    source_origin         text NOT NULL DEFAULT 'manual',
    audit_mode            text CHECK (audit_mode IN ('static','dynamic')),
    chain                 text,
    chain_tracer          text,
    chain_verdict         text,
    baseline              text,
    diff_evidence         text,
    marker_echo           text,
    request_pkt           text,
    response_pkt          text,
    impact                text,
    verify_note           text,
    retest_note           text,
    first_seen_at         timestamptz NOT NULL DEFAULT now(),
    last_seen_at          timestamptz NOT NULL DEFAULT now(),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);
CREATE INDEX IF NOT EXISTS ix_findings_state ON findings (tenant_id, state, severity);
CREATE INDEX IF NOT EXISTS ix_findings_domain ON findings (tenant_id, domain);
CREATE INDEX IF NOT EXISTS ix_findings_asset ON findings (asset_id);
CREATE INDEX IF NOT EXISTS ix_findings_time ON findings (tenant_id, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS finding_evidence (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id            uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    code                  text NOT NULL,
    kind                  text NOT NULL,
    summary               text NOT NULL DEFAULT '',
    content_hash          text NOT NULL,
    artifact_ref          text,
    collected_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_finding_evidence_code ON finding_evidence (finding_id, code);

CREATE TABLE IF NOT EXISTS risk_rules (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_key              text NOT NULL,
    name                  text NOT NULL,
    domain                text NOT NULL,
    severity              text NOT NULL,
    kind                  text NOT NULL,
    target                text NOT NULL,
    action                text NOT NULL DEFAULT 'audit',
    enabled               boolean NOT NULL DEFAULT true,
    rollout_percent       smallint NOT NULL DEFAULT 100 CHECK (rollout_percent BETWEEN 0 AND 100),
    tags                  jsonb NOT NULL DEFAULT '[]'::jsonb,
    references_           jsonb NOT NULL DEFAULT '[]'::jsonb,
    current_version       integer NOT NULL DEFAULT 1,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_risk_rules_key ON risk_rules (tenant_id, rule_key) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_risk_rules_domain ON risk_rules (tenant_id, domain, enabled);

CREATE TABLE IF NOT EXISTS rule_versions (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_key              text NOT NULL,
    version               integer NOT NULL,
    definition            jsonb NOT NULL,
    content_hash          text NOT NULL,
    state                 text NOT NULL DEFAULT 'draft'
                          CHECK (state IN ('draft','canary','published','retired')),
    positive_passed       integer NOT NULL DEFAULT 0,
    negative_passed       integer NOT NULL DEFAULT 0,
    sample_total          integer NOT NULL DEFAULT 0,
    published_by          uuid,
    published_at          timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_rule_versions ON rule_versions (tenant_id, rule_key, version);
CREATE INDEX IF NOT EXISTS ix_rule_versions_state ON rule_versions (tenant_id, state);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    job_kind              text NOT NULL,
    targets               jsonb NOT NULL DEFAULT '[]'::jsonb,
    rule_keys             jsonb NOT NULL DEFAULT '[]'::jsonb,
    state                 text NOT NULL DEFAULT 'queued'
                          CHECK (state IN ('queued','running','completed','failed','cancelled')),
    progress              smallint NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    total_targets         integer NOT NULL DEFAULT 0,
    scanned_targets       integer NOT NULL DEFAULT 0,
    findings_count        integer NOT NULL DEFAULT 0,
    error                 text,
    scheduled             boolean NOT NULL DEFAULT false,
    cron                  text,
    started_at            timestamptz,
    finished_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_scan_jobs_state ON scan_jobs (tenant_id, state, created_at DESC);

CREATE TABLE IF NOT EXISTS redteam_campaigns (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    target_agent_ids      jsonb NOT NULL DEFAULT '[]'::jsonb,
    target_mcp_ids        jsonb NOT NULL DEFAULT '[]'::jsonb,
    case_keys             jsonb NOT NULL DEFAULT '[]'::jsonb,
    categories            jsonb NOT NULL DEFAULT '[]'::jsonb,
    tags                  jsonb NOT NULL DEFAULT '[]'::jsonb,
    state                 text NOT NULL DEFAULT 'queued'
                          CHECK (state IN ('queued','running','completed','failed','cancelled')),
    launched_by           text NOT NULL DEFAULT '',
    scheduled             boolean NOT NULL DEFAULT false,
    cron                  text,
    ci_gate               boolean NOT NULL DEFAULT false,
    total_cases           integer NOT NULL DEFAULT 0,
    executed_cases        integer NOT NULL DEFAULT 0,
    succeeded_cases       integer NOT NULL DEFAULT 0,
    started_at            timestamptz,
    finished_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_redteam_campaigns_state ON redteam_campaigns (tenant_id, state, created_at DESC);

CREATE TABLE IF NOT EXISTS redteam_cases (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_key              text NOT NULL,
    title                 text NOT NULL,
    category              text NOT NULL,
    severity              text NOT NULL,
    mode                  text NOT NULL,
    definition            jsonb NOT NULL,
    public_poc            boolean NOT NULL DEFAULT false,
    enabled               boolean NOT NULL DEFAULT true,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_redteam_cases_key ON redteam_cases (tenant_id, case_key);

CREATE TABLE IF NOT EXISTS redteam_results (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    campaign_id           uuid NOT NULL REFERENCES redteam_campaigns(id) ON DELETE CASCADE,
    case_key              text NOT NULL,
    case_title            text NOT NULL DEFAULT '',
    category              text NOT NULL,
    target_asset_id       uuid NOT NULL,
    succeeded             boolean NOT NULL DEFAULT false,
    matched_signals       jsonb NOT NULL DEFAULT '[]'::jsonb,
    bypass_path           text,
    transcript            jsonb NOT NULL DEFAULT '[]'::jsonb,
    evidence_refs         jsonb NOT NULL DEFAULT '[]'::jsonb,
    evidence_level        text NOT NULL DEFAULT 'unknown',
    finding_id            uuid,
    latency_ms            bigint NOT NULL DEFAULT 0,
    model                 text NOT NULL DEFAULT '',
    mocked                boolean NOT NULL DEFAULT false,
    executed_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_redteam_results_campaign ON redteam_results (campaign_id, succeeded);

CREATE TABLE IF NOT EXISTS redteam_reports (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    campaign_id           uuid NOT NULL REFERENCES redteam_campaigns(id) ON DELETE CASCADE,
    title                 text NOT NULL,
    total_cases           integer NOT NULL DEFAULT 0,
    executed              integer NOT NULL DEFAULT 0,
    succeeded             integer NOT NULL DEFAULT 0,
    by_category           jsonb NOT NULL DEFAULT '[]'::jsonb,
    bypass_paths          jsonb NOT NULL DEFAULT '[]'::jsonb,
    remediations          jsonb NOT NULL DEFAULT '[]'::jsonb,
    finding_ids           jsonb NOT NULL DEFAULT '[]'::jsonb,
    verdict               text NOT NULL DEFAULT '',
    ci_passed             boolean NOT NULL DEFAULT false,
    markdown              text NOT NULL DEFAULT '',
    generated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_redteam_reports_campaign ON redteam_reports (campaign_id);

-- ===========================================================================
-- 4. 策略与配额
-- ===========================================================================

CREATE TABLE IF NOT EXISTS policies (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    description           text NOT NULL DEFAULT '',
    language              text NOT NULL DEFAULT 'structured' CHECK (language IN ('rego','cel','structured')),
    source                text NOT NULL DEFAULT '',
    structured            jsonb NOT NULL DEFAULT '{}'::jsonb,
    action                text NOT NULL DEFAULT 'audit',
    priority              integer NOT NULL DEFAULT 100,
    intercept_points      jsonb NOT NULL DEFAULT '[]'::jsonb,
    scope_agent_ids       jsonb NOT NULL DEFAULT '[]'::jsonb,
    scope_departments     jsonb NOT NULL DEFAULT '[]'::jsonb,
    enabled               boolean NOT NULL DEFAULT true,
    dry_run               boolean NOT NULL DEFAULT false,
    quota_id              uuid,
    degrade_endpoint_id   uuid,
    content_hash          text NOT NULL DEFAULT '',
    signature             text NOT NULL DEFAULT '',
    version               integer NOT NULL DEFAULT 1,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_policies_name ON policies (tenant_id, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_policies_priority ON policies (tenant_id, enabled, priority);

CREATE TABLE IF NOT EXISTS policy_versions (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_id             uuid NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version               integer NOT NULL,
    snapshot              jsonb NOT NULL,
    changed_by            uuid,
    change_note           text NOT NULL DEFAULT '',
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_policy_versions ON policy_versions (policy_id, version);

CREATE TABLE IF NOT EXISTS policy_hits (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_id             uuid NOT NULL,
    policy_name           text NOT NULL DEFAULT '',
    action                text NOT NULL,
    intercept_point       text NOT NULL,
    session_id            text NOT NULL DEFAULT '',
    agent_id              uuid,
    request_excerpt       text NOT NULL DEFAULT '',
    enforced              boolean NOT NULL DEFAULT false,
    overridden_by_approval boolean NOT NULL DEFAULT false,
    approval_id           uuid,
    at                    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_policy_hits_time ON policy_hits (tenant_id, at DESC);
CREATE INDEX IF NOT EXISTS ix_policy_hits_policy ON policy_hits (policy_id, at DESC);

CREATE TABLE IF NOT EXISTS quotas (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    scope                 text NOT NULL CHECK (scope IN ('tenant','agent','session')),
    dimension             text NOT NULL CHECK (dimension IN ('tokens','requests','concurrency','cost')),
    "window"              text NOT NULL CHECK ("window" IN ('minute','hour','day','month','session','total')),
    limit_                bigint NOT NULL,
    soft_threshold        bigint NOT NULL DEFAULT 0,
    on_exceed             text NOT NULL DEFAULT 'deny',
    enabled               boolean NOT NULL DEFAULT true,
    target_id             uuid,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
