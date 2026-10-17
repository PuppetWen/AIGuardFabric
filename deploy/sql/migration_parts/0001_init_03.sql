);
CREATE UNIQUE INDEX IF NOT EXISTS ux_quotas_scope ON quotas (tenant_id, scope, dimension, "window", coalesce(target_id, '00000000-0000-0000-0000-000000000000'::uuid));

CREATE TABLE IF NOT EXISTS quota_usage (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    quota_id              uuid NOT NULL,
    scope                 text NOT NULL,
    dimension             text NOT NULL,
    "window"              text NOT NULL,
    bucket                text NOT NULL,
    target_id             uuid,
    used                  bigint NOT NULL DEFAULT 0,
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_quota_usage ON quota_usage (quota_id, bucket, coalesce(target_id, '00000000-0000-0000-0000-000000000000'::uuid));
CREATE INDEX IF NOT EXISTS ix_quota_usage_tenant ON quota_usage (tenant_id, "window", bucket);

-- ===========================================================================
-- 5. 日志接入、归一化与告警
-- ===========================================================================

CREATE TABLE IF NOT EXISTS log_sources (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    protocol              text NOT NULL,
    vendor                text NOT NULL DEFAULT '',
    product               text NOT NULL DEFAULT '',
    enabled               boolean NOT NULL DEFAULT true,
    parser_id             uuid,
    connection            jsonb NOT NULL DEFAULT '{}'::jsonb,
    mode                  text NOT NULL DEFAULT 'push'
                          CHECK (mode IN ('push','pull','poll','subscribe','tail')),
    poll_interval_secs    bigint,
    require_mtls          boolean NOT NULL DEFAULT false,
    allowed_cidrs         jsonb NOT NULL DEFAULT '[]'::jsonb,
    max_message_bytes     integer NOT NULL DEFAULT 1048576,
    max_eps               integer NOT NULL DEFAULT 10000,
    tags                  jsonb NOT NULL DEFAULT '[]'::jsonb,
    health                text NOT NULL DEFAULT 'unconfigured',
    last_event_at         timestamptz,
    total_events          bigint NOT NULL DEFAULT 0,
    last_error            text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_log_sources_name ON log_sources (tenant_id, name);

CREATE TABLE IF NOT EXISTS parsers (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    parser_key            text NOT NULL,
    name                  text NOT NULL,
    vendor                text NOT NULL DEFAULT '',
    product               text NOT NULL DEFAULT '',
    engine                text NOT NULL,
    definition            jsonb NOT NULL,
    enabled               boolean NOT NULL DEFAULT true,
    priority              integer NOT NULL DEFAULT 100,
    content_hash          text NOT NULL DEFAULT '',
    success_count         bigint NOT NULL DEFAULT 0,
    failure_count         bigint NOT NULL DEFAULT 0,
    last_used_at          timestamptz,
    builtin               boolean NOT NULL DEFAULT false,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_parsers_key ON parsers (tenant_id, parser_key);
CREATE INDEX IF NOT EXISTS ix_parsers_priority ON parsers (tenant_id, enabled, priority);

CREATE TABLE IF NOT EXISTS events (
    id                    uuid NOT NULL,
    tenant_id             uuid NOT NULL,
    time                  timestamptz NOT NULL,
    ingested_at           timestamptz NOT NULL DEFAULT now(),
    category              text NOT NULL DEFAULT 'other',
    action                text NOT NULL DEFAULT 'unknown',
    action_raw            text NOT NULL DEFAULT '',
    severity              text NOT NULL DEFAULT 'info',
    source_id             uuid NOT NULL,
    source_name           text NOT NULL DEFAULT '',
    protocol              text NOT NULL,
    parser_id             uuid,
    parser_name           text,
    vendor                text NOT NULL DEFAULT '',
    product               text NOT NULL DEFAULT '',
    host                  jsonb NOT NULL DEFAULT '{}'::jsonb,
    "user"                jsonb NOT NULL DEFAULT '{}'::jsonb,
    network               jsonb NOT NULL DEFAULT '{}'::jsonb,
    ai                    jsonb NOT NULL DEFAULT '{}'::jsonb,
    message               text NOT NULL DEFAULT '',
    raw                   jsonb NOT NULL DEFAULT '{}'::jsonb,
    raw_ref               text,
    raw_hash              text NOT NULL DEFAULT '',
    redacted              boolean NOT NULL DEFAULT false,
    tags                  jsonb NOT NULL DEFAULT '[]'::jsonb,
    extra                 jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, time, id)
);
CREATE INDEX IF NOT EXISTS ix_events_source ON events (tenant_id, source_id, time DESC);
CREATE INDEX IF NOT EXISTS ix_events_severity ON events (tenant_id, severity, time DESC);
CREATE INDEX IF NOT EXISTS ix_events_category ON events (tenant_id, category, time DESC);
CREATE INDEX IF NOT EXISTS ix_events_raw_hash ON events (tenant_id, raw_hash);
CREATE INDEX IF NOT EXISTS ix_events_ai_agent ON events USING gin (ai jsonb_path_ops);
COMMENT ON TABLE events IS 'AGF-ECS 归一化事件。TimescaleDB 可用时为 hypertable，按 time 分区';

-- 尝试创建 hypertable（幂等；无 timescaledb 时跳过）
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable('events', 'time', chunk_time_interval => interval '1 day', if_not_exists => TRUE);
        RAISE NOTICE 'events 已创建为 TimescaleDB hypertable';
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'hypertable 创建跳过：%', SQLERRM;
END
$$;

CREATE TABLE IF NOT EXISTS raw_logs (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_id             uuid NOT NULL,
    received_at           timestamptz NOT NULL DEFAULT now(),
    protocol              text NOT NULL,
    payload_b64           text NOT NULL,
    payload_hash          text NOT NULL,
    bytes                 integer NOT NULL DEFAULT 0,
    origin                text NOT NULL DEFAULT '',
    parsed                boolean NOT NULL DEFAULT false,
    parse_error           text,
    event_id              uuid
);
CREATE INDEX IF NOT EXISTS ix_raw_logs_time ON raw_logs (tenant_id, received_at DESC);
CREATE INDEX IF NOT EXISTS ix_raw_logs_unparsed ON raw_logs (tenant_id) WHERE NOT parsed;
CREATE INDEX IF NOT EXISTS ix_raw_logs_hash ON raw_logs (tenant_id, payload_hash);

CREATE TABLE IF NOT EXISTS collector_registrations (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    collector_id          text NOT NULL,
    name                  text NOT NULL,
    site                  text NOT NULL DEFAULT '',
    version               text NOT NULL DEFAULT '',
    enabled               boolean NOT NULL DEFAULT true,
    last_heartbeat_at     timestamptz,
    heartbeat_interval_secs bigint NOT NULL DEFAULT 30,
    uplink_mode           text NOT NULL DEFAULT 'direct',
    cert_fingerprint      text,
    cert_expires_at       timestamptz,
    pending_upload        bigint NOT NULL DEFAULT 0,
    bound_source_ids      jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_collector_id ON collector_registrations (tenant_id, collector_id);

CREATE TABLE IF NOT EXISTS alerts (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title                 text NOT NULL,
    description           text NOT NULL DEFAULT '',
    severity              text NOT NULL,
    domain                text,
    state                 text NOT NULL DEFAULT 'open'
                          CHECK (state IN ('open','acknowledged','suppressed','escalated','closed')),
    finding_ids           jsonb NOT NULL DEFAULT '[]'::jsonb,
    dedup_count           integer NOT NULL DEFAULT 1,
    dedup_key             text NOT NULL,
    asset_ids             jsonb NOT NULL DEFAULT '[]'::jsonb,
    event_ids             jsonb NOT NULL DEFAULT '[]'::jsonb,
    affected_hosts        jsonb NOT NULL DEFAULT '[]'::jsonb,
    first_seen_at         timestamptz NOT NULL DEFAULT now(),
    last_seen_at          timestamptz NOT NULL DEFAULT now(),
    assignee              text,
    case_id               uuid,
    escalation_level      smallint NOT NULL DEFAULT 0,
    sla_due_at            timestamptz,
    sla_breached          boolean NOT NULL DEFAULT false,
    tags                  jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_alerts_dedup ON alerts (tenant_id, dedup_key, state);
CREATE INDEX IF NOT EXISTS ix_alerts_state ON alerts (tenant_id, state, severity, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS ix_alerts_sla ON alerts (tenant_id, sla_due_at) WHERE state IN ('open','acknowledged','escalated');

CREATE TABLE IF NOT EXISTS aggregation_policies (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    window_secs           bigint NOT NULL DEFAULT 300,
    suppress_lower_severity boolean NOT NULL DEFAULT true,
    suppress_below        text,
    maintenance_windows   jsonb NOT NULL DEFAULT '[]'::jsonb,
    enabled               boolean NOT NULL DEFAULT true,
    created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS escalation_rules (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    min_severity          text NOT NULL,
    after_secs            bigint NOT NULL DEFAULT 3600,
    notify_user_ids       jsonb NOT NULL DEFAULT '[]'::jsonb,
    channel_ids           jsonb NOT NULL DEFAULT '[]'::jsonb,
    level                 smallint NOT NULL DEFAULT 1,
    enabled               boolean NOT NULL DEFAULT true,
    created_at            timestamptz NOT NULL DEFAULT now()
);

-- ===========================================================================
-- 6. 案件与通知
-- ===========================================================================

CREATE TABLE IF NOT EXISTS cases (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code                  text NOT NULL,
    title                 text NOT NULL,
    summary               text NOT NULL DEFAULT '',
    severity              text NOT NULL,
    state                 text NOT NULL DEFAULT 'new'
                          CHECK (state IN ('new','investigating','containing','resolved','closed')),
    alert_ids             jsonb NOT NULL DEFAULT '[]'::jsonb,
    finding_ids           jsonb NOT NULL DEFAULT '[]'::jsonb,
    asset_ids             jsonb NOT NULL DEFAULT '[]'::jsonb,
    owner                 text,
    collaborators         jsonb NOT NULL DEFAULT '[]'::jsonb,
    security_incident     boolean NOT NULL DEFAULT false,
    resolution            text,
    root_cause            text,
    lessons               text,
    evidence_bundle_ref   text,
    sla_due_at            timestamptz,
    sla_breached          boolean NOT NULL DEFAULT false,
    tags                  jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    closed_at             timestamptz,
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cases_code ON cases (tenant_id, code);
CREATE INDEX IF NOT EXISTS ix_cases_state ON cases (tenant_id, state, severity, created_at DESC);

CREATE TABLE IF NOT EXISTS case_events (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id               uuid NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    kind                  text NOT NULL,
    actor                 text NOT NULL DEFAULT '',
    note                  text NOT NULL DEFAULT '',
    detail                jsonb NOT NULL DEFAULT '{}'::jsonb,
    automated             boolean NOT NULL DEFAULT false,
    at                    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_case_events_case ON case_events (case_id, at);

CREATE TABLE IF NOT EXISTS timelines (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_kind          text NOT NULL,
    subject_id            uuid NOT NULL,
    at                    timestamptz NOT NULL,
    title                 text NOT NULL,
    detail                text NOT NULL DEFAULT '',
    mitre_technique       text,
    related_event_ids     jsonb NOT NULL DEFAULT '[]'::jsonb,
    related_asset_ids     jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_timelines_subject ON timelines (tenant_id, subject_kind, subject_id, at);

CREATE TABLE IF NOT EXISTS notification_channels (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    kind                  text NOT NULL,
    enabled               boolean NOT NULL DEFAULT true,
    secret_ref            uuid,
    targets               jsonb NOT NULL DEFAULT '[]'::jsonb,
    min_severity          text,
    headers               jsonb NOT NULL DEFAULT '{}'::jsonb,
    template              text,
    silence_secs          bigint NOT NULL DEFAULT 300,
    max_retries           integer NOT NULL DEFAULT 3,
    last_sent_at          timestamptz,
    last_error            text,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_notification_channels_name ON notification_channels (tenant_id, name);

CREATE TABLE IF NOT EXISTS notifications (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    channel_id            uuid NOT NULL,
    kind                  text NOT NULL,
    subject_kind          text NOT NULL,
    subject_id            uuid NOT NULL,
    dedup_key             text NOT NULL,
    title                 text NOT NULL,
    body                  text NOT NULL DEFAULT '',
    state                 text NOT NULL DEFAULT 'pending'
                          CHECK (state IN ('pending','sent','delivered','failed','suppressed')),
    attempts              integer NOT NULL DEFAULT 0,
    error                 text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    delivered_at          timestamptz
);
CREATE INDEX IF NOT EXISTS ix_notifications_time ON notifications (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_notifications_state ON notifications (tenant_id, state) WHERE state <> 'delivered';

CREATE TABLE IF NOT EXISTS playbooks (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    playbook_key          text NOT NULL,
    name                  text NOT NULL,
    description           text NOT NULL DEFAULT '',
    definition            jsonb NOT NULL,
    enabled               boolean NOT NULL DEFAULT true,
    require_approval      boolean NOT NULL DEFAULT false,
    timeout_secs          bigint NOT NULL DEFAULT 300,
    version               integer NOT NULL DEFAULT 1,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_playbooks_key ON playbooks (tenant_id, playbook_key);

CREATE TABLE IF NOT EXISTS playbook_runs (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    playbook_id           uuid NOT NULL,
    case_id               uuid,
    state                 text NOT NULL DEFAULT 'running'
                          CHECK (state IN ('running','completed','failed','awaiting-approval')),
    steps_done            integer NOT NULL DEFAULT 0,
    steps_total           integer NOT NULL DEFAULT 0,
    log                   jsonb NOT NULL DEFAULT '[]'::jsonb,
    error                 text,
    started_at            timestamptz NOT NULL DEFAULT now(),
    finished_at           timestamptz
);
CREATE INDEX IF NOT EXISTS ix_playbook_runs_case ON playbook_runs (case_id);

-- ===========================================================================
-- 7. 平台能力：审计、报表、调度、集成
-- ===========================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sequence              bigint NOT NULL,
    action                text NOT NULL,
    outcome               text NOT NULL CHECK (outcome IN ('success','failure','denied')),
    actor                 jsonb NOT NULL DEFAULT '{}'::jsonb,
    target                jsonb NOT NULL DEFAULT '{}'::jsonb,
    before                jsonb,
    after                 jsonb,
    changed_fields        jsonb NOT NULL DEFAULT '[]'::jsonb,
    request_id            text,
    error                 text,
    note                  text NOT NULL DEFAULT '',
    prev_hash             text NOT NULL,
    entry_hash            text NOT NULL,
    at                    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_logs_seq ON audit_logs (tenant_id, sequence);
CREATE INDEX IF NOT EXISTS ix_audit_logs_time ON audit_logs (tenant_id, at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_logs_action ON audit_logs (tenant_id, action, at DESC);
COMMENT ON TABLE audit_logs IS '哈希链审计：entry_hash = SHA256(prev_hash ‖ 规范化载荷)，不可篡改';

CREATE TABLE IF NOT EXISTS audit_chain_anchors (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    up_to_sequence        bigint NOT NULL,
    tail_hash             text NOT NULL,
    entry_count           bigint NOT NULL,
    signature             text NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_audit_anchors_tenant ON audit_chain_anchors (tenant_id, up_to_sequence DESC);

CREATE TABLE IF NOT EXISTS reports (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind                  text NOT NULL,
    title                 text NOT NULL,
    state                 text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','completed','failed')),
    range_from            timestamptz NOT NULL,
    range_to              timestamptz NOT NULL,
    format                text NOT NULL DEFAULT 'markdown',
    template_key          text,
    filters               jsonb NOT NULL DEFAULT '{}'::jsonb,
    body                  text,
    artifact_ref          text,
    artifact_bytes        bigint,
    content_hash          text,
    ai_generated          boolean NOT NULL DEFAULT false,
    model                 text,
    mocked                boolean NOT NULL DEFAULT false,
    error                 text,
    created_by            uuid,
    schedule_id           uuid,
    created_at            timestamptz NOT NULL DEFAULT now(),
    completed_at          timestamptz
);
CREATE INDEX IF NOT EXISTS ix_reports_time ON reports (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS report_schedules (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    kind                  text NOT NULL,
    format                text NOT NULL DEFAULT 'markdown',
    cron                  text NOT NULL,
    window_secs           bigint NOT NULL DEFAULT 604800,
    channel_ids           jsonb NOT NULL DEFAULT '[]'::jsonb,
    recipients            jsonb NOT NULL DEFAULT '[]'::jsonb,
    enabled               boolean NOT NULL DEFAULT true,
    last_generated_at     timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now()
