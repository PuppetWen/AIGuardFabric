-- Untrusted messages belong to a platform-only queue, not to their claimed tenant.
CREATE TABLE broker_quarantine (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    id uuid NOT NULL,
    stream text NOT NULL,
    stream_sequence bigint NOT NULL,
    payload_hash text NOT NULL,
    payload_bytes bigint NOT NULL,
    sealed_envelope jsonb NOT NULL,
    reason_code text NOT NULL,
    state text NOT NULL DEFAULT 'quarantined' CHECK (state IN ('quarantined','retrying','resolved','dismissed')),
    version bigint NOT NULL DEFAULT 1,
    lease_id uuid,
    lease_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,id)
);
CREATE INDEX broker_quarantine_queue ON broker_quarantine (tenant_id,state,updated_at DESC,id);
CREATE TABLE broker_quarantine_actions (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    id uuid NOT NULL,
    message_id uuid NOT NULL,
    action text NOT NULL,
    actor_id text NOT NULL,
    note text NOT NULL,
    previous_version bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,id),
    FOREIGN KEY (tenant_id,message_id) REFERENCES broker_quarantine(tenant_id,id)
);
CREATE INDEX broker_quarantine_history ON broker_quarantine_actions (tenant_id,message_id,created_at DESC,id);
ALTER TABLE broker_quarantine ENABLE ROW LEVEL SECURITY;
ALTER TABLE broker_quarantine FORCE ROW LEVEL SECURITY;
CREATE POLICY broker_quarantine_tenant ON broker_quarantine
    USING (tenant_id=agf_current_tenant()) WITH CHECK (tenant_id=agf_current_tenant());
ALTER TABLE broker_quarantine_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE broker_quarantine_actions FORCE ROW LEVEL SECURITY;
CREATE POLICY broker_quarantine_action_tenant ON broker_quarantine_actions
    USING (tenant_id=agf_current_tenant()) WITH CHECK (tenant_id=agf_current_tenant());
GRANT SELECT,INSERT,UPDATE ON broker_quarantine TO agf_tenant_runtime;
GRANT SELECT,INSERT ON broker_quarantine_actions TO agf_tenant_runtime;
