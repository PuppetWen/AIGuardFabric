-- Verified source bindings and audit effects are checked/committed in the ingest transaction.
CREATE TABLE agentteams_audit (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    scope_id uuid NOT NULL,
    external_event_id text NOT NULL CHECK (length(external_event_id) BETWEEN 1 AND 256),
    content_hash text NOT NULL CHECK (content_hash ~ '^[0-9A-Fa-f]{64}$'),
    id uuid NOT NULL,
    source_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    event_time timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    kind text NOT NULL CHECK (kind IN ('call','message','task','heartbeat')),
    payload jsonb NOT NULL,
    PRIMARY KEY (tenant_id,scope_id,external_event_id),
    UNIQUE (tenant_id,id),
    CHECK (jsonb_typeof(payload)='object')
);
CREATE INDEX agentteams_audit_window ON agentteams_audit (tenant_id,scope_id,event_time DESC,id DESC);
ALTER TABLE agentteams_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE agentteams_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY agentteams_audit_tenant ON agentteams_audit
    USING (tenant_id=agf_current_tenant()) WITH CHECK (tenant_id=agf_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON agentteams_audit TO agf_tenant_runtime;

-- Tenant-directory rows are not readable by the runtime role. Expose only the current tenant.
CREATE FUNCTION agf_agentteams_lock_tenant() RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE active boolean;
BEGIN
    SELECT enabled INTO active FROM public.tenants
        WHERE id=public.agf_current_tenant() AND deleted_at IS NULL FOR SHARE;
    RETURN COALESCE(active,false);
END;
$$;
REVOKE ALL ON FUNCTION agf_agentteams_lock_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agf_agentteams_lock_tenant() TO agf_tenant_runtime;
