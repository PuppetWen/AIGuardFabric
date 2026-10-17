-- Durable control-plane settings; secrets inside payload must be AES-GCM envelopes.
CREATE TABLE IF NOT EXISTS console_configurations (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    kind text NOT NULL,
    id uuid NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    PRIMARY KEY (tenant_id, kind, id)
);
ALTER TABLE console_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE console_configurations FORCE ROW LEVEL SECURITY;
CREATE POLICY console_configuration_tenant ON console_configurations
    USING (tenant_id = nullif(current_setting('agf.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('agf.tenant_id', true), '')::uuid);
