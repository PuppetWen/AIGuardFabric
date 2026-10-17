-- Committed with raw evidence and normalized events; delivery survives broker/process outages.
CREATE TABLE event_delivery_outbox (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    event_id uuid NOT NULL,
    payload jsonb NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT now(),
    lease_until timestamptz,
    lease_id uuid,
    delivered_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX event_delivery_pending ON event_delivery_outbox (tenant_id, available_at)
    WHERE delivered_at IS NULL AND deleted_at IS NULL;
ALTER TABLE event_delivery_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_delivery_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY event_delivery_tenant ON event_delivery_outbox
    USING (tenant_id=agf_current_tenant()) WITH CHECK (tenant_id=agf_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON event_delivery_outbox TO agf_tenant_runtime;
