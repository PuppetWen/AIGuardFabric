-- Retry failures separately from completion receipts so one bad event cannot stop later events.
CREATE TABLE event_analysis_retries (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    event_id uuid NOT NULL,
    attempts integer NOT NULL DEFAULT 1,
    available_at timestamptz NOT NULL DEFAULT now() + interval '10 seconds',
    last_error text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, event_id)
);
ALTER TABLE event_analysis_retries ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_analysis_retries FORCE ROW LEVEL SECURITY;
CREATE POLICY event_analysis_retry_tenant ON event_analysis_retries
    USING (tenant_id=agf_current_tenant()) WITH CHECK (tenant_id=agf_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON event_analysis_retries TO agf_tenant_runtime;
