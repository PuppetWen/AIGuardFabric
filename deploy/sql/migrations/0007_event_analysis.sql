-- The receipt and generated findings/alerts commit together, before broker acknowledgement.
ALTER TABLE alerts ADD COLUMN deleted_at timestamptz;
CREATE TABLE event_analysis_receipts (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    event_id uuid NOT NULL,
    event_time timestamptz NOT NULL,
    rule_fingerprint text NOT NULL,
    finding_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    alert_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    notification_enqueued_at timestamptz,
    processed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX event_analysis_notifications ON event_analysis_receipts (tenant_id, processed_at)
    WHERE notification_enqueued_at IS NULL;
CREATE INDEX ix_events_ingested_id ON events (tenant_id, ingested_at, id);
ALTER TABLE event_analysis_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_analysis_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY event_analysis_tenant ON event_analysis_receipts
    USING (tenant_id=agf_current_tenant()) WITH CHECK (tenant_id=agf_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON event_analysis_receipts TO agf_tenant_runtime;
