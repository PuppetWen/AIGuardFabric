-- Keep failures and recovery history; quarantine never becomes a completion receipt.
ALTER TABLE event_analysis_retries
    ADD COLUMN error_code text NOT NULL DEFAULT 'analysis_failed',
    ADD COLUMN paused boolean NOT NULL DEFAULT false,
    ADD COLUMN version bigint NOT NULL DEFAULT 1,
    ADD COLUMN total_attempts bigint NOT NULL DEFAULT 1,
    ADD COLUMN first_failed_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN resolved_at timestamptz;
UPDATE event_analysis_retries SET total_attempts=attempts, first_failed_at=updated_at;
CREATE INDEX event_analysis_retry_open ON event_analysis_retries (tenant_id, available_at)
    WHERE resolved_at IS NULL AND NOT paused AND attempts < 8;

CREATE TABLE event_analysis_actions (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    id uuid NOT NULL,
    event_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('retry','pause')),
    actor_id text NOT NULL,
    previous_version bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,id)
);
CREATE INDEX event_analysis_action_history ON event_analysis_actions (tenant_id,event_id,created_at);
ALTER TABLE event_analysis_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_analysis_actions FORCE ROW LEVEL SECURITY;
CREATE POLICY event_analysis_action_tenant ON event_analysis_actions
    USING (tenant_id=agf_current_tenant()) WITH CHECK (tenant_id=agf_current_tenant());
GRANT SELECT, INSERT ON event_analysis_actions TO agf_tenant_runtime;
