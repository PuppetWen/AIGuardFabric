-- Trace lookups remain tenant/scope constrained and ordered by the existing event-time keys.
CREATE INDEX agentteams_audit_trace_window
    ON agentteams_audit (tenant_id, scope_id, (payload->>'trace_id'), event_time DESC, id DESC)
    WHERE payload->>'trace_id' IS NOT NULL;
