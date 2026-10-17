-- Completed SOAR history is not scanned or deserialized by every worker tick.
CREATE INDEX console_soar_pending ON console_configurations (tenant_id,updated_at,id)
    WHERE kind='soar-workflow' AND deleted_at IS NULL
    AND (payload->>'status' NOT IN ('completed','aborted','cancelled','not-started')
        OR (payload->>'projected_version')::bigint < (payload->>'version')::bigint);
CREATE INDEX console_soar_case ON console_configurations
    (tenant_id,(payload->>'case_id'),created_at DESC,id DESC)
    WHERE kind='soar-workflow' AND deleted_at IS NULL;
