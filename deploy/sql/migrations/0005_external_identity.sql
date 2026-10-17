-- Email is contact information, not the identity key of a federated account.
-- Preserve unique local-account emails while allowing distinct signed external subjects.
DROP INDEX IF EXISTS ux_users_tenant_email;
CREATE UNIQUE INDEX ux_users_tenant_email ON users (tenant_id, lower(email))
    WHERE deleted_at IS NULL AND idp = 'local' AND email <> '';
CREATE UNIQUE INDEX ux_users_external_subject ON users (tenant_id, idp, external_subject)
    WHERE deleted_at IS NULL AND idp <> 'local' AND external_subject IS NOT NULL;
