-- Prevent stale administrators from overwriting a newer tenant state.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS version bigint NOT NULL DEFAULT 1;
ALTER TABLE tenants ADD CONSTRAINT tenants_version_positive CHECK (version > 0);
