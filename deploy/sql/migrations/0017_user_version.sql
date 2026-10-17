-- Serialize account, authentication and MFA writes across API replicas.
ALTER TABLE users ADD COLUMN IF NOT EXISTS version bigint NOT NULL DEFAULT 1;
ALTER TABLE users ADD CONSTRAINT users_version_positive CHECK (version > 0);
