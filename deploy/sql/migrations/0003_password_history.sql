-- 保留最近 24 次 Argon2 哈希；与当前口令在同一用户行事务中更新。
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_history jsonb NOT NULL DEFAULT '[]'::jsonb;
