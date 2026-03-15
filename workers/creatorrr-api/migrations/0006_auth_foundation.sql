ALTER TABLE users ADD COLUMN email_verified_at TEXT;
ALTER TABLE users ADD COLUMN password_reset_token_hash TEXT;
ALTER TABLE users ADD COLUMN password_reset_expires_at TEXT;
ALTER TABLE users ADD COLUMN email_verify_token_hash TEXT;
ALTER TABLE users ADD COLUMN email_verify_expires_at TEXT;
ALTER TABLE users ADD COLUMN updated_at TEXT;

UPDATE users
SET updated_at = created_at
WHERE updated_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_users_email_verified_at
  ON users(email_verified_at);

CREATE INDEX IF NOT EXISTS idx_users_password_reset_expires_at
  ON users(password_reset_expires_at);

CREATE INDEX IF NOT EXISTS idx_users_email_verify_expires_at
  ON users(email_verify_expires_at);