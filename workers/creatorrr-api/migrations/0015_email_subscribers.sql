CREATE TABLE IF NOT EXISTS email_subscribers (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL,
  source TEXT,
  consent_text TEXT,
  verify_token_hash TEXT,
  verify_expires_at TEXT,
  verified_at TEXT,
  unsubscribed_at TEXT,
  user_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_email_subscribers_email
  ON email_subscribers(email);

CREATE INDEX IF NOT EXISTS idx_email_subscribers_status
  ON email_subscribers(status);

CREATE INDEX IF NOT EXISTS idx_email_subscribers_verify_expires_at
  ON email_subscribers(verify_expires_at);

CREATE INDEX IF NOT EXISTS idx_email_subscribers_user_id
  ON email_subscribers(user_id);
