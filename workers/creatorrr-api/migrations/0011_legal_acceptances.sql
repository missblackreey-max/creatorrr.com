CREATE TABLE IF NOT EXISTS legal_acceptances (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  terms_version TEXT NOT NULL,
  privacy_version TEXT NOT NULL,
  refund_version TEXT NOT NULL,
  accepted_at TEXT NOT NULL,
  acceptance_context TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_legal_acceptances_user_id
  ON legal_acceptances(user_id);

CREATE INDEX IF NOT EXISTS idx_legal_acceptances_user_versions
  ON legal_acceptances(user_id, terms_version, privacy_version, refund_version);
