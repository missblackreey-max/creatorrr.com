CREATE TABLE IF NOT EXISTS license_overrides (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  plan TEXT NOT NULL,
  status TEXT NOT NULL,
  source TEXT NOT NULL,
  note TEXT,
  starts_at TEXT NOT NULL,
  ends_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_license_overrides_user
  ON license_overrides(user_id);

CREATE INDEX IF NOT EXISTS idx_license_overrides_user_status
  ON license_overrides(user_id, status);

CREATE INDEX IF NOT EXISTS idx_license_overrides_ends_at
  ON license_overrides(ends_at);