CREATE TABLE IF NOT EXISTS boost_fit_requests (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  telegram TEXT,
  links TEXT NOT NULL,
  stage TEXT NOT NULL,
  revenue_have TEXT NOT NULL,
  revenue_want TEXT NOT NULL,
  help TEXT NOT NULL,
  time_per_day TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'received',
  ip_hash TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_boost_fit_requests_created_at
  ON boost_fit_requests(created_at);

CREATE INDEX IF NOT EXISTS idx_boost_fit_requests_ip_created
  ON boost_fit_requests(ip_hash, created_at);

CREATE TABLE IF NOT EXISTS boost_fit_rate_limits (
  ip_hash TEXT NOT NULL,
  window_start TEXT NOT NULL,
  submission_count INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (ip_hash, window_start)
);
