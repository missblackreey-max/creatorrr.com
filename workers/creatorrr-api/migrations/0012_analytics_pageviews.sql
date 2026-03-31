CREATE TABLE IF NOT EXISTS analytics_pageviews (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  path TEXT NOT NULL,
  query TEXT,
  referrer TEXT,
  title TEXT,
  country TEXT,
  user_agent TEXT,
  ip_hash TEXT,
  is_bot INTEGER NOT NULL DEFAULT 0,
  bot_score INTEGER,
  timezone TEXT,
  screen TEXT,
  language TEXT
);

CREATE INDEX IF NOT EXISTS idx_analytics_pageviews_created_at
  ON analytics_pageviews(created_at);

CREATE INDEX IF NOT EXISTS idx_analytics_pageviews_country
  ON analytics_pageviews(country);

CREATE INDEX IF NOT EXISTS idx_analytics_pageviews_path
  ON analytics_pageviews(path);
