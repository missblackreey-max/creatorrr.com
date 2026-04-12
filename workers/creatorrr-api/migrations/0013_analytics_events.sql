CREATE TABLE IF NOT EXISTS analytics_events (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  event_name TEXT NOT NULL,
  item_id TEXT,
  item_version TEXT,
  item_variant TEXT,
  path TEXT,
  country TEXT,
  user_agent TEXT,
  ip_hash TEXT,
  is_bot INTEGER NOT NULL DEFAULT 0,
  bot_score INTEGER
);

CREATE INDEX IF NOT EXISTS idx_analytics_events_created_at
  ON analytics_events(created_at);

CREATE INDEX IF NOT EXISTS idx_analytics_events_event_name
  ON analytics_events(event_name);

CREATE INDEX IF NOT EXISTS idx_analytics_events_item_id
  ON analytics_events(item_id);
