PRAGMA defer_foreign_keys = on;

CREATE TABLE licenses_new (
  user_id TEXT PRIMARY KEY,
  plan TEXT NOT NULL,
  status TEXT NOT NULL,
  notes TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  stripe_price_id TEXT,
  billing_interval TEXT,
  current_period_start TEXT,
  current_period_end TEXT,
  trial_start_at TEXT,
  trial_end_at TEXT,
  cancel_at TEXT,
  canceled_at TEXT,
  ended_at TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO licenses_new (
  user_id,
  plan,
  status,
  notes,
  created_at,
  updated_at,
  stripe_customer_id,
  stripe_subscription_id,
  stripe_price_id,
  billing_interval,
  current_period_start,
  current_period_end,
  trial_start_at,
  trial_end_at,
  cancel_at,
  canceled_at,
  ended_at
)
SELECT
  user_id,
  plan,
  status,
  notes,
  created_at,
  updated_at,
  stripe_customer_id,
  stripe_subscription_id,
  stripe_price_id,
  billing_interval,
  current_period_start,
  current_period_end,
  trial_start_at,
  trial_end_at,
  CASE
    WHEN status = 'canceling' AND current_period_end IS NOT NULL THEN current_period_end
    ELSE NULL
  END AS cancel_at,
  canceled_at,
  ended_at
FROM licenses;

DROP TABLE licenses;
ALTER TABLE licenses_new RENAME TO licenses;

CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_stripe_customer_id
  ON licenses(stripe_customer_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_stripe_subscription_id
  ON licenses(stripe_subscription_id);

CREATE INDEX IF NOT EXISTS idx_licenses_plan_status
  ON licenses(plan, status);

CREATE INDEX IF NOT EXISTS idx_licenses_current_period_end
  ON licenses(current_period_end);

CREATE INDEX IF NOT EXISTS idx_licenses_trial_end_at
  ON licenses(trial_end_at);
