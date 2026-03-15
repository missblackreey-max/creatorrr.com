ALTER TABLE licenses ADD COLUMN stripe_customer_id TEXT;
ALTER TABLE licenses ADD COLUMN stripe_subscription_id TEXT;
ALTER TABLE licenses ADD COLUMN stripe_price_id TEXT;

ALTER TABLE licenses ADD COLUMN billing_interval TEXT; -- trial | month | year
ALTER TABLE licenses ADD COLUMN current_period_start TEXT;
ALTER TABLE licenses ADD COLUMN current_period_end TEXT;

ALTER TABLE licenses ADD COLUMN trial_start_at TEXT;
ALTER TABLE licenses ADD COLUMN trial_end_at TEXT;

ALTER TABLE licenses ADD COLUMN cancel_at_period_end INTEGER NOT NULL DEFAULT 0;
ALTER TABLE licenses ADD COLUMN canceled_at TEXT;
ALTER TABLE licenses ADD COLUMN ended_at TEXT;

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