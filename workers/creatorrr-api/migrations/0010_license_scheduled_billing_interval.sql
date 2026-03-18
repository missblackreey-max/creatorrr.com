ALTER TABLE licenses ADD COLUMN scheduled_billing_interval TEXT;
ALTER TABLE licenses ADD COLUMN scheduled_change_at TEXT;

CREATE INDEX IF NOT EXISTS idx_licenses_scheduled_billing_interval
  ON licenses(scheduled_billing_interval);
