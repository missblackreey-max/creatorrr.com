UPDATE licenses
SET
  plan = 'free',
  status = 'active',
  billing_interval = NULL,
  trial_start_at = NULL,
  trial_end_at = NULL,
  current_period_start = NULL,
  current_period_end = NULL,
  scheduled_billing_interval = NULL,
  scheduled_change_at = NULL,
  cancel_at = NULL,
  canceled_at = NULL,
  ended_at = NULL,
  updated_at = datetime('now')
WHERE plan IN ('trial', 'beta', 'none')
   OR status IN ('trialing', 'none');

DROP INDEX IF EXISTS idx_licenses_trial_end_at;