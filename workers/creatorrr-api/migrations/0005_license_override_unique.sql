CREATE UNIQUE INDEX IF NOT EXISTS idx_license_override_one_per_user
ON license_overrides(user_id);