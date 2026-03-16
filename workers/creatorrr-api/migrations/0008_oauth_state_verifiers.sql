ALTER TABLE oauth_states ADD COLUMN browser_nonce_hash TEXT;
ALTER TABLE oauth_states ADD COLUMN client_nonce TEXT;

CREATE INDEX IF NOT EXISTS idx_oauth_states_client_nonce
  ON oauth_states(client_nonce);
