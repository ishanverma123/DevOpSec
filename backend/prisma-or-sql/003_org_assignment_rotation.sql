CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(120) UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL;

ALTER TABLE secrets
  ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS encryption_algorithm VARCHAR(40) NOT NULL DEFAULT 'aes-256-gcm',
  ADD COLUMN IF NOT EXISTS rotation_interval_days INT,
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS auto_rotate BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE secret_versions
  ADD COLUMN IF NOT EXISTS encryption_algorithm VARCHAR(40) NOT NULL DEFAULT 'aes-256-gcm';

CREATE TABLE IF NOT EXISTS secret_assignments (
  secret_id UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  assigned_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  can_read BOOLEAN NOT NULL DEFAULT TRUE,
  can_rotate BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (secret_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_secrets_org ON secrets(organization_id);
CREATE INDEX IF NOT EXISTS idx_secrets_expiry ON secrets(expires_at);
CREATE INDEX IF NOT EXISTS idx_secret_assignments_user ON secret_assignments(user_id);
