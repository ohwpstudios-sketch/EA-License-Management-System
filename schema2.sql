
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS tenants (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL DEFAULT 'Default',
  subdomain     TEXT,
  admin_email   TEXT,
  status        TEXT NOT NULL DEFAULT 'trialing',
  trial_end     TEXT,
  created_at    TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id                  TEXT PRIMARY KEY,
  tenant_id           TEXT NOT NULL,
  provider            TEXT NOT NULL,
  customer_id         TEXT,
  subscription_id     TEXT,
  plan_code           TEXT,
  status              TEXT NOT NULL,
  current_period_end  TEXT,
  trial_end           TEXT,
  created_at          TEXT DEFAULT CURRENT_TIMESTAMP
);

-- optional: plans table (not needed for Paystack initialize flow, but here for completeness)
CREATE TABLE IF NOT EXISTS plans (
  id           TEXT PRIMARY KEY,
  code         TEXT UNIQUE,
  name         TEXT,
  interval     TEXT,
  price_cents  INTEGER,
  trial_days   INTEGER DEFAULT 14,
  features_json TEXT
);

-- add columns to existing tables if not already
ALTER TABLE licenses       ADD COLUMN tenant_id TEXT;
ALTER TABLE activations    ADD COLUMN tenant_id TEXT;
ALTER TABLE activity_logs  ADD COLUMN tenant_id TEXT;

CREATE INDEX IF NOT EXISTS idx_licenses_tenant      ON licenses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_activations_tenant   ON activations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_logs_tenant_created  ON activity_logs(tenant_id, created_at);
