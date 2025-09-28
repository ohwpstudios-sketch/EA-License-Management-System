PRAGMA foreign_keys=ON;

-- Core tables (no-op if they already exist)
CREATE TABLE IF NOT EXISTS tenants (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL DEFAULT 'Default',
  subdomain     TEXT,
  admin_email   TEXT,
  status        TEXT NOT NULL DEFAULT 'trialing',
  trial_end     TEXT,
  created_at    TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tenant_api_keys (
  id         TEXT PRIMARY KEY,
  tenant_id  TEXT NOT NULL,
  key_hash   TEXT NOT NULL,
  label      TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Default tenant (safe if already present)
INSERT OR IGNORE INTO tenants (id, name, status) VALUES ('tenant_default', 'Default', 'active');

-- Backfill existing rows to default tenant (columns must already exist)
UPDATE licenses      SET tenant_id = 'tenant_default' WHERE tenant_id IS NULL;
UPDATE activations   SET tenant_id = 'tenant_default' WHERE tenant_id IS NULL;
UPDATE activity_logs SET tenant_id = 'tenant_default' WHERE tenant_id IS NULL;

-- Helpful indexes (safe)
CREATE INDEX IF NOT EXISTS idx_licenses_tenant      ON licenses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_activations_tenant   ON activations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_logs_tenant_created  ON activity_logs(tenant_id, created_at);
