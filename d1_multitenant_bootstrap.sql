-- D1 Multi-tenant bootstrap (run once; ALTERs may error if the column already exists)
-- Binding in worker: ea_license_db_new
-- Use your database_name (e.g., ea-license-db-new) with wrangler d1 execute

-- Add tenant_id columns (run individually; ignore 'duplicate column name' errors)
ALTER TABLE licenses ADD COLUMN tenant_id TEXT DEFAULT 'tenant_default';
ALTER TABLE activations ADD COLUMN tenant_id TEXT DEFAULT 'tenant_default';
ALTER TABLE activity_logs ADD COLUMN tenant_id TEXT DEFAULT 'tenant_default';

-- Tenants table
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT 'Default',
  subdomain TEXT,
  admin_email TEXT,
  status TEXT NOT NULL DEFAULT 'trialing',
  trial_end TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Default tenant
INSERT OR IGNORE INTO tenants (id, name, status, subdomain, admin_email)
VALUES ('tenant_default', 'Default Tenant', 'active', 'default', 'admin@example.com');

-- Backfill existing rows
UPDATE licenses SET tenant_id = 'tenant_default' WHERE tenant_id IS NULL;
UPDATE activations SET tenant_id = 'tenant_default' WHERE tenant_id IS NULL;
UPDATE activity_logs SET tenant_id = 'tenant_default' WHERE tenant_id IS NULL;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_licenses_tenant ON licenses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_activations_tenant ON activations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_logs_tenant ON activity_logs(tenant_id);