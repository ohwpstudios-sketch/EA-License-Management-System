-- 2025-09-17: Multi-tenancy columns & indexes (safe to run once)
ALTER TABLE licenses ADD COLUMN tenant_id TEXT;
UPDATE licenses SET tenant_id = COALESCE(tenant_id, 'tenant_default');
CREATE INDEX IF NOT EXISTS idx_licenses_tenant ON licenses(tenant_id);

ALTER TABLE activations ADD COLUMN tenant_id TEXT;
UPDATE activations SET tenant_id = COALESCE(tenant_id, 'tenant_default');
CREATE INDEX IF NOT EXISTS idx_activations_tenant ON activations(tenant_id);

ALTER TABLE activity_logs ADD COLUMN tenant_id TEXT;
UPDATE activity_logs SET tenant_id = COALESCE(tenant_id, 'tenant_default');
CREATE INDEX IF NOT EXISTS idx_logs_tenant_created ON activity_logs(tenant_id, created_at);
