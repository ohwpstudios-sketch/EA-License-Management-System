-- 2025-09-17_add_indexes_for_csv.sql
-- Safe, idempotent indexes to make CSV exports fast. No destructive changes.
CREATE INDEX IF NOT EXISTS idx_licenses_created_at ON licenses(created_at);
CREATE INDEX IF NOT EXISTS idx_activations_activation_date ON activations(activation_date);
CREATE INDEX IF NOT EXISTS idx_activity_logs_created_at ON activity_logs(created_at);
