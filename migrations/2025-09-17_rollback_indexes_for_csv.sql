-- 2025-09-17_rollback_indexes_for_csv.sql
-- Rollback for the CSV export performance indexes.
DROP INDEX IF EXISTS idx_licenses_created_at;
DROP INDEX IF EXISTS idx_activations_activation_date;
DROP INDEX IF EXISTS idx_activity_logs_created_at;
