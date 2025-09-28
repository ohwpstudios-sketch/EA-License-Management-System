-- Create archive table for activity logs (if not exists)
CREATE TABLE IF NOT EXISTS activity_logs_archive (
  id INTEGER PRIMARY KEY,
  license_key TEXT,
  action TEXT,
  details TEXT,
  ip_address TEXT,
  user_agent TEXT,
  created_at DATETIME,
  archived_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Optional: index for faster date queries
CREATE INDEX IF NOT EXISTS idx_activity_logs_archive_created_at ON activity_logs_archive(created_at);
CREATE INDEX IF NOT EXISTS idx_activity_logs_archive_license_key ON activity_logs_archive(license_key);
