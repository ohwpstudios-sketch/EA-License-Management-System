-- EA License System Database Schema for Cloudflare D1
-- Run these commands in your D1 database to set up the tables

-- 1. Licenses table - stores all license information
CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT UNIQUE NOT NULL,
    customer_email TEXT NOT NULL,
    customer_name TEXT,
    max_live_accounts INTEGER DEFAULT 5,
    max_demo_accounts INTEGER DEFAULT 2,
    purchase_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    expiry_date DATETIME,
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'expired', 'revoked')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    notes TEXT
);

-- 2. Activations table - tracks all account activations
CREATE TABLE IF NOT EXISTS activations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT NOT NULL,
    account_number TEXT NOT NULL,
    broker_server TEXT NOT NULL,
    account_type TEXT CHECK(account_type IN ('live', 'demo')),
    machine_id TEXT,
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'inactive')),
    activation_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    deactivation_date DATETIME,
    last_check DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    FOREIGN KEY (license_key) REFERENCES licenses(license_key),
    UNIQUE(license_key, account_number, broker_server)
);

-- 3. Activity logs table - tracks all system activities
CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT,
    action TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (license_key) REFERENCES licenses(license_key)
);

-- 4. Settings table - stores system configuration
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status);
CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(customer_email);
CREATE INDEX IF NOT EXISTS idx_licenses_expiry ON licenses(expiry_date);

CREATE INDEX IF NOT EXISTS idx_activations_license ON activations(license_key);
CREATE INDEX IF NOT EXISTS idx_activations_account ON activations(account_number);
CREATE INDEX IF NOT EXISTS idx_activations_status ON activations(status);
CREATE INDEX IF NOT EXISTS idx_activations_last_check ON activations(last_check);

CREATE INDEX IF NOT EXISTS idx_logs_license ON activity_logs(license_key);
CREATE INDEX IF NOT EXISTS idx_logs_action ON activity_logs(action);
CREATE INDEX IF NOT EXISTS idx_logs_created ON activity_logs(created_at);

-- Insert default settings
INSERT OR IGNORE INTO settings (key, value) VALUES 
    ('system_version', '2.0.1'),
    ('max_activation_attempts', '3'),
    ('activation_check_interval', '3600'),
    ('auto_cleanup_days', '30'),
    ('require_machine_id', 'true');

-- Create a view for license statistics
CREATE VIEW IF NOT EXISTS license_stats AS
SELECT 
    l.license_key,
    l.customer_email,
    l.status,
    COUNT(DISTINCT CASE WHEN a.account_type = 'live' AND a.status = 'active' THEN a.account_number END) as active_live_accounts,
    COUNT(DISTINCT CASE WHEN a.account_type = 'demo' AND a.status = 'active' THEN a.account_number END) as active_demo_accounts,
    l.max_live_accounts,
    l.max_demo_accounts,
    MIN(a.activation_date) as first_activation,
    MAX(a.last_check) as last_activity
FROM licenses l
LEFT JOIN activations a ON l.license_key = a.license_key
GROUP BY l.license_key;

-- Create a view for daily activity summary
CREATE VIEW IF NOT EXISTS daily_activity AS
SELECT 
    DATE(created_at) as date,
    COUNT(CASE WHEN action = 'activation' THEN 1 END) as activations,
    COUNT(CASE WHEN action = 'deactivation' THEN 1 END) as deactivations,
    COUNT(CASE WHEN action = 'verification' THEN 1 END) as verifications,
    COUNT(CASE WHEN action = 'generate' THEN 1 END) as new_licenses,
    COUNT(*) as total_actions
FROM activity_logs
GROUP BY DATE(created_at);

-- Sample data for testing (remove in production)
INSERT INTO licenses (license_key, customer_email, customer_name, max_live_accounts, max_demo_accounts, expiry_date) VALUES
    ('TEST-1234-ABCD-EFGH', 'demo@example.com', 'Demo User', 5, 2, datetime('now', '+30 days')),
    ('PROD-5678-IJKL-MNOP', 'customer1@example.com', 'John Doe', 10, 5, datetime('now', '+365 days')),
    ('TRIAL-9012-QRST-UVWX', 'trial@example.com', 'Trial User', 1, 1, datetime('now', '+7 days'));

-- Cleanup old inactive activations (run periodically)
-- DELETE FROM activations 
-- WHERE status = 'inactive' 
-- AND deactivation_date < datetime('now', '-30 days');

-- Query to check license usage
-- SELECT 
--     l.*,
--     COUNT(a.id) as total_activations,
--     SUM(CASE WHEN a.status = 'active' THEN 1 ELSE 0 END) as active_activations
-- FROM licenses l
-- LEFT JOIN activations a ON l.license_key = a.license_key
-- GROUP BY l.license_key;