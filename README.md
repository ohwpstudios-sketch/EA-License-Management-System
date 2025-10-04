A professional, cloud-based licensing system for MetaTrader 4/5 Expert Advisors (EAs) built on Cloudflare's global edge network. Protect your trading algorithms with enterprise-grade security while maintaining sub-100ms response times worldwide.

✨ Features
Core Functionality

🔐 Secure License Generation - Unique keys with customizable parameters
📊 Real-time Dashboard - Monitor activations and usage patterns
🌍 Global Performance - Cloudflare edge network deployment
💳 Multi-tenant Support - Manage multiple EA vendors/builders
📱 Telegram Notifications - Instant alerts for important events
🔄 Auto-renewal Support - Subscription management ready

License Management

Account-based activation limits (Live/Demo)
Time-limited and lifetime licenses
Machine ID binding for additional security
Bulk operations and CSV export
License suspension and revocation

Security Features

Server-side validation
IP tracking and rate limiting
Activity audit logs
Bearer token authentication
CORS-enabled API

🚀 Quick Start
Prerequisites

Cloudflare account (free tier works)
Node.js 16+ installed
Domain name (optional)
MetaTrader 4/5 terminal

1. Clone and Setup
bash# Clone the repository
git clone https://github.com/yourusername/ea-license-system.git
cd ea-license-system

# Install Wrangler CLI
npm install -g wrangler

# Login to Cloudflare
wrangler login
2. Database Setup
bash# Create D1 database
wrangler d1 create ea-license-db-new

# Copy the database_id from output and update wrangler.toml

# Apply schema
wrangler d1 execute ea-license-db-new --file=./schema.sql
3. Configuration
Update wrangler.toml:
tomlname = "ea-license-system"
main = "worker.js"
compatibility_date = "2024-01-01"

[[d1_databases]]
binding = "ea_license_db_new"
database_name = "ea-license-db-new"
database_id = "YOUR_DATABASE_ID_HERE"

[vars]
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID"

# Set secrets
# wrangler secret put ADMIN_API_KEY
# wrangler secret put TELEGRAM_BOT_TOKEN
4. Deploy
bash# Deploy Worker
wrangler deploy

# Deploy Dashboard
npx wrangler pages deploy dashboard --project-name=ea-dashboard
📖 API Documentation
Public Endpoints
Activate License
httpPOST /api/activate
Content-Type: application/json

{
  "license_key": "XXXX-XXXX-XXXX-XXXX",
  "account_number": "12345678",
  "broker_server": "ICMarkets-Demo",
  "account_type": "demo",
  "machine_id": "MACHINE123"
}
Verify License
httpPOST /api/verify
Content-Type: application/json

{
  "license_key": "XXXX-XXXX-XXXX-XXXX",
  "account_number": "12345678",
  "broker_server": "ICMarkets-Demo"
}
Admin Endpoints (Requires Authentication)
Generate License
httpPOST /api/generate
Authorization: Bearer YOUR_ADMIN_KEY
Content-Type: application/json

{
  "customer_email": "customer@example.com",
  "customer_name": "John Doe",
  "max_live": 5,
  "max_demo": 2,
  "expiry_days": 365
}
Get Statistics
httpGET /api/admin/stats
Authorization: Bearer YOUR_ADMIN_KEY
🔧 MQL5/4 Integration
Add to your Expert Advisor:
cppinput string InpLicenseKey = "";  // License Key

string g_apiUrl = "https://your-worker.workers.dev";

int OnInit() {
    if(!ValidateLicense(InpLicenseKey)) {
        Alert("Invalid License!");
        return INIT_FAILED;
    }
    return INIT_SUCCEEDED;
}

bool ValidateLicense(string key) {
    // Implementation in ea-mql5-integration file
    // Handles activation and verification
    return true;
}
🏗️ Architecture
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   MetaTrader    │────▶│ Cloudflare      │────▶│   D1 Database   │
│   Terminal      │◀────│   Worker        │◀────│   (Sqlite)      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                              │
                              ▼
                        ┌─────────────────┐
                        │   Dashboard     │
                        │  (Pages/HTML)   │
                        └─────────────────┘
📊 Dashboard Access

Navigate to https://your-dashboard.pages.dev
Click "Sign In"
Enter your admin API key
Access features:

Generate licenses
Monitor activations
View activity logs
Export data



🔐 Security Best Practices

Strong Admin Key: Generate using openssl rand -hex 32
Enable Cloudflare Access: Add authentication layer
Rate Limiting: Configure WAF rules
Regular Backups: Export data weekly
Monitor Logs: Check for suspicious activity

📝 Environment Variables
VariableDescriptionRequiredADMIN_API_KEYGlobal admin authentication✅TELEGRAM_BOT_TOKENTelegram bot token❌TELEGRAM_CHAT_IDTelegram chat for notifications❌ENFORCE_BILLINGEnable payment enforcement (0/1)❌DEFAULT_TENANT_IDDefault tenant identifier❌
🤝 Multi-Tenant Support
Create a new tenant for EA builders:
bashcurl -X POST https://your-worker.workers.dev/api/admin/tenants/create \
  -H "Authorization: Bearer GLOBAL_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme EAs",
    "email": "admin@acme.com",
    "subdomain": "acme",
    "trial_days": 14
  }'
📈 Monitoring

Wrangler Tail: wrangler tail for real-time logs
Telegram Alerts: Automatic notifications for key events
Dashboard Stats: Real-time metrics and activity tracking

🧪 Testing
bash# Test API endpoint
curl https://your-worker.workers.dev

# Test license generation
curl -X POST https://your-worker.workers.dev/api/generate \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"customer_email":"test@example.com","max_live":1}'
📦 Project Structure
ea-license-system/
├── worker.js           # Main API backend
├── index.html          # Dashboard interface
├── schema.sql          # Database schema
├── wrangler.toml       # Cloudflare configuration
├── dashboard/          # Dashboard files
│   └── index.html      # Enhanced dashboard
└── mql5/              # MetaTrader integration
    ├── LicenseProtectedEA.mq5
    └── LicenseProtectedEA.mq4
🛠️ Troubleshooting
IssueSolution405 ErrorCheck API URL in dashboard matches worker URLWebRequest FailedAdd worker URL to MT4/5 allowed URLsUnauthorizedVerify admin key is correctDatabase ErrorRun wrangler d1 execute to check schema
📄 License
MIT License - see LICENSE file for details
🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

Fork the repository
Create your feature branch (git checkout -b feature/AmazingFeature)
Commit your changes (git commit -m 'Add some AmazingFeature')
Push to the branch (git push origin feature/AmazingFeature)
Open a Pull Request

💬 Support

Documentation: Wiki
Issues: GitHub Issues
Telegram: Join us @ghwmelite

🙏 Acknowledgments

Built on Cloudflare Workers
Database powered by Cloudflare D1
UI framework inspiration from modern fintech platforms


Built with ❤️ for MetaTrader EA developers
