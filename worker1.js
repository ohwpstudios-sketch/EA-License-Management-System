// EA License System - Cloudflare Worker Backend
// Deploy this to your Cloudflare Worker at ea-license-system.ghwmelite.workers.dev

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    
    // CORS headers for API access
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Content-Type': 'application/json'
    };
    
    // Handle preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    
    // Route the request
    try {
      // Public endpoints (no auth required)
      if (path === '/api/activate' && request.method === 'POST') {
        return await handleActivation(request, env, corsHeaders);
      }
      
      if (path === '/api/verify' && request.method === 'POST') {
        return await handleVerification(request, env, corsHeaders);
      }
      
      if (path === '/api/deactivate' && request.method === 'POST') {
        return await handleDeactivation(request, env, corsHeaders);
      }
      
      // Admin endpoints (require auth)
      const isAdmin = await verifyAdminAuth(request, env);
      
      if (path === '/api/generate' && request.method === 'POST') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await generateLicense(request, env, corsHeaders);
      }
      
      if (path === '/api/admin/stats' && request.method === 'GET') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await getStats(env, corsHeaders);
      }
      
      if (path === '/api/admin/licenses' && request.method === 'GET') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await getLicenses(request, env, corsHeaders);
      }
      
      if (path === '/api/admin/activations' && request.method === 'GET') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await getActivations(request, env, corsHeaders);
      }
      
      if (path === '/api/admin/logs' && request.method === 'GET') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await getLogs(request, env, corsHeaders);
      }
      
      if (path === '/api/admin/suspend' && request.method === 'POST') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await suspendLicense(request, env, corsHeaders);
      }
      
      if (path === '/api/admin/revoke' && request.method === 'POST') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await revokeLicense(request, env, corsHeaders);
      }
      
      // Default response
      return new Response(JSON.stringify({
        success: true,
        message: 'EA License System API',
        version: '2.0.1',
        endpoints: {
          public: ['/api/activate', '/api/verify', '/api/deactivate'],
          admin: ['/api/generate', '/api/admin/stats', '/api/admin/licenses']
        }
      }), { headers: corsHeaders });
      
    } catch (error) {
      return new Response(JSON.stringify({
        success: false,
        error: error.message
      }), { 
        status: 500, 
        headers: corsHeaders 
      });
    }
  }
};

// ============= AUTHENTICATION =============
async function verifyAdminAuth(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return false;
  }
  
  const token = authHeader.substring(7);
  const adminKey = env.ADMIN_API_KEY || 'your-secure-admin-key-here';
  
  return token === adminKey;
}

function unauthorized(headers) {
  return new Response(JSON.stringify({
    success: false,
    error: 'Unauthorized'
  }), { 
    status: 401, 
    headers 
  });
}

// ============= LICENSE GENERATION =============
async function generateLicense(request, env, headers) {
  const data = await request.json();
  const {
    customer_email,
    customer_name,
    max_live = 5,
    max_demo = 2,
    expiry_days = null
  } = data;
  
  // Generate unique license key
  const licenseKey = generateLicenseKey();
  
  // Calculate expiry date
  const expiryDate = expiry_days 
    ? new Date(Date.now() + expiry_days * 24 * 60 * 60 * 1000).toISOString()
    : null;
  
  // Store in D1 database
  const result = await env.ea_license_db_new.prepare(`
    INSERT INTO licenses (
      license_key,
      customer_email,
      customer_name,
      max_live_accounts,
      max_demo_accounts,
      expiry_date,
      status,
      created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'active', datetime('now'))
  `).bind(
    licenseKey,
    customer_email,
    customer_name,
    max_live,
    max_demo,
    expiryDate
  ).run();
  
  // Log the action
  await logActivity(env, licenseKey, 'generate', `License created for ${customer_email}`, request);
  
  return new Response(JSON.stringify({
    success: true,
    license_key: licenseKey,
    customer_email,
    max_live_accounts: max_live,
    max_demo_accounts: max_demo,
    expiry_date: expiryDate,
    message: 'License generated successfully'
  }), { headers });
}

function generateLicenseKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const segments = 4;
  const segmentLength = 4;
  const key = [];
  
  for (let i = 0; i < segments; i++) {
    let segment = '';
    for (let j = 0; j < segmentLength; j++) {
      segment += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    key.push(segment);
  }
  
  return key.join('-');
}

// ============= ACTIVATION HANDLING =============
async function handleActivation(request, env, headers) {
  const data = await request.json();
  const {
    license_key,
    account_number,
    broker_server,
    account_type,
    machine_id
  } = data;
  
  // Validate license
  const license = await env.ea_license_db_new.prepare(`
    SELECT * FROM licenses WHERE license_key = ? AND status = 'active'
  `).bind(license_key).first();
  
  if (!license) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Invalid or inactive license'
    }), { status: 400, headers });
  }
  
  // Check expiry
  if (license.expiry_date && new Date(license.expiry_date) < new Date()) {
    await env.ea_license_db_new.prepare(`
      UPDATE licenses SET status = 'expired' WHERE license_key = ?
    `).bind(license_key).run();
    
    return new Response(JSON.stringify({
      success: false,
      error: 'License has expired'
    }), { status: 400, headers });
  }
  
  // Check activation limits
  const activations = await env.ea_license_db_new.prepare(`
    SELECT COUNT(*) as count FROM activations 
    WHERE license_key = ? AND account_type = ? AND status = 'active'
  `).bind(license_key, account_type).first();
  
  const maxAllowed = account_type === 'live' 
    ? license.max_live_accounts 
    : license.max_demo_accounts;
  
  if (activations.count >= maxAllowed) {
    return new Response(JSON.stringify({
      success: false,
      error: `Maximum ${account_type} activations reached (${maxAllowed})`
    }), { status: 400, headers });
  }
  
  // Check if already activated
  const existing = await env.ea_license_db_new.prepare(`
    SELECT * FROM activations 
    WHERE license_key = ? AND account_number = ? AND broker_server = ?
  `).bind(license_key, account_number, broker_server).first();
  
  if (existing) {
    // Update last check time
    await env.ea_license_db_new.prepare(`
      UPDATE activations 
      SET last_check = datetime('now'), status = 'active'
      WHERE id = ?
    `).bind(existing.id).run();
    
    return new Response(JSON.stringify({
      success: true,
      message: 'Account already activated',
      activation_id: existing.id
    }), { headers });
  }
  
  // Create new activation
  const activation = await env.ea_license_db_new.prepare(`
    INSERT INTO activations (
      license_key,
      account_number,
      broker_server,
      account_type,
      machine_id,
      status,
      activation_date,
      last_check
    ) VALUES (?, ?, ?, ?, ?, 'active', datetime('now'), datetime('now'))
  `).bind(
    license_key,
    account_number,
    broker_server,
    account_type,
    machine_id
  ).run();
  
  // Log activity
  await logActivity(env, license_key, 'activation', 
    `${account_type} account ${account_number} activated`, request);
  
  return new Response(JSON.stringify({
    success: true,
    message: 'Activation successful',
    activation_id: activation.meta.last_row_id,
    expires: license.expiry_date
  }), { headers });
}

// ============= VERIFICATION HANDLING =============
async function handleVerification(request, env, headers) {
  const data = await request.json();
  const { license_key, account_number, broker_server } = data;
  
  // Check license status
  const license = await env.ea_license_db_new.prepare(`
    SELECT * FROM licenses WHERE license_key = ?
  `).bind(license_key).first();
  
  if (!license || license.status !== 'active') {
    return new Response(JSON.stringify({
      success: false,
      valid: false,
      error: 'License is not active'
    }), { status: 200, headers });
  }
  
  // Check expiry
  if (license.expiry_date && new Date(license.expiry_date) < new Date()) {
    return new Response(JSON.stringify({
      success: false,
      valid: false,
      error: 'License has expired'
    }), { status: 200, headers });
  }
  
  // Check activation
  const activation = await env.ea_license_db_new.prepare(`
    SELECT * FROM activations 
    WHERE license_key = ? AND account_number = ? AND broker_server = ? AND status = 'active'
  `).bind(license_key, account_number, broker_server).first();
  
  if (!activation) {
    return new Response(JSON.stringify({
      success: false,
      valid: false,
      error: 'Account not activated'
    }), { status: 200, headers });
  }
  
  // Update last check
  await env.ea_license_db_new.prepare(`
    UPDATE activations SET last_check = datetime('now') WHERE id = ?
  `).bind(activation.id).run();
  
  // Log verification
  await logActivity(env, license_key, 'verification', 
    `Account ${account_number} verified`, request);
  
  return new Response(JSON.stringify({
    success: true,
    valid: true,
    expires: license.expiry_date,
    account_type: activation.account_type,
    message: 'License valid and active'
  }), { headers });
}

// ============= DEACTIVATION HANDLING =============
async function handleDeactivation(request, env, headers) {
  const data = await request.json();
  const { license_key, account_number, broker_server } = data;
  
  const result = await env.ea_license_db_new.prepare(`
    UPDATE activations 
    SET status = 'inactive', deactivation_date = datetime('now')
    WHERE license_key = ? AND account_number = ? AND broker_server = ?
  `).bind(license_key, account_number, broker_server).run();
  
  if (result.meta.changes === 0) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Activation not found'
    }), { status: 404, headers });
  }
  
  await logActivity(env, license_key, 'deactivation', 
    `Account ${account_number} deactivated`, request);
  
  return new Response(JSON.stringify({
    success: true,
    message: 'Deactivation successful'
  }), { headers });
}

// ============= ADMIN FUNCTIONS =============
async function getStats(env, headers) {
  const stats = await env.ea_license_db_new.prepare(`
    SELECT 
      (SELECT COUNT(*) FROM licenses) as total_licenses,
      (SELECT COUNT(*) FROM licenses WHERE status = 'active') as active_licenses,
      (SELECT COUNT(*) FROM activations WHERE status = 'active') as total_activations,
      (SELECT COUNT(*) FROM activity_logs WHERE DATE(created_at) = DATE('now')) as activity_today
  `).first();
  
  const recent = await env.ea_license_db_new.prepare(`
    SELECT * FROM licenses 
    ORDER BY created_at DESC 
    LIMIT 5
  `).all();
  
  return new Response(JSON.stringify({
    success: true,
    ...stats,
    recent: recent.results
  }), { headers });
}

async function getLicenses(request, env, headers) {
  const url = new URL(request.url);
  const search = url.searchParams.get('search') || '';
  const status = url.searchParams.get('status') || '';
  const page = parseInt(url.searchParams.get('page') || '1');
  const pageSize = parseInt(url.searchParams.get('page_size') || '25');
  const exportFormat = url.searchParams.get('export');
  
  let query = 'SELECT * FROM licenses WHERE 1=1';
  const params = [];
  
  if (search) {
    query += ' AND (license_key LIKE ? OR customer_email LIKE ? OR customer_name LIKE ?)';
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }
  
  if (status) {
    query += ' AND status = ?';
    params.push(status);
  }
  
  // Get total count
  const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as total');
  const stmt = env.ea_license_db_new.prepare(countQuery);
  if (params.length) stmt.bind(...params);
  const { total } = await stmt.first();
  
  // Handle CSV export
  if (exportFormat === 'csv') {
    const allResults = await env.ea_license_db_new.prepare(query).bind(...params).all();
    const csv = convertToCSV(allResults.results);
    
    return new Response(csv, {
      headers: {
        ...headers,
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="licenses.csv"'
      }
    });
  }
  
  // Add pagination
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(pageSize, (page - 1) * pageSize);
  
  const results = await env.ea_license_db_new.prepare(query).bind(...params).all();
  
  return new Response(JSON.stringify({
    success: true,
    items: results.results,
    total,
    page,
    page_size: pageSize,
    total_pages: Math.ceil(total / pageSize)
  }), { headers });
}

async function getActivations(request, env, headers) {
  const url = new URL(request.url);
  const search = url.searchParams.get('search') || '';
  const type = url.searchParams.get('type') || '';
  const page = parseInt(url.searchParams.get('page') || '1');
  const pageSize = parseInt(url.searchParams.get('page_size') || '25');
  
  let query = 'SELECT * FROM activations WHERE 1=1';
  const params = [];
  
  if (search) {
    query += ' AND (license_key LIKE ? OR account_number LIKE ? OR broker_server LIKE ?)';
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }
  
  if (type) {
    query += ' AND account_type = ?';
    params.push(type);
  }
  
  // Get total count
  const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as total');
  const { total } = await env.ea_license_db_new.prepare(countQuery).bind(...params).first();
  
  // Add pagination
  query += ' ORDER BY activation_date DESC LIMIT ? OFFSET ?';
  params.push(pageSize, (page - 1) * pageSize);
  
  const results = await env.ea_license_db_new.prepare(query).bind(...params).all();
  
  return new Response(JSON.stringify({
    success: true,
    items: results.results,
    total,
    page,
    page_size: pageSize,
    total_pages: Math.ceil(total / pageSize)
  }), { headers });
}

async function getLogs(request, env, headers) {
  const url = new URL(request.url);
  const from = url.searchParams.get('from');
  const to = url.searchParams.get('to');
  const action = url.searchParams.get('action');
  const page = parseInt(url.searchParams.get('page') || '1');
  const pageSize = parseInt(url.searchParams.get('page_size') || '25');
  
  let query = 'SELECT * FROM activity_logs WHERE 1=1';
  const params = [];
  
  if (from) {
    query += ' AND DATE(created_at) >= DATE(?)';
    params.push(from);
  }
  
  if (to) {
    query += ' AND DATE(created_at) <= DATE(?)';
    params.push(to);
  }
  
  if (action) {
    query += ' AND action = ?';
    params.push(action);
  }
  
  // Get total count
  const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as total');
  const { total } = await env.ea_license_db_new.prepare(countQuery).bind(...params).first();
  
  // Add pagination
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(pageSize, (page - 1) * pageSize);
  
  const results = await env.ea_license_db_new.prepare(query).bind(...params).all();
  
  return new Response(JSON.stringify({
    success: true,
    items: results.results,
    total,
    page,
    page_size: pageSize,
    total_pages: Math.ceil(total / pageSize)
  }), { headers });
}

async function suspendLicense(request, env, headers) {
  const { license_key } = await request.json();
  
  await env.ea_license_db_new.prepare(`
    UPDATE licenses SET status = 'suspended' WHERE license_key = ?
  `).bind(license_key).run();
  
  await logActivity(env, license_key, 'suspension', 'License suspended by admin', request);
  
  return new Response(JSON.stringify({
    success: true,
    message: 'License suspended'
  }), { headers });
}

async function revokeLicense(request, env, headers) {
  const { license_key } = await request.json();
  
  // Deactivate all activations
  await env.ea_license_db_new.prepare(`
    UPDATE activations SET status = 'inactive' WHERE license_key = ?
  `).bind(license_key).run();
  
  // Revoke license
  await env.ea_license_db_new.prepare(`
    UPDATE licenses SET status = 'revoked' WHERE license_key = ?
  `).bind(license_key).run();
  
  await logActivity(env, license_key, 'revocation', 'License revoked by admin', request);
  
  return new Response(JSON.stringify({
    success: true,
    message: 'License revoked'
  }), { headers });
}

// ============= UTILITY FUNCTIONS =============
async function logActivity(env, licenseKey, action, details, request) {
  const ip = request.headers.get('CF-Connecting-IP') || 
              request.headers.get('X-Forwarded-For') || 
              'unknown';
  
  await env.ea_license_db_new.prepare(`
    INSERT INTO activity_logs (license_key, action, details, ip_address, created_at)
    VALUES (?, ?, ?, ?, datetime('now'))
  `).bind(licenseKey, action, details, ip).run();
}

function convertToCSV(data) {
  if (!data || data.length === 0) return '';
  
  const headers = Object.keys(data[0]);
  const csvHeaders = headers.join(',');
  
  const csvRows = data.map(row => {
    return headers.map(header => {
      const value = row[header];
      return typeof value === 'string' && value.includes(',') 
        ? `"${value}"` 
        : value;
    }).join(',');
  });
  
  return [csvHeaders, ...csvRows].join('\n');
}