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
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Tenant-Id',
      'Content-Type': 'application/json'
    };
    
    // Handle preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    
    // Get tenant ID from header or use default
    const tenantId = request.headers.get('X-Tenant-Id') || env.DEFAULT_TENANT_ID || 'tenant_default';
    
    // Route the request
    try {
      // Public endpoints (no auth required but tenant-aware)
      if (path === '/api/activate' && request.method === 'POST') {
        return await handleActivation(request, env, corsHeaders, tenantId);
      }
      
      if (path === '/api/store/complete-purchase' && request.method === 'POST') {
        return await completePaystackPurchase(request, env, corsHeaders, tenantId);
      }

      if (path === '/api/verify' && request.method === 'POST') {
        return await handleVerification(request, env, corsHeaders, tenantId);
      }
      
      if (path === '/api/deactivate' && request.method === 'POST') {
        return await handleDeactivation(request, env, corsHeaders, tenantId);
      }
      
      // Admin endpoints (require auth)
      const isAdmin = await verifyAdminAuth(request, env);
      
      if (path === '/api/generate' && request.method === 'POST') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await generateLicense(request, env, corsHeaders, tenantId);
      }
      
      if (path === '/api/admin/stats' && request.method === 'GET') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await getStats(env, corsHeaders, tenantId);
      }
      
      if (path === '/api/admin/licenses' && request.method === 'GET') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await getLicenses(request, env, corsHeaders, tenantId);
      }
      
      if (path === '/api/admin/activations' && request.method === 'GET') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await getActivations(request, env, corsHeaders, tenantId);
      }
      
      if (path === '/api/admin/logs' && request.method === 'GET') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await getLogs(request, env, corsHeaders, tenantId);
      }
      
      if (path === '/api/admin/suspend' && request.method === 'POST') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await suspendLicense(request, env, corsHeaders, tenantId);
      }
      
      if (path === '/api/admin/revoke' && request.method === 'POST') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await revokeLicense(request, env, corsHeaders, tenantId);
      }
      
      // Tenant management endpoints
      if (path === '/api/admin/tenants' && request.method === 'GET') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await listTenants(env, corsHeaders);
      }
      
      if (path === '/api/admin/tenants' && request.method === 'POST') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await createTenant(request, env, corsHeaders);
      }
      
      if (path === '/api/admin/tenant/switch' && request.method === 'POST') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await switchTenant(request, env, corsHeaders);
      }
      
      // Store endpoints - Public
      if (path === '/api/store/products' && request.method === 'GET') {
        return await getProducts(request, env, corsHeaders, tenantId);
      }
      
      // Store endpoints - Admin (require auth)
      if (path === '/api/admin/products' && request.method === 'GET') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await getProducts(request, env, corsHeaders, tenantId);
      }
      
      if (path === '/api/admin/products' && request.method === 'POST') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await createProduct(request, env, corsHeaders, tenantId);
      }
      
      if (path === '/api/admin/products' && request.method === 'PUT') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await updateProduct(request, env, corsHeaders, tenantId);
      }
      
      if (path === '/api/admin/store/stats' && request.method === 'GET') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await getStoreStats(env, corsHeaders, tenantId);
      }
      
      // User Registration endpoints (public)
      if (path === '/api/auth/register' && request.method === 'POST') {
        return await registerUser(request, env, corsHeaders);
      }
      
      // User Login endpoint (public)
      if (path === '/api/auth/login' && request.method === 'POST') {
        return await loginUser(request, env, corsHeaders);
      }
      
      if (path === '/api/store/guest-checkout' && request.method === 'POST') {
        return await guestCheckout(request, env, corsHeaders, tenantId);
      }
	  
	  // === User-facing: purchase history ===
      if (path === '/api/user/orders' && request.method === 'GET') {
        return await getUserOrders(request, env, corsHeaders, tenantId);
}

	  
	  // === User-facing endpoints (add these) ===
      if (path === '/api/user/licenses' && request.method === 'GET') {
        return await getUserLicenses(request, env, corsHeaders, tenantId);
      }

      if (path === '/api/user/activations' && request.method === 'GET') {
        return await getUserActivations(request, env, corsHeaders, tenantId);
      }

      
      // Admin user management endpoints
      if (path === '/api/admin/registrations' && request.method === 'GET') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await getPendingRegistrations(env, corsHeaders);
      }
      
      if (path === '/api/admin/registrations/approve' && request.method === 'POST') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await approveRegistration(request, env, corsHeaders);
      }
      
      if (path === '/api/admin/registrations/reject' && request.method === 'POST') {
        if (!isAdmin) return unauthorized(corsHeaders);
        return await rejectRegistration(request, env, corsHeaders);
      }
      
      // Default response
      return new Response(JSON.stringify({
        success: true,
        message: 'EA License System API',
        version: '2.0.1',
        tenant: tenantId,
        endpoints: {
          public: ['/api/activate', '/api/verify', '/api/deactivate'],
          admin: ['/api/generate', '/api/admin/stats', '/api/admin/licenses']
        }
      }), { headers: corsHeaders });
      
    } catch (error) {
      console.error('API Error:', error);
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

// Edit Product Function
async function editProduct(request, env, headers, tenantId) {
  const data = await request.json();
  const { 
    id, 
    product_name, 
    description, 
    price, 
    max_live_accounts,
    max_demo_accounts,
    license_duration_days,
    product_image,
    is_active 
  } = data;
  
  await env.ea_license_db_new.prepare(`
    UPDATE products 
    SET product_name = ?,
        description = ?,
        price = ?,
        max_live_accounts = ?,
        max_demo_accounts = ?,
        license_duration_days = ?,
        product_image = ?,
        is_active = ?,
        updated_at = datetime('now')
    WHERE id = ? AND tenant_id = ?
  `).bind(
    product_name,
    description,
    price,
    max_live_accounts || 5,
    max_demo_accounts || 2,
    license_duration_days || null,
    product_image || '',
    is_active ? 1 : 0,
    id,
    tenantId
  ).run();
  
  return new Response(JSON.stringify({
    success: true,
    message: 'Product updated successfully'
  }), { headers });
}

// ============= LICENSE GENERATION =============
async function generateLicense(request, env, headers, tenantId) {
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
  
  // Check if tenant_id column exists
  const hasMultiTenancy = env.ENABLE_MULTI_TENANCY === '1';
  
  // Store in D1 database with tenant_id
  const query = hasMultiTenancy ? `
    INSERT INTO licenses (
      license_key,
      customer_email,
      customer_name,
      max_live_accounts,
      max_demo_accounts,
      expiry_date,
      status,
      tenant_id,
      created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, datetime('now'))
  ` : `
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
  `;
  
  const params = hasMultiTenancy ? 
    [licenseKey, customer_email, customer_name, max_live, max_demo, expiryDate, tenantId] :
    [licenseKey, customer_email, customer_name, max_live, max_demo, expiryDate];
  
  const result = await env.ea_license_db_new.prepare(query).bind(...params).run();
  
  // Log the action
  await logActivity(env, licenseKey, 'generate', `License created for ${customer_email}`, request, tenantId);
  
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

// ============= ADMIN FUNCTIONS =============
async function getStats(env, headers, tenantId) {
  const mt = env.ENABLE_MULTI_TENANCY === '1';

  const stats = await env.ea_license_db_new.prepare(`
    SELECT
      (SELECT COUNT(*) FROM licenses ${mt ? 'WHERE tenant_id = ?' : ''}) AS total_licenses,
      (SELECT COUNT(*) FROM licenses WHERE status = 'active' ${mt ? 'AND tenant_id = ?' : ''}) AS active_licenses,
      (SELECT COUNT(*) FROM activations WHERE status = 'active' ${mt ? 'AND tenant_id = ?' : ''}) AS total_activations,
      (SELECT COUNT(*) FROM activity_logs WHERE DATE(created_at) = DATE('now') ${mt ? 'AND tenant_id = ?' : ''}) AS activity_today
  `).bind(...(mt ? [tenantId, tenantId, tenantId, tenantId] : [])).first();

  const recent = await env.ea_license_db_new.prepare(
    `SELECT * FROM licenses ${mt ? 'WHERE tenant_id = ?' : ''} ORDER BY created_at DESC LIMIT 5`
  ).bind(...(mt ? [tenantId] : [])).all();

  return new Response(JSON.stringify({ success: true, ...stats, recent: recent.results }), { headers });
}

async function getLicenses(request, env, headers, tenantId) {
  const url = new URL(request.url);
  const search = url.searchParams.get('search') || '';
  const status = url.searchParams.get('status') || '';
  const page = parseInt(url.searchParams.get('page') || '1');
  const pageSize = parseInt(url.searchParams.get('page_size') || '25');
  const exportFormat = url.searchParams.get('export');
  
  const hasMultiTenancy = env.ENABLE_MULTI_TENANCY === '1';
  
  let query = 'SELECT * FROM licenses WHERE 1=1';
  const params = [];
  
  // Add tenant filter
  if (hasMultiTenancy) {
    query += ' AND tenant_id = ?';
    params.push(tenantId);
  }
  
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
  const countStmt = env.ea_license_db_new.prepare(countQuery);
  const { total } = await countStmt.bind(...params).first();
  
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

async function getActivations(request, env, headers, tenantId) {
  const url = new URL(request.url);
  const search = url.searchParams.get('search') || '';
  const type = url.searchParams.get('type') || '';
  const page = parseInt(url.searchParams.get('page') || '1');
  const pageSize = parseInt(url.searchParams.get('page_size') || '25');
  const exportFormat = url.searchParams.get('export');

  
  const hasMultiTenancy = env.ENABLE_MULTI_TENANCY === '1';
  
  let query = 'SELECT * FROM activations WHERE 1=1';
  const params = [];
  
  // Add tenant filter
  if (hasMultiTenancy) {
    query += ' AND tenant_id = ?';
    params.push(tenantId);
  }
  
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
  
  if (exportFormat === 'csv') {
    const allRows = await env.ea_license_db_new
      .prepare(query + ' ORDER BY activation_date DESC')
      .bind(...params)
      .all();

    return new Response(convertToCSV(allRows.results), {
      headers: {
        ...headers,
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="activations.csv"'
      }
    });
  }

  
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

async function getLogs(request, env, headers, tenantId) {
  const url = new URL(request.url);
  const from = url.searchParams.get('from');
  const to = url.searchParams.get('to');
  const action = url.searchParams.get('action');
  const page = parseInt(url.searchParams.get('page') || '1');
  const pageSize = parseInt(url.searchParams.get('page_size') || '25');
  const exportFormat = url.searchParams.get('export');

  
  const hasMultiTenancy = env.ENABLE_MULTI_TENANCY === '1';
  
  let query = 'SELECT * FROM activity_logs WHERE 1=1';
  const params = [];
  
  // Add tenant filter
  if (hasMultiTenancy) {
    query += ' AND tenant_id = ?';
    params.push(tenantId);
  }
  
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
  
  // CSV export (uses the same filters; no pagination for full extract)
  if (exportFormat === 'csv') {
    // (Optional feature flag – leave or remove as you prefer)
    if (env.ENABLE_CSV_EXPORT === '0') {
      return new Response(JSON.stringify({ success:false, error:'CSV export disabled' }), { status:403, headers });
    }

    const allRows = await env.ea_license_db_new
      .prepare(query + ' ORDER BY created_at DESC')
      .bind(...params)
      .all();

    return new Response(convertToCSV(allRows.results), {
      headers: {
        ...headers,
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="activity_logs.csv"'
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

// ============= ACTIVATION HANDLING =============
async function handleActivation(request, env, headers, tenantId) {
  const data = await request.json();
  const {
    license_key,
    account_number,
    broker_server,
    account_type,
    machine_id
  } = data;
  
  const hasMultiTenancy = env.ENABLE_MULTI_TENANCY === '1';
  const tenantClause = hasMultiTenancy ? ' AND tenant_id = ?' : '';
  
  // Validate license
  const licenseQuery = `SELECT * FROM licenses WHERE license_key = ? AND status = 'active'${tenantClause}`;
  const licenseParams = hasMultiTenancy ? [license_key, tenantId] : [license_key];
  const license = await env.ea_license_db_new.prepare(licenseQuery).bind(...licenseParams).first();
  
  if (!license) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Invalid or inactive license'
    }), { status: 400, headers });
  }
  
  // Check expiry
  if (license.expiry_date && new Date(license.expiry_date) < new Date()) {
    await env.ea_license_db_new.prepare(`
      UPDATE licenses SET status = 'expired' WHERE license_key = ?${tenantClause}
    `).bind(...licenseParams).run();
    
    return new Response(JSON.stringify({
      success: false,
      error: 'License has expired'
    }), { status: 400, headers });
  }
  
  // Check activation limits
  const activationsQuery = `
    SELECT COUNT(*) as count FROM activations 
    WHERE license_key = ? AND account_type = ? AND status = 'active'${tenantClause}
  `;
  const activationsParams = hasMultiTenancy ? 
    [license_key, account_type, tenantId] : 
    [license_key, account_type];
  const activations = await env.ea_license_db_new.prepare(activationsQuery)
    .bind(...activationsParams).first();
  
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
  const existingQuery = `
    SELECT * FROM activations 
    WHERE license_key = ? AND account_number = ? AND broker_server = ?${tenantClause}
  `;
  const existingParams = hasMultiTenancy ?
    [license_key, account_number, broker_server, tenantId] :
    [license_key, account_number, broker_server];
  const existing = await env.ea_license_db_new.prepare(existingQuery)
    .bind(...existingParams).first();
  
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
  const insertQuery = hasMultiTenancy ? `
    INSERT INTO activations (
      license_key,
      account_number,
      broker_server,
      account_type,
      machine_id,
      tenant_id,
      status,
      activation_date,
      last_check
    ) VALUES (?, ?, ?, ?, ?, ?, 'active', datetime('now'), datetime('now'))
  ` : `
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
  `;
  
  const insertParams = hasMultiTenancy ?
    [license_key, account_number, broker_server, account_type, machine_id, tenantId] :
    [license_key, account_number, broker_server, account_type, machine_id];
    
  const activation = await env.ea_license_db_new.prepare(insertQuery)
    .bind(...insertParams).run();
  
  // Log activity
  await logActivity(env, license_key, 'activation', 
    `${account_type} account ${account_number} activated`, request, tenantId);
  
  return new Response(JSON.stringify({
    success: true,
    message: 'Activation successful',
    activation_id: activation.meta.last_row_id,
    expires: license.expiry_date
  }), { headers });
}

// ============= VERIFICATION HANDLING =============
async function handleVerification(request, env, headers, tenantId) {
  const data = await request.json();
  const { license_key, account_number, broker_server } = data;
  
  const hasMultiTenancy = env.ENABLE_MULTI_TENANCY === '1';
  const tenantClause = hasMultiTenancy ? ' AND tenant_id = ?' : '';
  
  // Check license status
  const licenseQuery = `SELECT * FROM licenses WHERE license_key = ?${tenantClause}`;
  const licenseParams = hasMultiTenancy ? [license_key, tenantId] : [license_key];
  const license = await env.ea_license_db_new.prepare(licenseQuery).bind(...licenseParams).first();
  
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
  const activationQuery = `
    SELECT * FROM activations 
    WHERE license_key = ? AND account_number = ? AND broker_server = ? AND status = 'active'${tenantClause}
  `;
  const activationParams = hasMultiTenancy ?
    [license_key, account_number, broker_server, tenantId] :
    [license_key, account_number, broker_server];
  const activation = await env.ea_license_db_new.prepare(activationQuery)
    .bind(...activationParams).first();
  
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
    `Account ${account_number} verified`, request, tenantId);
  
  return new Response(JSON.stringify({
    success: true,
    valid: true,
    expires: license.expiry_date,
    account_type: activation.account_type,
    message: 'License valid and active'
  }), { headers });
}

// ============= DEACTIVATION HANDLING =============
async function handleDeactivation(request, env, headers, tenantId) {
  const data = await request.json();
  const { license_key, account_number, broker_server } = data;
  
  const hasMultiTenancy = env.ENABLE_MULTI_TENANCY === '1';
  const tenantClause = hasMultiTenancy ? ' AND tenant_id = ?' : '';
  
  const query = `
    UPDATE activations 
    SET status = 'inactive', deactivation_date = datetime('now')
    WHERE license_key = ? AND account_number = ? AND broker_server = ?${tenantClause}
  `;
  const params = hasMultiTenancy ?
    [license_key, account_number, broker_server, tenantId] :
    [license_key, account_number, broker_server];
    
  const result = await env.ea_license_db_new.prepare(query).bind(...params).run();
  
  if (result.meta.changes === 0) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Activation not found'
    }), { status: 404, headers });
  }
  
  await logActivity(env, license_key, 'deactivation', 
    `Account ${account_number} deactivated`, request, tenantId);
  
  return new Response(JSON.stringify({
    success: true,
    message: 'Deactivation successful'
  }), { headers });
}

async function suspendLicense(request, env, headers, tenantId) {
  const { license_key } = await request.json();
  
  const hasMultiTenancy = env.ENABLE_MULTI_TENANCY === '1';
  const tenantClause = hasMultiTenancy ? ' AND tenant_id = ?' : '';
  
  const query = `UPDATE licenses SET status = 'suspended' WHERE license_key = ?${tenantClause}`;
  const params = hasMultiTenancy ? [license_key, tenantId] : [license_key];
  
  await env.ea_license_db_new.prepare(query).bind(...params).run();
  
  await logActivity(env, license_key, 'suspension', 'License suspended by admin', request, tenantId);
  
  return new Response(JSON.stringify({
    success: true,
    message: 'License suspended'
  }), { headers });
}

async function revokeLicense(request, env, headers, tenantId) {
  const { license_key } = await request.json();
  
  const hasMultiTenancy = env.ENABLE_MULTI_TENANCY === '1';
  const tenantClause = hasMultiTenancy ? ' AND tenant_id = ?' : '';
  
  // Deactivate all activations
  const deactivateQuery = `UPDATE activations SET status = 'inactive' WHERE license_key = ?${tenantClause}`;
  const deactivateParams = hasMultiTenancy ? [license_key, tenantId] : [license_key];
  await env.ea_license_db_new.prepare(deactivateQuery).bind(...deactivateParams).run();
  
  // Revoke license
  const revokeQuery = `UPDATE licenses SET status = 'revoked' WHERE license_key = ?${tenantClause}`;
  const revokeParams = hasMultiTenancy ? [license_key, tenantId] : [license_key];
  await env.ea_license_db_new.prepare(revokeQuery).bind(...revokeParams).run();
  
  await logActivity(env, license_key, 'revocation', 'License revoked by admin', request, tenantId);
  
  return new Response(JSON.stringify({
    success: true,
    message: 'License revoked'
  }), { headers });
}

// ============= UTILITY FUNCTIONS =============
async function logActivity(env, licenseKey, action, details, request, tenantId) {
  const ip = request.headers.get('CF-Connecting-IP') || 
              request.headers.get('X-Forwarded-For') || 
              'unknown';
  
  const hasMultiTenancy = env.ENABLE_MULTI_TENANCY === '1';
  
  const query = hasMultiTenancy ? `
    INSERT INTO activity_logs (license_key, action, details, ip_address, tenant_id, created_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
  ` : `
    INSERT INTO activity_logs (license_key, action, details, ip_address, created_at)
    VALUES (?, ?, ?, ?, datetime('now'))
  `;
  
  const params = hasMultiTenancy ?
    [licenseKey, action, details, ip, tenantId] :
    [licenseKey, action, details, ip];
    
  await env.ea_license_db_new.prepare(query).bind(...params).run();
}

function convertToCSV(items) {
  if (!items || items.length === 0) return '';

  const headers = Object.keys(items[0]);
  const head = headers.join(',');

  const rows = items.map(row =>
    headers.map(h => {
      const v = row[h];
      if (v === null || v === undefined) return '';
      const s = String(v);
      // Escape quotes and wrap if value has comma/newline/quote
      if (s.includes(',') || s.includes('\n') || s.includes('"')) {
        return `"${s.replace(/"/g, '""')}"`;
      }
      return s;
    }).join(',')
  );

  return [head, ...rows].join('\n');
}

// ============= TENANT MANAGEMENT =============
async function listTenants(env, headers) {
  try {
    const tenants = await env.ea_license_db_new.prepare(`
      SELECT id, name, subdomain, admin_email, status, created_at 
      FROM tenants 
      ORDER BY created_at DESC
    `).all();
    
    return new Response(JSON.stringify({
      success: true,
      tenants: tenants.results || []
    }), { headers });
  } catch (error) {
    console.error('List tenants error:', error);
    return new Response(JSON.stringify({
      success: false,
      error: 'Failed to list tenants'
    }), { status: 500, headers });
  }
}

async function createTenant(request, env, headers) {
  try {
    const data = await request.json();
    const { id, name, subdomain, admin_email } = data;
    
    // Validate input
    if (!id || !name) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Tenant ID and name are required'
      }), { status: 400, headers });
    }
    
    // Check if tenant ID already exists
    const existing = await env.ea_license_db_new.prepare(
      'SELECT id FROM tenants WHERE id = ?'
    ).bind(id).first();
    
    if (existing) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Tenant ID already exists'
      }), { status: 400, headers });
    }
    
    // Create the tenant
    await env.ea_license_db_new.prepare(`
      INSERT INTO tenants (id, name, subdomain, admin_email, status, created_at)
      VALUES (?, ?, ?, ?, 'active', datetime('now'))
    `).bind(id, name, subdomain || null, admin_email || null).run();
    
    return new Response(JSON.stringify({
      success: true,
      message: 'Tenant created successfully',
      tenant: { id, name, subdomain, admin_email }
    }), { headers });
  } catch (error) {
    console.error('Create tenant error:', error);
    return new Response(JSON.stringify({
      success: false,
      error: 'Failed to create tenant'
    }), { status: 500, headers });
  }
}

async function switchTenant(request, env, headers) {
  try {
    const { tenant_id } = await request.json();
    
    // Verify tenant exists
    const tenant = await env.ea_license_db_new.prepare(
      'SELECT * FROM tenants WHERE id = ?'
    ).bind(tenant_id).first();
    
    if (!tenant) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Tenant not found'
      }), { status: 404, headers });
    }
    
    return new Response(JSON.stringify({
      success: true,
      tenant: tenant
    }), { headers });
  } catch (error) {
    console.error('Switch tenant error:', error);
    return new Response(JSON.stringify({
      success: false,
      error: 'Failed to switch tenant'
    }), { status: 500, headers });
  }
}

// ============= PRODUCT MANAGEMENT =============
async function getProducts(request, env, headers, tenantId) {
  const url = new URL(request.url);
  const search = url.searchParams.get('search') || '';
  const active = url.searchParams.get('active');
  const page = parseInt(url.searchParams.get('page') || '1');
  const pageSize = parseInt(url.searchParams.get('page_size') || '12');
  
  let query = 'SELECT * FROM products WHERE tenant_id = ?';
  const params = [tenantId];
  
  if (search) {
    query += ' AND (product_name LIKE ? OR description LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }
  
  if (active !== null && active !== undefined) {
    query += ' AND is_active = ?';
    params.push(active === 'true' ? 1 : 0);
  }
  
  const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as total');
  const { total } = await env.ea_license_db_new.prepare(countQuery).bind(...params).first();
  
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(pageSize, (page - 1) * pageSize);
  
  const results = await env.ea_license_db_new.prepare(query).bind(...params).all();
  
  return new Response(JSON.stringify({
    success: true,
    products: results.results || [],
    total: total || 0,
    page,
    page_size: pageSize,
    total_pages: Math.ceil((total || 0) / pageSize)
  }), { headers });
}

async function createProduct(request, env, headers, tenantId) {
  const data = await request.json();
  const {
    product_name,
    description,
    price,
    currency = 'GHS',
    license_type = 'lifetime',
    license_duration_days,
    max_live_accounts = 5,
    max_demo_accounts = 2,
    features = [],
    download_url,
    product_image,
    is_featured = false,
    stock_quantity = -1
  } = data;
  
  const product_slug = product_name.toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') + '-' + Date.now();
  
  const result = await env.ea_license_db_new.prepare(`
    INSERT INTO products (
      tenant_id, product_name, product_slug, description, price, currency,
      license_type, license_duration_days, max_live_accounts, max_demo_accounts,
      features, download_url, product_image, is_featured, stock_quantity
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    tenantId, product_name, product_slug, description || '', price, currency,
    license_type, license_duration_days || null, max_live_accounts, max_demo_accounts,
    JSON.stringify(features), download_url || '', product_image || '', is_featured ? 1 : 0, stock_quantity
  ).run();
  
  return new Response(JSON.stringify({
    success: true,
    product_id: result.meta.last_row_id,
    product_slug,
    message: 'Product created successfully'
  }), { headers });
}

async function getStoreStats(env, headers, tenantId) {
  const stats = await env.ea_license_db_new.prepare(`
    SELECT
      (SELECT COUNT(*) FROM products WHERE tenant_id = ?) AS total_products,
      (SELECT COUNT(*) FROM products WHERE tenant_id = ? AND is_active = 1) AS active_products,
      (SELECT COUNT(*) FROM orders WHERE tenant_id = ?) AS total_orders,
      (SELECT COUNT(*) FROM orders WHERE tenant_id = ? AND payment_status = 'completed') AS completed_orders,
      (SELECT IFNULL(SUM(amount), 0) FROM orders WHERE tenant_id = ? AND payment_status = 'completed') AS total_revenue
  `).bind(tenantId, tenantId, tenantId, tenantId, tenantId).first();
  
  return new Response(JSON.stringify({
    success: true,
    total_products: stats.total_products || 0,
    active_products: stats.active_products || 0,
    total_orders: stats.total_orders || 0,
    completed_orders: stats.completed_orders || 0,
    total_revenue: stats.total_revenue || 0
  }), { headers });
}

async function updateProduct(request, env, headers, tenantId) {
  const data = await request.json();
  const { id, is_active } = data;
  
  await env.ea_license_db_new.prepare(`
    UPDATE products 
    SET is_active = ?, updated_at = datetime('now')
    WHERE id = ? AND tenant_id = ?
  `).bind(is_active ? 1 : 0, id, tenantId).run();
  
  return new Response(JSON.stringify({
    success: true,
    message: 'Product updated successfully'
  }), { headers });
}

// Return licenses for a specific user email (used by /api/user/licenses)
async function getUserLicenses(request, env, headers, tenantId) {
  const url = new URL(request.url);
  const email = (url.searchParams.get('email') || '').trim().toLowerCase();
  if (!email) {
    return new Response(JSON.stringify({ success: false, error: 'Missing email' }), { status: 400, headers });
  }

  const mt = env.ENABLE_MULTI_TENANCY === '1';

  // Join orders -> products to show product_name for each license
  const query = `
    SELECT
      l.license_key,
      l.customer_email,
      l.customer_name,
      l.status,
      l.expiry_date,
      l.max_live_accounts,
      l.max_demo_accounts,
      COALESCE(p.product_name, 'EA License') AS product_name
    FROM licenses l
    LEFT JOIN orders   o ON o.license_key = l.license_key ${mt ? 'AND o.tenant_id = l.tenant_id' : ''}
    LEFT JOIN products p ON p.id = o.product_id        ${mt ? 'AND p.tenant_id = l.tenant_id' : ''}
    WHERE l.customer_email = ?
    ${mt ? 'AND l.tenant_id = ?' : ''}
    ORDER BY l.created_at DESC
  `;

  const params = mt ? [email, tenantId] : [email];
  const rows = await env.ea_license_db_new.prepare(query).bind(...params).all();

  return new Response(JSON.stringify({
    success: true,
    licenses: rows.results || []
  }), { headers });
}

// Return activations for licenses owned by a specific user (used by /api/user/activations)
async function getUserActivations(request, env, headers, tenantId) {
  const url = new URL(request.url);
  const email = (url.searchParams.get('email') || '').trim().toLowerCase();
  if (!email) {
    return new Response(JSON.stringify({ success: false, error: 'Missing email' }), { status: 400, headers });
  }

  const mt = env.ENABLE_MULTI_TENANCY === '1';

  // Only activations for licenses where this email is the owner
  const query = `
    SELECT
      a.account_number,
      a.broker_server,
      a.account_type,
      a.status,
      a.activation_date,
      a.last_check,
      a.license_key
    FROM activations a
    JOIN licenses l
      ON l.license_key = a.license_key
      ${mt ? 'AND l.tenant_id = a.tenant_id' : ''}
    WHERE l.customer_email = ?
    ${mt ? 'AND a.tenant_id = ?' : ''}
    ORDER BY a.activation_date DESC
  `;

  const params = mt ? [email, tenantId] : [email];
  const rows = await env.ea_license_db_new.prepare(query).bind(...params).all();

  return new Response(JSON.stringify({
    success: true,
    activations: rows.results || []
  }), { headers });
}


// ============= USER AUTHENTICATION HELPERS =============
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

async function generateSessionToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array));
}

// User Registration (Public - no auth needed)
async function registerUser(request, env, headers) {
  const data = await request.json();
  const { email, password, full_name, company, phone, reason } = data;
  
  if (!email || !password) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Email and password are required'
    }), { status: 400, headers });
  }
  
  // Check if user exists
  const existing = await env.ea_license_db_new.prepare(
    'SELECT id FROM user_accounts WHERE email = ?'
  ).bind(email.toLowerCase()).first();
  
  if (existing) {
    return new Response(JSON.stringify({
      success: false,
      error: 'An account with this email already exists'
    }), { status: 400, headers });
  }
  
  const password_hash = await hashPassword(password);
  const verification_token = await generateSessionToken();
  
  // Create user account
  const result = await env.ea_license_db_new.prepare(`
    INSERT INTO user_accounts (
      email, password_hash, full_name, company, phone,
      account_status, verification_token
    ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
  `).bind(
    email.toLowerCase(),
    password_hash,
    full_name || null,
    company || null,
    phone || null,
    verification_token
  ).run();
  
  // Create registration request
  await env.ea_license_db_new.prepare(`
    INSERT INTO registration_requests (email, full_name, company, reason)
    VALUES (?, ?, ?, ?)
  `).bind(
    email.toLowerCase(),
    full_name || null,
    company || null,
    reason || null
  ).run();
  
  return new Response(JSON.stringify({
    success: true,
    message: 'Registration successful! Your account is pending approval.',
    user_id: result.meta.last_row_id
  }), { headers });
}

// User Login Function
async function loginUser(request, env, headers) {
  const data = await request.json();
  const { email, password } = data;
  
  if (!email || !password) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Email and password are required'
    }), { status: 400, headers });
  }
  
  // Get user account
  const user = await env.ea_license_db_new.prepare(
    'SELECT * FROM user_accounts WHERE email = ?'
  ).bind(email.toLowerCase()).first();
  
  if (!user) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Invalid email or password'
    }), { status: 401, headers });
  }
  
  // Check if account is approved
  if (user.account_status !== 'approved') {
    return new Response(JSON.stringify({
      success: false,
      error: user.account_status === 'pending' 
        ? 'Your account is pending approval. Please wait for admin approval.' 
        : 'Your account has been rejected. Please contact support.'
    }), { status: 403, headers });
  }
  
  // Verify password
  const passwordHash = await hashPassword(password);
  if (passwordHash !== user.password_hash) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Invalid email or password'
    }), { status: 401, headers });
  }
  
  // Generate session token
  const sessionToken = await generateSessionToken();
  
  return new Response(JSON.stringify({
    success: true,
    message: 'Login successful',
    token: sessionToken,
    email: user.email,
    full_name: user.full_name,
    role: user.email === 'admin@ghwmelite.com' ? 'admin' : 'user'
  }), { headers });
}

// Admin: Get Pending Registrations
async function getPendingRegistrations(env, headers) {
  const requests = await env.ea_license_db_new.prepare(`
    SELECT * FROM registration_requests 
    WHERE status = 'pending'
    ORDER BY created_at DESC
  `).all();
  
  return new Response(JSON.stringify({
    success: true,
    requests: requests.results || []
  }), { headers });
}

// Admin: Approve Registration
async function approveRegistration(request, env, headers) {
  const { email, notes } = await request.json();
  
  await env.ea_license_db_new.prepare(`
    UPDATE user_accounts 
    SET account_status = 'approved',
        approved_at = datetime('now')
    WHERE email = ?
  `).bind(email.toLowerCase()).run();
  
  await env.ea_license_db_new.prepare(`
    UPDATE registration_requests 
    SET status = 'approved',
        reviewed_at = datetime('now'),
        review_notes = ?
    WHERE email = ?
  `).bind(notes || null, email.toLowerCase()).run();
  
  return new Response(JSON.stringify({
    success: true,
    message: 'Registration approved successfully'
  }), { headers });
}

// Admin: Reject Registration  
async function rejectRegistration(request, env, headers) {
  const { email, reason } = await request.json();
  
  await env.ea_license_db_new.prepare(`
    UPDATE user_accounts 
    SET account_status = 'rejected'
    WHERE email = ?
  `).bind(email.toLowerCase()).run();
  
  await env.ea_license_db_new.prepare(`
    UPDATE registration_requests 
    SET status = 'rejected',
        reviewed_at = datetime('now'),
        review_notes = ?
    WHERE email = ?
  `).bind(reason || null, email.toLowerCase()).run();
  
  return new Response(JSON.stringify({
    success: true,
    message: 'Registration rejected'
  }), { headers });
}

// ============= PAYMENT PROCESSING FUNCTIONS =============

// Guest Checkout - Creates an order for guest users
async function guestCheckout(request, env, headers, tenantId) {
  const data = await request.json();
  const { product_id, customer_email, customer_name, customer_phone } = data;
  
  if (!product_id || !customer_email) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Product and email are required'
    }), { status: 400, headers });
  }
  
  // Get product details
  const product = await env.ea_license_db_new.prepare(
    'SELECT * FROM products WHERE id = ? AND tenant_id = ? AND is_active = 1'
  ).bind(product_id, tenantId).first();
  
  if (!product) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Product not found'
    }), { status: 404, headers });
  }
  
  // Generate order ID
  const orderDate = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const randomId = Math.random().toString(36).substr(2, 5).toUpperCase();
  const order_id = `ORD-${orderDate}-${randomId}`;
  
  // Create order with pending status
  await env.ea_license_db_new.prepare(`
    INSERT INTO orders (
      order_id, tenant_id, product_id, customer_email, customer_name,
      customer_phone, amount, currency, payment_status, metadata
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
  `).bind(
    order_id,
    tenantId,
    product_id,
    customer_email.toLowerCase(),
    customer_name || null,
    customer_phone || null,
    product.price,
    product.currency || 'GHS',
    JSON.stringify({ guest_checkout: true })
  ).run();
  
  return new Response(JSON.stringify({
    success: true,
    order_id,
    product_id,
    amount: product.price,
    currency: product.currency || 'GHS',
    customer_email: customer_email,
    message: 'Order created successfully. Proceed to payment.'
  }), { headers });
}

// Complete Paystack Purchase - Processes payment and creates license
async function completePaystackPurchase(request, env, headers, tenantId) {
  const data = await request.json();
  const { payment_reference, order_id, product_id, customer_email, customer_name } = data;
  
  if (!payment_reference || !order_id || !customer_email) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Missing required fields'
    }), { status: 400, headers });
  }
  
  // Check if Paystack secret key exists
  if (!env.PAYSTACK_SECRET_KEY) {
    console.error('PAYSTACK_SECRET_KEY is not configured');
    return new Response(JSON.stringify({
      success: false,
      error: 'Payment verification configuration missing. Please contact support.'
    }), { status: 500, headers });
  }
  
  // TODO: Verify payment with Paystack API
  try {
    const paystackVerification = await fetch(`https://api.paystack.co/transaction/verify/${payment_reference}`, {
      headers: {
        'Authorization': `Bearer ${env.PAYSTACK_SECRET_KEY}`
      }
    });
    
    const verificationData = await paystackVerification.json();
    
    if (!verificationData.status || verificationData.data.status !== 'success') {
      return new Response(JSON.stringify({
        success: false,
        error: 'Payment verification failed'
      }), { status: 400, headers });
    }
  } catch (error) {
    console.error('Paystack verification error:', error);
    return new Response(JSON.stringify({
      success: false,
      error: 'Payment verification failed'
    }), { status: 500, headers });
  }
  
  // Get the order
  const order = await env.ea_license_db_new.prepare(
    'SELECT * FROM orders WHERE order_id = ? AND payment_status = "pending"'
  ).bind(order_id).first();
  
  if (!order) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Order not found or already processed'
    }), { status: 404, headers });
  }
  
  // Get product details
  const product = await env.ea_license_db_new.prepare(
    'SELECT * FROM products WHERE id = ? AND tenant_id = ?'
  ).bind(order.product_id, tenantId).first();
  
  if (!product) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Product not found'
    }), { status: 404, headers });
  }
  
  // Generate license key
  const licenseKey = generateLicenseKey();
  const expiryDate = product.license_type === 'subscription' 
    ? new Date(Date.now() + product.license_duration_days * 24 * 60 * 60 * 1000).toISOString()
    : null;
  
  // Create license
  await env.ea_license_db_new.prepare(`
    INSERT INTO licenses (
      license_key, customer_email, customer_name,
      max_live_accounts, max_demo_accounts,
      expiry_date, status, tenant_id, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, datetime('now'))
  `).bind(
    licenseKey,
    customer_email.toLowerCase(),
    customer_name || order.customer_name || null,
    product.max_live_accounts,
    product.max_demo_accounts,
    expiryDate,
    tenantId
  ).run();
  
  // Update order to completed
  await env.ea_license_db_new.prepare(`
    UPDATE orders 
    SET payment_status = 'completed',
        payment_reference = ?,
        license_key = ?,
        completed_at = datetime('now')
    WHERE order_id = ?
  `).bind(payment_reference, licenseKey, order_id).run();
  
  // Log the activity
  await logActivity(env, licenseKey, 'purchase', 
    `License purchased via Paystack for ${customer_email}`, request, tenantId);
  
  return new Response(JSON.stringify({
    success: true,
    license_key: licenseKey,
    download_url: product.download_url || '',
    message: 'Payment successful! Your license has been created.',
    expiry_date: expiryDate
  }), { headers });
}