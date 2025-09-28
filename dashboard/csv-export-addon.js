/* csv-export-addon.js
 * Plug-and-play: adds CSV Export to Licenses, Activations, and Activity Logs.
 * Safe: prefers server CSV (export=csv). Falls back to client CSV if server returns JSON.
 * Requires existing helpers in index.html: showAlert(), getToken(), getTenantId(), api().
 */

(function(){
  function ts(){ return new Date().toISOString().split('T')[0]; }

  function getApiUrl(){
    // Try persisted URL first, then settings input, then current origin
    try {
      const stored = localStorage.getItem('API_URL') || localStorage.getItem('api_url');
      if (stored && /^https?:\/\//i.test(stored)) return stored.replace(/\/+$/,''); 
    } catch(e){}
    const el = document.getElementById('workerUrl');
    if (el && el.value) return el.value.replace(/\/+$/,'');
    return location.origin;
  }

  async function downloadCsv(path, filename){
    const API_URL = getApiUrl();
    const token = (typeof getToken === 'function') ? getToken() : null;
    const tenantId = (typeof getTenantId === 'function') ? getTenantId() : 'tenant_default';

    const res = await fetch(`${API_URL}${path}`, {
      headers: {
        'Authorization': token ? `Bearer ${token}` : '',
        'X-Tenant-Id': tenantId
      }
    });

    // If server responded with CSV, download directly
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    if (res.ok && ct.includes('text/csv')){
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      return;
    }

    // Fallback: read JSON and build CSV on client
    const data = await res.json().catch(() => ({ items: [] }));
    const items = data.items || [];
    if (!Array.isArray(items) || items.length === 0){
      throw new Error('No data to export');
    }
    const csv = convertToCSV(items);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Minimal CSV encoder (safe quoting). If index.html already defines one, we reuse it.
  function convertToCSV(items){
    if (!items || !items.length) return '';
    const headers = Object.keys(items[0]);
    const lines = [headers.join(',')];
    for (const row of items){
      const values = headers.map(h => {
        const v = row[h];
        if (v === null || v === undefined) return '';
        const s = String(v);
        return (/[",\n]/.test(s)) ? \"{\" + s.replace(/\"/g,'\"\"') + }\" : s;
      });
      lines.push(values.join(','));
    }
    return lines.join('\n');
  }

  function ensureButtons(){
    // Licenses
    const licBox = document.querySelector('#licenses .search-box');
    if (licBox && !document.getElementById('exportLicensesCSV')){
      const btn = document.createElement('button');
      btn.id = 'exportLicensesCSV';
      btn.className = 'btn-warning';
      btn.textContent = '📥 Export CSV';
      licBox.appendChild(btn);
    }
    // Activations
    const actBox = document.querySelector('#activations .search-box');
    if (actBox && !document.getElementById('exportActivationsCSV')){
      const btn = document.createElement('button');
      btn.id = 'exportActivationsCSV';
      btn.className = 'btn-warning';
      btn.textContent = '📥 Export CSV';
      actBox.appendChild(btn);
    }
    // Logs
    const logBox = document.querySelector('#logs .search-box');
    if (logBox && !document.getElementById('exportLogsCSV')){
      const btn = document.createElement('button');
      btn.id = 'exportLogsCSV';
      btn.className = 'btn-warning';
      btn.textContent = '📥 Export CSV';
      logBox.appendChild(btn);
    }
  }

  function wireUp(){
    ensureButtons();

    // Licenses
    const licBtn = document.getElementById('exportLicensesCSV');
    if (licBtn && !licBtn.dataset.wired){
      licBtn.dataset.wired = '1';
      licBtn.addEventListener('click', async () => {
        try {
          if (typeof showAlert === 'function') showAlert('Preparing licenses export...', 'success');
          const search = (document.getElementById('licenseSearch')?.value || '').trim();
          const status = (document.getElementById('licenseFilter')?.value || '').trim();
          const q = new URLSearchParams({ search, status, export: 'csv' });
          await downloadCsv(`/api/admin/licenses?${q.toString()}`, `licenses_${(typeof getTenantId==='function'?getTenantId():'tenant')}_${ts()}.csv`);
          if (typeof showAlert === 'function') showAlert('Licenses exported.', 'success');
        } catch (e){
          if (typeof showAlert === 'function') showAlert('Export failed: ' + e.message, 'error');
        }
      });
    }

    // Activations
    const actBtn = document.getElementById('exportActivationsCSV');
    if (actBtn && !actBtn.dataset.wired){
      actBtn.dataset.wired = '1';
      actBtn.addEventListener('click', async () => {
        try {
          if (typeof showAlert === 'function') showAlert('Preparing activations export...', 'success');
          const search = (document.getElementById('activationSearch')?.value || '').trim();
          const type = (document.getElementById('activationType')?.value || '').trim();
          const q = new URLSearchParams({ search, type, export: 'csv' });
          await downloadCsv(`/api/admin/activations?${q.toString()}`, `activations_${(typeof getTenantId==='function'?getTenantId():'tenant')}_${ts()}.csv`);
          if (typeof showAlert === 'function') showAlert('Activations exported.', 'success');
        } catch (e){
          if (typeof showAlert === 'function') showAlert('Export failed: ' + e.message, 'error');
        }
      });
    }

    // Logs
    const logBtn = document.getElementById('exportLogsCSV');
    if (logBtn && !logBtn.dataset.wired){
      logBtn.dataset.wired = '1';
      logBtn.addEventListener('click', async () => {
        try {
          if (typeof showAlert === 'function') showAlert('Preparing logs export...', 'success');
          const from = document.getElementById('logDateFrom')?.value || '';
          const to = document.getElementById('logDateTo')?.value || '';
          const action = document.getElementById('logAction')?.value || '';
          const q = new URLSearchParams({ from, to, action, export: 'csv' });
          await downloadCsv(`/api/admin/logs?${q.toString()}`, `activity_logs_${(typeof getTenantId==='function'?getTenantId():'tenant')}_${ts()}.csv`);
          if (typeof showAlert === 'function') showAlert('Logs exported.', 'success');
        } catch (e){
          if (typeof showAlert === 'function') showAlert('Export failed: ' + e.message, 'error');
        }
      });
    }
  }

  // Run after DOM is ready (works even if placed in <head>)
  if (document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', wireUp);
  } else {
    wireUp();
  }
})();