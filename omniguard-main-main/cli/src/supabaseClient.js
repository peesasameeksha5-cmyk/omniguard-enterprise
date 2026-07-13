const https = require('https');
const path = require('path');

// Load .env.credentials or .env if present (supports dev mode without shell export)
const envCandidates = [
  path.join(__dirname, '../../.env.credentials'),
  path.join(__dirname, '../../.env'),
  path.join(require('os').homedir(), '.omniguard', '.env')
];
for (const f of envCandidates) {
  try {
    const lines = require('fs').readFileSync(f, 'utf8').split('\n');
    for (const line of lines) {
      const m = line.match(/^([A-Z_][A-Z0-9_]*)=(.+)$/);
      if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim().replace(/^["']|["']$/g, '');
    }
    break;
  } catch {}
}

const SUPABASE_URL = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL || '';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY || '';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || SUPABASE_ANON_KEY;

function supabaseCall(method, table, query = '', body = null, useServiceKey = false) {
  if (!SUPABASE_URL) {
    return Promise.resolve({ ok: false, status: 0, body: { error: 'SUPABASE_URL not configured' } });
  }
  return new Promise((resolve, reject) => {
    const target = `${SUPABASE_URL}/rest/v1/${table}${query}`;
    const urlObj = new URL(target);
    const key = useServiceKey ? SUPABASE_SERVICE_KEY : SUPABASE_ANON_KEY;
    const headers = {
      'apikey': key,
      'Authorization': `Bearer ${key}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=representation'
    };

    const req = https.request({
      hostname: urlObj.hostname,
      port: 443,
      path: urlObj.pathname + urlObj.search,
      method,
      headers
    }, res => {
      let data = '';
      res.on('data', d => { data += d; });
      res.on('end', () => {
        let parsed = data;
        try { parsed = data ? JSON.parse(data) : {}; } catch {}
        resolve({ ok: res.statusCode < 300, status: res.statusCode, body: parsed });
      });
    });

    req.on('error', reject);
    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

module.exports = {
  supabaseCall,
  SUPABASE_URL,
  SUPABASE_ANON_KEY
};
