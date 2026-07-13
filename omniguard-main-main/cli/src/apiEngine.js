const url = require('url');
const { supabaseCall } = require('./supabaseClient');
const { COMPLIANCE_RULES } = require('./complianceRules');
const sbomEngine = require('./sbomEngine');
const metrics = require('./metrics');

class ApiEngine {
  constructor() {
    this.routes = {
      GET: {},
      POST: {}
    };
    
    // Registering Endpoints per Phase 12
    this.registerRoute('GET', '/findings', this.getFindings.bind(this));
    this.registerRoute('GET', '/projects', this.getProjects.bind(this));
    this.registerRoute('GET', '/policies', this.getPolicies.bind(this));
    this.registerRoute('GET', '/agents', this.getAgents.bind(this));
    this.registerRoute('GET', '/scans', this.getScans.bind(this));
    this.registerRoute('GET', '/sbom', this.getSbom.bind(this));
    this.registerRoute('GET', '/compliance', this.getCompliance.bind(this));
    this.registerRoute('GET', '/audit', this.getAudit.bind(this));
    this.registerRoute('GET', '/metrics', this.getMetrics.bind(this));

    // Simple IP-based rate limiting
    this.rateLimits = {};
  }

  registerRoute(method, path, handler) {
    this.routes[method][path] = handler;
  }

  async handleRequest(req, res) {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    const method = req.method;

    // 1. Rate Limiting Check
    const ip = req.socket.remoteAddress || 'unknown';
    if (!this.checkRateLimit(ip)) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Too Many Requests (Rate limit: 60/min)' }));
      return true;
    }

    // 2. Authentication Check (Phase 12 API Key Check)
    // /scan-file is an internal local-only endpoint — no remote API key required
    const publicPaths = ['/status', '/healthz', '/readyz', '/metrics', '/scan-file'];
    if (!publicPaths.includes(pathname)) {
      const apiKey = req.headers['authorization'] || req.headers['x-api-key'];
      if (!apiKey || !apiKey.startsWith('Bearer og_live_')) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Missing or invalid API Key (Must start with Bearer og_live_)' }));
        return true;
      }
    }

    // 3. Route matching
    if (this.routes[method] && this.routes[method][pathname]) {
      try {
        await this.routes[method][pathname](req, res, parsedUrl.query);
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Internal Server Error: ${e.message}` }));
      }
      return true; // Handled
    }
    return false; // Propagate to default handlers in daemon.js
  }

  checkRateLimit(ip) {
    const now = Date.now();
    if (!this.rateLimits[ip]) {
      this.rateLimits[ip] = [];
    }
    // Filter requests in the last 60 seconds
    this.rateLimits[ip] = this.rateLimits[ip].filter(timestamp => now - timestamp < 60000);
    if (this.rateLimits[ip].length >= 60) {
      return false; // Limit exceeded
    }
    this.rateLimits[ip].push(now);
    return true;
  }

  // Helper to query and apply pagination, filtering, search, sorting
  applyQueryParameters(items, query) {
    let result = [...items];

    // Search
    if (query.q) {
      const q = query.q.toLowerCase();
      result = result.filter(item => 
        (item.title && item.title.toLowerCase().includes(q)) ||
        (item.description && item.description.toLowerCase().includes(q)) ||
        (item.rule_id && item.rule_id.toLowerCase().includes(q))
      );
    }

    // Filtering (exact match for provided query params matching object keys)
    for (const [key, val] of Object.entries(query)) {
      if (['page', 'limit', 'q', 'sort_by', 'order'].includes(key)) continue;
      result = result.filter(item => String(item[key]).toLowerCase() === String(val).toLowerCase());
    }

    // Sorting
    if (query.sort_by) {
      const field = query.sort_by;
      const order = query.order === 'desc' ? -1 : 1;
      result.sort((a, b) => {
        if (!a[field]) return 1 * order;
        if (!b[field]) return -1 * order;
        return String(a[field]).localeCompare(String(b[field])) * order;
      });
    }

    // Pagination
    const page = parseInt(query.page) || 1;
    const limit = parseInt(query.limit) || 20;
    const startIndex = (page - 1) * limit;
    const paginated = result.slice(startIndex, startIndex + limit);

    return {
      total: result.length,
      page,
      limit,
      data: paginated
    };
  }

  async getFindings(req, res, query) {
    const dbRes = await supabaseCall('GET', 'findings');
    const items = dbRes.body || [];
    const formatted = this.applyQueryParameters(items, query);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(formatted));
  }

  async getProjects(req, res, query) {
    const dbRes = await supabaseCall('GET', 'repositories');
    const items = dbRes.body || [];
    const formatted = this.applyQueryParameters(items, query);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(formatted));
  }

  async getPolicies(req, res, query) {
    const formatted = this.applyQueryParameters(COMPLIANCE_RULES, query);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(formatted));
  }

  async getAgents(req, res, query) {
    const agentsList = [
      { id: 'coordinator', name: 'Coordinator Agent', status: 'ready' },
      { id: 'scanner', name: 'Scanner Agent', status: 'ready' },
      { id: 'policy', name: 'Policy Agent', status: 'ready' },
      { id: 'compliance', name: 'Compliance Agent', status: 'ready' },
      { id: 'remediation', name: 'Remediation Agent', status: 'ready' }
    ];
    const formatted = this.applyQueryParameters(agentsList, query);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(formatted));
  }

  async getScans(req, res, query) {
    const dbRes = await supabaseCall('GET', 'scans');
    const items = dbRes.body || [];
    const formatted = this.applyQueryParameters(items, query);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(formatted));
  }

  async getSbom(req, res, query) {
    const sbom = await sbomEngine.generateSBOM(process.cwd(), query.format || 'cyclonedx');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(sbom));
  }

  async getCompliance(req, res, query) {
    const dbRes = await supabaseCall('GET', 'findings', '?status=eq.open');
    const openFindings = dbRes.body || [];
    
    // basic compliance coverage scoring
    const totalRulesCount = COMPLIANCE_RULES.length;
    const violatedRules = new Set(openFindings.map(f => f.rule_id));
    const passedCount = totalRulesCount - violatedRules.size;
    const score = totalRulesCount > 0 ? Math.round((passedCount / totalRulesCount) * 100) : 100;

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      compliance_score: score,
      total_rules: totalRulesCount,
      violated_rules_count: violatedRules.size,
      passed_rules_count: passedCount,
      violated_rules: Array.from(violatedRules)
    }));
  }

  async getAudit(req, res, query) {
    const dbRes = await supabaseCall('GET', 'audit_logs');
    const items = dbRes.body || [];
    const formatted = this.applyQueryParameters(items, query);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(formatted));
  }

  async getMetrics(req, res, query) {
    res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' });
    res.end(metrics.getPrometheusFormat());
  }
}

const apiEngine = new ApiEngine();
module.exports = apiEngine;
