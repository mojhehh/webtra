/**
 * Encrypted Link Gateway Server
 * Main entry point
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const fetch = require('node-fetch');
const https = require('https');
const http = require('http');
const path = require('path');

// ============================================================================
// DEBUG LOGGING SYSTEM - Comprehensive debugging for all operations
// ============================================================================

const DEBUG_CATEGORIES = {
  REQUEST: true,     // Incoming requests
  PROXY: true,       // Proxy operations
  TOKEN: true,       // Token creation/resolution
  SESSION: true,     // Session operations
  HTML: true,        // HTML rewriting
  FETCH: true,       // Upstream fetches
  ERROR: true,       // All errors
  CACHE: true,       // Caching operations
  STREAM: true       // Video/audio streaming
};

function debug(category, message, data = {}) {
  if (DEBUG_CATEGORIES[category] || DEBUG_CATEGORIES.ALL) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}][${category}] ${message}`, Object.keys(data).length > 0 ? JSON.stringify(data, null, 2) : '');
  }
}

function debugError(category, message, error, data = {}) {
  const timestamp = new Date().toISOString();
  console.error(`[${timestamp}][${category}] ❌ ${message}`, {
    error: error?.message || String(error),
    stack: error?.stack?.split('\n').slice(0, 5).join('\n'),
    code: error?.code,
    ...data
  });
}

function debugWarn(category, message, data = {}) {
  const timestamp = new Date().toISOString();
  console.warn(`[${timestamp}][${category}] ⚠️ ${message}`, JSON.stringify(data, null, 2));
}

// Global uncaught exception/rejection handlers to keep server running
process.on('uncaughtException', (err) => {
  debugError('FATAL', 'Uncaught exception (server continuing)', err);
});
process.on('unhandledRejection', (reason) => {
  debugError('FATAL', 'Unhandled rejection (server continuing)', reason);
});

// Import modules
const { TokenStore, SessionStore } = require('./token-store');
const { RateLimiter, SecurityLogger } = require('./rate-limiter');
const { validateUrl, validateUrlWithDNS, filterRequestHeaders, filterResponseHeaders } = require('./ssrf-guard');
const { rewriteHtml, rewriteStyleUrls, isHtmlContentType, resolveUrl } = require('./html-rewriter');

// ============================================================================
// Configuration
// ============================================================================

const config = {
  // Server port
  port: process.env.PORT || 3000,
  
  // Allowed origin (REQUIRED - set this to your target site)
  allowedOrigin: process.env.ALLOWED_ORIGIN || 'https://mojhheh.gtihub.io',
  
  // Additional allowed origins (comma-separated)
  additionalOrigins: (process.env.ADDITIONAL_ORIGINS || '').split(',').filter(Boolean),
  
  // Gateway base URL (for HTML rewriting)
  gatewayBase: process.env.GATEWAY_BASE || '',
  
  // Enable WebSocket support (default: false)
  allowWebSocket: process.env.ALLOW_WEBSOCKET === 'true',
  
  // Single allowed WebSocket origin
  allowedWsOrigin: process.env.ALLOWED_WS_ORIGIN || '',
  
  // Token TTL in milliseconds (default: 1 hour)
  tokenTTL: parseInt(process.env.TOKEN_TTL, 10) || 60 * 60 * 1000,
  
  // Session TTL in milliseconds (default: 24 hours)
  sessionTTL: parseInt(process.env.SESSION_TTL, 10) || 24 * 60 * 60 * 1000,
  
  // Rate limits
  rateLimitRequests: parseInt(process.env.RATE_LIMIT_REQUESTS, 10) || 2000,
  rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW, 10) || 60 * 1000,
  
  // CORS allowed origins for frontend
  corsOrigins: (process.env.CORS_ORIGINS || '*').split(',').filter(Boolean),
  
  // Trust proxy (for deployment behind reverse proxy)
  trustProxy: process.env.TRUST_PROXY === 'true',
  
  // Allow any public http(s) origin (opt-in, still blocks private IPs)
  // Default to true for development to enable proxying any site like YouTube
  allowAny: process.env.ALLOW_ANY !== 'false'
};

// Debug mode - set DEBUG=true for verbose logging
const DEBUG = process.env.DEBUG === 'true' || true; // Enable by default for now

function debugLog(...args) {
  if (DEBUG) debug('LEGACY', args.join(' '));
}

function errorLog(...args) {
  debugError('LEGACY', args.join(' '), null);
}

function warnLog(...args) {
  debugWarn('LEGACY', args.join(' '));
}

// Debug: print configured origins for troubleshooting
debug('CONFIG', 'Server configuration loaded', {
  allowedOrigin: config.allowedOrigin,
  additionalOrigins: config.additionalOrigins,
  allowAny: config.allowAny,
  port: config.port,
  tokenTTL: config.tokenTTL,
  sessionTTL: config.sessionTTL
});

// ============================================================================
// Initialize Services
// ============================================================================

const tokenStore = new TokenStore({ ttl: config.tokenTTL });
const sessionStore = new SessionStore({ ttl: config.sessionTTL });
const rateLimiter = new RateLimiter({
  requestsPerWindow: config.rateLimitRequests,
  windowMs: config.rateLimitWindow,
  trustProxy: config.trustProxy  // Pass trust proxy setting for proper IP extraction
});
const securityLogger = new SecurityLogger();

// Keep-alive agent for efficient upstream connections
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 100, keepAliveMsecs: 30000 });
const httpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 100,
  keepAliveMsecs: 30000,
  rejectUnauthorized: false // Allow self-signed certs for compatibility
});

// Response cache for static assets (CSS, JS, fonts, images)
const responseCache = new Map();
const RESPONSE_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const MAX_CACHE_SIZE = 100 * 1024 * 1024; // 100MB max cache
let currentCacheSize = 0;

function getCachedResponse(key) {
  const cached = responseCache.get(key);
  if (cached && cached.exp > Date.now()) {
    return cached;
  }
  if (cached) {
    currentCacheSize -= cached.body.length;
    responseCache.delete(key);
  }
  return null;
}

function setCachedResponse(key, body, contentType, status = 200) {
  // Evict old entries if cache is too large
  while (currentCacheSize + body.length > MAX_CACHE_SIZE && responseCache.size > 0) {
    const oldestKey = responseCache.keys().next().value;
    const oldest = responseCache.get(oldestKey);
    if (oldest) currentCacheSize -= oldest.body.length;
    responseCache.delete(oldestKey);
  }
  responseCache.set(key, {
    body,
    contentType,
    status,
    exp: Date.now() + RESPONSE_CACHE_TTL
  });
  currentCacheSize += body.length;
}

// Check if URL is cacheable (static assets)
function isCacheableUrl(url, contentType) {
  const ext = url.match(/\.([a-z0-9]+)(?:\?|$)/i);
  const cacheableExts = ['js', 'css', 'woff', 'woff2', 'ttf', 'otf', 'eot', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'ico'];
  if (ext && cacheableExts.includes(ext[1].toLowerCase())) return true;
  if (contentType && (contentType.includes('font') || contentType.includes('image'))) return true;
  return false;
}

// ============================================================================
// Playwright Browser Pool (for speed)
// ============================================================================

let playwrightBrowser = null;
const browserContextPool = [];
const MAX_CONTEXTS = 2;
const pageCache = new Map(); // URL -> { html, timestamp }
const PAGE_CACHE_TTL = 30000; // 30 seconds

async function getPlaywrightBrowser() {
  if (playwrightBrowser) return playwrightBrowser;
  try {
    const { chromium } = require('playwright');
    playwrightBrowser = await chromium.launch({
      headless: true,
      // Use a minimal, stable argset on Windows to reduce crashes
      args: [
        '--no-sandbox',
        '--disable-gpu',
        '--mute-audio'
      ]
    });

    // Restart/cleanup handling when the browser disconnects
    playwrightBrowser.on('disconnected', async () => {
      console.warn('[Playwright] Browser disconnected - clearing pool and scheduling relaunch');
      // clear pool
      while (browserContextPool.length) {
        const c = browserContextPool.pop();
        try { c.close().catch(() => {}); } catch (e) {}
      }
      playwrightBrowser = null;
      // Auto-relaunch after a short delay
      setTimeout(async () => {
        try {
          console.log('[Playwright] Auto-relaunching browser...');
          await getPlaywrightBrowser();
        } catch (e) {
          console.error('[Playwright] Auto-relaunch failed:', e.message);
        }
      }, 1000);
    });

    console.log('[Playwright] Browser launched');
    return playwrightBrowser;
  } catch (e) {
    console.warn('Playwright not available:', e.message);
    throw e;
  }
}

// Helper: wait for browser to be available (retries up to 3 times)
async function ensureBrowser(retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const b = await getPlaywrightBrowser();
      if (b && b.isConnected()) return b;
    } catch (e) {
      console.warn(`[Playwright] ensureBrowser attempt ${i+1} failed:`, e.message);
    }
    // Wait before retry
    await new Promise(r => setTimeout(r, 500 * (i + 1)));
  }
  throw new Error('Playwright browser unavailable after retries');
}

async function getBrowserContext() {
  let browser = await ensureBrowser();

  // Try to reuse a healthy context from the pool
  while (browserContextPool.length > 0) {
    const ctx = browserContextPool.pop();
    try {
      // Quick health-check: open & close a page
      const p = await ctx.newPage();
      await p.close();
      return ctx;
    } catch (err) {
      // Context is unusable - close and continue
      try { await ctx.close(); } catch (e) {}
    }
  }

  // Create new context with optimized settings. If browser crashed/closed,
  // try restarting Playwright once.
  const createContext = async () => {
    return await browser.newContext({
      bypassCSP: true,
      ignoreHTTPSErrors: true,
      viewport: { width: 1280, height: 720 },
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      locale: 'en-US',
      timezoneId: 'America/New_York',
      javaScriptEnabled: true
    });
  };

  try {
    const context = await createContext();
    return context;
  } catch (err) {
    console.warn('[Playwright] Context creation failed, restarting browser:', err && err.message ? err.message : err);
    try { if (playwrightBrowser) await playwrightBrowser.close(); } catch (e) {}
    playwrightBrowser = null;
    // Relaunch browser and create context
    browser = await getPlaywrightBrowser();
    const context2 = await createContext();
    return context2;
  }
}

function returnContextToPool(context) {
  if (browserContextPool.length < MAX_CONTEXTS) {
    browserContextPool.push(context);
  } else {
    context.close().catch(() => {});
  }
}

// Check cache for page
function getCachedPage(url) {
  const cached = pageCache.get(url);
  if (cached && Date.now() - cached.timestamp < PAGE_CACHE_TTL) {
    return cached.html;
  }
  return null;
}

function setCachedPage(url, html) {
  pageCache.set(url, { html, timestamp: Date.now() });
  // Limit cache size
  if (pageCache.size > 100) {
    const oldest = pageCache.keys().next().value;
    pageCache.delete(oldest);
  }
}

// ============================================================================
// Express App Setup
// ============================================================================

const compression = require('compression');
const app = express();

// Trust proxy if configured
if (config.trustProxy) {
  app.set('trust proxy', true);
}

// Compression for faster responses
app.use(compression({ level: 6, threshold: 1024 }));

// Security headers
app.use(helmet({
  contentSecurityPolicy: false, // We need to allow inline scripts for bootstrap
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false
}));

// CORS - Allow requests from any origin including null (sandboxed iframes)
app.use(cors({
  origin: true,  // Allow all origins including null
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-Token', 'X-Parent-Token']
}));

// Body parsing - capture raw body for proxy forwarding
app.use(express.json({ limit: '1mb' }));
app.use(express.text({ limit: '1mb', type: '*/*' }));
app.use(express.raw({ limit: '10mb', type: ['application/octet-stream', 'image/*', 'audio/*', 'video/*'] }));

// Request logging with enhanced details
app.use((req, res, next) => {
  const start = Date.now();
  const reqId = Math.random().toString(36).substring(2, 8);
  req.reqId = reqId;
  
  // Log incoming request with headers for debugging
  if (DEBUG && (req.path.includes('/tokenize') || req.path.includes('/go/'))) {
    debugLog(`[${reqId}] Incoming: ${req.method} ${req.path}`);
    debugLog(`[${reqId}] Headers:`, JSON.stringify({
      authorization: req.headers.authorization ? 'Bearer ...' + req.headers.authorization.slice(-8) : null,
      'x-parent-token': req.headers['x-parent-token'] ? '...' + req.headers['x-parent-token'].slice(-8) : null,
      referer: req.headers.referer,
      accept: req.headers.accept,
      'content-type': req.headers['content-type']
    }));
  }
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logLevel = res.statusCode >= 400 ? 'WARN' : 'INFO';
    console.log(`[${logLevel}] [${reqId}] ${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
  });
  next();
});

// ============================================================================
// Auth Middleware
// ============================================================================

function authMiddleware(req, res, next) {
  debug('SESSION', 'Auth middleware invoked', { 
    path: req.path,
    method: req.method,
    hasAuthHeader: !!req.headers.authorization,
    hasSessionHeader: !!req.headers['x-session-token']
  });
  
  // Support multiple ways to provide the session token:
  //  - Authorization: Bearer <token>
  //  - X-Session-Token: <token>
  //  - { sessionToken: '<token>' } in JSON body
  let sessionToken = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    sessionToken = authHeader.slice(7);
    debug('SESSION', 'Token from Authorization header', { tokenPreview: sessionToken?.substring(0, 12) + '...' });
  } else if (req.headers['x-session-token']) {
    sessionToken = req.headers['x-session-token'];
    debug('SESSION', 'Token from X-Session-Token header', { tokenPreview: sessionToken?.substring(0, 12) + '...' });
  } else if (req.body && req.body.sessionToken) {
    sessionToken = req.body.sessionToken;
    debug('SESSION', 'Token from body', { tokenPreview: sessionToken?.substring(0, 12) + '...' });
  }
  
  if (!sessionToken) {
    debug('SESSION', 'NO SESSION TOKEN FOUND - rejecting request', { 
      path: req.path, 
      headers: Object.keys(req.headers).join(', ')
    });
    return res.status(401).json({ 
      error: 'Missing or invalid session token',
      details: 'No session token found in Authorization header, X-Session-Token header, or request body',
      hint: 'Create a session first with POST /session, then include the token'
    });
  }
  const ip = req.ip || req.connection.remoteAddress;
  // Allow a special anonymous token to facilitate bootstrap tokenization
  // for rewritten pages that do not have an explicit client session.
  if (sessionToken === 'anonymous') {
    debug('SESSION', 'Anonymous session allowed');
    req.sessionId = 'anonymous';
    req.sessionData = { anonymous: true };
    return next();
  }

  const result = sessionStore.validateSession(sessionToken, ip);

  if (!result.valid) {
    debugWarn('SESSION', 'Session validation FAILED', { 
      reason: result.reason,
      tokenPreview: sessionToken?.substring(0, 12) + '...',
      ip,
      path: req.path
    });
    securityLogger.logBlocked('AUTH', result.reason, { ip, path: req.path });
    return res.status(401).json({ 
      error: result.reason,
      details: 'Session validation failed - session may have expired or be invalid',
      hint: 'Create a new session with POST /session'
    });
  }
  
  debug('SESSION', 'Session validated successfully', { 
    tokenPreview: sessionToken?.substring(0, 12) + '...',
    ip
  });
  
  // Attach session info to request
  req.sessionId = sessionToken;
  req.sessionData = result.session;
  
  // Refresh session
  sessionStore.refreshSession(sessionToken);
  
  next();
}

// ============================================================================
// Routes
// ============================================================================

/**
 * Health check
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    stats: {
      tokens: tokenStore.getStats(),
      rateLimiter: rateLimiter.getStats()
    }
  });
});

/**
 * Create a new session
 * POST /session
 */
app.post('/session', rateLimiter.middleware('request'), (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'] || '';
  
  debug('SESSION', 'Creating new session', { ip, userAgent: userAgent?.substring(0, 50) });
  
  try {
    const { sessionToken, expiresIn } = sessionStore.createSession(ip, userAgent);
    
    debug('SESSION', 'Session created successfully', { 
      tokenPreview: sessionToken?.substring(0, 12) + '...',
      expiresIn
    });
    
    res.json({
      sessionToken,
      expiresIn,
      expiresAt: new Date(Date.now() + expiresIn).toISOString()
    });
  } catch (e) {
    debugError('SESSION', 'Failed to create session', e, { ip });
    res.status(500).json({ 
      error: 'Failed to create session',
      details: e.message
    });
  }
});

/**
 * Tokenize a URL
 * POST /tokenize
 * Body: { url: string }
 */
app.post('/tokenize', authMiddleware, rateLimiter.middleware('token'), async (req, res) => {
  const { url } = req.body;
  const reqId = req.reqId || Math.random().toString(36).substring(7);
  
  debug('TOKEN', `========== TOKENIZE REQUEST [${reqId}] ==========`, {
    url: url?.substring(0, 120),
    session: req.sessionId === 'anonymous' ? 'ANONYMOUS' : req.sessionId?.substring(0, 12) + '...',
    hasParentToken: !!(req.headers['x-parent-token'] || req.body.parentToken)
  });
  
  if (!url || typeof url !== 'string') {
    debugWarn('TOKEN', 'Missing url parameter', { reqId });
    return res.status(400).json({ 
      error: 'Missing or invalid url parameter',
      details: 'The "url" field is required in the request body',
      received: typeof url
    });
  }
  
  // Resolve relative URLs if base URL provided
  let targetUrl = url;
  if (req.body.baseUrl) {
    targetUrl = resolveUrl(url, req.body.baseUrl) || url;
    debug('TOKEN', `Resolved relative URL`, { original: url?.substring(0, 80), resolved: targetUrl?.substring(0, 100) });
  }
  
  // Validate URL. If the request is authenticated with a real session
  // (not the special 'anonymous' bootstrap token), allow tokenization of
  // arbitrary public http(s) origins to support pages that load assets
  // from many CDNs. This keeps the stricter allowlist for anonymous
  // bootstrap tokenization while being practical for real user sessions.
  let validation;
  // Allow anonymous bootstrap tokenize if a valid parent token is provided
  const parentTokenHeader = (req.headers['x-parent-token'] || req.body.parentToken || '').toString();
  
  if (req.sessionId === 'anonymous' && parentTokenHeader) {
    // Resolve the parent token and allow tokenization for same-origin resources
    debug('TOKEN', 'VALIDATION PATH: Anonymous + Parent Token', { reqId, parentToken: parentTokenHeader?.substring(0, 12) + '...' });
    const parentRes = tokenStore.resolveToken(parentTokenHeader, null);
    
    if (parentRes && parentRes.valid) {
      try {
        const tu = new URL(targetUrl);
        const pu = new URL(parentRes.url);
        
        debug('TOKEN', 'Origin comparison', {
          targetOrigin: tu.origin,
          parentOrigin: pu.origin,
          match: tu.origin === pu.origin
        });
        
        // ENHANCED: Allow any public http(s) URL when allowAny is enabled
        if ((tu.protocol === 'http:' || tu.protocol === 'https:')) {
          if (tu.origin === pu.origin) {
            validation = { valid: true, url: tu };
            debug('TOKEN', '✓ Same-origin anonymous tokenize ALLOWED', { reqId });
          } else if (config.allowAny) {
            // allowAny mode: allow cross-origin from anonymous bootstrap
            validation = { valid: true, url: tu };
            debug('TOKEN', '✓ Cross-origin anonymous tokenize ALLOWED (allowAny=true)', { reqId, targetOrigin: tu.origin });
          } else {
            validation = { valid: false, reason: `Origin mismatch: ${tu.origin} vs ${pu.origin}` };
            debugWarn('TOKEN', 'Origin mismatch BLOCKED', { reqId, targetOrigin: tu.origin, parentOrigin: pu.origin });
          }
        } else {
          validation = { valid: false, reason: `Unsupported protocol: ${tu.protocol}` };
          debugWarn('TOKEN', 'Unsupported protocol', { reqId, protocol: tu.protocol });
        }
      } catch (e) {
        validation = { valid: false, reason: 'Invalid URL format: ' + e.message };
        debugError('TOKEN', 'Invalid URL format', e, { reqId, url: targetUrl?.substring(0, 100) });
      }
    } else {
      validation = { valid: false, reason: `Invalid parent token: ${parentRes?.reason || 'unknown'}` };
      debugWarn('TOKEN', 'Invalid parent token', { reqId, reason: parentRes?.reason });
    }
  } else if (req.sessionId && req.sessionId !== 'anonymous') {
    debug('TOKEN', 'VALIDATION PATH: Real Session', { reqId });
    try {
      const u = new URL(targetUrl);
      if (u.protocol === 'http:' || u.protocol === 'https:') {
        validation = { valid: true, url: u };
        console.log(`[${reqId}] ✓ Real session tokenize ALLOWED`);
      } else {
        validation = { valid: false, reason: `Unsupported scheme: ${u.protocol}` };
      }
    } catch (e) {
      validation = { valid: false, reason: 'Invalid URL format' };
    }
  } else {
    console.log(`[${reqId}] VALIDATION PATH: DNS Validation (no parent token)`);
    validation = await validateUrlWithDNS(targetUrl, {
      allowedOrigin: config.allowedOrigin,
      additionalOrigins: config.additionalOrigins,
      allowWebSocket: config.allowWebSocket,
      allowedWsOrigin: config.allowedWsOrigin,
      allowAnyOrigin: config.allowAny
    });
    console.log(`[${reqId}] DNS validation result:`, { valid: validation.valid, reason: validation.reason || 'OK' });
  }
  
  debug('TOKEN', 'FINAL VALIDATION', { reqId, valid: validation.valid, reason: validation.reason || 'OK' });
  
  if (!validation.valid) {
    if (validation.passthrough) {
      debug('TOKEN', 'Passthrough URL (mailto/tel/etc)', { reqId, url: targetUrl });
      return res.json({ token: null, passthrough: true, url: targetUrl });
    }
    
    debugWarn('TOKEN', 'TOKENIZE BLOCKED', { 
      reqId, 
      reason: validation.reason, 
      url: targetUrl?.substring(0, 100),
      sessionId: req.sessionId === 'anonymous' ? 'anonymous' : req.sessionId?.substring(0, 12) + '...'
    });
    securityLogger.logBlocked('TOKENIZE', validation.reason, {
      url: targetUrl,
      sessionId: req.sessionId
    });
    
    return res.status(403).json({ 
      error: 'URL not allowed',
      reason: validation.reason,
      url: targetUrl?.substring(0, 100),
      hint: 'Check that the URL is a valid http/https URL and matches origin restrictions'
    });
  }
  
  try {
    const { token, cached } = tokenStore.createToken(targetUrl, req.sessionId);
    debug('TOKEN', '✓ Token created', { 
      reqId, 
      tokenPreview: token?.substring(0, 12) + '...', 
      cached, 
      url: targetUrl?.substring(0, 60) 
    });
    
    res.json({
      token,
      cached,
      gatewayUrl: `/go/${token}`
    });
  } catch (e) {
    debugError('TOKEN', 'Token creation failed', e, { reqId, url: targetUrl?.substring(0, 100) });
    securityLogger.logWarning('Token creation failed', { error: e.message });
    res.status(429).json({ 
      error: 'Token creation failed',
      details: e.message,
      hint: 'This may be due to rate limiting or internal errors'
    });
  }
});

/**
 * Mock responses for anti-bot/analytics endpoints that would otherwise fail
 * These endpoints use request signing that can't work through a proxy
 */
const MOCK_ENDPOINTS = {
  // TikTok bytesync - anti-bot protection endpoint
  '/v2/bytesync/api/pipeline': {
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ code: 0, data: {}, message: 'success' })
  },
  '/bytesync/api/pipeline': {
    status: 200,
    contentType: 'application/json', 
    body: JSON.stringify({ code: 0, data: {}, message: 'success' })
  },
  // TikTok webmssdk endpoints
  '/v1/web_report': {
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ code: 0, message: 'ok' })
  },
  // TikTok cookie/privacy banner config - return empty/disabled config
  '/api/v1/web-cookie-privacy/config': {
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      status_code: 0,
      data: {
        show_banner: false,
        is_gdpr: false,
        has_consented: true,
        consent_version: '1.0'
      }
    })
  },
  '/web-cookie-privacy/config': {
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      status_code: 0,
      data: {
        show_banner: false,
        is_gdpr: false,
        has_consented: true,
        consent_version: '1.0'
      }
    })
  },
  // TikTok wallet/coins APIs - return "not available" gracefully
  '/webcast/wallet_api_tiktok/recharge/check_external_entry': {
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ data: { show_entrance: false }, status_code: 0 })
  },
  '/wallet/recharge': {
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ data: { show_entrance: false }, status_code: 0 })
  },
  // TikTok feed/recommend API - return empty feed (prevents "Something went wrong")
  '/api/recommend/item_list': {
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      statusCode: 0,
      itemList: [],
      cursor: 0,
      hasMore: false
    })
  },
  // TikTok user info - return minimal valid response
  '/api/user/detail': {
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      statusCode: 0,
      userInfo: { user: {}, stats: {} }
    })
  },
  // TikTok comment list
  '/api/comment/list': {
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      statusCode: 0,
      comments: [],
      cursor: 0,
      hasMore: false
    })
  },
  // TikTok sigi state - initial app state
  '/api/sigi/': {
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ statusCode: 0, data: {} })
  },
  // Common analytics/tracking endpoints to mock
  '/collect': {
    status: 204,
    contentType: 'text/plain',
    body: ''
  },
  '/api/v2/user/report': {
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ status: 'ok' })
  },
  // WebSocket fallback - return empty for HTTP requests to WS endpoints
  '/ws/': {
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ status: 'ok' })
  }
};

/**
 * Check if URL matches a mock endpoint pattern
 */
function getMockResponse(url) {
  try {
    const parsedUrl = new URL(url);
    const pathname = parsedUrl.pathname;
    
    // Check exact matches first
    for (const [pattern, response] of Object.entries(MOCK_ENDPOINTS)) {
      if (pathname === pattern || pathname.endsWith(pattern)) {
        console.log(`[Mock] Intercepting anti-bot endpoint: ${pathname}`);
        return response;
      }
    }
    
    // Check if it's a bytesync URL by query params or path patterns
    if (pathname.includes('bytesync') || parsedUrl.searchParams.has('biz_id')) {
      // Check if this looks like a monitoring/tracking endpoint
      if (pathname.includes('pipeline') || pathname.includes('report')) {
        console.log(`[Mock] Intercepting analytics/tracking endpoint: ${pathname}`);
        return MOCK_ENDPOINTS['/v2/bytesync/api/pipeline'];
      }
    }
    
    // Check for wallet/coins API patterns
    if (pathname.includes('wallet_api') || pathname.includes('recharge') || pathname.includes('get_coins')) {
      console.log(`[Mock] Intercepting wallet/coins endpoint: ${pathname}`);
      return MOCK_ENDPOINTS['/webcast/wallet_api_tiktok/recharge/check_external_entry'];
    }
    
    // Check for cookie/privacy config patterns
    if (pathname.includes('web-cookie-privacy') || pathname.includes('cookie-privacy')) {
      console.log(`[Mock] Intercepting cookie-privacy endpoint: ${pathname}`);
      return MOCK_ENDPOINTS['/api/v1/web-cookie-privacy/config'];
    }
    
    // Mock mssdk endpoints (TikTok's security SDK) - return success to prevent crashes
    if (pathname.includes('/web/resource') || pathname.includes('/web/report') || parsedUrl.hostname.includes('mssdk')) {
      console.log(`[Mock] Intercepting mssdk endpoint: ${pathname}`);
      return {
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ code: 0, data: {}, message: 'success' })
      };
    }
    
    // Mock mcs.tiktokw.us list endpoint
    if (pathname.includes('/v1/list') && parsedUrl.hostname.includes('mcs')) {
      console.log(`[Mock] Intercepting mcs list endpoint: ${pathname}`);
      return {
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ code: 0, data: [], message: 'success' })
      };
    }
    
    // Mock item_list endpoints to prevent TikTok returning HTML error pages
    // TikTok blocks API requests without proper cookies, returning HTML which crashes the JS
    // The initial page load via Playwright contains embedded video data in __UNIVERSAL_DATA_FOR_REHYDRATION__
    if (pathname.includes('item_list') || pathname.includes('/sigi/')) {
      console.log(`[Mock] Intercepting feed endpoint (preventing HTML error): ${pathname}`);
      return MOCK_ENDPOINTS['/api/recommend/item_list'];
    }
    
    return null;
  } catch (e) {
    return null;
  }
}

/**
 * Gateway handler - Uses Playwright for HTML, fetch for other resources
 * GET /go/:token
 * Note: No auth middleware - the token itself is the authentication
 */
app.all('/go/:token', rateLimiter.middleware('proxy'), async (req, res) => {
  const { token } = req.params;
  const ip = req.ip || req.connection.remoteAddress;
  const reqId = req.reqId || Math.random().toString(36).substring(2, 8);
  
  debug('PROXY', `========== GATEWAY REQUEST [${reqId}] ==========`, {
    token: token?.substring(0, 12) + '...',
    method: req.method,
    ip,
    accept: req.get('accept')?.substring(0, 50),
    secFetchDest: req.get('sec-fetch-dest'),
    secFetchMode: req.get('sec-fetch-mode'),
    referer: req.get('referer')?.substring(0, 80)
  });
  
  // Detect if this looks like a file path rather than a token (e.g., core.js, styles.css)
  // Valid tokens are base64url encoded and typically ~43 chars without dots/extensions
  const looksLikeFile = /\.(js|css|json|html|png|jpg|jpeg|gif|svg|woff2?|ttf|eot|ico|mp[34]|webm|wav|pdf|map|xml)(\?|$)/i.test(token);
  if (looksLikeFile) {
    debugWarn('PROXY', 'Token looks like file path, not a valid token', { 
      reqId, 
      token: token?.substring(0, 50),
      hint: 'This URL was not tokenized - check the HTML rewriting'
    });
    // This is likely a relative path that wasn't tokenized - return MIME-appropriate error
    const ext = (token.match(/\.([a-z0-9]+)(\?|$)/i) || [])[1] || '';
    const mimeMap = {
      'js': 'application/javascript', 'mjs': 'application/javascript',
      'css': 'text/css', 'json': 'application/json',
      'html': 'text/html', 'xml': 'application/xml',
      'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
      'gif': 'image/gif', 'svg': 'image/svg+xml', 'webp': 'image/webp', 'ico': 'image/x-icon',
      'woff': 'font/woff', 'woff2': 'font/woff2', 'ttf': 'font/ttf', 'eot': 'application/vnd.ms-fontobject'
    };
    const mime = mimeMap[ext.toLowerCase()] || 'text/plain';
    res.type(mime);
    if (mime.startsWith('application/javascript')) return res.status(404).send('// Not found - path not tokenized');
    if (mime === 'text/css') return res.status(404).send('/* Not found - path not tokenized */');
    if (mime === 'application/json') return res.status(404).json({ error: 'Not found - path not tokenized' });
    return res.status(404).send('');
  }
  
  debug('PROXY', 'Resolving token', { reqId, tokenPreview: token?.substring(0, 12) + '...' });
  
  // Resolve token (no session validation needed - token is the auth)
  const resolution = tokenStore.resolveToken(token, null);
  
  debug('PROXY', 'Token resolution result', { 
    reqId,
    valid: resolution.valid, 
    reason: resolution.reason || 'OK',
    url: resolution.url?.substring(0, 80)
  });
  
  if (!resolution.valid) {
    debugWarn('PROXY', 'TOKEN INVALID', {
      reqId,
      reason: resolution.reason,
      tokenPreview: token?.substring(0, 16) + '...',
      ip,
      acceptHeader: req.get('accept')?.substring(0, 50),
      referer: req.get('referer')?.substring(0, 80),
      hint: 'Token may have expired (1 hour TTL) or never existed'
    });
    securityLogger.logBlocked('TOKEN', resolution.reason, { token: token.slice(0, 8) + '...', ip });
    
    // Return a MIME-appropriate error so browsers don't reject scripts/styles
    const acceptHeader = req.get('accept') || '';
    const referer = req.get('referer') || '';
    // Infer expected type from Accept header or referer patterns
    const wantsJS = acceptHeader.includes('javascript') || acceptHeader.includes('script');
    const wantsCSS = acceptHeader.includes('css');
    const wantsImage = acceptHeader.includes('image');
    const wantsFont = acceptHeader.includes('font');
    const wantsHTML = acceptHeader.includes('html') || acceptHeader === '*/*' || !acceptHeader;
    
    if (wantsJS) {
      res.type('application/javascript');
      return res.status(403).send(`// Gateway: forbidden - ${resolution.reason}`);
    }
    if (wantsCSS) {
      res.type('text/css');
      return res.status(403).send(`/* Gateway: forbidden - ${resolution.reason} */`);
    }
    if (wantsImage || wantsFont) {
      return res.status(404).send('');
    }
    if (wantsHTML) {
      return res.status(403).type('text/html').send(`<!-- Gateway: forbidden - ${resolution.reason} -->`);
    }
    return res.status(403).type('text/plain').send(`Forbidden: ${resolution.reason}`);
  }
  
  const targetUrl = resolution.url;
  debug('PROXY', 'Proxying to upstream', { reqId, url: targetUrl?.substring(0, 100) });

  // Check if this URL should return a mock response (anti-bot endpoints)
  const mockResponse = getMockResponse(targetUrl);
  if (mockResponse) {
    debug('PROXY', 'Returning mock response for anti-bot endpoint', { reqId });
    res.status(mockResponse.status);
    res.type(mockResponse.contentType);
    return res.send(mockResponse.body);
  }
// CodeRabbit test

  // NOTE: token was created via the gateway's `/tokenize` flow whichh
  // already validated the target URL against the allowlist/DNS checks.
  // Re-validating here causes legitimate tokenized subresource requests
  // (assets on other hosts) to be blocked. Trust the token resolution
  // and skip a second validation step.
  
  // Determine if this is likely an HTML page request
  // Use Sec-Fetch-Dest header (modern browsers) for accurate detection
  const acceptHeader = req.get('accept') || '';
  const secFetchDest = req.get('sec-fetch-dest') || '';
  const secFetchMode = req.get('sec-fetch-mode') || '';
  
  // Check if this is definitely NOT an HTML request based on Sec-Fetch-Dest
  const isDefinitelyNotHtml = ['script', 'style', 'image', 'font', 'audio', 'video', 'worker', 'sharedworker'].includes(secFetchDest);
  
  // Check if URL has a known non-HTML extension
  const hasNonHtmlExtension = targetUrl.match(/\.(js|mjs|css|json|png|jpg|jpeg|gif|svg|webp|woff|woff2|ttf|eot|otf|ico|mp4|webm|mp3|wav|pdf|xml|map|ts)(\?|$)/i);
  
  // Only use Playwright for actual HTML page navigations
  const isHtmlRequest = req.method === 'GET' && 
    !isDefinitelyNotHtml &&
    !hasNonHtmlExtension &&
    (acceptHeader.includes('text/html') || (secFetchDest === 'document') || (secFetchMode === 'navigate'));
  
  debug('PROXY', 'Request type analysis', {
    reqId,
    isHtmlRequest,
    isDefinitelyNotHtml,
    hasNonHtmlExtension: !!hasNonHtmlExtension,
    secFetchDest,
    secFetchMode,
    willUsePlaywright: isHtmlRequest
  });
  
  // Use Playwright for HTML page requests (for better JS compatibility)
  if (isHtmlRequest) {
    try {
      // Check cache first
      const cachedHtml = getCachedPage(targetUrl);
      if (cachedHtml) {
        const gatewayBase = config.gatewayBase || `${req.protocol}://${req.get('host')}`;
        const tokenizeUrlSync = (url) => {
          try {
            const { token: newToken } = tokenStore.createToken(url, resolution.sessionId || 'anonymous');
            return `/go/${newToken}`;
          } catch { return url; }
        };
        const rewrittenHtml = rewriteHtml(cachedHtml, targetUrl, tokenizeUrlSync, {
          gatewayBase,
          sessionToken: resolution.sessionId || 'anonymous',
          pageToken: token
        });
        res.set('Content-Type', 'text/html; charset=utf-8');
        return res.send(rewrittenHtml);
      }

      // Use Playwright with request interception
      const context = await getBrowserContext();
      const page = await context.newPage();

      // Page-level diagnostics to capture runtime errors and failed requests
      page.on('console', msg => {
        try {
          const text = msg.text();
          debug('HTML', '[Playwright console]', { text: text?.substring(0, 200) });
        } catch (e) {}
      });
      page.on('pageerror', err => {
        debugError('HTML', 'Playwright page error', err, { url: targetUrl?.substring(0, 100) });
        securityLogger.logWarning('Playwright pageerror', { url: targetUrl, error: err && err.message ? err.message : String(err) });
      });
      page.on('requestfailed', reqFail => {
        try {
          const failure = reqFail.failure();
          debugWarn('HTML', 'Playwright request failed', { 
            url: reqFail.url()?.substring(0, 100), 
            error: failure?.errorText || String(failure)
          });
          securityLogger.logWarning('Playwright requestfailed', { url: targetUrl, request: reqFail.url(), reason: failure && failure.errorText ? failure.errorText : String(failure) });
        } catch (e) {}
      });
      page.on('crash', () => {
        debugError('HTML', 'Playwright page CRASHED', new Error('Page crash'), { url: targetUrl });
        securityLogger.logWarning('Playwright page crash', { url: targetUrl });
      });

      // Set up request interception to handle all sub-requests
      await page.route('**/*', async (route) => {
        const request = route.request();
        const requestUrl = request.url();
        
        // Allow data: and blob: URLs
        if (requestUrl.startsWith('data:') || requestUrl.startsWith('blob:')) {
          return route.continue();
        }
        
        // Validate and proxy the request
        // Allow subresource requests for SSR browsing while still
        // enforcing scheme and private-IP checks. Use allowAnyOrigin
        // here so pages can load assets from multiple CDNs (fonts,
        // analytics, CDN images) without being blocked by the gateway
        // allowlist which is primarily used for initial tokenization.
        const subValidation = validateUrl(requestUrl, {
          allowedOrigin: config.allowedOrigin,
          additionalOrigins: config.additionalOrigins,
          allowAnyOrigin: true
        });

        if (!subValidation.valid) {
          debug('HTML', 'Playwright sub-request BLOCKED', { url: requestUrl?.substring(0, 100), reason: subValidation.reason });
          return route.abort('blockedbyclient');
        }
        
        // Continue with the request (let browser handle it)
        return route.continue();
      });
      
      debug('HTML', 'Navigating with Playwright', { reqId, url: targetUrl?.substring(0, 100) });
      
      // Navigate to the page
      const response = await page.goto(targetUrl, {
        waitUntil: 'domcontentloaded',
        timeout: 20000
      });
      
      debug('HTML', 'Page loaded, waiting for JS execution', { reqId, status: response?.status() });
      
      // Wait a bit for JS to execute
      await page.waitForTimeout(1500);
      
      // Get the rendered HTML
      const html = await page.content();
      
      debug('HTML', 'Got rendered HTML', { reqId, htmlLength: html?.length });
      
      // Return page to pool
      await page.close();
      returnContextToPool(context);
      
      // Cache the result
      setCachedPage(targetUrl, html);
      
      // Rewrite and send
      const gatewayBase = config.gatewayBase || `${req.protocol}://${req.get('host')}`;
      const tokenizeUrlSync = (url) => {
        try {
          const { token: newToken } = tokenStore.createToken(url, resolution.sessionId || 'anonymous');
          return `/go/${newToken}`;
        } catch { return url; }
      };
      
      const rewrittenHtml = rewriteHtml(html, targetUrl, tokenizeUrlSync, {
        gatewayBase,
        sessionToken: resolution.sessionId || 'anonymous',
        pageToken: token
      });
      
      debug('HTML', 'HTML rewritten, sending response', { reqId, originalLength: html?.length, rewrittenLength: rewrittenHtml?.length });
      
      res.set('Content-Type', 'text/html; charset=utf-8');
      return res.send(rewrittenHtml);
      
    } catch (e) {
      debugError('HTML', 'Playwright proxy error - falling back to fetch', e, { reqId, url: targetUrl?.substring(0, 100) });
      // Fall through to fetch-based proxy
    }
  }
  
  // Use fetch for non-HTML or if Playwright fails
  // Helper to attempt HTTP fallback for SSL errors
  async function fetchWithHttpFallback(url, options) {
    debug('FETCH', 'Starting fetch', { url: url?.substring(0, 150), method: options?.method || 'GET' });
    try {
      const response = await fetch(url, options);
      debug('FETCH', 'Fetch successful', { 
        url: url?.substring(0, 100), 
        status: response.status, 
        contentType: response.headers.get('content-type')?.substring(0, 50)
      });
      return response;
    } catch (e) {
      debugError('FETCH', 'Fetch failed', e, { url: url?.substring(0, 100) });
      // If HTTPS fails with SSL error, try HTTP fallback
      if (url.startsWith('https://') && 
          (e.message.includes('SSL') || e.message.includes('EPROTO') || 
           e.message.includes('certificate') || e.message.includes('TLS'))) {
        debug('FETCH', 'Attempting HTTP fallback for SSL error', { url: url?.substring(0, 100) });
        const httpUrl = url.replace(/^https:/, 'http:');
        try {
          const response = await fetch(httpUrl, { ...options, agent: httpAgent });
          debug('FETCH', 'HTTP fallback successful', { url: httpUrl?.substring(0, 100), status: response.status });
          return response;
        } catch (e2) {
          debugError('FETCH', 'HTTP fallback also failed', e2, { url: httpUrl?.substring(0, 100) });
          throw e2;
        }
      }
      throw e;
    }
  }

  try {
    const headers = filterRequestHeaders(req.headers);
    // Keep Authorization headers - upstream APIs may need them
    // Only strip our gateway's session token if present
    // delete headers.authorization;
    // delete headers.Authorization;
    
    const agent = targetUrl.startsWith('https:') ? httpsAgent : httpAgent;
    
    // Check response cache for GET requests on static assets (pre-fetch)
    const preCacheKey = `${req.method}:${targetUrl}`;
    if (req.method === 'GET' && isCacheableUrl(targetUrl, '')) {
      const cached = getCachedResponse(preCacheKey);
      if (cached) {
        res.set('Content-Type', cached.contentType);
        res.set('X-Cache', 'HIT');
        return res.status(cached.status).send(cached.body);
      }
    }
    
    let forwardBody = undefined;
    if (!['GET', 'HEAD'].includes(req.method)) {
      if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
        forwardBody = JSON.stringify(req.body);
        if (!headers['content-type'] && !headers['Content-Type']) {
          headers['content-type'] = 'application/json';
        }
      } else {
        forwardBody = req.body;
      }
    }

    const upstreamResponse = await fetchWithHttpFallback(targetUrl, {
      method: req.method,
      headers,
      body: forwardBody,
      agent,
      redirect: 'manual',
      timeout: 30000
    });
    
    // Handle redirects
    if ([301, 302, 303, 307, 308].includes(upstreamResponse.status)) {
      const location = upstreamResponse.headers.get('location');
      if (location) {
        const resolvedLocation = resolveUrl(location, targetUrl);
        const redirectValidation = validateUrl(resolvedLocation, {
          allowedOrigin: config.allowedOrigin,
          additionalOrigins: config.additionalOrigins,
          allowAnyOrigin: config.allowAny
        });
        
        if (redirectValidation.valid) {
          try {
            const { token: redirectToken } = tokenStore.createToken(resolvedLocation, resolution.sessionId || 'anonymous');
            return res.redirect(upstreamResponse.status, `/go/${redirectToken}`);
          } catch (e) {
            securityLogger.logWarning('Redirect token creation failed', { location: resolvedLocation });
          }
        }
      }
      // Return MIME-appropriate error for blocked redirect
      const acceptHeader = req.get('accept') || '';
      if (acceptHeader.includes('javascript') || targetUrl.match(/\.js(\?|$)/i)) {
        return res.status(403).type('application/javascript').send('// Redirect to blocked location');
      }
      if (acceptHeader.includes('css') || targetUrl.match(/\.css(\?|$)/i)) {
        return res.status(403).type('text/css').send('/* Redirect to blocked location */');
      }
      if (acceptHeader.includes('image')) {
        return res.status(403).send('');
      }
      return res.status(403).type('text/plain').send('Redirect to blocked location');
    }
    
    const contentType = upstreamResponse.headers.get('content-type') || '';
    const responseHeaders = filterResponseHeaders(Object.fromEntries(upstreamResponse.headers.entries()));
    delete responseHeaders['content-encoding'];
    delete responseHeaders['content-length'];

    for (const [key, value] of Object.entries(responseHeaders)) {
      res.set(key, value);
    }
    res.status(upstreamResponse.status);
    
    // Check response cache first for static assets
    const cacheKey = `${req.method}:${targetUrl}`;
    const isCacheable = isCacheableUrl(targetUrl, contentType);
    
    // Only rewrite HTML if the content-type is explicitly HTML and not a JS/CSS/JSON file
    const isActualHtml = isHtmlContentType(contentType) && 
      !targetUrl.match(/\.(js|css|json|xml|map)($|\?)/i) &&
      !contentType.includes('javascript') &&
      !contentType.includes('json') &&
      !contentType.includes('css');
    
    // Check if it's CSS that needs url() rewriting
    const isActualCss = contentType.includes('text/css') || targetUrl.match(/\.css($|\?)/i);
    
    const gatewayBase = config.gatewayBase || `${req.protocol}://${req.get('host')}`;
    const tokenizeUrlSync = (url) => {
      try {
        const { token: newToken } = tokenStore.createToken(url, resolution.sessionId || 'anonymous');
        return `/go/${newToken}`;
      } catch { return url; }
    };
    
    if (isActualHtml) {
      const html = await upstreamResponse.text();
      const rewrittenHtml = rewriteHtml(html, targetUrl, tokenizeUrlSync, {
        gatewayBase,
        sessionToken: resolution.sessionId || 'anonymous',
        pageToken: token
      });
      res.set('Content-Type', 'text/html; charset=utf-8');
      res.send(rewrittenHtml);
    } else if (isActualCss) {
      // Rewrite url() in CSS files
      const css = await upstreamResponse.text();
      const rewrittenCss = rewriteStyleUrls(css, targetUrl, tokenizeUrlSync);
      res.set('Content-Type', 'text/css; charset=utf-8');
      // Cache rewritten CSS
      if (isCacheable && rewrittenCss.length < 5 * 1024 * 1024) {
        setCachedResponse(cacheKey, Buffer.from(rewrittenCss), 'text/css; charset=utf-8');
      }
      res.send(rewrittenCss);
    } else {
      // Preserve original content-type for non-HTML/CSS resources
      if (contentType) {
        res.set('Content-Type', contentType);
      }
      
      // Special handling for video/audio streaming with Range support
      const isMedia = contentType.includes('video') || contentType.includes('audio') || 
                      targetUrl.match(/\.(mp4|webm|m4v|mov|mp3|m4a|aac|ogg|wav|m3u8|ts)(\?|$)/i);
      
      if (isMedia) {
        // Forward Content-Range, Accept-Ranges, Content-Length for seeking
        const contentRange = upstreamResponse.headers.get('content-range');
        const acceptRanges = upstreamResponse.headers.get('accept-ranges');
        const contentLength = upstreamResponse.headers.get('content-length');
        
        if (contentRange) res.set('Content-Range', contentRange);
        if (acceptRanges) res.set('Accept-Ranges', acceptRanges);
        if (contentLength) res.set('Content-Length', contentLength);
        
        debug('STREAM', 'Streaming media content', {
          reqId,
          url: targetUrl?.substring(0, 80),
          contentType,
          contentLength: contentLength || 'unknown',
          contentRange: contentRange || 'none',
          acceptRanges: acceptRanges || 'none',
          status: upstreamResponse.status
        });
        
        // Stream directly without caching (videos are too large)
        upstreamResponse.body.pipe(res);
        upstreamResponse.body.on('error', (err) => {
          debugError('STREAM', 'Media stream error', err, { url: targetUrl?.substring(0, 80) });
        });
        return;
      }
      
      // For cacheable static assets, buffer and cache
      if (isCacheable && req.method === 'GET') {
        const chunks = [];
        upstreamResponse.body.on('data', chunk => chunks.push(chunk));
        upstreamResponse.body.on('end', () => {
          const body = Buffer.concat(chunks);
          if (body.length < 5 * 1024 * 1024) { // Only cache < 5MB
            debug('CACHE', 'Caching response', { cacheKey, size: body.length });
            setCachedResponse(cacheKey, body, contentType);
          }
          res.send(body);
        });
        upstreamResponse.body.on('error', (err) => {
          debugError('PROXY', 'Upstream body stream error', err, { url: targetUrl?.substring(0, 100) });
          if (!res.headersSent) res.status(502).send('Upstream error');
        });
      } else {
        upstreamResponse.body.pipe(res);
      }
    }
    
  } catch (e) {
    debugError('PROXY', 'PROXY REQUEST FAILED', e, { 
      reqId,
      url: targetUrl?.substring(0, 100),
      method: req.method,
      errorCode: e.code,
      errorType: e.type,
      hint: 'Check if the upstream server is reachable and responding'
    });
    securityLogger.logWarning('Proxy request failed', { url: targetUrl, error: e.message });
    if (!res.headersSent) {
      // Return appropriate error based on expected content type
      const acceptHeader = req.get('accept') || '';
      if (acceptHeader.includes('text/html') || acceptHeader === '*/*' || !acceptHeader) {
        res.status(502).send(`<!-- Gateway Error: ${e.message} -->`);
      } else if (acceptHeader.includes('javascript') || targetUrl.endsWith('.js')) {
        res.status(502).type('application/javascript').send(`// Gateway Error: ${e.message}`);
      } else if (acceptHeader.includes('css') || targetUrl.endsWith('.css')) {
        res.status(502).type('text/css').send(`/* Gateway Error: ${e.message} */`);
      } else {
        res.status(502).json({ 
          error: 'Upstream request failed',
          details: e.message,
          code: e.code,
          url: targetUrl?.substring(0, 100)
        });
      }
    }
  }
});

/**
 * SSR endpoint using Playwright
 * GET /go-ssr/:token
 * Note: No auth middleware - the token itself is the authentication
 */
app.get('/go-ssr/:token', rateLimiter.middleware('proxy'), async (req, res) => {
  const { token } = req.params;
  const ip = req.ip || req.connection.remoteAddress;

  const resolution = tokenStore.resolveToken(token, null);
  if (!resolution.valid) {
    securityLogger.logBlocked('TOKEN_SSR', resolution.reason, { token: token.slice(0, 8) + '...', ip });
    return res.status(403).json({ error: resolution.reason });
  }

  const targetUrl = resolution.url;
  // Trust tokens created by authenticated sessions. Only perform
  // allowlist/DNS validation for anonymous tokens (bootstrap cases)
  // to avoid blocking legitimate tokenized pages that load assets
  // from multiple public CDNs.
  if (!resolution.sessionId || resolution.sessionId === 'anonymous') {
    const validation = validateUrl(targetUrl, {
      allowedOrigin: config.allowedOrigin,
      additionalOrigins: config.additionalOrigins,
      allowAnyOrigin: config.allowAny
    });
    if (!validation.valid) {
      securityLogger.logBlocked('PROXY_SSR', validation.reason, { url: targetUrl, ip });
      return res.status(403).json({ error: validation.reason });
    }
  }

  let page = null;
  let context = null;
  let urlToLoad = targetUrl;
  
  try {
    context = await getBrowserContext();
    page = await context.newPage();
    
    // Block heavy resources to speed up loading and prevent hangs
    await page.route('**/*', (route) => {
      const resourceType = route.request().resourceType();
      // Block images, media, fonts to speed up SSR
      if (['image', 'media', 'font', 'stylesheet'].includes(resourceType)) {
        return route.abort();
      }
      return route.continue();
    });
    
    // Use domcontentloaded instead of networkidle - sites like now.gg never go idle
    // Try HTTPS first, fallback to HTTP if SSL error
    try {
      await page.goto(urlToLoad, { waitUntil: 'domcontentloaded', timeout: 15000 });
    } catch (navError) {
      if (urlToLoad.startsWith('https://') && 
          (navError.message.includes('SSL') || navError.message.includes('ERR_SSL') || 
           navError.message.includes('certificate') || navError.message.includes('EPROTO'))) {
        console.log('[SSR] HTTPS failed, trying HTTP fallback for:', urlToLoad);
        urlToLoad = urlToLoad.replace(/^https:/, 'http:');
        await page.goto(urlToLoad, { waitUntil: 'domcontentloaded', timeout: 15000 });
      } else {
        throw navError;
      }
    }
    
    // Give JS a moment to execute initial scripts
    await page.waitForTimeout(1000);
    
    const html = await page.content();
    
    await page.close();
    page = null;
    returnContextToPool(context);
    context = null;

    // Rewrite HTML using existing tokenizer
    const gatewayBase = config.gatewayBase || `${req.protocol}://${req.get('host')}`;
    const tokenizeUrlSync = (url) => {
      try {
        const { token: newToken } = tokenStore.createToken(url, resolution.sessionId || 'anonymous');
        return `/go/${newToken}`;
      } catch {
        return url;
      }
    };

    const rewrittenHtml = rewriteHtml(html, targetUrl, tokenizeUrlSync, {
        gatewayBase,
        sessionToken: resolution.sessionId || 'anonymous',
        pageToken: token
      });

    res.set('Content-Type', 'text/html; charset=utf-8');
    res.send(rewrittenHtml);
  } catch (e) {
    console.error('SSR error:', e.message);
    securityLogger.logWarning('SSR failed', { url: targetUrl, error: e.message });
    
    // Cleanup on error
    if (page) {
      try { await page.close(); } catch {}
    }
    if (context) {
      returnContextToPool(context);
    }
    
    // Fallback: redirect to the regular /go/:token endpoint instead of failing
    const fallbackToken = tokenStore.createToken(targetUrl, resolution.sessionId || 'anonymous').token;
    return res.redirect(`/go/${fallbackToken}?ssr_fallback=1`);
  }
});

/**
 * Demo API endpoint (for testing)
 */
app.get('/api/example', authMiddleware, (req, res) => {
  res.json({
    message: 'Hello from the gateway API!',
    timestamp: new Date().toISOString(),
    sessionId: req.sessionId.slice(0, 8) + '...'
  });
});

/**
 * Security logs endpoint (for debugging)
 */
app.get('/admin/logs', (req, res) => {
  // In production, add admin authentication here
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY && process.env.NODE_ENV === 'production') {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  res.json({
    stats: securityLogger.getStats(),
    recentLogs: securityLogger.getRecentLogs(50)
  });
});

/**
 * Debug endpoint - shows token store stats and recent activity
 */
app.get('/admin/debug', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY && process.env.NODE_ENV === 'production') {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  res.json({
    config: {
      allowedOrigin: config.allowedOrigin,
      additionalOrigins: config.additionalOrigins,
      allowAny: config.allowAny,
      debug: DEBUG
    },
    tokenStore: tokenStore.getStats(),
    sessionStore: {
      activeSessions: sessionStore.getActiveSessions ? sessionStore.getActiveSessions() : 'N/A'
    },
    rateLimiter: rateLimiter.getStats(),
    securityLogs: securityLogger.getStats(),
    recentBlocks: securityLogger.getRecentLogs(20).filter(l => l.type === 'blocked'),
    cache: {
      responseCache: responseCache.size,
      pageCache: pageCache.size
    }
  });
});

/**
 * Token lookup endpoint for debugging
 */
app.get('/admin/token/:token', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY && process.env.NODE_ENV === 'production') {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { token } = req.params;
  const resolution = tokenStore.resolveToken(token, null);
  
  res.json({
    token: token.substring(0, 12) + '...',
    resolution: {
      valid: resolution.valid,
      reason: resolution.reason,
      url: resolution.url,
      sessionId: resolution.sessionId ? '...' + resolution.sessionId.slice(-8) : null
    }
  });
});

/**
 * Serve static frontend files
 */
app.use(express.static(path.join(__dirname, '../../frontend')));

/**
 * Handle framework-specific paths like /_next/, /__webpack/, etc.
 * These are often dynamically loaded by JS and hit localhost directly
 */
app.all(['/_next/*', '/__webpack/*', '/_nuxt/*', '/static/*', '/assets/*', '/_astro/*'], async (req, res) => {
  try {
    const referer = req.get('referer') || '';
    const m = referer.match(/\/go\/([A-Za-z0-9-_]+)/);
    if (m) {
      const token = m[1];
      const resolution = tokenStore.resolveToken(token, null);
      if (resolution.valid) {
        const baseUrl = new URL(resolution.url);
        const upstreamUrl = `${baseUrl.origin}${req.path}${req.url.includes('?') ? '?' + req.url.split('?')[1] : ''}`;
        console.log(`[Framework asset] Proxying ${req.path} -> ${upstreamUrl}`);

        const headers = filterRequestHeaders(req.headers);
        delete headers.authorization;
        delete headers.Authorization;
        const agent = upstreamUrl.startsWith('https:') ? httpsAgent : httpAgent;

        const upstreamResponse = await fetch(upstreamUrl, {
          method: 'GET',
          headers,
          agent,
          redirect: 'follow',
          timeout: 30000
        });

        const contentType = upstreamResponse.headers.get('content-type') || '';
        const responseHeaders = filterResponseHeaders(Object.fromEntries(upstreamResponse.headers.entries()));
        delete responseHeaders['content-encoding'];
        delete responseHeaders['content-length'];

        for (const [k, v] of Object.entries(responseHeaders)) res.set(k, v);
        
        // Ensure correct MIME type for JS/CSS
        if (req.path.endsWith('.js') && !contentType.includes('javascript')) {
          res.set('Content-Type', 'application/javascript; charset=utf-8');
        } else if (req.path.endsWith('.css') && !contentType.includes('css')) {
          res.set('Content-Type', 'text/css; charset=utf-8');
        }
        
        res.status(upstreamResponse.status);
        upstreamResponse.body.pipe(res);
        return;
      }
    }
    // No valid referer token - return appropriate 404
    const ext = req.path.match(/\.([a-z0-9]+)$/i);
    if (ext && ext[1] === 'js') {
      res.type('application/javascript').status(404).send('// Not found');
    } else if (ext && ext[1] === 'css') {
      res.type('text/css').status(404).send('/* Not found */');
    } else {
      res.status(404).send('');
    }
  } catch (e) {
    console.error('[Framework asset proxy error]', e.message);
    res.status(502).send('');
  }
});

/**
 * Fallback - serve index.html for SPA routing
 * Only serve index.html for navigation requests (not assets)
 */
app.all('*', async (req, res) => {
  // Handle YouTube-style /s/ static paths (e.g. /s/search/audio/*.mp3)
  if (req.path.startsWith('/s/')) {
    try {
      const referer = req.get('referer') || '';
      const m = referer.match(/\/go\/([A-Za-z0-9-_]+)/);
      if (m) {
        const token = m[1];
        const resolution = tokenStore.resolveToken(token, null);
        if (resolution.valid) {
          const baseUrl = new URL(resolution.url);
          const upstreamUrl = `${baseUrl.origin}${req.originalUrl || req.path}`;

          const validation = validateUrl(upstreamUrl, {
            allowedOrigin: config.allowedOrigin,
            additionalOrigins: config.additionalOrigins,
            allowAnyOrigin: config.allowAny
          });

          if (validation.valid) {
            const headers = filterRequestHeaders(req.headers);
            delete headers.authorization;
            const agent = upstreamUrl.startsWith('https:') ? httpsAgent : httpAgent;

            const upstreamResponse = await fetch(upstreamUrl, {
              method: 'GET',
              headers,
              agent,
              redirect: 'follow',
              timeout: 30000
            });

            const responseHeaders = filterResponseHeaders(Object.fromEntries(upstreamResponse.headers.entries()));
            delete responseHeaders['content-encoding'];
            delete responseHeaders['content-length'];

            for (const [k, v] of Object.entries(responseHeaders)) res.set(k, v);
            res.status(upstreamResponse.status);
            upstreamResponse.body.pipe(res);
            return;
          }
        }
      }
    } catch (err) {
      console.error('[/s/ proxy error]', err.message);
    }
  }

  // Check if this looks like an asset request (has file extension)
  const hasExtension = /\.\w{2,5}$/.test(req.path);

  // If it's an asset-like path that wasn't found, attempt to proxy
  // the asset by resolving it against the Referer token's original URL.
  // This helps when pages generate relative asset URLs client-side
  // that hit the gateway host directly.
  if (hasExtension) {
    try {
      const referer = req.get('referer') || '';
      const m = referer.match(/\/go\/([A-Za-z0-9-_]+)/);
      if (m) {
        const token = m[1];
        const resolution = tokenStore.resolveToken(token, null);
        if (resolution.valid) {
          const upstreamUrl = resolveUrl(req.originalUrl || req.path, resolution.url);

          const validation = validateUrl(upstreamUrl, {
            allowedOrigin: config.allowedOrigin,
            additionalOrigins: config.additionalOrigins,
            allowAnyOrigin: config.allowAny
          });

          if (validation.valid) {
            const headers = filterRequestHeaders(req.headers);
            delete headers.authorization;
            delete headers.Authorization;

            const agent = upstreamUrl.startsWith('https:') ? httpsAgent : httpAgent;

            const upstreamResponse = await fetch(upstreamUrl, {
              method: 'GET',
              headers,
              agent,
              redirect: 'manual',
              timeout: 30000
            });

            const contentType = upstreamResponse.headers.get('content-type') || '';
            const responseHeaders = filterResponseHeaders(Object.fromEntries(upstreamResponse.headers.entries()));
            // Always strip encoding headers (node-fetch auto-decompresses)
            delete responseHeaders['content-encoding'];
            delete responseHeaders['content-length'];
            for (const [k, v] of Object.entries(responseHeaders)) res.set(k, v);
            res.status(upstreamResponse.status);
            if (isHtmlContentType(contentType)) {
              const html = await upstreamResponse.text();
              res.send(html);
            } else {
              upstreamResponse.body.pipe(res);
            }
            return;
          }
        }
      }
    } catch (e) {
      console.warn('Asset proxy failed:', e && e.message ? e.message : e);
    }

    return res.status(404).json({
      error: 'Not found',
      hint: 'This path was not tokenized. Use /go/<token> format.'
    });
  }

  // For non-asset paths (API calls like /youtubei/...), also try to proxy
  // using the Referer token. This catches relative API requests from JS.
  try {
    const referer = req.get('referer') || '';
    const m = referer.match(/\/go\/([A-Za-z0-9-_]+)/);
    if (m) {
      const token = m[1];
      const resolution = tokenStore.resolveToken(token, null);
      if (resolution.valid) {
        const upstreamUrl = resolveUrl(req.originalUrl || req.path, resolution.url);

        const validation = validateUrl(upstreamUrl, {
          allowedOrigin: config.allowedOrigin,
          additionalOrigins: config.additionalOrigins,
          allowAnyOrigin: config.allowAny
        });

        if (validation.valid) {
          const headers = filterRequestHeaders(req.headers);
          delete headers.authorization;
          delete headers.Authorization;

          const agent = upstreamUrl.startsWith('https:') ? httpsAgent : httpAgent;

          // Prepare body for POST/PUT
          let forwardBody = undefined;
          if (!['GET', 'HEAD'].includes(req.method)) {
            if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
              forwardBody = JSON.stringify(req.body);
              if (!headers['content-type'] && !headers['Content-Type']) {
                headers['content-type'] = 'application/json';
              }
            } else {
              forwardBody = req.body;
            }
          }

          const upstreamResponse = await fetch(upstreamUrl, {
            method: req.method,
            headers,
            body: forwardBody,
            agent,
            redirect: 'manual',
            timeout: 30000
          });

          const contentType = upstreamResponse.headers.get('content-type') || '';
          const responseHeaders = filterResponseHeaders(Object.fromEntries(upstreamResponse.headers.entries()));
          // Always strip encoding headers (node-fetch auto-decompresses)
          delete responseHeaders['content-encoding'];
          delete responseHeaders['content-length'];

          for (const [k, v] of Object.entries(responseHeaders)) res.set(k, v);
          res.status(upstreamResponse.status);

          if (isHtmlContentType(contentType)) {
            const html = await upstreamResponse.text();
            res.send(html);
          } else {
            upstreamResponse.body.pipe(res);
          }
          return;
        }
      }
    }
  } catch (e) {
    console.warn('API proxy failed:', e && e.message ? e.message : e);
  }

  // Only serve frontend HTML for the root path or explicit navigation
  // Don't serve it for any other paths to prevent redirect loops
  const isRoot = req.path === '/' || req.path === '/index.html';
  const isNavigation = req.get('accept')?.includes('text/html') && 
                       !req.path.startsWith('/go/') && 
                       !req.path.startsWith('/go-ssr/');
  
  if (isRoot) {
    return res.sendFile(path.join(__dirname, '../../frontend/index.html'));
  }
  
  // For non-root paths that look like navigation (HTML accept header),
  // try to resolve against the Referer's original URL and redirect to tokenized version
  if (isNavigation) {
    try {
      const referer = req.get('referer') || '';
      const m = referer.match(/\/go\/([A-Za-z0-9_-]+)/);
      if (m) {
        const refToken = m[1];
        const resolution = tokenStore.resolveToken(refToken, null);
        if (resolution.valid) {
          // Resolve the relative path against the original page URL
          const upstreamUrl = resolveUrl(req.originalUrl || req.path, resolution.url);
          console.log(`[Catch-all] Resolving navigation: ${req.path} -> ${upstreamUrl}`);
          
          const validation = validateUrl(upstreamUrl, {
            allowedOrigin: config.allowedOrigin,
            additionalOrigins: config.additionalOrigins,
            allowAnyOrigin: config.allowAny
          });
          
          if (validation.valid) {
            // Create a token for the resolved URL and redirect
            try {
              const { token: newToken } = tokenStore.createToken(upstreamUrl, resolution.sessionId || 'anonymous');
              console.log(`[Catch-all] Redirecting to tokenized: /go/${newToken}`);
              return res.redirect(302, `/go/${newToken}`);
            } catch (e) {
              console.warn('[Catch-all] Token creation failed:', e.message);
            }
          }
        }
      }
    } catch (e) {
      console.warn('[Catch-all] Navigation resolution failed:', e.message);
    }
    
    return res.status(404).type('text/html').send(`
      <!DOCTYPE html>
      <html>
      <head><title>404 - Not Found</title></head>
      <body style="font-family: sans-serif; padding: 2rem; background: #0f172a; color: #e2e8f0;">
        <h1>404 - Page Not Found</h1>
        <p>The requested path <code>${req.path}</code> was not found.</p>
        <p>If you're trying to browse a site, please use the <a href="/" style="color: #6366f1;">Gateway Browser</a>.</p>
      </body>
      </html>
    `);
  }
  
  // For all other unmatched paths, return appropriate error
  res.status(404).type('text/plain').send('Not found');
});

// ============================================================================
// Error Handling
// ============================================================================

app.use((err, req, res, next) => {
  debugError('ERROR', 'UNHANDLED EXPRESS ERROR', err, {
    path: req.path,
    method: req.method,
    query: req.query,
    ip: req.ip,
    headers: {
      accept: req.get('accept')?.substring(0, 50),
      referer: req.get('referer')?.substring(0, 80),
      'content-type': req.get('content-type')
    }
  });
  securityLogger.logWarning('Unhandled error', { error: err.message });
  
  if (!res.headersSent) {
    res.status(500).json({ 
      error: 'Internal server error',
      details: err.message,
      path: req.path,
      hint: 'Check server logs for full stack trace'
    });
  }
});

// ============================================================================
// Start Server
// ============================================================================

const server = app.listen(config.port, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║           Encrypted Link Gateway Server                     ║
╠══════════════════════════════════════════════════════════════╣
║  Port:           ${config.port.toString().padEnd(42)}║
║  Allowed Origin: ${config.allowedOrigin.slice(0, 42).padEnd(42)}║
║  WebSocket:      ${(config.allowWebSocket ? 'Enabled' : 'Disabled').padEnd(42)}║
╚══════════════════════════════════════════════════════════════╝
  `);
  
  if (config.allowedOrigin === 'https://example.com') {
    console.warn('⚠️  WARNING: Using default allowed origin. Set ALLOWED_ORIGIN env var!');
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down...');
  server.close(() => {
    tokenStore.shutdown();
    sessionStore.shutdown();
    rateLimiter.shutdown();
    process.exit(0);
  });
});

module.exports = app;


