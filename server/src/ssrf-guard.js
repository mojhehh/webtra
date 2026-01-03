/**
 * SSRF Guard Module
 * Validates URLs against allowlist and blocks dangerous targets
 */

const { URL } = require('url');
const dns = require('dns');
const { promisify } = require('util');

const dnsLookup = promisify(dns.lookup);

// Debug logging
function debug(category, message, data = {}) {
  console.log(`[SSRF-GUARD:${category}] ${message}`, JSON.stringify(data, null, 2));
}

function debugError(category, message, error, data = {}) {
  console.error(`[SSRF-GUARD:${category}] ❌ ${message}`, {
    error: error?.message || error,
    stack: error?.stack?.split('\n').slice(0, 3).join('\n'),
    ...data
  });
}

// Forbidden URL schemes
const FORBIDDEN_SCHEMES = new Set([
  'file:',
  'ftp:',
  'ws:',
  'wss:',
  'data:',
  'blob:',
  'javascript:',
  'vbscript:'
]);

// Safe schemes that should pass through without rewriting
const PASSTHROUGH_SCHEMES = new Set([
  'mailto:',
  'tel:',
  'sms:'
]);

// Blocked hostnames
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  '[::1]'
]);

/**
 * Check if an IP is in a private/reserved range
 */
function isPrivateIP(ip) {
  // Remove IPv6 brackets if present
  ip = ip.replace(/^\[|\]$/g, '');
  
  // IPv4 private ranges
  const ipv4Patterns = [
    /^10\./,                          // 10.0.0.0/8
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
    /^192\.168\./,                    // 192.168.0.0/16
    /^169\.254\./,                    // 169.254.0.0/16 (link-local)
    /^127\./,                         // 127.0.0.0/8 (loopback)
    /^0\./,                           // 0.0.0.0/8
    /^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./, // 100.64.0.0/10 (CGNAT)
  ];
  
  for (const pattern of ipv4Patterns) {
    if (pattern.test(ip)) return true;
  }
  
  // IPv6 private/reserved
  const ipv6LowerCase = ip.toLowerCase();
  const ipv6Patterns = [
    /^::1$/,                    // Loopback
    /^fc[0-9a-f]{2}:/,          // fc00::/7 (Unique local)
    /^fd[0-9a-f]{2}:/,          // fd00::/8 (Unique local)
    /^fe[89ab][0-9a-f]:/,       // fe80::/10 (Link-local)
    /^::ffff:/i,                // IPv4-mapped IPv6
  ];
  
  for (const pattern of ipv6Patterns) {
    if (pattern.test(ipv6LowerCase)) return true;
  }
  
  return false;
}

/**
 * Check if hostname looks like an IP address
 */
function looksLikeIP(hostname) {
  // IPv4
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    return true;
  }
  // IPv6 (with or without brackets)
  if (/^\[?[0-9a-fA-F:]+\]?$/.test(hostname)) {
    return true;
  }
  return false;
}

/**
 * Validate a URL against the allowlist and security rules
 * @param {string} targetUrl - The URL to validate
 * @param {Object} config - Configuration object
 * @param {string} config.allowedOrigin - Primary allowed origin (e.g., 'https://example.com')
 * @param {string[]} [config.additionalOrigins] - Additional allowed origins
 * @param {boolean} [config.allowWebSocket] - Enable WebSocket support (default: false)
 * @param {string} [config.allowedWsOrigin] - Single allowed WebSocket origin
 * @returns {{ valid: boolean, reason?: string, url?: URL }}
 */
function validateUrl(targetUrl, config) {
  const { allowedOrigin, additionalOrigins = [], allowWebSocket = false, allowedWsOrigin, allowAnyOrigin = false } = config;
  
  debug('VALIDATE', 'Validating URL', { 
    url: targetUrl?.substring(0, 100),
    allowAnyOrigin,
    allowWebSocket 
  });
  
  // Check for passthrough schemes (mailto:, tel:, etc.)
  for (const scheme of PASSTHROUGH_SCHEMES) {
    if (targetUrl.toLowerCase().startsWith(scheme)) {
      debug('VALIDATE', 'Passthrough scheme detected', { scheme, url: targetUrl });
      return { valid: true, passthrough: true, url: null };
    }
  }
  
  let url;
  try {
    url = new URL(targetUrl);
  } catch (e) {
    debug('VALIDATE', 'URL REJECTED - Invalid format', { url: targetUrl, error: e.message });
    return { valid: false, reason: `Invalid URL format: ${e.message}` };
  }
  
  // Check for forbidden schemes
  if (FORBIDDEN_SCHEMES.has(url.protocol)) {
    // Special handling for WebSocket if enabled
    if ((url.protocol === 'ws:' || url.protocol === 'wss:') && allowWebSocket) {
      if (allowedWsOrigin && url.origin === new URL(allowedWsOrigin).origin) {
        debug('VALIDATE', 'WebSocket URL allowed', { url: targetUrl });
        return { valid: true, url };
      }
      debug('VALIDATE', 'URL REJECTED - WebSocket origin not allowed', { 
        url: targetUrl, 
        origin: url.origin, 
        allowedWsOrigin 
      });
      return { valid: false, reason: `WebSocket origin not allowed: ${url.origin}` };
    }
    debug('VALIDATE', 'URL REJECTED - Forbidden scheme', { url: targetUrl, scheme: url.protocol });
    return { valid: false, reason: `Forbidden scheme: ${url.protocol}` };
  }
  
  // Only allow http and https
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    debug('VALIDATE', 'URL REJECTED - Unsupported scheme', { url: targetUrl, scheme: url.protocol });
    return { valid: false, reason: `Unsupported scheme: ${url.protocol}` };
  }
  
  // Check blocked hostnames
  const hostname = url.hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(hostname)) {
    debug('VALIDATE', 'URL REJECTED - Blocked hostname', { url: targetUrl, hostname });
    return { valid: false, reason: `Blocked hostname: ${hostname}` };
  }
  
  // Check if hostname is an IP address in private range
  if (looksLikeIP(hostname) && isPrivateIP(hostname)) {
    debug('VALIDATE', 'URL REJECTED - Private IP', { url: targetUrl, hostname });
    return { valid: false, reason: `Private IP address blocked: ${hostname}` };
  }
  
  // If configured, allow any http(s) origin (DANGEROUS: opt-in only)
  if (allowAnyOrigin) {
    if (url.protocol === 'http:' || url.protocol === 'https:') {
      debug('VALIDATE', 'URL ALLOWED (allowAnyOrigin=true)', { url: targetUrl });
      return { valid: true, url };
    }
    debug('VALIDATE', 'URL REJECTED - Unsupported scheme with allowAnyOrigin', { url: targetUrl, scheme: url.protocol });
    return { valid: false, reason: `Unsupported scheme: ${url.protocol}` };
  }

  // Build list of allowed origins
  const allAllowedOrigins = [allowedOrigin, ...additionalOrigins]
    .filter(Boolean)
    .map(o => {
      try {
        return new URL(o).origin;
      } catch {
        return null;
      }
    })
    .filter(Boolean);

  // Check against allowlist
  if (!allAllowedOrigins.includes(url.origin)) {
    debug('VALIDATE', 'URL REJECTED - Origin not in allowlist', { 
      url: targetUrl, 
      urlOrigin: url.origin,
      allowedOrigins: allAllowedOrigins 
    });
    return { valid: false, reason: `Origin not in allowlist: ${url.origin}. Allowed: ${allAllowedOrigins.join(', ')}` };
  }
  
  debug('VALIDATE', 'URL ALLOWED', { url: targetUrl });
  return { valid: true, url };
}

/**
 * Async validation with DNS resolution check
 * Ensures hostname doesn't resolve to a private IP
 */
async function validateUrlWithDNS(targetUrl, config) {
  debug('VALIDATE_DNS', 'Starting DNS validation', { url: targetUrl?.substring(0, 100) });
  
  const result = validateUrl(targetUrl, config);
  if (!result.valid || result.passthrough) {
    debug('VALIDATE_DNS', 'Skipping DNS check - basic validation result', { valid: result.valid, passthrough: result.passthrough });
    return result;
  }
  
  const { url } = result;
  const hostname = url.hostname;

  // If operator explicitly enabled allowAnyOrigin, skip DNS resolution
  // to avoid blocking valid public hosts due to transient DNS failures.
  if (config && config.allowAnyOrigin) {
    debug('VALIDATE_DNS', 'Skipping DNS check - allowAnyOrigin enabled', { hostname });
    return result;
  }
  
  // Skip DNS check for allowed IP addresses
  if (looksLikeIP(hostname)) {
    debug('VALIDATE_DNS', 'Skipping DNS check - already an IP', { hostname });
    return result;
  }
  
  try {
    // Resolve hostname to check for DNS rebinding attacks
    const { address } = await dnsLookup(hostname);
    debug('VALIDATE_DNS', 'DNS resolved', { hostname, resolvedIP: address });
    
    if (isPrivateIP(address)) {
      debug('VALIDATE_DNS', 'URL REJECTED - Resolves to private IP', { hostname, address });
      return { valid: false, reason: `Hostname resolves to private IP: ${address}` };
    }
  } catch (e) {
    // DNS resolution failed - could be intentional for internal hosts
    debugError('VALIDATE_DNS', 'DNS resolution failed', e, { hostname });
    return { valid: false, reason: `DNS resolution failed for: ${hostname} (${e.message})` };
  }
  
  debug('VALIDATE_DNS', 'URL passed DNS validation', { hostname });
  return result;
}

/**
 * List of headers that should NOT be forwarded to upstream
 */
const DANGEROUS_HEADERS = new Set([
  'host',
  'connection',
  'transfer-encoding',
  'upgrade',
  'proxy-connection',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'keep-alive',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
  'cf-connecting-ip',
  'true-client-ip',
  'x-client-ip',
  'forwarded'
]);

/**
 * Filter headers for safe forwarding to upstream
 */
function filterRequestHeaders(headers) {
  const filtered = {};
  const removed = [];
  for (const [key, value] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();
    if (!DANGEROUS_HEADERS.has(lowerKey) && !lowerKey.startsWith('proxy-')) {
      filtered[key] = value;
    } else {
      removed.push(key);
    }
  }
  if (removed.length > 0) {
    debug('FILTER_REQ', 'Removed dangerous headers', { removed });
  }
  return filtered;
}

/**
 * List of response headers to preserve
 */
const PRESERVE_RESPONSE_HEADERS = [
  'content-type',
  'content-length',
  'content-encoding',
  'content-language',
  'content-disposition',
  'cache-control',
  'expires',
  'etag',
  'last-modified',
  'vary',
  'accept-ranges',
  'content-range'  // For video/audio seeking support
];

/**
 * Filter response headers for safe forwarding to client
 */
function filterResponseHeaders(headers) {
  const filtered = {};
  const preserved = [];
  for (const key of PRESERVE_RESPONSE_HEADERS) {
    if (headers[key] || headers[key.toLowerCase()]) {
      filtered[key] = headers[key] || headers[key.toLowerCase()];
      preserved.push(key);
    }
  }
  debug('FILTER_RES', 'Preserved response headers', { preserved, total: Object.keys(headers).length });
  return filtered;
}

module.exports = {
  validateUrl,
  validateUrlWithDNS,
  filterRequestHeaders,
  filterResponseHeaders,
  isPrivateIP,
  FORBIDDEN_SCHEMES,
  PASSTHROUGH_SCHEMES,
  BLOCKED_HOSTNAMES,
  DANGEROUS_HEADERS
};
