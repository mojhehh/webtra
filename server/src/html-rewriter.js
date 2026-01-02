/**
 * HTML Rewriter Module
 * Parses HTML and rewrites all URLs to go through the gateway
 */

const cheerio = require('cheerio');
const { URL } = require('url');
const { PASSTHROUGH_SCHEMES } = require('./ssrf-guard');

// Attributes that contain URLs to rewrite
const URL_ATTRIBUTES = {
  'a': ['href'],
  'link': ['href'],
  'script': ['src'],
  'img': ['src', 'srcset'],
  'iframe': ['src'],
  'form': ['action'],
  'source': ['src', 'srcset'],
  'video': ['src', 'poster'],
  'audio': ['src'],
  'embed': ['src'],
  'object': ['data'],
  'area': ['href'],
  'base': ['href'],
  'input': ['src'], // for type="image"
};

// CSS url() pattern
const CSS_URL_PATTERN = /url\s*\(\s*['"]?([^'")\s]+)['"]?\s*\)/gi;

// Video/media CDN domains that must bypass proxy (signed URLs check IP)
// These CDN URLs should NOT be tokenized - they need direct access
const VIDEO_CDN_BYPASS = [
  'googlevideo.com',      // YouTube video CDN
  'ytimg.com',            // YouTube images/thumbnails  
  'ggpht.com',            // Google profile pics
  'googleusercontent.com', // Google user content
  'tiktokcdn.com',        // TikTok video CDN
  'tiktokcdn-us.com',     // TikTok US CDN
  'musical.ly',           // TikTok legacy CDN
  'muscdn.com',           // TikTok music CDN
  'ibytedtos.com',        // ByteDance CDN
  'ibyteimg.com',         // ByteDance image CDN
  'tiktokv.com',          // TikTok video hosting
  'tiktokv.us',           // TikTok US video
  'akamaized.net',        // Akamai CDN (used by many)
  'cloudfront.net',       // AWS CloudFront  
  'fastly.net',           // Fastly CDN
  'cdn.jsdelivr.net',     // JSDelivr
  'unpkg.com'             // UNPKG CDN
];

/**
 * Check if URL is a video/media CDN that should bypass proxy
 */
function isVideoCdnUrl(url) {
  try {
    const u = new URL(url);
    const hostname = u.hostname.toLowerCase();
    for (const cdn of VIDEO_CDN_BYPASS) {
      if (hostname === cdn || hostname.endsWith('.' + cdn)) {
        return true;
      }
    }
  } catch (e) {}
  return false;
}

/**
 * Check if URL should be passed through without rewriting
 */
function shouldPassthrough(url) {
  if (!url || typeof url !== 'string') return true;
  
  const trimmed = url.trim().toLowerCase();
  
  // Empty or fragment-only URLs
  if (!trimmed || trimmed.startsWith('#')) return true;
  
  // Passthrough schemes (mailto:, tel:, etc.)
  for (const scheme of PASSTHROUGH_SCHEMES) {
    if (trimmed.startsWith(scheme)) return true;
  }
  
  // Data URLs (we block these in SSRF guard, but they shouldn't be tokenized)
  if (trimmed.startsWith('data:')) return true;
  
  // JavaScript pseudo-protocol
  if (trimmed.startsWith('javascript:')) return true;
  
  // Video/media CDN URLs must bypass proxy (signed URLs verify IP)
  if (isVideoCdnUrl(url)) return true;
  
  return false;
}

/**
 * Resolve a potentially relative URL against a base URL
 */
function resolveUrl(href, baseUrl) {
  try {
    return new URL(href, baseUrl).href;
  } catch {
    return null;
  }
}

/**
 * Parse srcset attribute and rewrite URLs
 */
function parseSrcset(srcset, baseUrl, tokenizeUrl) {
  if (!srcset) return srcset;
  
  const parts = srcset.split(',').map(part => part.trim());
  const rewritten = parts.map(part => {
    const match = part.match(/^(\S+)(\s+.*)?$/);
    if (!match) return part;
    
    const [, url, descriptor = ''] = match;
    const resolved = resolveUrl(url, baseUrl);
    
    if (!resolved || shouldPassthrough(url) || isVideoCdnUrl(resolved)) {
      return part;
    }
    
    const tokenized = tokenizeUrl(resolved);
    return tokenized + descriptor;
  });
  
  return rewritten.join(', ');
}

/**
 * Rewrite inline styles containing url()
 */
function rewriteStyleUrls(style, baseUrl, tokenizeUrl) {
  if (!style) return style;
  
  return style.replace(CSS_URL_PATTERN, (match, url) => {
    if (shouldPassthrough(url)) return match;
    
    const resolved = resolveUrl(url, baseUrl);
    if (!resolved) return match;
    
    // Skip video CDN URLs
    if (isVideoCdnUrl(resolved)) return match;
    
    const tokenized = tokenizeUrl(resolved);
    return `url('${tokenized}')`;
  });
}

/**
 * Generate the bootstrap script to inject into HTML
 * This script intercepts fetch/XHR and link clicks
 * @param {string} gatewayBase - Base URL of the gateway
 * @param {string} sessionToken - Session token for auth
 * @param {string} pageToken - Token for the current page
 * @param {Object} options - Additional options
 * @param {string} options.originalBaseUrl - Original URL of the page being proxied
 */
function generateBootstrapScript(gatewayBase, sessionToken, pageToken, options = {}) {
  return `
<script data-gateway-bootstrap="true">
(function() {
  'use strict';
  
  // CRITICAL: Capture the NATIVE fetch and XHR references IMMEDIATELY
  // before any other scripts (like TikTok's security SDKs) can wrap them.
  // We use Object.getOwnPropertyDescriptor to get the true native function
  // from the Window prototype, bypassing any wrappers on the instance.
  var _nativeFetch = (function() {
    // Try to get the native fetch from Window.prototype first
    try {
      var desc = Object.getOwnPropertyDescriptor(Window.prototype, 'fetch');
      if (desc && typeof desc.value === 'function') {
        return desc.value.bind(window);
      }
    } catch (e) {}
    // Fall back to current window.fetch (might already be wrapped but try anyway)
    return window.fetch.bind(window);
  })();
  
  var _nativeXHROpen = XMLHttpRequest.prototype.open;
  var _nativeXHRSend = XMLHttpRequest.prototype.send;
  
  // Store natives GLOBALLY so all contexts can access them
  // Using defineProperty with configurable:false to prevent modification
  if (!window._gatewayNatives) {
    Object.defineProperty(window, '_gatewayNatives', {
      value: Object.freeze({
        fetch: _nativeFetch,
        xhrOpen: _nativeXHROpen,
        xhrSend: _nativeXHRSend
      }),
      writable: false,
      configurable: false,
      enumerable: false
    });
  }
  
  // Local reference for convenience
  var _gatewayNatives = window._gatewayNatives;
  
  console.log('[Gateway Bootstrap] Native fetch captured:', typeof _gatewayNatives.fetch);
  
  // URL SPOOFING: Make client-side routers think they're on the original URL
  // This is critical for SPAs like TikTok that check window.location for routing
  const ORIGINAL_BASE_URL = ${JSON.stringify(options.originalBaseUrl || null)};
  if (ORIGINAL_BASE_URL) {
    try {
      const originalUrl = new URL(ORIGINAL_BASE_URL);
      
      // Use history.replaceState to change the displayed URL without navigation
      // This makes the URL bar and window.location show the original URL
      try {
        history.replaceState(history.state, '', originalUrl.pathname + originalUrl.search + originalUrl.hash);
        console.log('[Gateway Bootstrap] URL spoofed via replaceState to:', originalUrl.pathname);
      } catch (e) {
        console.warn('[Gateway Bootstrap] replaceState failed:', e.message);
      }
      
      // Also override location getters as a fallback for code that caches location
      var _originalLocation = window.location;
      var locationOverrides = {
        href: originalUrl.href,
        origin: originalUrl.origin,
        protocol: originalUrl.protocol,
        host: originalUrl.host,
        hostname: originalUrl.hostname,
        port: originalUrl.port,
        pathname: originalUrl.pathname,
        search: originalUrl.search,
        hash: originalUrl.hash
      };
      
      // Create a proxy-like object for location reads
      // Note: We can't actually replace window.location, but we can intercept reads
      // by overriding document.location getter
      try {
        var locationProxy = {};
        Object.keys(locationOverrides).forEach(function(key) {
          Object.defineProperty(locationProxy, key, {
            get: function() { return locationOverrides[key]; },
            configurable: true
          });
        });
        // Copy methods
        locationProxy.assign = _originalLocation.assign.bind(_originalLocation);
        locationProxy.replace = _originalLocation.replace.bind(_originalLocation);
        locationProxy.reload = _originalLocation.reload.bind(_originalLocation);
        locationProxy.toString = function() { return originalUrl.href; };
        
        // Store the original URL info globally for other code to use
        window._gatewayOriginalUrl = originalUrl.href;
        window._gatewayOriginalOrigin = originalUrl.origin;
        
        console.log('[Gateway Bootstrap] Location info spoofed to:', originalUrl.origin);
      } catch (e) {
        console.warn('[Gateway Bootstrap] Location spoofing failed:', e.message);
      }
    } catch (e) {
      console.warn('[Gateway Bootstrap] URL parsing failed:', e.message);
    }
  }
  
  // Comprehensive stub for TCF/CMP APIs used by consent management libraries.
  // Many third-party consent managers expect these globals to exist; when
  // running inside a sandboxed/about:srcdoc iframe, this prevents errors.
  if (typeof window.__tcfapi !== 'function') {
    var tcfListeners = [];
    var listenerId = 0;
    window.__tcfapi = function(command, version, callback, parameter) {
      try {
        // Build complete mock TCData that CMP libraries expect
        var tcData = {
          tcString: 'CO_placeholder_consent_string',
          tcfPolicyVersion: 2,
          cmpId: 1,
          cmpVersion: 1,
          gdprApplies: false,
          eventStatus: 'tcloaded',
          cmpStatus: 'loaded',
          listenerId: null,
          isServiceSpecific: true,
          useNonStandardStacks: false,
          publisherCC: 'US',
          purposeOneTreatment: false,
          purpose: { 
            consents: { 1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true, 8: true, 9: true, 10: true },
            legitimateInterests: { 2: true, 7: true, 8: true, 9: true, 10: true }
          },
          vendor: { consents: {}, legitimateInterests: {} },
          specialFeatureOptins: { 1: true, 2: true },
          publisher: { 
            consents: {}, 
            legitimateInterests: {}, 
            customPurpose: { consents: {}, legitimateInterests: {} }, 
            restrictions: {} 
          },
          outOfBand: { allowedVendors: {}, disclosedVendors: {} }
        };
        
        if (command === 'addEventListener') {
          tcData.listenerId = ++listenerId;
          tcfListeners.push({ id: listenerId, callback: callback });
          if (typeof callback === 'function') {
            setTimeout(function() { callback(tcData, true); }, 0);
          }
        } else if (command === 'removeEventListener') {
          tcfListeners = tcfListeners.filter(function(l) { return l.id !== parameter; });
          if (typeof callback === 'function') {
            setTimeout(function() { callback(true); }, 0);
          }
        } else if (command === 'getTCData' || command === 'ping') {
          if (typeof callback === 'function') {
            if (command === 'ping') {
              setTimeout(function() { 
                callback({ 
                  gdprApplies: false, 
                  cmpLoaded: true, 
                  cmpStatus: 'loaded',
                  displayStatus: 'hidden',
                  apiVersion: '2.0',
                  cmpVersion: 1,
                  cmpId: 1,
                  gvlVersion: 1,
                  tcfPolicyVersion: 2
                }); 
              }, 0);
            } else {
              setTimeout(function() { callback(tcData, true); }, 0);
            }
          }
        } else if (typeof callback === 'function') {
          setTimeout(function() { callback(tcData, true); }, 0);
        }
      } catch (e) {
        // swallow errors
      }
    };
  }
  
  // Stub for __gpp (Global Privacy Platform) API
  if (typeof window.__gpp !== 'function') {
    window.__gpp = function(command, callback, parameter) {
      try {
        if (command === 'ping' && typeof callback === 'function') {
          setTimeout(function() {
            callback({
              gppVersion: '1.1',
              cmpStatus: 'loaded',
              cmpDisplayStatus: 'hidden',
              signalStatus: 'ready',
              supportedAPIs: ['tcfeuv2', 'uspv1'],
              cmpId: 1,
              sectionList: [],
              applicableSections: [],
              gppString: ''
            }, true);
          }, 0);
        } else if (typeof callback === 'function') {
          setTimeout(function() { callback({}, true); }, 0);
        }
      } catch (e) {}
    };
    window.__gpp.domReady = true;
  }
  
  // Stub for US Privacy (CCPA) API
  if (typeof window.__uspapi !== 'function') {
    window.__uspapi = function(command, version, callback) {
      try {
        if (typeof callback === 'function') {
          setTimeout(function() { 
            callback({ uspString: '1---', version: 1 }, true); 
          }, 0);
        }
      } catch (e) {}
    };
  }
  
  const GATEWAY_BASE = ${JSON.stringify(gatewayBase)};
  const SESSION_TOKEN = ${JSON.stringify(sessionToken)};
  const PAGE_TOKEN = ${JSON.stringify(pageToken || null)};
  // ORIGINAL_BASE_URL already declared above for URL spoofing
  const TOKEN_CACHE = new Map();
  
  // Debug logging helper
  const DEBUG_BOOTSTRAP = true;
  function debugLog(...args) {
    if (DEBUG_BOOTSTRAP) console.log('[Gateway Bootstrap]', ...args);
  }
  
  debugLog('Initializing with:', { 
    gatewayBase: GATEWAY_BASE, 
    sessionToken: SESSION_TOKEN ? '...' + SESSION_TOKEN.slice(-8) : 'none',
    pageToken: PAGE_TOKEN ? '...' + PAGE_TOKEN.slice(-8) : 'none',
    originalBaseUrl: ORIGINAL_BASE_URL
  });
  
  // Fix URLs that incorrectly point to localhost when they should point to the original domain
  function fixLocalhostUrl(url) {
    if (!ORIGINAL_BASE_URL || !url) return url;
    try {
      const u = new URL(url);
      // If URL points to localhost/gateway but has a path that looks like an original site resource
      if ((u.hostname === 'localhost' || u.hostname === '127.0.0.1') && 
          !u.pathname.startsWith('/go/') && 
          !u.pathname.startsWith('/go-ssr/') && 
          !u.pathname.startsWith('/tokenize') &&
          !u.pathname.startsWith('/session') &&
          !u.pathname.startsWith('/admin')) {
        // Rewrite to original domain
        const originalUrl = new URL(ORIGINAL_BASE_URL);
        const fixedUrl = originalUrl.origin + u.pathname + u.search + u.hash;
        debugLog('Fixed localhost URL:', url.substring(0, 50), '->', fixedUrl.substring(0, 50));
        return fixedUrl;
      }
    } catch (e) {
      // If URL parsing fails, return as-is
    }
    return url;
  }
  
  // Tokenize URL via the server - with extensive debugging
  var tokenizeRequestCount = 0;
  var tokenizeInFlight = new Map(); // Track in-flight requests to deduplicate
  
  async function tokenizeUrl(url) {
    // First, fix any localhost URLs that should point to original domain
    url = fixLocalhostUrl(url);
    
    // Check cache first
    const cached = TOKEN_CACHE.get(url);
    if (cached && cached.exp > Date.now()) {
      debugLog('Cache HIT for:', url.substring(0, 60));
      return cached.token;
    }
    
    // Deduplicate in-flight requests for same URL
    if (tokenizeInFlight.has(url)) {
      debugLog('Waiting for in-flight tokenize:', url.substring(0, 60));
      return tokenizeInFlight.get(url);
    }
    
    const requestId = ++tokenizeRequestCount;
    console.log('[Gateway DEBUG] [#' + requestId + '] Tokenize START:', {
      url: url.substring(0, 100),
      gatewayBase: GATEWAY_BASE,
      hasSessionToken: !!SESSION_TOKEN,
      hasPageToken: !!PAGE_TOKEN,
      pageToken: PAGE_TOKEN ? '...' + PAGE_TOKEN.slice(-12) : 'none'
    });
    
    const promise = (async () => {
      try {
        // Use the original fetch reference to call the gateway tokenize
        // endpoint directly so our overridden window.fetch doesn't
        // intercept and re-tokenize the request (causing recursion).
        const headers = {
          'Content-Type': 'application/json'
        };
        // Send session header when available; also send parent page token
        if (SESSION_TOKEN) headers['Authorization'] = 'Bearer ' + SESSION_TOKEN;
        if (PAGE_TOKEN) headers['X-Parent-Token'] = PAGE_TOKEN;
        
        const tokenizeEndpoint = GATEWAY_BASE + '/tokenize';
        console.log('[Gateway DEBUG] [#' + requestId + '] Fetching:', tokenizeEndpoint);
        console.log('[Gateway DEBUG] [#' + requestId + '] Headers:', JSON.stringify(headers));
        
        const startTime = performance.now();
        const response = await _gatewayNatives.fetch(tokenizeEndpoint, {
          method: 'POST',
          headers,
          body: JSON.stringify({ url }),
          credentials: 'include',
          mode: 'cors'
        });
        const duration = (performance.now() - startTime).toFixed(0);
        
        console.log('[Gateway DEBUG] [#' + requestId + '] Response:', {
          status: response.status,
          statusText: response.statusText,
          ok: response.ok,
          duration: duration + 'ms',
          headers: {
            contentType: response.headers.get('content-type'),
            accessControlAllowOrigin: response.headers.get('access-control-allow-origin')
          }
        });
        
        if (!response.ok) {
          const errorText = await response.text().catch(() => 'unknown');
          console.error('[Gateway DEBUG] [#' + requestId + '] Tokenize FAILED:', {
            status: response.status,
            statusText: response.statusText,
            body: errorText.substring(0, 500),
            url: url.substring(0, 100)
          });
          return null;
        }
        
        const data = await response.json();
        console.log('[Gateway DEBUG] [#' + requestId + '] Tokenize SUCCESS:', {
          token: data.token ? '...' + data.token.slice(-12) : 'MISSING',
          cached: data.cached,
          url: url.substring(0, 60)
        });
        
        // Cache with 55 minute expiry (tokens last 1 hour)
        TOKEN_CACHE.set(url, {
          token: data.token,
          exp: Date.now() + 55 * 60 * 1000
        });
        
        return data.token;
      } catch (e) {
        console.error('[Gateway DEBUG] [#' + requestId + '] Tokenize EXCEPTION:', {
          name: e.name,
          message: e.message,
          stack: e.stack ? e.stack.substring(0, 300) : 'no stack',
          url: url.substring(0, 100)
        });
        // Check if it's a network error
        if (e.name === 'TypeError' && e.message.includes('fetch')) {
          console.error('[Gateway DEBUG] [#' + requestId + '] Network error - check if server is reachable at:', GATEWAY_BASE);
        }
        return null;
      } finally {
        tokenizeInFlight.delete(url);
      }
    })();
    
    tokenizeInFlight.set(url, promise);
    return promise;
  }
  
  // Convert URL to gateway path
  function toGatewayUrl(token) {
    return GATEWAY_BASE + '/go/' + token;
  }
  
  // Video/media CDN domains that must bypass proxy (signed URLs check IP)
  const VIDEO_CDN_BYPASS = [
    'googlevideo.com',      // YouTube video CDN
    'ytimg.com',            // YouTube images/thumbnails  
    'ggpht.com',            // Google profile pics
    'googleusercontent.com', // Google user content
    'tiktokcdn.com',        // TikTok video CDN
    'tiktokcdn-us.com',     // TikTok US CDN
    'musical.ly',           // TikTok legacy CDN
    'muscdn.com',           // TikTok music CDN
    'ibytedtos.com',        // ByteDance CDN
    'ibyteimg.com',         // ByteDance image CDN
    'tiktokv.com',          // TikTok video hosting
    'tiktokv.us',           // TikTok US video
    'akamaized.net',        // Akamai CDN (used by many)
    'cloudfront.net',       // AWS CloudFront
    'fastly.net',           // Fastly CDN
    'cdn.jsdelivr.net',     // JSDelivr
    'unpkg.com'             // UNPKG CDN
  ];
  
  // Check if URL is a video/media CDN that should bypass proxy
  function isVideoCdnUrl(url) {
    try {
      const u = new URL(url, window.location.href);
      const hostname = u.hostname.toLowerCase();
      for (const cdn of VIDEO_CDN_BYPASS) {
        if (hostname === cdn || hostname.endsWith('.' + cdn)) {
          return true;
        }
      }
      // Also check for video file extensions
      const path = u.pathname.toLowerCase();
      const videoExtensions = ['mp4', 'webm', 'm3u8', 'ts', 'm4s', 'mp3', 'aac', 'ogg', 'wav', 'flac'];
      for (const ext of videoExtensions) {
        if (path.endsWith('.' + ext) || path.includes('.' + ext + '?')) {
          return true;
        }
      }
      // Check for videoplayback in path (YouTube)
      if (path.includes('videoplayback')) {
        return true;
      }
    } catch (e) {}
    return false;
  }
  
  // Check if URL needs tokenization
  function needsTokenization(url) {
    if (!url || typeof url !== 'string') return false;
    const lower = url.toLowerCase().trim();
    if (lower.startsWith('#') || lower.startsWith('data:') || 
        lower.startsWith('blob:') || lower.startsWith('javascript:') ||
        lower.startsWith('mailto:') || lower.startsWith('tel:')) {
      return false;
    }
    // Video CDN URLs must bypass proxy (signed URLs verify IP)
    if (isVideoCdnUrl(url)) {
      console.log('[Gateway] Bypassing proxy for video CDN:', url.substring(0, 80));
      return false;
    }
    // Do not tokenize gateway-internal endpoints or calls back to the
    // gateway itself (avoid tokenizing /tokenize, /go/, /go-ssr/, etc.)
    if (url.includes('/go/') || url.includes('/go-ssr/') || url.includes('/tokenize') || url.startsWith(GATEWAY_BASE)) return false;
    // Don't tokenize if URL already points to gateway
    try {
      const u = new URL(url, window.location.href);
      if (u.pathname.startsWith('/go/') || u.pathname.startsWith('/go-ssr/') || u.pathname.startsWith('/tokenize')) {
        return false;
      }
    } catch (e) {}
    return true;
  }
  
  // Override fetch - with debug logging
  var fetchRequestCount = 0;
  // Use our frozen native fetch reference for the fetch override
  const originalFetch = _gatewayNatives.fetch;
  window.fetch = async function(input, init = {}) {
    let url = typeof input === 'string' ? input : input.url;
    const fetchId = ++fetchRequestCount;
    
    console.log('[Gateway FETCH] [#' + fetchId + ']', {
      url: url ? url.substring(0, 100) : 'undefined',
      needsTokenization: needsTokenization(url),
      method: init.method || 'GET'
    });
    
    if (needsTokenization(url)) {
      // Resolve relative URL against original base if available, otherwise window.location
      const baseForResolve = ORIGINAL_BASE_URL || window.location.href;
      const resolvedUrl = new URL(url, baseForResolve).href;
      url = fixLocalhostUrl(resolvedUrl);
      
      console.log('[Gateway FETCH] [#' + fetchId + '] Resolved URL:', url.substring(0, 100));
      
      const token = await tokenizeUrl(url);
      
      if (token) {
        const newUrl = toGatewayUrl(token);
        console.log('[Gateway FETCH] [#' + fetchId + '] Tokenized to:', newUrl.substring(0, 80));
        
        // Create new init with auth header
        const newInit = { ...init };
        newInit.headers = new Headers(init.headers || {});
        newInit.headers.set('Authorization', 'Bearer ' + SESSION_TOKEN);
        
        if (typeof input === 'string') {
          return _gatewayNatives.fetch.call(this, newUrl, newInit);
        } else {
          return _gatewayNatives.fetch.call(this, new Request(newUrl, input), newInit);
        }
      } else {
        // Tokenization failed - return a fake failed response instead of trying original URL
        // (original URL would fail due to CORS anyway)
        console.error('[Gateway FETCH] [#' + fetchId + '] Tokenization FAILED, returning error response');
        return new Response(JSON.stringify({ error: 'Gateway: tokenization failed', status_code: -1 }), {
          status: 503,
          statusText: 'Gateway Unavailable',
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
    
    return _gatewayNatives.fetch.call(this, input, init);
  };
  
  // Make fetch override non-bypassable using defineProperty
  var _wrappedFetch = window.fetch;
  try {
    Object.defineProperty(window, 'fetch', {
      get: function() { return _wrappedFetch; },
      set: function(val) {
        // Allow other scripts to set fetch, but wrap their version too
        console.log('[Gateway Bootstrap] Script tried to replace fetch, keeping our wrapper');
        // Don't allow overwriting
      },
      configurable: false,
      enumerable: true
    });
  } catch (e) {
    console.warn('[Gateway Bootstrap] Could not lock fetch:', e.message);
  }
  
  // Override XMLHttpRequest using frozen native references
  const originalXHROpen = _gatewayNatives.xhrOpen;
  const originalXHRSend = _gatewayNatives.xhrSend;
  
  XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
    this._gatewayUrl = url;
    this._gatewayMethod = method;
    this._gatewayAsync = async !== false;
    return originalXHROpen.apply(this, arguments);
  };
  
  XMLHttpRequest.prototype.send = async function(body) {
    const xhr = this;
    let url = this._gatewayUrl;
    
    if (needsTokenization(url)) {
      // Resolve relative URL against original base if available
      const baseForResolve = ORIGINAL_BASE_URL || window.location.href;
      url = new URL(url, baseForResolve).href;
      // Fix any localhost URLs
      url = fixLocalhostUrl(url);
      
      const token = await tokenizeUrl(url);
      
      if (token) {
        const newUrl = toGatewayUrl(token);
        originalXHROpen.call(xhr, xhr._gatewayMethod, newUrl, xhr._gatewayAsync);
        xhr.setRequestHeader('Authorization', 'Bearer ' + SESSION_TOKEN);
      }
    }
    
    return originalXHRSend.call(xhr, body);
  };
  
  // Lock XMLHttpRequest.prototype methods to prevent bypassing
  try {
    Object.defineProperty(XMLHttpRequest.prototype, 'open', {
      value: XMLHttpRequest.prototype.open,
      writable: false,
      configurable: false
    });
    Object.defineProperty(XMLHttpRequest.prototype, 'send', {
      value: XMLHttpRequest.prototype.send,
      writable: false,
      configurable: false
    });
  } catch (e) {
    console.warn('[Gateway Bootstrap] Could not lock XHR:', e.message);
  }
  
  // Intercept script element src property to tokenize dynamically loaded scripts
  // This is critical for Next.js and other frameworks that load chunks dynamically
  (function() {
    var originalCreateElement = document.createElement.bind(document);
    var scriptSrcDescriptor = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
    
    if (scriptSrcDescriptor && scriptSrcDescriptor.set) {
      var originalSrcSetter = scriptSrcDescriptor.set;
      
      Object.defineProperty(HTMLScriptElement.prototype, 'src', {
        get: scriptSrcDescriptor.get,
        set: function(value) {
          if (value && needsTokenization(value)) {
            var baseForResolve = ORIGINAL_BASE_URL || window.location.href;
            var resolvedUrl = new URL(value, baseForResolve).href;
            resolvedUrl = fixLocalhostUrl(resolvedUrl);
            
            console.log('[Gateway] Intercepting script src:', resolvedUrl.substring(0, 80));
            
            // Tokenize and set
            var script = this;
            tokenizeUrl(resolvedUrl).then(function(token) {
              if (token) {
                originalSrcSetter.call(script, toGatewayUrl(token));
              } else {
                console.warn('[Gateway] Script tokenization failed for:', resolvedUrl.substring(0, 80));
                // Don't set src if tokenization failed - would 404 anyway
              }
            });
            return;
          }
          originalSrcSetter.call(this, value);
        },
        configurable: true,
        enumerable: true
      });
    }
  })();
  
  // Intercept link clicks
  document.addEventListener('click', async function(e) {
    const link = e.target.closest('a[href]');
    if (!link) return;
    
    const href = link.getAttribute('href');
    if (!needsTokenization(href)) return;
    
    // Already handled by server-side rewriting in most cases
    // This is a fallback for dynamically added links
    if (!href.includes('/go/')) {
      e.preventDefault();
      e.stopPropagation();
      
      // Resolve relative URL against original base if available
      const baseForResolve = ORIGINAL_BASE_URL || window.location.href;
      let resolvedUrl = new URL(href, baseForResolve).href;
      resolvedUrl = fixLocalhostUrl(resolvedUrl);
      
      const token = await tokenizeUrl(resolvedUrl);
      
      if (token) {
        const targetUrl = toGatewayUrl(token);
        // Preserve target attribute
        if (link.target === '_blank') {
          window.open(targetUrl, '_blank');
        } else {
          // Use top-level navigation to avoid nested proxy scenarios
          // when running inside an iframe or sandbox context
          try {
            if (window.top && window.top !== window) {
              window.top.location.href = targetUrl;
            } else {
              window.location.href = targetUrl;
            }
          } catch (crossOriginErr) {
            // If cross-origin, just navigate current window
            window.location.href = targetUrl;
          }
        }
      }
    }
  }, true);
  
  // Intercept form submissions
  document.addEventListener('submit', async function(e) {
    const form = e.target;
    const action = form.getAttribute('action');
    
    if (action && needsTokenization(action) && !action.includes('/go/')) {
      e.preventDefault();
      
      // Resolve relative URL against original base if available
      const baseForResolve = ORIGINAL_BASE_URL || window.location.href;
      let resolvedUrl = new URL(action, baseForResolve).href;
      resolvedUrl = fixLocalhostUrl(resolvedUrl);
      
      const token = await tokenizeUrl(resolvedUrl);
      
      if (token) {
        form.setAttribute('action', toGatewayUrl(token));
        // Re-submit
        form.submit();
      }
    }
  }, true);
  
  // Override window.open to tokenize URLs
  const originalWindowOpen = window.open;
  window.open = async function(url, target, features) {
    if (url && needsTokenization(url)) {
      const resolvedUrl = new URL(url, window.location.href).href;
      const token = await tokenizeUrl(resolvedUrl);
      if (token) {
        return originalWindowOpen.call(window, toGatewayUrl(token), target, features);
      }
    }
    return originalWindowOpen.call(window, url, target, features);
  };
  
  // Handle dynamically added scripts and iframes
  const observer = new MutationObserver(function(mutations) {
    mutations.forEach(function(mutation) {
      mutation.addedNodes.forEach(function(node) {
        if (node.nodeType !== 1) return;
        
        // Handle dynamically added scripts
        if (node.tagName === 'SCRIPT' && node.src && needsTokenization(node.src)) {
          const resolvedUrl = new URL(node.src, window.location.href).href;
          tokenizeUrl(resolvedUrl).then(function(token) {
            if (token) {
              node.src = toGatewayUrl(token);
            }
          });
        }
        
        // Handle dynamically added iframes
        if (node.tagName === 'IFRAME' && node.src && needsTokenization(node.src)) {
          const resolvedUrl = new URL(node.src, window.location.href).href;
          tokenizeUrl(resolvedUrl).then(function(token) {
            if (token) {
              node.src = toGatewayUrl(token);
            }
          });
        }
      });
    });
  });
  
  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  } else {
    document.addEventListener('DOMContentLoaded', function() {
      observer.observe(document.body, { childList: true, subtree: true });
    });
  }
  
  console.log('[Gateway] Bootstrap loaded');
})();
</script>
`;
}

/**
 * Rewrite HTML content
 * @param {string} html - The HTML content to rewrite
 * @param {string} baseUrl - The base URL for resolving relative URLs
 * @param {Function} tokenizeUrlSync - Synchronous function to tokenize a URL
 * @param {Object} options - Options
 * @param {string} options.gatewayBase - Base URL of the gateway
 * @param {string} options.sessionToken - Session token for auth
 * @returns {string} - Rewritten HTML
 */
function rewriteHtml(html, baseUrl, tokenizeUrlSync, options = {}) {
  const { gatewayBase, sessionToken } = options;
  
  const $ = cheerio.load(html, {
    decodeEntities: false,
    xmlMode: false
  });
  
  // Track if we found a <head> tag
  let hasHead = $('head').length > 0;
  
  // Fix iframe sandbox attributes to prevent script blocking
  $('iframe').each((i, elem) => {
    const $elem = $(elem);
    const sandbox = $elem.attr('sandbox');
    // If sandbox exists but doesn't have allow-scripts, add necessary permissions
    // to prevent "Blocked script execution" errors in proxied content
    if (sandbox !== undefined) {
      const permissions = sandbox.split(/\s+/).filter(Boolean);
      const neededPerms = ['allow-scripts', 'allow-same-origin', 'allow-forms', 'allow-popups'];
      let modified = false;
      for (const perm of neededPerms) {
        if (!permissions.includes(perm)) {
          permissions.push(perm);
          modified = true;
        }
      }
      if (modified) {
        $elem.attr('sandbox', permissions.join(' '));
      }
    }
  });

  // Rewrite URL attributes
  for (const [tag, attrs] of Object.entries(URL_ATTRIBUTES)) {
    $(tag).each((i, elem) => {
      const $elem = $(elem);
      
      for (const attr of attrs) {
        const value = $elem.attr(attr);
        if (!value) continue;
        
        // Handle srcset specially
        if (attr === 'srcset') {
          const rewritten = parseSrcset(value, baseUrl, tokenizeUrlSync);
          if (rewritten !== value) {
            $elem.attr(attr, rewritten);
          }
          continue;
        }
        
        // Skip passthrough URLs (check original value for schemes like mailto:, data:, etc.)
        if (shouldPassthrough(value)) continue;
        
        // Extract and preserve hash fragment
        let urlPart = value;
        let hashPart = '';
        const hashIndex = value.indexOf('#');
        if (hashIndex !== -1) {
          urlPart = value.substring(0, hashIndex);
          hashPart = value.substring(hashIndex);
        }
        
        // Resolve relative URL
        const resolved = resolveUrl(urlPart, baseUrl);
        if (!resolved) continue;
        
        // Skip video CDN URLs after resolution (they may have been relative)
        if (isVideoCdnUrl(resolved)) continue;
        
        // Tokenize
        const tokenized = tokenizeUrlSync(resolved);
        if (tokenized) {
          $elem.attr(attr, tokenized + hashPart);
        }
      }
    });
  }
  
  // Rewrite inline styles
  $('[style]').each((i, elem) => {
    const $elem = $(elem);
    const style = $elem.attr('style');
    const rewritten = rewriteStyleUrls(style, baseUrl, tokenizeUrlSync);
    if (rewritten !== style) {
      $elem.attr('style', rewritten);
    }
  });
  
  // Rewrite <style> tags
  $('style').each((i, elem) => {
    const $elem = $(elem);
    const css = $elem.html();
    const rewritten = rewriteStyleUrls(css, baseUrl, tokenizeUrlSync);
    if (rewritten !== css) {
      $elem.html(rewritten);
    }
  });
  
  // Inject bootstrap script into <head>
  if (gatewayBase && sessionToken) {
    const bootstrapScript = generateBootstrapScript(
      gatewayBase, 
      sessionToken, 
      options && options.pageToken ? options.pageToken : null,
      { originalBaseUrl: baseUrl }  // Pass the original page URL
    );
    
    if (hasHead) {
      $('head').prepend(bootstrapScript);
    } else {
      // No head tag, prepend to body or html
      const $body = $('body');
      if ($body.length) {
        $body.prepend(bootstrapScript);
      } else {
        $.root().prepend(bootstrapScript);
      }
    }
  }
  
  return $.html();
}

/**
 * Check if content type is HTML
 */
function isHtmlContentType(contentType) {
  if (!contentType) return false;
  const lower = contentType.toLowerCase();
  return lower.includes('text/html') || lower.includes('application/xhtml');
}

module.exports = {
  rewriteHtml,
  rewriteStyleUrls,
  isHtmlContentType,
  resolveUrl,
  shouldPassthrough,
  generateBootstrapScript
};
