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

// Video/media CDN domains - NOW PROXIED for full encryption
// Previously these were bypassed, but that exposed video traffic.
// With server-side Playwright fetching pages, video URLs are signed for
// the SERVER's IP, so proxying them through works and keeps all traffic encrypted.
const VIDEO_CDN_BYPASS = [
  // DISABLED - We now proxy everything for full encryption
  // Videos work because Playwright fetches pages and gets URLs signed for server IP
];

/**
 * Check if URL is a video/media CDN that should bypass proxy
 * NOTE: Now returns false for everything - we proxy ALL content for full encryption
 */
function isVideoCdnUrl(url) {
  // DISABLED - All content now goes through proxy for full encryption
  // The proxy server streams video content, keeping it hidden from network observers
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
        // Copy methods - but INTERCEPT assign and replace to tokenize URLs!
        var _origAssign = _originalLocation.assign.bind(_originalLocation);
        var _origReplace = _originalLocation.replace.bind(_originalLocation);
        
        locationProxy.assign = function(url) {
          console.log('[Gateway Bootstrap] location.assign intercepted:', url);
          handleLocationNavigation(url, _origAssign);
        };
        locationProxy.replace = function(url) {
          console.log('[Gateway Bootstrap] location.replace intercepted:', url);
          handleLocationNavigation(url, _origReplace);
        };
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
  
  // Helper function to handle location navigations (assign, replace, href setter)
  // This MUST be defined early but uses tokenizeUrl which is defined later
  // So we set up a deferred handler
  var _pendingLocationNavs = [];
  var _locationNavReady = false;
  
  function handleLocationNavigation(url, originalMethod) {
    console.log('[Gateway Bootstrap] handleLocationNavigation called:', url?.substring?.(0, 100) || url);
    
    // If url is empty/null, just navigate
    if (!url) {
      originalMethod(url);
      return;
    }
    
    // Convert to string if needed
    url = String(url);
    
    // If it's a hash-only change, allow it
    if (url.startsWith('#')) {
      originalMethod(url);
      return;
    }
    
    // If already a gateway URL, allow it
    if (url.includes('/go/') || url.includes('/go-ssr/')) {
      console.log('[Gateway Bootstrap] Location nav already tokenized, allowing');
      originalMethod(url);
      return;
    }
    
    // Check if tokenizeUrl is ready
    if (!_locationNavReady) {
      console.log('[Gateway Bootstrap] Queuing location nav until ready');
      _pendingLocationNavs.push({ url: url, method: originalMethod });
      return;
    }
    
    // Resolve relative URL against original base
    var baseForResolve = ORIGINAL_BASE_URL || window._gatewayOriginalUrl || 'about:blank';
    var resolvedUrl;
    try {
      resolvedUrl = new URL(url, baseForResolve).href;
    } catch (e) {
      console.warn('[Gateway Bootstrap] Could not resolve location URL:', url);
      originalMethod(url);
      return;
    }
    
    console.log('[Gateway Bootstrap] Location nav resolved to:', resolvedUrl?.substring(0, 100));
    
    // Tokenize and navigate
    tokenizeUrl(resolvedUrl).then(function(token) {
      if (token) {
        var gatewayUrl = GATEWAY_BASE + '/go/' + token;
        console.log('[Gateway Bootstrap] Location nav tokenized, navigating to:', gatewayUrl);
        originalMethod(gatewayUrl);
      } else {
        console.error('[Gateway Bootstrap] Location nav tokenization failed, navigating anyway:', resolvedUrl);
        // Navigate to original - will likely 404 but better than nothing
        originalMethod(resolvedUrl);
      }
    }).catch(function(err) {
      console.error('[Gateway Bootstrap] Location nav error:', err);
      originalMethod(resolvedUrl);
    });
  }
  
  // Intercept direct window.location.href assignments
  // This is tricky because we can't override window.location itself
  // But we CAN intercept when code does: location.href = 'url' or location = 'url'
  (function() {
    // Store original location for later use
    var origLocation = window.location;
    var origHref = Object.getOwnPropertyDescriptor(window.Location.prototype, 'href');
    
    if (origHref && origHref.set) {
      Object.defineProperty(window.Location.prototype, 'href', {
        get: origHref.get,
        set: function(value) {
          console.log('[Gateway Bootstrap] location.href setter intercepted:', value?.substring?.(0, 100) || value);
          
          // If it's already a gateway URL (including SSR) or hash change, allow it
          if (!value || String(value).startsWith('#') || String(value).includes('/go/') || String(value).includes('/go-ssr/')) {
            return origHref.set.call(this, value);
          }
          
          // Otherwise tokenize and navigate
          handleLocationNavigation(value, function(url) {
            origHref.set.call(origLocation, url);
          });
        },
        configurable: true,
        enumerable: true
      });
      console.log('[Gateway Bootstrap] location.href setter override installed');
    } else {
      console.warn('[Gateway Bootstrap] Could not override location.href - origHref.set not available');
    }
    
    // Also intercept Location.prototype.assign and replace
    var origAssign = window.Location.prototype.assign;
    var origReplace = window.Location.prototype.replace;
    
    window.Location.prototype.assign = function(url) {
      console.log('[Gateway Bootstrap] Location.prototype.assign intercepted:', url);
      handleLocationNavigation(url, origAssign.bind(origLocation));
    };
    
    window.Location.prototype.replace = function(url) {
      console.log('[Gateway Bootstrap] Location.prototype.replace intercepted:', url);
      handleLocationNavigation(url, origReplace.bind(origLocation));
    };
    
    console.log('[Gateway Bootstrap] Location navigation interception installed');
  })();
  
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
  
  // Store page token in cookie for catch-all fallback recovery
  if (PAGE_TOKEN) {
    try {
      document.cookie = 'gatewayToken=' + PAGE_TOKEN + '; path=/; SameSite=Lax';
    } catch (e) {}
  }
  
  // Debug logging helper - COMPREHENSIVE MODE
  const DEBUG_BOOTSTRAP = true;
  const DEBUG_VERBOSE = true; // Set to true for extra verbose logging
  function debugLog(...args) {
    if (DEBUG_BOOTSTRAP) console.log('[Gateway Bootstrap]', ...args);
  }
  function debugError(...args) {
    console.error('[Gateway Bootstrap] ❌', ...args);
  }
  function debugWarn(...args) {
    console.warn('[Gateway Bootstrap] ⚠️', ...args);
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
  
  // Mark location navigation as ready and process any pending navigations
  _locationNavReady = true;
  if (_pendingLocationNavs.length > 0) {
    console.log('[Gateway Bootstrap] Processing', _pendingLocationNavs.length, 'pending location navigations');
    _pendingLocationNavs.forEach(function(nav) {
      handleLocationNavigation(nav.url, nav.method);
    });
    _pendingLocationNavs = [];
  }
  
  // Convert URL to gateway path
  function toGatewayUrl(token) {
    return GATEWAY_BASE + '/go/' + token;
  }
  
  // Video/media CDN domains - NOW PROXIED for full encryption
  // Previously bypassed, but now we proxy everything so all traffic is encrypted
  const VIDEO_CDN_BYPASS = [
    // DISABLED - All video/media now goes through proxy for full encryption
    // Videos work because Playwright fetches pages server-side, getting URLs
    // signed for the server's IP which can then fetch and stream the content
  ];
  
  // Check if URL is a video/media CDN that should bypass proxy
  // NOTE: Now returns false - everything is proxied for encryption
  function isVideoCdnUrl(url) {
    // DISABLED - All content now proxied for full encryption
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
    // Video/media CDNs are NOW tokenized and proxied for full encryption
    // The isVideoCdnUrl function now returns false, so all videos go through proxy
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
        debugError('[#' + fetchId + '] Tokenization FAILED for URL:', url.substring(0, 100));
        debugError('[#' + fetchId + '] Possible causes: Server not reachable, invalid URL, rate limiting');
        debugError('[#' + fetchId + '] Gateway base:', GATEWAY_BASE);
        debugError('[#' + fetchId + '] Session token present:', !!SESSION_TOKEN);
        debugError('[#' + fetchId + '] Page token present:', !!PAGE_TOKEN);
        return new Response(JSON.stringify({ 
          error: 'Gateway: tokenization failed', 
          status_code: -1,
          details: 'Could not obtain token for URL: ' + url.substring(0, 100),
          hint: 'Check browser console and server logs for more details'
        }), {
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
  
  XMLHttpRequest.prototype.send = function(body) {
    const xhr = this;
    let url = this._gatewayUrl;
    
    if (needsTokenization(url)) {
      // Resolve relative URL against original base if available
      const baseForResolve = ORIGINAL_BASE_URL || window.location.href;
      url = new URL(url, baseForResolve).href;
      // Fix any localhost URLs
      url = fixLocalhostUrl(url);
      
      // Use async IIFE to tokenize without making send async
      (async function() {
        try {
          const token = await tokenizeUrl(url);
          if (token) {
            const newUrl = toGatewayUrl(token);
            originalXHROpen.call(xhr, xhr._gatewayMethod, newUrl, xhr._gatewayAsync);
            xhr.setRequestHeader('Authorization', 'Bearer ' + SESSION_TOKEN);
          }
          originalXHRSend.call(xhr, body);
        } catch (err) {
          console.warn('[Gateway] XHR tokenization failed:', err);
          originalXHRSend.call(xhr, body);
        }
      })();
      return; // Return undefined synchronously as expected
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
  
  // Intercept video src property for dynamic video URLs (TikTok, etc.)
  (function() {
    var videoSrcDescriptor = Object.getOwnPropertyDescriptor(HTMLVideoElement.prototype, 'src');
    
    if (videoSrcDescriptor && videoSrcDescriptor.set) {
      var originalVideoSrcSetter = videoSrcDescriptor.set;
      
      Object.defineProperty(HTMLVideoElement.prototype, 'src', {
        get: videoSrcDescriptor.get,
        set: function(value) {
          if (value && needsTokenization(value)) {
            var baseForResolve = ORIGINAL_BASE_URL || window.location.href;
            var resolvedUrl = new URL(value, baseForResolve).href;
            resolvedUrl = fixLocalhostUrl(resolvedUrl);
            
            console.log('[Gateway] Intercepting video src:', resolvedUrl.substring(0, 80));
            
            // Tokenize and set
            var video = this;
            tokenizeUrl(resolvedUrl).then(function(token) {
              if (token) {
                originalVideoSrcSetter.call(video, toGatewayUrl(token));
              } else {
                console.warn('[Gateway] Video tokenization failed for:', resolvedUrl.substring(0, 80));
                // Set original URL as fallback
                originalVideoSrcSetter.call(video, value);
              }
            }).catch(function(err) {
              console.warn('[Gateway] Video tokenization error:', err);
              originalVideoSrcSetter.call(video, value);
            });
            return;
          }
          originalVideoSrcSetter.call(this, value);
        },
        configurable: true,
        enumerable: true
      });
    }
  })();
  
  // Intercept audio src property
  (function() {
    var audioSrcDescriptor = Object.getOwnPropertyDescriptor(HTMLAudioElement.prototype, 'src');
    
    if (audioSrcDescriptor && audioSrcDescriptor.set) {
      var originalAudioSrcSetter = audioSrcDescriptor.set;
      
      Object.defineProperty(HTMLAudioElement.prototype, 'src', {
        get: audioSrcDescriptor.get,
        set: function(value) {
          if (value && needsTokenization(value)) {
            var baseForResolve = ORIGINAL_BASE_URL || window.location.href;
            var resolvedUrl = new URL(value, baseForResolve).href;
            resolvedUrl = fixLocalhostUrl(resolvedUrl);
            
            console.log('[Gateway] Intercepting audio src:', resolvedUrl.substring(0, 80));
            
            var audio = this;
            tokenizeUrl(resolvedUrl).then(function(token) {
              if (token) {
                originalAudioSrcSetter.call(audio, toGatewayUrl(token));
              } else {
                originalAudioSrcSetter.call(audio, value);
              }
            }).catch(function() {
              originalAudioSrcSetter.call(audio, value);
            });
            return;
          }
          originalAudioSrcSetter.call(this, value);
        },
        configurable: true,
        enumerable: true
      });
    }
  })();
  
  // Intercept source element src property (for <source> inside <video>/<audio>)
  (function() {
    var sourceSrcDescriptor = Object.getOwnPropertyDescriptor(HTMLSourceElement.prototype, 'src');
    
    if (sourceSrcDescriptor && sourceSrcDescriptor.set) {
      var originalSourceSrcSetter = sourceSrcDescriptor.set;
      
      Object.defineProperty(HTMLSourceElement.prototype, 'src', {
        get: sourceSrcDescriptor.get,
        set: function(value) {
          if (value && needsTokenization(value)) {
            var baseForResolve = ORIGINAL_BASE_URL || window.location.href;
            var resolvedUrl = new URL(value, baseForResolve).href;
            resolvedUrl = fixLocalhostUrl(resolvedUrl);
            
            console.log('[Gateway] Intercepting source src:', resolvedUrl.substring(0, 80));
            
            var source = this;
            tokenizeUrl(resolvedUrl).then(function(token) {
              if (token) {
                originalSourceSrcSetter.call(source, toGatewayUrl(token));
                // Reload parent media element
                var parent = source.parentElement;
                if (parent && (parent.tagName === 'VIDEO' || parent.tagName === 'AUDIO')) {
                  parent.load();
                }
              } else {
                originalSourceSrcSetter.call(source, value);
              }
            }).catch(function() {
              originalSourceSrcSetter.call(source, value);
            });
            return;
          }
          originalSourceSrcSetter.call(this, value);
        },
        configurable: true,
        enumerable: true
      });
    }
  })();
  
  // Intercept setAttribute for video/audio/source elements
  (function() {
    var originalSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {
      var lowerName = name.toLowerCase();
      
      // Check if setting src on video/audio/source elements
      if (lowerName === 'src' && value && needsTokenization(value)) {
        var tagName = this.tagName;
        if (tagName === 'VIDEO' || tagName === 'AUDIO' || tagName === 'SOURCE' || 
            tagName === 'SCRIPT' || tagName === 'IFRAME' || tagName === 'IMG') {
          var baseForResolve = ORIGINAL_BASE_URL || window.location.href;
          var resolvedUrl = new URL(value, baseForResolve).href;
          resolvedUrl = fixLocalhostUrl(resolvedUrl);
          
          console.log('[Gateway] Intercepting setAttribute src on ' + tagName + ':', resolvedUrl.substring(0, 80));
          
          var elem = this;
          tokenizeUrl(resolvedUrl).then(function(token) {
            if (token) {
              originalSetAttribute.call(elem, name, toGatewayUrl(token));
              // Reload parent media element if source
              if (tagName === 'SOURCE') {
                var parent = elem.parentElement;
                if (parent && (parent.tagName === 'VIDEO' || parent.tagName === 'AUDIO')) {
                  parent.load();
                }
              }
            } else {
              originalSetAttribute.call(elem, name, value);
            }
          }).catch(function() {
            originalSetAttribute.call(elem, name, value);
          });
          return;
        }
      }
      
      // Check if setting poster on video elements
      if (lowerName === 'poster' && value && needsTokenization(value) && this.tagName === 'VIDEO') {
        var baseForResolve = ORIGINAL_BASE_URL || window.location.href;
        var resolvedUrl = new URL(value, baseForResolve).href;
        resolvedUrl = fixLocalhostUrl(resolvedUrl);
        
        var elem = this;
        tokenizeUrl(resolvedUrl).then(function(token) {
          if (token) {
            originalSetAttribute.call(elem, name, toGatewayUrl(token));
          } else {
            originalSetAttribute.call(elem, name, value);
          }
        }).catch(function() {
          originalSetAttribute.call(elem, name, value);
        });
        return;
      }
      
      return originalSetAttribute.call(this, name, value);
    };
  })();
  
  // ============================================================================
  // Safari/iOS Compatibility
  // ============================================================================
  
  // Detect Safari/iOS
  var isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
  var isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || 
              (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  
  console.log('[Gateway] Browser detection - Safari:', isSafari, 'iOS:', isIOS);
  
  // Safari doesn't support MediaSource Extensions well - intercept and handle
  if (isIOS || isSafari) {
    // For iOS Safari, we need to ensure videos are set up correctly
    // iOS requires user interaction to play videos, so we track interaction state
    var hasUserInteracted = false;
    
    document.addEventListener('touchstart', function() {
      hasUserInteracted = true;
    }, { once: true, passive: true });
    
    document.addEventListener('click', function() {
      hasUserInteracted = true;
    }, { once: true, passive: true });
    
    // Ensure all video elements have required iOS attributes
    function setupVideoForIOS(video) {
      if (!video || video._iosSetup) return;
      video._iosSetup = true;
      
      // Required for inline playback on iOS
      video.setAttribute('playsinline', '');
      video.setAttribute('webkit-playsinline', '');
      
      // CORS setup
      if (!video.hasAttribute('crossorigin')) {
        video.setAttribute('crossorigin', 'anonymous');
      }
      
      // If autoplay is set, ensure muted for iOS autoplay policy
      if (video.hasAttribute('autoplay')) {
        video.muted = true;
      }
      
      console.log('[Gateway iOS] Video configured for iOS playback');
    }
    
    // Apply to all existing videos
    document.querySelectorAll('video').forEach(setupVideoForIOS);
    
    // Watch for new videos
    var videoObserver = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {
        mutation.addedNodes.forEach(function(node) {
          if (node.nodeType === 1) {
            if (node.tagName === 'VIDEO') {
              setupVideoForIOS(node);
            }
            // Also check descendants
            if (node.querySelectorAll) {
              node.querySelectorAll('video').forEach(setupVideoForIOS);
            }
          }
        });
      });
    });
    
    if (document.body) {
      videoObserver.observe(document.body, { childList: true, subtree: true });
    } else {
      document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('video').forEach(setupVideoForIOS);
        videoObserver.observe(document.body, { childList: true, subtree: true });
      });
    }
  }
  
  // Intercept blob URL creation to track video blobs
  (function() {
    var originalCreateObjectURL = URL.createObjectURL;
    var originalRevokeObjectURL = URL.revokeObjectURL;
    var blobUrlMap = new Map();
    
    URL.createObjectURL = function(blob) {
      var url = originalCreateObjectURL.call(URL, blob);
      
      // Track blob URLs for debugging
      if (blob && blob.type && blob.type.startsWith('video/')) {
        console.log('[Gateway] Video blob URL created:', url, 'type:', blob.type, 'size:', blob.size);
        blobUrlMap.set(url, { type: blob.type, size: blob.size });
      }
      
      return url;
    };
    
    URL.revokeObjectURL = function(url) {
      if (blobUrlMap.has(url)) {
        console.log('[Gateway] Video blob URL revoked:', url);
        blobUrlMap.delete(url);
      }
      return originalRevokeObjectURL.call(URL, url);
    };
  })();
  
  // ============================================================================
  // Click and Touch Event Handling
  // ============================================================================
  
  // Helper function to handle link navigation (shared between click and touch)
  async function handleLinkNavigation(link, e) {
    const href = link.getAttribute('href');
    
    debugLog('[NAV] Link activated:', {
      href: href?.substring(0, 100),
      needsTokenization: needsTokenization(href),
      alreadyHasGo: href?.includes('/go/'),
      target: link.target || 'none'
    });
    
    if (!needsTokenization(href)) {
      debugLog('[NAV] Skipping - does not need tokenization');
      return false; // Don't prevent default
    }
    
    // Already handled by server-side rewriting in most cases
    if (!href.includes('/go/')) {
      debugLog('[NAV] Intercepting - needs tokenization');
      e.preventDefault();
      e.stopPropagation();
      
      // Resolve relative URL against original base if available
      const baseForResolve = ORIGINAL_BASE_URL || window.location.href;
      let resolvedUrl;
      try {
        resolvedUrl = new URL(href, baseForResolve).href;
        resolvedUrl = fixLocalhostUrl(resolvedUrl);
      } catch (urlErr) {
        debugError('[NAV] URL resolution failed:', urlErr.message, { href, baseForResolve });
        return true; // Prevented
      }
      
      debugLog('[NAV] Resolved URL:', resolvedUrl?.substring(0, 100));
      
      const token = await tokenizeUrl(resolvedUrl);
      
      if (token) {
        const targetUrl = toGatewayUrl(token);
        debugLog('[NAV] Navigating to tokenized URL:', targetUrl);
        // Preserve target attribute
        if (link.target === '_blank') {
          window.open(targetUrl, '_blank');
        } else {
          try {
            if (window.top && window.top !== window) {
              window.top.location.href = targetUrl;
            } else {
              window.location.href = targetUrl;
            }
          } catch (crossOriginErr) {
            window.location.href = targetUrl;
          }
        }
      } else {
        debugError('[NAV] Tokenization failed for:', resolvedUrl?.substring(0, 100));
      }
      return true; // Prevented
    }
    
    debugLog('[NAV] Link already has /go/ token, allowing default');
    return false; // Don't prevent default
  }
  
  // Touch event handling for Safari/iOS (fires before click on touch devices)
  // This is important because Safari can have 300ms click delay
  var touchHandledLinks = new WeakSet();
  
  document.addEventListener('touchend', async function(e) {
    // Only handle single-finger taps
    if (e.changedTouches.length !== 1) return;
    
    const touch = e.changedTouches[0];
    const target = document.elementFromPoint(touch.clientX, touch.clientY);
    if (!target) return;
    
    const link = target.closest('a[href]');
    if (!link) return;
    
    // Mark this link as handled by touch to avoid double-handling in click
    touchHandledLinks.add(link);
    
    // Handle the navigation
    const prevented = await handleLinkNavigation(link, e);
    
    // Clear the marker after a short delay
    setTimeout(function() {
      touchHandledLinks.delete(link);
    }, 500);
  }, { passive: false, capture: true });
  
  // Intercept link clicks (desktop and as fallback)
  document.addEventListener('click', async function(e) {
    const link = e.target.closest('a[href]');
    if (!link) return;
    
    // Skip if already handled by touch event
    if (touchHandledLinks.has(link)) {
      debugLog('[CLICK] Skipping - already handled by touch');
      e.preventDefault();
      return;
    }
    
    await handleLinkNavigation(link, e);
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
        // Re-submit using original submit to avoid infinite loop
        originalFormSubmit.call(form);
      }
    }
  }, true);
  
  // Override HTMLFormElement.prototype.submit to intercept programmatic form submissions
  // 
  // IMPORTANT: Async behavior note
  // -----------------------------
  // This override makes form.submit() behave asynchronously when the form action
  // requires tokenization. Code calling form.submit() will return BEFORE the form
  // is actually submitted. This differs from the standard synchronous behavior.
  // 
  // This is an unavoidable constraint because:
  // 1. HTMLFormElement.prototype.submit cannot return a Promise (API contract)
  // 2. URL tokenization requires an async fetch to the gateway server
  // 
  // Security note: On tokenization failure, we intentionally BLOCK submission
  // rather than falling back to the untokenized URL, which would bypass the proxy.
  //
  var originalFormSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function() {
    var form = this;
    var action = form.getAttribute('action') || form.action || '';
    
    console.log('[Gateway Bootstrap] Form.submit() intercepted:', action?.substring?.(0, 100) || action);
    
    if (action && needsTokenization(action) && !String(action).includes('/go/') && !String(action).includes('/go-ssr/')) {
      // Resolve relative URL against original base if available
      var baseForResolve = ORIGINAL_BASE_URL || window.location.href;
      var resolvedUrl;
      try {
        resolvedUrl = new URL(action, baseForResolve).href;
        resolvedUrl = fixLocalhostUrl(resolvedUrl);
      } catch (e) {
        console.warn('[Gateway Bootstrap] Form action URL parse failed:', e.message);
        // Block submission on parse failure - don't bypass proxy
        showFormSubmissionError(form, 'Invalid form action URL');
        return;
      }
      
      console.log('[Gateway Bootstrap] Form.submit() tokenizing:', resolvedUrl?.substring(0, 100));
      
      // Tokenize and then submit
      tokenizeUrl(resolvedUrl).then(function(token) {
        if (token) {
          form.setAttribute('action', toGatewayUrl(token));
          console.log('[Gateway Bootstrap] Form.submit() navigating to tokenized:', toGatewayUrl(token));
          originalFormSubmit.call(form);
        } else {
          // SECURITY: Block submission on tokenization failure
          // Submitting with untokenized URL would bypass the proxy entirely
          console.error('[Gateway Bootstrap] Form.submit() BLOCKED - tokenization failed for:', resolvedUrl?.substring(0, 100));
          showFormSubmissionError(form, 'Form submission failed - please try again');
        }
      }).catch(function(err) {
        // SECURITY: Block submission on error - don't bypass proxy
        console.error('[Gateway Bootstrap] Form.submit() BLOCKED - tokenization error:', err);
        showFormSubmissionError(form, 'Form submission failed - please try again');
      });
      return; // Don't submit yet, wait for tokenization (async behavior)
    }
    
    return originalFormSubmit.call(form);
  };
  
  // Helper to show user-visible error when form submission is blocked
  function showFormSubmissionError(form, message) {
    // Try to find or create an error display element
    var errorId = 'gateway-form-error-' + Math.random().toString(36).substring(2, 11);
    var errorEl = document.createElement('div');
    errorEl.id = errorId;
    errorEl.style.cssText = 'background:#fee;border:1px solid #c00;color:#c00;padding:10px;margin:10px 0;border-radius:4px;font-family:sans-serif;';
    errorEl.textContent = message;
    
    // Insert error message before the form or append to body as fallback
    try {
      if (form.parentNode) {
        form.parentNode.insertBefore(errorEl, form);
      } else if (document && document.body) {
        document.body.appendChild(errorEl);
      } else if (document && document.documentElement) {
        document.documentElement.appendChild(errorEl);
      } else {
        throw new Error('No valid DOM container available');
      }
      // Auto-remove after 5 seconds
      setTimeout(function() {
        var el = document.getElementById(errorId);
        if (el && el.parentNode) {
          el.parentNode.removeChild(el);
        }
      }, 5000);
    } catch (e) {
      // Fallback to alert if DOM manipulation fails
      console.error('[Gateway Bootstrap] Could not display form error:', e);
      alert('Form submission failed: ' + message);
    }
  }
  
  // Override window.open to tokenize URLs (synchronous to return Window immediately)
  const originalWindowOpen = window.open;
  window.open = function(url, target, features) {
    if (url && needsTokenization(url)) {
      // Try to parse URL before opening popup to avoid orphaned windows on malformed URLs
      let resolvedUrl;
      try {
        resolvedUrl = new URL(url, window.location.href).href;
      } catch (parseErr) {
        console.warn('[Gateway] window.open URL parse failed:', parseErr.message, url?.substring?.(0, 100));
        // Fall back to original behavior for malformed URLs
        return originalWindowOpen.call(window, url, target, features);
      }
      
      // URL parsed successfully, now open about:blank to return a Window synchronously
      const popup = originalWindowOpen.call(window, 'about:blank', target, features);
      // Asynchronously tokenize and navigate
      tokenizeUrl(resolvedUrl).then(function(token) {
        if (token && popup && !popup.closed) {
          popup.location.href = toGatewayUrl(token);
        } else if (popup && !popup.closed) {
          // Fallback: navigate to original URL if tokenization failed
          popup.location.href = url;
        }
      }).catch(function(err) {
        console.warn('[Gateway] window.open tokenization failed:', err);
        if (popup && !popup.closed) {
          popup.location.href = url;
        }
      });
      return popup;
    }
    return originalWindowOpen.call(window, url, target, features);
  };
  
  // Handle dynamically added scripts, iframes, videos, and source elements
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
        
        // Handle dynamically added video elements
        if (node.tagName === 'VIDEO' && node.src && needsTokenization(node.src)) {
          const resolvedUrl = new URL(node.src, window.location.href).href;
          console.log('[Gateway] MutationObserver: video src detected:', resolvedUrl.substring(0, 80));
          tokenizeUrl(resolvedUrl).then(function(token) {
            if (token) {
              node.src = toGatewayUrl(token);
            }
          });
        }
        
        // Handle dynamically added audio elements
        if (node.tagName === 'AUDIO' && node.src && needsTokenization(node.src)) {
          const resolvedUrl = new URL(node.src, window.location.href).href;
          tokenizeUrl(resolvedUrl).then(function(token) {
            if (token) {
              node.src = toGatewayUrl(token);
            }
          });
        }
        
        // Handle dynamically added source elements (inside video/audio)
        if (node.tagName === 'SOURCE' && node.src && needsTokenization(node.src)) {
          const resolvedUrl = new URL(node.src, window.location.href).href;
          console.log('[Gateway] MutationObserver: source src detected:', resolvedUrl.substring(0, 80));
          tokenizeUrl(resolvedUrl).then(function(token) {
            if (token) {
              node.src = toGatewayUrl(token);
              // Reload parent media element
              var parent = node.parentElement;
              if (parent && (parent.tagName === 'VIDEO' || parent.tagName === 'AUDIO')) {
                parent.load();
              }
            }
          });
        }
        
        // Also check for source children inside newly added video/audio elements
        if (node.tagName === 'VIDEO' || node.tagName === 'AUDIO') {
          var sources = node.querySelectorAll('source[src]');
          sources.forEach(function(source) {
            if (needsTokenization(source.src)) {
              const resolvedUrl = new URL(source.src, window.location.href).href;
              tokenizeUrl(resolvedUrl).then(function(token) {
                if (token) {
                  source.src = toGatewayUrl(token);
                  node.load();
                }
              });
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
  
  // Add Safari/iOS video compatibility attributes
  $('video').each((i, elem) => {
    const $elem = $(elem);
    // Required for iOS inline playback (not fullscreen)
    $elem.attr('playsinline', '');
    $elem.attr('webkit-playsinline', '');
    // Allow autoplay on iOS (muted videos can autoplay)
    if ($elem.attr('autoplay') !== undefined) {
      $elem.attr('muted', '');
    }
    // Add cross-origin for CORS
    if (!$elem.attr('crossorigin')) {
      $elem.attr('crossorigin', 'anonymous');
    }
  });
  
  // Add Safari/iOS meta tags for proper viewport and web app behavior
  const safariMeta = `
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="format-detection" content="telephone=no">
  `;
  
  // Inject bootstrap script into <head>
  if (gatewayBase && sessionToken) {
    const bootstrapScript = generateBootstrapScript(
      gatewayBase, 
      sessionToken, 
      options && options.pageToken ? options.pageToken : null,
      { originalBaseUrl: baseUrl }  // Pass the original page URL
    );
    
    if (hasHead) {
      // Check if viewport meta exists, if not add Safari meta
      if (!$('meta[name="viewport"]').length) {
        $('head').prepend(safariMeta);
      }
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
