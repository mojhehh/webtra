/**
 * Rate Limiter Middleware
 * Implements per-IP and per-session rate limiting
 */

// Debug logging
function debug(category, message, data = {}) {
  console.log(`[RATE-LIMIT:${category}] ${message}`, JSON.stringify(data, null, 2));
}

function debugWarn(category, message, data = {}) {
  console.warn(`[RATE-LIMIT:${category}] ⚠️ ${message}`, JSON.stringify(data, null, 2));
}

class RateLimiter {
  constructor(options = {}) {
    debug('INIT', 'Creating RateLimiter', options);
    
    // Default limits (set high to support modern JS-heavy sites)
    this.limits = {
      // Requests per window (per IP)
      requestsPerWindow: options.requestsPerWindow || 2000,
      // Separate session limit (lower to prevent session-based bypass)
      sessionRequestsPerWindow: options.sessionRequestsPerWindow || 500,
      // Window size in milliseconds (default: 1 minute)
      windowMs: options.windowMs || 60 * 1000,
      // Max tokens per minute per IP (needs to be high for JS-heavy sites)
      tokensPerWindow: options.tokensPerWindow || 5000,
      // Max tokens per minute per session (prevent session rotation attacks)
      sessionTokensPerWindow: options.sessionTokensPerWindow || 1000,
      // Max concurrent requests per IP
      maxConcurrent: options.maxConcurrent || 50
    };
    
    debug('INIT', 'Rate limits configured', this.limits);
    
    // Whether to trust proxy headers for IP extraction
    this.trustProxy = options.trustProxy || false;
    
    // Storage
    this.ipRequests = new Map();      // ip -> { count, windowStart }
    this.sessionRequests = new Map(); // session -> { count, windowStart }
    this.ipTokens = new Map();        // ip -> { count, windowStart }
    this.sessionTokens = new Map();   // session -> { count, windowStart }
    this.concurrentRequests = new Map(); // ip -> { count, lastActivity }
    
    // Cleanup interval
    this.cleanupInterval = setInterval(() => this.cleanup(), 60 * 1000);
  }
  
  /**
   * Extract IP address from request, handling proxy headers if trusted
   */
  getClientIP(req) {
    if (this.trustProxy) {
      // Trust X-Forwarded-For header
      const forwarded = req.headers['x-forwarded-for'];
      if (forwarded) {
        return forwarded.split(',')[0].trim();
      }
    }
    return req.ip || req.connection?.remoteAddress || 'unknown';
  }
  
  /**
   * Get or create a rate limit bucket
   */
  getBucket(map, key) {
    const now = Date.now();
    let bucket = map.get(key);
    
    if (!bucket || (now - bucket.windowStart) > this.limits.windowMs) {
      bucket = { count: 0, windowStart: now };
      map.set(key, bucket);
    }
    
    return bucket;
  }
  
  /**
   * Check if a request should be allowed
   * @param {string} ip - Client IP address
   * @param {string} sessionId - Session identifier (optional)
   * @param {string} type - Type of request ('request', 'token')
   * @returns {{ allowed: boolean, retryAfter?: number, reason?: string }}
   */
  checkLimit(ip, sessionId, type = 'request') {
    const now = Date.now();
    
    // Check concurrent requests limit
    const concurrentEntry = this.concurrentRequests.get(ip);
    const concurrent = concurrentEntry ? concurrentEntry.count : 0;
    if (concurrent >= this.limits.maxConcurrent) {
      debugWarn('LIMIT', 'BLOCKED - Too many concurrent requests', { 
        ip, 
        concurrent, 
        max: this.limits.maxConcurrent 
      });
      return {
        allowed: false,
        reason: `Too many concurrent requests: ${concurrent}/${this.limits.maxConcurrent}`,
        retryAfter: 1
      };
    }
    
    // Check IP rate limit
    const ipBucket = this.getBucket(this.ipRequests, ip);
    if (ipBucket.count >= this.limits.requestsPerWindow) {
      const retryAfter = Math.ceil((ipBucket.windowStart + this.limits.windowMs - now) / 1000);
      debugWarn('LIMIT', 'BLOCKED - IP rate limit exceeded', { 
        ip, 
        count: ipBucket.count, 
        max: this.limits.requestsPerWindow,
        retryAfter 
      });
      return {
        allowed: false,
        reason: `IP rate limit exceeded: ${ipBucket.count}/${this.limits.requestsPerWindow} requests`,
        retryAfter: Math.max(retryAfter, 1)
      };
    }
    
    // Check session rate limit (if provided) - uses separate lower limit
    if (sessionId) {
      const sessionBucket = this.getBucket(this.sessionRequests, sessionId);
      if (sessionBucket.count >= this.limits.sessionRequestsPerWindow) {
        const retryAfter = Math.ceil((sessionBucket.windowStart + this.limits.windowMs - now) / 1000);
        debugWarn('LIMIT', 'BLOCKED - Session rate limit exceeded', { 
          sessionId: sessionId.substring(0, 12) + '...', 
          count: sessionBucket.count, 
          max: this.limits.sessionRequestsPerWindow,
          retryAfter 
        });
        return {
          allowed: false,
          reason: `Session rate limit exceeded: ${sessionBucket.count}/${this.limits.sessionRequestsPerWindow} requests`,
          retryAfter: Math.max(retryAfter, 1)
        };
      }
    }
    
    // For token requests, check both IP and session token limits
    if (type === 'token') {
      // IP-based token limit
      const tokenBucket = this.getBucket(this.ipTokens, ip);
      if (tokenBucket.count >= this.limits.tokensPerWindow) {
        const retryAfter = Math.ceil((tokenBucket.windowStart + this.limits.windowMs - now) / 1000);
        debugWarn('LIMIT', 'BLOCKED - IP token rate limit exceeded', { 
          ip, 
          count: tokenBucket.count, 
          max: this.limits.tokensPerWindow,
          retryAfter 
        });
        return {
          allowed: false,
          reason: `IP token rate limit exceeded: ${tokenBucket.count}/${this.limits.tokensPerWindow} tokens`,
          retryAfter: Math.max(retryAfter, 1)
        };
      }
      
      // Session-based token limit (prevent session rotation attacks)
      if (sessionId) {
        const sessionTokenBucket = this.getBucket(this.sessionTokens, sessionId);
        if (sessionTokenBucket.count >= this.limits.sessionTokensPerWindow) {
          const retryAfter = Math.ceil((sessionTokenBucket.windowStart + this.limits.windowMs - now) / 1000);
          debugWarn('LIMIT', 'BLOCKED - Session token rate limit exceeded', { 
            sessionId: sessionId.substring(0, 12) + '...', 
            count: sessionTokenBucket.count, 
            max: this.limits.sessionTokensPerWindow,
            retryAfter 
          });
          return {
            allowed: false,
            reason: `Session token rate limit exceeded: ${sessionTokenBucket.count}/${this.limits.sessionTokensPerWindow} tokens`,
            retryAfter: Math.max(retryAfter, 1)
          };
        }
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Record a request
   */
  recordRequest(ip, sessionId, type = 'request') {
    // Increment IP counter
    const ipBucket = this.getBucket(this.ipRequests, ip);
    ipBucket.count++;
    
    // Increment session counter
    if (sessionId) {
      const sessionBucket = this.getBucket(this.sessionRequests, sessionId);
      sessionBucket.count++;
    }
    
    // Increment token counters if applicable (both IP and session)
    if (type === 'token') {
      const tokenBucket = this.getBucket(this.ipTokens, ip);
      tokenBucket.count++;
      
      // Also track tokens per session
      if (sessionId) {
        const sessionTokenBucket = this.getBucket(this.sessionTokens, sessionId);
        sessionTokenBucket.count++;
      }
    }
  }
  
  /**
   * Track concurrent request start
   */
  startRequest(ip) {
    const entry = this.concurrentRequests.get(ip) || { count: 0, lastActivity: Date.now() };
    entry.count++;
    entry.lastActivity = Date.now();
    this.concurrentRequests.set(ip, entry);
  }
  
  /**
   * Track concurrent request end
   */
  endRequest(ip) {
    const entry = this.concurrentRequests.get(ip);
    if (!entry || entry.count <= 1) {
      this.concurrentRequests.delete(ip);
    } else {
      entry.count--;
      entry.lastActivity = Date.now();
    }
  }
  
  /**
   * Clean up old buckets
   */
  cleanup() {
    const now = Date.now();
    const expiry = this.limits.windowMs * 2;
    // Concurrent requests stuck for more than 5 minutes are considered leaked
    const concurrentExpiry = 5 * 60 * 1000;
    
    for (const [key, bucket] of this.ipRequests.entries()) {
      if (now - bucket.windowStart > expiry) {
        this.ipRequests.delete(key);
      }
    }
    
    for (const [key, bucket] of this.sessionRequests.entries()) {
      if (now - bucket.windowStart > expiry) {
        this.sessionRequests.delete(key);
      }
    }
    
    for (const [key, bucket] of this.ipTokens.entries()) {
      if (now - bucket.windowStart > expiry) {
        this.ipTokens.delete(key);
      }
    }
    
    for (const [key, bucket] of this.sessionTokens.entries()) {
      if (now - bucket.windowStart > expiry) {
        this.sessionTokens.delete(key);
      }
    }
    
    // Clean up stale concurrent request entries (prevents counter leaks)
    for (const [ip, entry] of this.concurrentRequests.entries()) {
      if (now - entry.lastActivity > concurrentExpiry) {
        console.warn(`[RateLimiter] Cleaning stale concurrent entry for IP: ${ip} (count: ${entry.count})`);
        this.concurrentRequests.delete(ip);
      }
    }
  }
  
  /**
   * Create Express middleware
   */
  middleware(type = 'request') {
    return (req, res, next) => {
      const ip = this.getClientIP(req);
      const sessionId = req.sessionId; // Set by auth middleware
      
      const result = this.checkLimit(ip, sessionId, type);
      
      if (!result.allowed) {
        res.set('Retry-After', String(result.retryAfter));
        return res.status(429).json({
          error: 'Rate limit exceeded',
          reason: result.reason,
          retryAfter: result.retryAfter
        });
      }
      
      // Track concurrent requests for proxy endpoints
      // Use guarded callback to prevent double-decrement
      if (type === 'proxy') {
        this.startRequest(ip);
        let ended = false;
        const endOnce = () => {
          if (!ended) {
            ended = true;
            this.endRequest(ip);
          }
        };
        res.on('finish', endOnce);
        res.on('close', endOnce);
      }
      
      this.recordRequest(ip, sessionId, type);
      next();
    };
  }
  
  /**
   * Get statistics
   */
  getStats() {
    return {
      trackedIPs: this.ipRequests.size,
      trackedSessions: this.sessionRequests.size,
      trackedSessionTokens: this.sessionTokens.size,
      activeConnections: Array.from(this.concurrentRequests.values()).reduce((a, entry) => a + entry.count, 0)
    };
  }
  
  /**
   * Shutdown
   */
  shutdown() {
    clearInterval(this.cleanupInterval);
  }
}

/**
 * Security Logger
 * Logs blocked requests for security analysis
 */
class SecurityLogger {
  constructor(options = {}) {
    this.logs = [];
    this.maxLogs = options.maxLogs || 10000;
    this.logToConsole = options.logToConsole !== false;
  }
  
  log(event) {
    const entry = {
      timestamp: new Date().toISOString(),
      ...event
    };
    
    this.logs.push(entry);
    
    // Trim old logs
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs / 2);
    }
    
    if (this.logToConsole) {
      console.log(`[SECURITY] ${entry.type}: ${entry.message}`, entry.details || '');
    }
  }
  
  logBlocked(type, message, details = {}) {
    this.log({
      type: 'BLOCKED',
      subtype: type,
      message,
      details
    });
  }
  
  logWarning(message, details = {}) {
    this.log({
      type: 'WARNING',
      message,
      details
    });
  }
  
  getRecentLogs(count = 100) {
    return this.logs.slice(-count);
  }
  
  getStats() {
    const stats = {
      total: this.logs.length,
      byType: {}
    };
    
    for (const log of this.logs) {
      const type = log.subtype || log.type;
      stats.byType[type] = (stats.byType[type] || 0) + 1;
    }
    
    return stats;
  }
}

module.exports = { RateLimiter, SecurityLogger };
