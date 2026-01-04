/**
 * Token Store Module
 * Method A: Random token with server-side storage
 * Implements token generation, storage, and expiration
 */

const crypto = require('crypto');

// Debug helper
function debug(category, message, data = {}) {
  const timestamp = new Date().toISOString();
  console.log(`[DEBUG][${timestamp}][TokenStore][${category}]`, message, JSON.stringify(data, null, 2));
}

function debugError(category, message, error, data = {}) {
  const timestamp = new Date().toISOString();
  console.error(`[ERROR][${timestamp}][TokenStore][${category}]`, message, {
    error: error?.message || error,
    stack: error?.stack?.substring(0, 500),
    ...data
  });
}

class TokenStore {
  constructor(options = {}) {
    debug('INIT', 'Creating TokenStore', { ttl: options.ttl, maxTokensPerSession: options.maxTokensPerSession });
    
    // Token expiration time in milliseconds (default: 1 hour)
    this.defaultTTL = options.ttl || 60 * 60 * 1000;
    
    // Maximum tokens per session (prevent abuse)
    this.maxTokensPerSession = options.maxTokensPerSession || 10000;
    
    // Storage maps
    this.tokens = new Map();        // token -> { url, exp, sessionId }
    this.urlToToken = new Map();    // url:sessionId -> token (for caching)
    this.sessionTokenCount = new Map(); // sessionId -> count
    
    // Cleanup interval (run every 5 minutes)
    this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000);
    
    debug('INIT', 'TokenStore initialized', { defaultTTL: this.defaultTTL, maxTokensPerSession: this.maxTokensPerSession });
  }
  
  /**
   * Generate a secure random token
   */
  generateToken() {
    const token = crypto.randomBytes(32).toString('base64url');
    debug('GENERATE', 'Generated new token', { tokenPreview: token.substring(0, 12) + '...' });
    return token;
  }
  
  /**
   * Create a token for a URL
   */
  createToken(url, sessionId, options = {}) {
    debug('CREATE', 'createToken called', { 
      url: url?.substring(0, 100), 
      sessionId: sessionId?.substring(0, 12) + '...',
      options 
    });
    
    try {
      const ttl = options.ttl || this.defaultTTL;
      const cacheKey = `${url}:${sessionId}`;
      
      // Check if we already have a valid token for this URL + session
      const existingToken = this.urlToToken.get(cacheKey);
      if (existingToken) {
        const data = this.tokens.get(existingToken);
        if (data && data.exp > Date.now()) {
          debug('CREATE', 'Returning cached token', { 
            tokenPreview: existingToken.substring(0, 12) + '...',
            expiresIn: data.exp - Date.now()
          });
          return { token: existingToken, cached: true };
        }
        // Token expired, clean it up
        debug('CREATE', 'Cached token expired, cleaning up', { tokenPreview: existingToken.substring(0, 12) + '...' });
        this.tokens.delete(existingToken);
        this.urlToToken.delete(cacheKey);
      }
      
      // Check session token limit
      const currentCount = this.sessionTokenCount.get(sessionId) || 0;
      if (currentCount >= this.maxTokensPerSession) {
        debugError('CREATE', 'Token limit exceeded', null, { 
          sessionId: sessionId?.substring(0, 12) + '...',
          currentCount,
          maxTokensPerSession: this.maxTokensPerSession
        });
        throw new Error(`Token limit exceeded for session (${currentCount}/${this.maxTokensPerSession})`);
      }
      
      // Generate new token
      const token = this.generateToken();
      const exp = Date.now() + ttl;
      
      // Store mappings
      this.tokens.set(token, { url, exp, sessionId });
      this.urlToToken.set(cacheKey, token);
      this.sessionTokenCount.set(sessionId, currentCount + 1);
      
      debug('CREATE', 'Token created successfully', { 
        tokenPreview: token.substring(0, 12) + '...',
        url: url.substring(0, 80),
        expiresIn: ttl,
        sessionTokenCount: currentCount + 1
      });
      
      return { token, cached: false };
    } catch (e) {
      debugError('CREATE', 'Failed to create token', e, { url: url?.substring(0, 100), sessionId: sessionId?.substring(0, 12) + '...' });
      throw e;
    }
  }
  
  /**
   * Resolve a token to its URL
   */
  resolveToken(token, sessionId) {
    debug('RESOLVE', 'resolveToken called', { 
      tokenPreview: token?.substring(0, 12) + '...',
      sessionId: sessionId ? sessionId.substring(0, 12) + '...' : 'null'
    });
    
    try {
      const data = this.tokens.get(token);
      
      if (!data) {
        debug('RESOLVE', 'Token NOT FOUND in store', { 
          tokenPreview: token?.substring(0, 12) + '...',
          totalTokensInStore: this.tokens.size
        });
        return { valid: false, reason: 'Token not found' };
      }
      
      const now = Date.now();
      if (data.exp < now) {
        debug('RESOLVE', 'Token EXPIRED', { 
          tokenPreview: token?.substring(0, 12) + '...',
          expiredAt: new Date(data.exp).toISOString(),
          expiredAgo: now - data.exp
        });
        // Clean up expired token using revokeToken for proper bookkeeping (including sessionTokenCount)
        this.revokeToken(token);
        return { valid: false, reason: `Token expired ${Math.round((now - data.exp) / 1000)}s ago` };
      }
      
      debug('RESOLVE', 'Token VALID', { 
        tokenPreview: token?.substring(0, 12) + '...',
        url: data.url?.substring(0, 80),
        expiresIn: data.exp - now,
        sessionId: data.sessionId?.substring(0, 12) + '...'
      });
      
      return { valid: true, url: data.url, sessionId: data.sessionId };
    } catch (e) {
      debugError('RESOLVE', 'Failed to resolve token', e, { tokenPreview: token?.substring(0, 12) + '...' });
      return { valid: false, reason: `Resolution error: ${e.message}` };
    }
  }
  
  /**
   * Revoke a specific token
   */
  revokeToken(token) {
    const data = this.tokens.get(token);
    if (data) {
      this.tokens.delete(token);
      const cacheKey = `${data.url}:${data.sessionId}`;
      this.urlToToken.delete(cacheKey);
      
      const count = this.sessionTokenCount.get(data.sessionId) || 0;
      if (count > 0) {
        this.sessionTokenCount.set(data.sessionId, count - 1);
      }
    }
  }
  
  /**
   * Revoke all tokens for a session
   */
  revokeSession(sessionId) {
    const tokensToDelete = [];
    
    for (const [token, data] of this.tokens.entries()) {
      if (data.sessionId === sessionId) {
        tokensToDelete.push(token);
      }
    }
    
    for (const token of tokensToDelete) {
      this.revokeToken(token);
    }
    
    this.sessionTokenCount.delete(sessionId);
  }
  
  /**
   * Clean up expired tokens
   */
  cleanup() {
    const now = Date.now();
    const tokensToDelete = [];
    
    for (const [token, data] of this.tokens.entries()) {
      if (data.exp < now) {
        tokensToDelete.push(token);
      }
    }
    
    for (const token of tokensToDelete) {
      this.revokeToken(token);
    }
    
    return tokensToDelete.length;
  }
  
  /**
   * Get statistics about the store
   */
  getStats() {
    return {
      totalTokens: this.tokens.size,
      cachedMappings: this.urlToToken.size,
      activeSessions: this.sessionTokenCount.size
    };
  }
  
  /**
   * Shutdown the store (clear cleanup interval)
   */
  shutdown() {
    clearInterval(this.cleanupInterval);
    this.tokens.clear();
    this.urlToToken.clear();
    this.sessionTokenCount.clear();
  }
}

/**
 * Session Store
 * Manages session tokens for authentication
 */
class SessionStore {
  constructor(options = {}) {
    debug('SESSION_INIT', 'Creating SessionStore', { ttl: options.ttl });
    
    // Session expiration time (default: 24 hours)
    this.defaultTTL = options.ttl || 24 * 60 * 60 * 1000;
    
    // Storage
    this.sessions = new Map(); // sessionToken -> { exp, ip, userAgent, createdAt }
    
    // Cleanup interval
    this.cleanupInterval = setInterval(() => this.cleanup(), 10 * 60 * 1000);
    
    debug('SESSION_INIT', 'SessionStore initialized', { defaultTTL: this.defaultTTL });
  }
  
  /**
   * Create a new session
   */
  createSession(ip, userAgent = '') {
    debug('SESSION_CREATE', 'Creating new session', { ip, userAgent: userAgent?.substring(0, 50) });
    
    try {
      const sessionToken = crypto.randomBytes(32).toString('base64url');
      const now = Date.now();
      
      this.sessions.set(sessionToken, {
        exp: now + this.defaultTTL,
        ip,
        userAgent,
        createdAt: now
      });
      
      debug('SESSION_CREATE', 'Session created successfully', { 
        tokenPreview: sessionToken.substring(0, 12) + '...',
        expiresIn: this.defaultTTL,
        totalSessions: this.sessions.size
      });
      
      return { sessionToken, expiresIn: this.defaultTTL };
    } catch (e) {
      debugError('SESSION_CREATE', 'Failed to create session', e, { ip, userAgent: userAgent?.substring(0, 50) });
      throw e;
    }
  }
  
  /**
   * Validate a session token
   */
  validateSession(sessionToken, ip) {
    debug('SESSION_VALIDATE', 'Validating session', { 
      tokenPreview: sessionToken?.substring(0, 12) + '...',
      ip
    });
    
    try {
      const data = this.sessions.get(sessionToken);
      
      if (!data) {
        debug('SESSION_VALIDATE', 'Session NOT FOUND', { 
          tokenPreview: sessionToken?.substring(0, 12) + '...',
          totalSessions: this.sessions.size
        });
        return { valid: false, reason: 'Session not found' };
      }
      
      const now = Date.now();
      if (data.exp < now) {
        debug('SESSION_VALIDATE', 'Session EXPIRED', { 
          tokenPreview: sessionToken?.substring(0, 12) + '...',
          expiredAt: new Date(data.exp).toISOString(),
          expiredAgo: now - data.exp
        });
        this.sessions.delete(sessionToken);
        return { valid: false, reason: `Session expired ${Math.round((now - data.exp) / 1000)}s ago` };
      }
      
      debug('SESSION_VALIDATE', 'Session VALID', { 
        tokenPreview: sessionToken?.substring(0, 12) + '...',
        expiresIn: data.exp - now,
        originalIp: data.ip,
        requestIp: ip
      });
      
      return { valid: true, session: data };
    } catch (e) {
      debugError('SESSION_VALIDATE', 'Failed to validate session', e, { tokenPreview: sessionToken?.substring(0, 12) + '...' });
      return { valid: false, reason: `Validation error: ${e.message}` };
    }
  }
  
  /**
   * Refresh session expiration
   */
  refreshSession(sessionToken) {
    const data = this.sessions.get(sessionToken);
    if (data) {
      data.exp = Date.now() + this.defaultTTL;
      debug('SESSION_REFRESH', 'Session refreshed', { tokenPreview: sessionToken.substring(0, 12) + '...' });
      return true;
    }
    debug('SESSION_REFRESH', 'Session not found for refresh', { tokenPreview: sessionToken?.substring(0, 12) + '...' });
    return false;
  }
  
  /**
   * Revoke a session
   */
  revokeSession(sessionToken) {
    const deleted = this.sessions.delete(sessionToken);
    debug('SESSION_REVOKE', deleted ? 'Session revoked' : 'Session not found', { tokenPreview: sessionToken?.substring(0, 12) + '...' });
    return deleted;
  }
  
  /**
   * Clean up expired sessions
   */
  cleanup() {
    const now = Date.now();
    let cleaned = 0;
    for (const [token, data] of this.sessions.entries()) {
      if (data.exp < now) {
        this.sessions.delete(token);
        cleaned++;
      }
    }
    if (cleaned > 0) {
      debug('SESSION_CLEANUP', 'Cleaned expired sessions', { cleaned, remaining: this.sessions.size });
    }
  }
  
  /**
   * Get count of active sessions
   */
  getActiveSessions() {
    return this.sessions.size;
  }
  
  /**
   * Shutdown
   */
  shutdown() {
    debug('SESSION_SHUTDOWN', 'Shutting down SessionStore', { sessions: this.sessions.size });
    clearInterval(this.cleanupInterval);
    this.sessions.clear();
  }
}

module.exports = { TokenStore, SessionStore };
