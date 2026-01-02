/**
 * Token Store Module
 * Method A: Random token with server-side storage
 * Implements token generation, storage, and expiration
 */

const crypto = require('crypto');

class TokenStore {
  constructor(options = {}) {
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
  }
  
  /**
   * Generate a secure random token
   */
  generateToken() {
    return crypto.randomBytes(32).toString('base64url');
  }
  
  /**
   * Create a token for a URL
   * @param {string} url - The target URL
   * @param {string} sessionId - Session identifier
   * @param {Object} options - Additional options
   * @param {number} [options.ttl] - Custom TTL for this token
   * @returns {{ token: string, cached: boolean }}
   */
  createToken(url, sessionId, options = {}) {
    const ttl = options.ttl || this.defaultTTL;
    const cacheKey = `${url}:${sessionId}`;
    
    // Check if we already have a valid token for this URL + session
    const existingToken = this.urlToToken.get(cacheKey);
    if (existingToken) {
      const data = this.tokens.get(existingToken);
      if (data && data.exp > Date.now()) {
        return { token: existingToken, cached: true };
      }
      // Token expired, clean it up
      this.tokens.delete(existingToken);
      this.urlToToken.delete(cacheKey);
    }
    
    // Check session token limit
    const currentCount = this.sessionTokenCount.get(sessionId) || 0;
    if (currentCount >= this.maxTokensPerSession) {
      throw new Error('Token limit exceeded for session');
    }
    
    // Generate new token
    const token = this.generateToken();
    const exp = Date.now() + ttl;
    
    // Store mappings
    this.tokens.set(token, { url, exp, sessionId });
    this.urlToToken.set(cacheKey, token);
    this.sessionTokenCount.set(sessionId, currentCount + 1);
    
    return { token, cached: false };
  }
  
  /**
   * Resolve a token to its URL
   * @param {string} token - The token to resolve
   * @param {string} sessionId - Session identifier (for validation)
   * @returns {{ valid: boolean, url?: string, reason?: string }}
   */
  resolveToken(token, sessionId) {
    const data = this.tokens.get(token);
    
    if (!data) {
      return { valid: false, reason: 'Token not found' };
    }
    
    if (data.exp < Date.now()) {
      // Clean up expired token
      this.tokens.delete(token);
      const cacheKey = `${data.url}:${data.sessionId}`;
      this.urlToToken.delete(cacheKey);
      return { valid: false, reason: 'Token expired' };
    }
    
    // Optionally validate session matches (can be disabled for shared resources)
    // if (data.sessionId !== sessionId) {
    //   return { valid: false, reason: 'Session mismatch' };
    // }
    
    // Return sessionId so callers can use it for creating sub-tokens
    return { valid: true, url: data.url, sessionId: data.sessionId };
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
    // Session expiration time (default: 24 hours)
    this.defaultTTL = options.ttl || 24 * 60 * 60 * 1000;
    
    // Storage
    this.sessions = new Map(); // sessionToken -> { exp, ip, userAgent, createdAt }
    
    // Cleanup interval
    this.cleanupInterval = setInterval(() => this.cleanup(), 10 * 60 * 1000);
  }
  
  /**
   * Create a new session
   */
  createSession(ip, userAgent = '') {
    const sessionToken = crypto.randomBytes(32).toString('base64url');
    const now = Date.now();
    
    this.sessions.set(sessionToken, {
      exp: now + this.defaultTTL,
      ip,
      userAgent,
      createdAt: now
    });
    
    return { sessionToken, expiresIn: this.defaultTTL };
  }
  
  /**
   * Validate a session token
   */
  validateSession(sessionToken, ip) {
    const data = this.sessions.get(sessionToken);
    
    if (!data) {
      return { valid: false, reason: 'Session not found' };
    }
    
    if (data.exp < Date.now()) {
      this.sessions.delete(sessionToken);
      return { valid: false, reason: 'Session expired' };
    }
    
    // Optional: Validate IP hasn't changed (can be strict or relaxed)
    // if (data.ip !== ip) {
    //   return { valid: false, reason: 'IP mismatch' };
    // }
    
    return { valid: true, session: data };
  }
  
  /**
   * Refresh session expiration
   */
  refreshSession(sessionToken) {
    const data = this.sessions.get(sessionToken);
    if (data) {
      data.exp = Date.now() + this.defaultTTL;
      return true;
    }
    return false;
  }
  
  /**
   * Revoke a session
   */
  revokeSession(sessionToken) {
    return this.sessions.delete(sessionToken);
  }
  
  /**
   * Clean up expired sessions
   */
  cleanup() {
    const now = Date.now();
    for (const [token, data] of this.sessions.entries()) {
      if (data.exp < now) {
        this.sessions.delete(token);
      }
    }
  }
  
  /**
   * Shutdown
   */
  shutdown() {
    clearInterval(this.cleanupInterval);
    this.sessions.clear();
  }
}

module.exports = { TokenStore, SessionStore };
