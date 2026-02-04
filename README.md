# 🌐 Transparent Web Proxy (CroxyProxy-Style)

A server-side transparent proxy that actually works with YouTube, Reddit, and other complex sites.

## Why This is Different

### ❌ The Old Way (URL Rewriting - Ultraviolet, etc.)
```
Your URL: yourproxy.com/proxy/https%3A%2F%2Fyoutube.com%2Fwatch%3Fv%3Dxyz
```
- Every URL gets encoded in the path
- Browser sees different "origins" for different encoded URLs
- Iframes break: "Domains, protocols and ports must match"
- JavaScript checks `window.location` and fails
- Integrity hashes don't match

### ✅ The New Way (Server-Side Transparent Proxy)
```
Your URL: proxyserver.com/watch?v=xyz
```
- URLs stay NATIVE (no encoding!)
- All requests go to ONE server
- Server tracks your target in a session
- No cross-origin issues
- Works with complex sites!

## How CroxyProxy Actually Works

1. **Main Site** (croxyproxy.com) - Landing page
2. **Server Selector** (/servers) - Picks an available proxy server
3. **Proxy Server** (random IP like 108.181.88.29) - Handles YOUR session
4. **All traffic** goes through that ONE server - no URL encoding needed!

```
┌──────────────────┐
│  croxyproxy.com  │  ← Landing page
└────────┬─────────┘
         │ Redirect to proxy server
         ▼
┌──────────────────┐
│  108.181.88.29   │  ← Your dedicated proxy server
│  (tracks your    │
│   target site)   │
└────────┬─────────┘
         │ Forwards requests
         ▼
┌──────────────────┐
│  youtube.com     │  ← Target site
└──────────────────┘
```

## Quick Start

```bash
# Install dependencies
npm install

# Run the advanced proxy with WebSocket support
npm start

# Or run the simple version
npm run simple

# Open browser
open http://localhost:8080
```

## Files

| File | Description |
|------|-------------|
| `src/advanced-proxy.js` | Full proxy with WebSocket support |
| `src/transparent-proxy.js` | Simple version without WS |
| `src/ARCHITECTURE.md.js` | Detailed explanation of how it works |
| `src/server.js` | Old URL-rewriting proxy (has issues) |

## How It Works

1. **Session Tracking**: When you visit `/browse/https://youtube.com`, we:
   - Create a session ID (stored in cookie)
   - Remember your target: `youtube.com`
   
2. **Request Forwarding**: For subsequent requests like `/watch?v=xyz`:
   - Read session cookie
   - Look up your target (youtube.com)
   - Forward to `https://youtube.com/watch?v=xyz`
   - Return response
   
3. **HTML Rewriting** (minimal):
   - Convert `https://youtube.com/path` → `/path` (relative)
   - Inject small helper script
   - Remove CSP/X-Frame-Options headers
   
4. **WebSocket Proxy**: 
   - Intercept WS upgrade requests
   - Connect to target WS
   - Relay messages both ways

## Why This Fixes Your Errors

Your error log showed:
```
Unsafe attempt to load URL <URL> from frame with URL <URL>. 
Domains, protocols and ports must match.
```

**The Problem**: URL-rewriting creates different "virtual origins":
- Main page: `proxy.com/proxy/aHR0cHM6Ly95b3V0dWJl...`
- Iframe: `proxy.com/proxy/aHR0cHM6Ly9pLnl0aW1n...`
- Browser thinks these are different origins!

**The Solution**: Transparent proxy = ONE origin for everything:
- Main page: `proxy.com/`
- Iframe: `proxy.com/iframe-path`
- All requests to `proxy.com` = same origin ✓

## Deploy

### Render.com / Railway.app
1. Connect your GitHub repo
2. Build command: `npm install`
3. Start command: `npm start`
4. Port: `8080`

### Local Development
```bash
npm install
npm start
# Open http://localhost:8080
```

## Limitations

- Service Workers need to be blocked/intercepted
- Some OAuth flows may need special handling
- Target sites may rate-limit your proxy IP
