# Encrypted Link Gateway

A secure proxy gateway that encrypts all URLs through `/go/<token>` endpoints. The browser **never** requests raw URLs directly - all navigation, assets, and API calls go through tokenized gateway URLs.

## ⚠️ Security Notice

This is designed as a **private gateway** for your own site or a **strict allowlist you control**. 
**Never** accept arbitrary URLs - that would create an open proxy vulnerable to abuse.

## Features

- 🔐 **Token-based URL encryption** - URLs are converted to opaque tokens
- 🛡️ **SSRF protection** - Blocks private IPs, dangerous schemes, and DNS rebinding
- 📝 **HTML rewriting** - Automatically rewrites all URLs in HTML responses
- 🔄 **Fetch/XHR interception** - Client-side JavaScript is patched to use gateway
- ⏱️ **Rate limiting** - Per-IP and per-session rate limits
- 📊 **Security logging** - All blocked requests are logged
- 🚀 **Performance optimized** - Keep-alive connections, token caching

## Architecture

```
┌─────────────┐     ┌─────────────────────────────────────────┐
│   Browser   │────▶│           Gateway Server                │
│             │     │  ┌─────────────────────────────────┐   │
│  /go/abc123 │     │  │  1. Validate auth (session)     │   │
│             │     │  │  2. Decode token → URL          │   │
│             │◀────│  │  3. Validate against allowlist  │   │
│  (Response) │     │  │  4. Fetch from upstream         │   │
└─────────────┘     │  │  5. Rewrite HTML (if needed)    │   │
                    │  │  6. Return response             │   │
                    │  └─────────────────────────────────┘   │
                    └─────────────────────────────────────────┘
```

## Quick Start

### 1. Install dependencies

```bash
cd server
npm install
```

### 2. Configure environment

Create a `.env` file or set environment variables:

```bash
# Required: The origin you want to proxy
ALLOWED_ORIGIN=https://example.com

# Optional: Additional allowed origins (comma-separated)
ADDITIONAL_ORIGINS=https://cdn.example.com,https://api.example.com

# Optional: Server configuration
PORT=3000
GATEWAY_BASE=http://localhost:3000

# Optional: Security settings
TOKEN_TTL=3600000        # Token lifetime in ms (default: 1 hour)
SESSION_TTL=86400000     # Session lifetime in ms (default: 24 hours)
RATE_LIMIT_REQUESTS=100  # Requests per minute per IP
CORS_ORIGINS=*           # Allowed CORS origins
TRUST_PROXY=false        # Set true if behind reverse proxy

# Optional: WebSocket support (VERY STRICT - single origin only)
ALLOW_WEBSOCKET=false
ALLOWED_WS_ORIGIN=wss://example.com
```

### 3. Start the server

```bash
# Development
npm run dev

# Production
npm start
```

### 4. Open the demo

Navigate to `http://localhost:3000` to see the demo frontend.

## API Endpoints

### `POST /session`
Create a new session token for authentication.

**Response:**
```json
{
  "sessionToken": "abc123...",
  "expiresIn": 86400000,
  "expiresAt": "2024-12-19T12:00:00.000Z"
}
```

### `POST /tokenize`
Convert a URL to a gateway token.

**Headers:**
```
Authorization: Bearer <sessionToken>
Content-Type: application/json
```

**Body:**
```json
{
  "url": "https://example.com/page.html"
}
```

**Response:**
```json
{
  "token": "xyz789...",
  "cached": false,
  "gatewayUrl": "/go/xyz789..."
}
```

### `GET /go/:token`
Fetch a resource through the gateway.

**Headers:**
```
Authorization: Bearer <sessionToken>
```

The gateway will:
1. Validate the session token
2. Decode the URL token
3. Verify the URL is in the allowlist
4. Fetch from upstream
5. Rewrite HTML if applicable
6. Return the response

### `GET /health`
Health check endpoint (no auth required).

### `GET /admin/logs`
View security logs (requires `X-Admin-Key` header in production).

## Security Rules

### Blocked Schemes
- `file:`, `ftp:`, `ws:`, `wss:`, `data:`, `blob:`, `javascript:`

### Blocked Targets
- `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`
- Private IP ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Link-local: `169.254.0.0/16`
- IPv6 local: `fc00::/7`, `fe80::/10`

### Header Safety
These headers are **not** forwarded to upstream:
- `Host`, `Connection`, `Transfer-Encoding`, `Upgrade`
- `Proxy-*` headers
- `X-Forwarded-*`, `X-Real-IP`, etc.

### Rate Limits
- 100 requests per minute per IP (configurable)
- 200 tokens per minute per IP
- 10 concurrent requests per IP

## HTML Rewriting

When proxying HTML content, the gateway:

1. **Rewrites URL attributes:**
   - `<a href>`, `<link href>`, `<script src>`
   - `<img src>`, `<img srcset>`, `<iframe src>`
   - `<form action>`, `<source src>`, etc.

2. **Rewrites CSS URLs:**
   - Inline styles with `url()`
   - `<style>` tag contents

3. **Injects bootstrap script:**
   - Overrides `window.fetch`
   - Overrides `XMLHttpRequest`
   - Intercepts link clicks
   - Intercepts form submissions

4. **Preserves:**
   - Hash fragments (`#section`)
   - `mailto:`, `tel:`, `sms:` links

## Deployment

### Wispbyte / Docker

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY server/package*.json ./
RUN npm ci --production
COPY server/src ./src
COPY frontend ../frontend
ENV NODE_ENV=production
EXPOSE 3000
CMD ["npm", "start"]
```

### Environment Variables for Production

```bash
ALLOWED_ORIGIN=https://your-target-site.com
GATEWAY_BASE=https://your-gateway-domain.com
TRUST_PROXY=true
NODE_ENV=production
ADMIN_KEY=your-secure-admin-key
```

### GitHub Pages (Frontend Only)

If deploying frontend separately:

1. Update `gatewayUrlInput.value` in `index.html` to your gateway URL
2. Deploy to GitHub Pages
3. Add your GitHub Pages domain to `CORS_ORIGINS`

## Testing

### Acceptance Tests

✅ **No raw URLs in output:** HTML responses should only contain `/go/...` URLs  
✅ **Links work:** Clicking rewritten links navigates correctly  
✅ **Assets load:** JS, CSS, images load through gateway  
✅ **Private IPs blocked:** `http://127.0.0.1` returns 403  
✅ **Allowlist enforced:** Non-allowed domains return 403  
✅ **Expired tokens rejected:** Old tokens return 403  

### Manual Testing

```bash
# Create session
curl -X POST http://localhost:3000/session

# Tokenize URL (use session token from above)
curl -X POST http://localhost:3000/tokenize \
  -H "Authorization: Bearer <sessionToken>" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# Fetch through gateway
curl http://localhost:3000/go/<token> \
  -H "Authorization: Bearer <sessionToken>"

# Test blocked URL
curl -X POST http://localhost:3000/tokenize \
  -H "Authorization: Bearer <sessionToken>" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:8080"}'
# Should return 403
```

## Project Structure

```
proxy/
├── server/
│   ├── package.json
│   └── src/
│       ├── index.js          # Main Express server
│       ├── token-store.js    # Token & session management
│       ├── ssrf-guard.js     # URL validation & SSRF protection
│       ├── html-rewriter.js  # HTML parsing & URL rewriting
│       └── rate-limiter.js   # Rate limiting & security logging
│
├── frontend/
│   └── index.html            # Demo frontend
│
└── README.md
```

## Security Notes

1. **Never expose without allowlist** - Always configure `ALLOWED_ORIGIN`
2. **Use HTTPS in production** - Token interception is a risk over HTTP
3. **Set strong session TTL** - Balance usability vs security
4. **Monitor security logs** - Check `/admin/logs` for blocked requests
5. **Rate limit aggressively** - Prevent abuse
6. **DNS rebinding protection** - The gateway validates DNS resolution
7. **No credential forwarding** - Auth headers are not sent upstream

## Limitations

- WebSocket support is very limited (single origin only)
- Some JavaScript-heavy sites may not work perfectly
- Service workers are not intercepted
- Web Workers fetch calls are not intercepted

## License

MIT
