# openclaw-api-proxy

**Zero-knowledge API proxy for AI agents.**
API keys live in environment variables on your server. Agents never see the raw key values.

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template?template=https://github.com/isaackaara/openclaw-api-proxy)
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/isaackaara/openclaw-api-proxy)

---

## Why This Exists

When an AI agent calls an external API directly, the API key ends up in the agent's context window. That means:

- The key appears in logs, traces, and conversation history.
- Any model that processes the context can read the key.
- If the context is leaked or logged, the key is compromised.

**The zero-knowledge pattern:** agents call the proxy using a service name only (e.g. `resend`). The proxy looks up the real API key from environment variables and forwards the request. The agent never touches the key.

```
Agent  -->  proxy/resend/emails  -->  (proxy injects RESEND_API_KEY)  -->  api.resend.com
```

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/isaackaara/openclaw-api-proxy.git
cd openclaw-api-proxy

# 2. Install dependencies
npm install

# 3. Configure
cp .env.example .env
# Edit .env and fill in your API keys

# 4. Run
npm start
```

The proxy starts on port `3000` by default.

---

## Docker

```bash
# Build and run with Docker Compose
cp .env.example .env
# Fill in your keys in .env, then:
docker compose up -d
```

Or run directly:

```bash
docker build -t openclaw-api-proxy .
docker run -p 3000:3000 --env-file .env openclaw-api-proxy
```

---

## Configuration

### services.json

The service registry lives in `services.json` at the project root. Each entry maps a service name to:

| Field | Description |
|-------|-------------|
| `baseUrl` | The real API base URL |
| `keyEnv` | Environment variable name holding the API key |
| `authHeader` | HTTP header to inject (usually `Authorization`) |
| `authPrefix` | Header value prefix (usually `Bearer`) |

Example entry:

```json
{
  "resend": {
    "baseUrl": "https://api.resend.com",
    "keyEnv": "RESEND_API_KEY",
    "authHeader": "Authorization",
    "authPrefix": "Bearer"
  }
}
```

To add a new service, add an entry to `services.json` and restart.

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Port to listen on (default: `3000`) |
| `PROXY_AUTH_TOKEN` | No | Bearer token to guard the proxy. Leave blank for open access (use only on private networks). |
| `RESEND_API_KEY` | No | Resend API key |
| `YNAB_API_KEY` | No | YNAB personal access token |
| `OPENROUTER_API_KEY` | No | OpenRouter API key |
| `GITHUB_TOKEN` | No | GitHub personal access token |
| `CLOUDFLARE_API_TOKEN` | No | Cloudflare API token |
| `DARAJA_ACCESS_TOKEN` | No | Safaricom Daraja access token |
| `GOOGLE_API_KEY` | No | Google API key |
| `STRIPE_SECRET_KEY` | No | Stripe secret key |
| `SLACK_BOT_TOKEN` | No | Slack bot token |
| `TWILIO_AUTH_TOKEN` | No | Twilio auth token |
| `GOOGLE_SHEETS_TOKEN` | No | Leave blank - auto-fetched via Nango (provider: google, connectionId: isaac-google) |

Only set the keys you need. Unset services still work at the proxy level; they just forward without an auth header.

---

## Usage

### Check health

```bash
curl http://localhost:3000/health
```

Response:
```json
{
  "status": "ok",
  "services": [
    { "name": "resend", "configured": true },
    { "name": "ynab", "configured": false }
  ]
}
```

### List services

```bash
curl http://localhost:3000/services
```

### Make a proxied request

Replace the real API base URL with `http://localhost:3000/proxy/:service`.

**Resend - send an email**
```bash
curl -X POST http://localhost:3000/proxy/resend/emails \
  -H "Content-Type: application/json" \
  -d '{
    "from": "hello@example.com",
    "to": ["user@example.com"],
    "subject": "Test",
    "html": "<p>Sent via proxy</p>"
  }'
```

**YNAB - get budgets**
```bash
curl http://localhost:3000/proxy/ynab/v1/budgets
```

**OpenRouter - chat completion**
```bash
curl -X POST http://localhost:3000/proxy/openrouter/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "openai/gpt-4o-mini",
    "messages": [{ "role": "user", "content": "Hello" }]
  }'
```

**GitHub - list repos**
```bash
curl http://localhost:3000/proxy/github/user/repos
```

**Stripe - list customers**
```bash
curl http://localhost:3000/proxy/stripe/v1/customers
```

**Slack - post message**
```bash
curl -X POST http://localhost:3000/proxy/slack/chat.postMessage \
  -H "Content-Type: application/json" \
  -d '{ "channel": "#general", "text": "Hello from the proxy" }'
```

**Twilio - send SMS**
```bash
curl -X POST "http://localhost:3000/proxy/twilio/2010-04-01/Accounts/ACXXXX/Messages.json" \
  -d "To=%2B254700000000&From=%2B1234567890&Body=Hello"
```

### With proxy auth guard enabled

If `PROXY_AUTH_TOKEN` is set, include it as a Bearer token:

```bash
curl http://localhost:3000/proxy/ynab/v1/budgets \
  -H "Authorization: Bearer your-proxy-token"
```

---

## How It Works

1. Agent sends a request to `/proxy/:service/path`.
2. The proxy looks up `:service` in `services.json`.
3. It reads the API key from the environment variable named in `keyEnv`.
4. It **removes** any `Authorization` header the agent supplied (never trust agent-provided keys).
5. It injects the real key as the correct auth header.
6. It forwards the request to the real API base URL.
7. The response is streamed back to the agent.

The agent only ever sees:
- The service name (e.g. `resend`)
- The request path and body
- The response body

The agent never sees the API key value.

---

## Supported Services

| Service | Service Name | Env Variable |
|---------|-------------|--------------|
| Resend | `resend` | `RESEND_API_KEY` |
| YNAB | `ynab` | `YNAB_API_KEY` |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` |
| GitHub | `github` | `GITHUB_TOKEN` |
| Cloudflare | `cloudflare` | `CLOUDFLARE_API_TOKEN` |
| Safaricom Daraja | `safaricom-daraja` | `DARAJA_ACCESS_TOKEN` |
| Google Calendar | `google-calendar` | `GOOGLE_API_KEY` |
| Stripe | `stripe` | `STRIPE_SECRET_KEY` |
| Slack | `slack` | `SLACK_BOT_TOKEN` |
| Twilio | `twilio` | `TWILIO_AUTH_TOKEN` |
| Google Sheets | `google-sheets` | via Nango `isaac-google` (leave `GOOGLE_SHEETS_TOKEN` blank) |

Adding more services is a one-line edit in `services.json`.

---

## Security Notes

- **Never expose the proxy publicly without `PROXY_AUTH_TOKEN`** unless it runs on a private network.
- Treat `PROXY_AUTH_TOKEN` like an API key. Rotate it periodically.
- The proxy logs method + path but never logs key values or request bodies.
- For production deployments, run behind a reverse proxy (nginx, Caddy) with TLS.
- Secrets should be injected via your platform's secret management (Railway/Render env vars, Docker secrets, GCP Secret Manager).

---

## Troubleshooting

### Deploy takes more than 5 minutes
Check Railway logs (your project → Deployments → latest → Logs). If it's stuck at "Building", it may have hit a Railway quota limit.
- Out of free credits: Go to [Railway billing](https://railway.com/account/billing) and add a payment method ($5 tops up the free tier).
- Quota exceeded: Railway shows "Usage limit exceeded" in the deploy log. Upgrade plan or wait for monthly reset.
- If the deploy hangs indefinitely: Click "Cancel" and redeploy. Railway does not auto-timeout hung deploys.

### I deployed but my token is gone after a restart
If you didn't set `PROXY_AUTH_TOKEN` as a Railway environment variable, a new random token is generated each restart. Fix: in Railway dashboard → your project → Variables, set `PROXY_AUTH_TOKEN` to a value you control.

### `/proxy/ynab` returns a 404
Check that `YNAB_API_KEY` in Railway is a valid, unexpired token. YNAB tokens expire - regenerate at [app.youneedabudget.com/settings](https://app.youneedabudget.com/settings) → Personal Access Tokens. After updating the variable, Railway will redeploy automatically (takes ~90 seconds).

### I updated an env var but the proxy isn't picking it up
Railway redeploys automatically when you change variables - this takes about 90 seconds. Check the Deployments tab to confirm the redeploy triggered. If not, click "Redeploy" manually.

### The proxy starts but all services show `configured: false`
Your API keys are not set. Go to Railway dashboard → Variables and add the keys for the services you want to use. Only set keys you actually need.

---

## Contributing

PRs welcome. Add new services to `services.json`. Keep `index.js` under 150 lines.

---

## License

MIT. See [LICENSE](./LICENSE).

---

Built by [Kaara Works](https://kaara.works).
