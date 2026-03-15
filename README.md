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
Agent  -->  proxy/openai/chat/completions  -->  (proxy injects OPENAI_API_KEY)  -->  api.openai.com
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
| `authHeader` | HTTP header to inject (e.g. `Authorization` or `x-api-key`) |
| `authPrefix` | Header value prefix (e.g. `Bearer`; leave empty for raw key) |

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

| Variable | Description |
|----------|-------------|
| `PORT` | Port to listen on (default: `3000`) |
| `PROXY_AUTH_TOKEN` | Bearer token to guard the proxy. If unset, a random token is generated on startup and printed to logs. |
| `OPENAI_API_KEY` | OpenAI API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `RESEND_API_KEY` | Resend API key |
| `SENDGRID_API_KEY` | SendGrid API key |
| `YNAB_REFRESH_TOKEN` | YNAB OAuth refresh token |
| `YNAB_CLIENT_ID` | YNAB OAuth client ID |
| `YNAB_CLIENT_SECRET` | YNAB OAuth client secret |
| `OPENROUTER_API_KEY` | OpenRouter API key |
| `GITHUB_TOKEN` | GitHub personal access token |
| `NOTION_API_KEY` | Notion integration token |
| `AIRTABLE_API_KEY` | Airtable personal access token |
| `LINEAR_API_KEY` | Linear API key |
| `HUBSPOT_API_KEY` | HubSpot private app token |
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token |
| `STRIPE_SECRET_KEY` | Stripe secret key |
| `SLACK_BOT_TOKEN` | Slack bot token |
| `TWILIO_AUTH_TOKEN` | Twilio auth token |
| `QUICKBOOKS_REFRESH_TOKEN` | QuickBooks OAuth refresh token |
| `QUICKBOOKS_CLIENT_ID` | QuickBooks OAuth client ID |
| `QUICKBOOKS_CLIENT_SECRET` | QuickBooks OAuth client secret |
| `DARAJA_ACCESS_TOKEN` | Safaricom Daraja access token |

Only set the keys you need. Unconfigured services return a clear `503` with instructions.

---

## Usage

### Check health

```bash
curl http://localhost:3000/health
```

### List services

```bash
curl http://localhost:3000/services
```

### Make a proxied request

Replace the real API base URL with `http://localhost:3000/proxy/:service`.

**OpenAI - chat completion**
```bash
curl -X POST http://localhost:3000/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{ "role": "user", "content": "Hello" }]
  }'
```

**Anthropic - messages**
```bash
curl -X POST http://localhost:3000/proxy/anthropic/v1/messages \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-3-5-haiku-20241022",
    "max_tokens": 1024,
    "messages": [{ "role": "user", "content": "Hello" }]
  }'
```

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

**Notion - query a database**
```bash
curl -X POST http://localhost:3000/proxy/notion/v1/databases/DATABASE_ID/query \
  -H "Content-Type: application/json" \
  -H "Notion-Version: 2022-06-28"
```

**GitHub - list repos**
```bash
curl http://localhost:3000/proxy/github/user/repos
```

**Stripe - list customers**
```bash
curl http://localhost:3000/proxy/stripe/v1/customers
```

**Linear - list issues (GraphQL)**
```bash
curl -X POST http://localhost:3000/proxy/linear/graphql \
  -H "Content-Type: application/json" \
  -d '{ "query": "{ viewer { id name } }" }'
```

### With proxy auth guard enabled

If `PROXY_AUTH_TOKEN` is set, include it as a Bearer token:

```bash
curl http://localhost:3000/proxy/openai/v1/models \
  -H "Authorization: Bearer your-proxy-token"
```

---

## How It Works

1. Agent sends a request to `/proxy/:service/path`.
2. The proxy looks up `:service` in `services.json`.
3. It reads the API key from the environment variable named in `keyEnv`.
4. It **removes** any auth header the agent supplied (never trust agent-provided keys).
5. It injects the real key as the correct auth header.
6. It forwards the request to the real API base URL.
7. The response is streamed back to the agent.

The agent only ever sees the service name, the request path and body, and the response. The key value never leaves the server.

---

## Supported Services

| Service | Service Name | Env Variable | Auth Type |
|---------|-------------|--------------|-----------|
| OpenAI | `openai` | `OPENAI_API_KEY` | Bearer |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | x-api-key |
| Resend | `resend` | `RESEND_API_KEY` | Bearer |
| SendGrid | `sendgrid` | `SENDGRID_API_KEY` | Bearer |
| YNAB | `ynab` | `YNAB_REFRESH_TOKEN` | OAuth (auto-refresh) |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` | Bearer |
| GitHub | `github` | `GITHUB_TOKEN` | Bearer |
| Notion | `notion` | `NOTION_API_KEY` | Bearer |
| Airtable | `airtable` | `AIRTABLE_API_KEY` | Bearer |
| Linear | `linear` | `LINEAR_API_KEY` | Bearer |
| HubSpot | `hubspot` | `HUBSPOT_API_KEY` | Bearer |
| Stripe | `stripe` | `STRIPE_SECRET_KEY` | Bearer |
| Slack | `slack` | `SLACK_BOT_TOKEN` | Bearer |
| Twilio | `twilio` | `TWILIO_AUTH_TOKEN` | Bearer |
| Cloudflare | `cloudflare` | `CLOUDFLARE_API_TOKEN` | Bearer |
| QuickBooks | `quickbooks` | `QUICKBOOKS_REFRESH_TOKEN` | OAuth (auto-refresh) |
| Safaricom Daraja | `safaricom-daraja` | `DARAJA_ACCESS_TOKEN` | Bearer |
| Google Sheets | `google-sheets` | via Nango | OAuth (Nango) |

Adding more services is a one-line edit in `services.json`.

---

## Gmail Integration

The proxy includes a purpose-built Gmail integration at `/api/gmail/...` that supports three auth methods (in priority order):

1. **Direct OAuth** (recommended) -- provide `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`, and `GMAIL_REFRESH_TOKEN`.
2. **Google Service Account** -- provide `GOOGLE_SERVICE_ACCOUNT_KEY` (JSON) and `GMAIL_IMPERSONATE_EMAIL` for domain-wide delegation.
3. **Nango OAuth** -- provide `NANGO_SECRET_KEY`, `NANGO_CONNECTION_ID`, and `NANGO_PROVIDER_CONFIG_KEY=google`.

Available endpoints:
- `POST /api/gmail/drafts/create`
- `POST /api/gmail/drafts/send`
- `POST /api/gmail/messages/send`
- `GET  /api/gmail/messages`
- `GET  /api/gmail/messages/:id`
- `DELETE /api/gmail/messages/:id`

---

## Google Sheets Integration

Google Sheets is proxied at `/proxy/google-sheets/...` and fetches OAuth tokens automatically via Nango.

Set these three environment variables to enable it:

| Variable | Description |
|----------|-------------|
| `NANGO_SECRET_KEY` | Your Nango secret key |
| `NANGO_CONNECTION_ID` | The Nango connection ID for your Google account |
| `NANGO_PROVIDER_CONFIG_KEY` | The Nango provider config key (usually `google`) |

Tokens are cached for 55 minutes and refreshed automatically on expiry or 401 responses.

---

## Security Notes

- **Never expose the proxy publicly without `PROXY_AUTH_TOKEN`** unless it runs on a private network.
- Treat `PROXY_AUTH_TOKEN` like an API key. Rotate it periodically.
- The proxy logs method and path but never logs key values or request bodies.
- For production, run behind a reverse proxy (nginx, Caddy) with TLS.
- Inject secrets via your platform's secret management (Railway/Render env vars, Docker secrets, GCP Secret Manager).

---

## Troubleshooting

### Deploy takes more than 5 minutes
Check Railway logs (your project -> Deployments -> latest -> Logs). If stuck at "Building", you may have hit a Railway quota limit. Go to [Railway billing](https://railway.com/account/billing) to check. If the deploy hangs indefinitely, click "Cancel" and redeploy.

### My token disappears after a restart
If you did not set `PROXY_AUTH_TOKEN` as an environment variable, a new random token is generated each restart. Fix: add `PROXY_AUTH_TOKEN` to your Railway Variables with a value you control.

### `/proxy/ynab` returns 401
YNAB uses OAuth. Make sure `YNAB_REFRESH_TOKEN`, `YNAB_CLIENT_ID`, and `YNAB_CLIENT_SECRET` are all set. The proxy handles token refresh automatically.

### I updated an env var but nothing changed
Railway redeploys automatically when you change variables -- this takes about 90 seconds. Check the Deployments tab to confirm. If not triggered, click "Redeploy" manually.

### All services show `configured: false`
Your API keys are not set. Go to your host's environment variables and add the keys for the services you need.

---

## Contributing

PRs welcome. Add new services to `services.json` -- no code changes required for standard key-based APIs. Keep `index.js` focused on infrastructure, not service-specific logic.

---

## License

MIT. See [LICENSE](./LICENSE).

---

MIT License. Built for the open-source community.
