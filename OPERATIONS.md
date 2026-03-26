# Operations & Runbook

Zero-Knowledge API Proxy
Production Deployment & Maintenance

---

## Deployment

### Railway

1. **One-click deploy:**
   [![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template?template=https://github.com/isaackaara/openclaw-api-proxy)

2. **Manual deploy:**
   ```bash
   # Install Railway CLI
   npm i -g @railway/cli
   
   # Login
   railway login
   
   # Create project
   railway init
   
   # Add variables in Railway dashboard
   PORT=3000
   YNAB_API_KEY=***
   RESEND_API_KEY=***
   PROXY_AUTH_TOKEN=*** (optional but recommended)
   
   # Deploy
   railway up
   ```

3. **GitHub auto-deploy:**
   - Connect repo to Railway
   - Enable auto-deploy on push to `main`
   - Every commit automatically builds and deploys

### Render

1. **One-click deploy:**
   [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/isaackaara/openclaw-api-proxy)

2. **Manual deploy:**
   - Create Web Service
   - GitHub repo: isaackaara/openclaw-api-proxy
   - Build Command: `npm install`
   - Start Command: `npm start`
   - Add environment variables (same as Railway)
   - Deploy

### Docker (local or private cloud)

```bash
# Build
docker build -t openclaw-api-proxy:latest .

# Run
docker run -p 3000:3000 \
  -e YNAB_API_KEY=*** \
  -e RESEND_API_KEY=*** \
  -e PROXY_AUTH_TOKEN=*** \
  openclaw-api-proxy:latest

# Or use docker-compose
docker compose up -d
```

---

## Configuration

### Environment Variables

All variables are optional except `PORT` (defaults to 3000).

```bash
# Server
PORT=3000

# Auth guard (recommended for production)
PROXY_AUTH_TOKEN=your-secret-bearer-token-here

# API Keys (only set the ones you need)
YNAB_API_KEY=
RESEND_API_KEY=
GITHUB_TOKEN=
OPENROUTER_API_KEY=
STRIPE_SECRET_KEY=
CLOUDFLARE_API_TOKEN=
GOOGLE_API_KEY=
SLACK_BOT_TOKEN=
TWILIO_AUTH_TOKEN=
DARAJA_ACCESS_TOKEN=

# Gmail via Nango OAuth
NANGO_SECRET_KEY=
NANGO_CONNECTION_ID=
NANGO_PROVIDER_CONFIG_KEY=google
```

### Rotating API Keys

No downtime required:

1. Update the environment variable on Railway/Render/Docker
2. Restart (Railway: one button; Render: automatic; Docker: restart container)
3. Next request uses new key
4. Old connections finish with old key, new ones use new

---

## Monitoring

### Health Check

```bash
curl http://your-proxy.railway.app/health
```

Response:
```json
{
  "status": "ok",
  "services": [
    { "name": "ynab", "configured": true },
    { "name": "resend", "configured": false }
  ],
  "gmail": { "configured": false, "endpoints": [...] }
}
```

### Logs

**Railway:**
- Logs tab in dashboard
- Auto-rotate after 100 MB
- 30-day retention

**Render:**
- Logs in dashboard
- Auto-rotate and compress
- 7-day retention

**Docker:**
- `docker logs <container-id>`
- Delegate rotation to log driver (`--log-driver=json-file --log-opt max-size=10m`)

### Metrics

**Railway:**
- CPU usage (typically <5%)
- Memory usage (typically 50-100 MB)
- Requests/sec
- Response times

**Render:**
- CPU, memory, disk
- Request count + response times
- Uptime percentage

**Both:** Set alerts for:
- CPU > 80%
- Memory > 200 MB
- Error rate > 5%
- Response time > 5s

---

## Incident Runbook

### Scenario: Upstream API Error (502/503)

**Symptoms:**
- Requests to `/proxy/:service` return 502 or 503
- Proxy logs show "Proxy error" message

**Diagnosis:**
1. Check if upstream API is down: `curl https://api.youneedabudget.com/health` (or service-specific health endpoint)
2. Check Railway/Render metrics: is the proxy CPU/memory normal?
3. Check proxy logs: are there error messages?

**Resolution:**
1. If upstream is down: wait for their recovery, no action needed (proxy is working correctly)
2. If proxy is overloaded: scale up (Railway: increase dyno, Render: increase instance size)
3. If proxy crashed: check logs for error, restart

**Prevent:**
- Monitor upstream API status page
- Set alert on Sentry/Rollbar for 5xx errors
- Have fallback API keys (backup YNAB account, etc.)

---

### Scenario: Authentication Error (401)

**Symptoms:**
- All requests to proxy return 401
- Logs show "Unauthorized"

**Diagnosis:**
1. Is `PROXY_AUTH_TOKEN` set? Check Railway/Render dashboard
2. Are clients sending the correct token?

**Resolution:**
1. If clients missing token: send them the correct header: `Authorization: Bearer <token>`
2. If token is wrong: reset it in environment variables, notify clients with new token

**Prevent:**
- Document token in team wiki
- Rotate token every 90 days (calendar reminder)
- Use strong random tokens (32+ chars)

---

### Scenario: API Key Expired

**Symptoms:**
- Some requests to `/proxy/:service` return 401 or 403
- Service-specific (e.g., only YNAB fails, others work)

**Diagnosis:**
1. Which service is failing? Check logs
2. Is the API key valid? Test directly with `curl https://api.service.com -H "Authorization: Bearer $KEY"`

**Resolution:**
1. Generate new API key from service's dashboard
2. Update environment variable on Railway/Render
3. Restart proxy (automatic on Railway, manual on Render)
4. Test: `curl http://your-proxy/proxy/service/health`

**Prevent:**
- Document all API key expiration dates in a shared doc
- Set calendar reminders 2 weeks before expiry
- Rotate keys annually even if not expired

---

### Scenario: Proxy Memory Leak

**Symptoms:**
- Memory usage grows over 24 hours
- Eventually crashes (Render) or gets OOMkilled (Railway)

**Diagnosis:**
1. Check Railway/Render memory graph: is it steadily rising?
2. Check request count: is traffic normal?
3. If memory rises with traffic, it's a real leak

**Resolution:**
1. Restart proxy immediately (stops leak, buys time)
2. Review recent code changes (index.js)
3. Check for accumulating arrays, event listeners not cleaned up
4. Open issue on GitHub

**Prevent:**
- Monitor memory % weekly
- Set alert at 80% on Railway/Render
- Automatic restart on daily/weekly schedule (Railway: use cron plugin; Render: built-in)

---

## Scaling

### Single Dyno Limits

- **Requests/sec:** 100+ (no load balancing needed)
- **Concurrent connections:** 100+ (Node.js default)
- **Daily requests:** 1M+ (based on 10 req/sec average)
- **Data throughput:** 10 GB+/month (minimal proxy overhead)
- **Storage:** Logs only (auto-rotated, no bloat)

### When to Scale

| Metric | Threshold | Action |
|--------|-----------|--------|
| CPU | > 80% for 5 min | Increase dyno size (Starter → Standard) |
| Memory | > 200 MB | Check for memory leak (see incident above) or increase dyno |
| Error rate | > 5% | Check logs; is upstream API down or misconfigured? |
| Response time | > 5s avg | Check upstream latency; scale if needed |

### Horizontal Scaling

Railway:
1. Enable "Private Networking"
2. Add replica: Dashboard → Deployments → + Add Deployment
3. Use Railway Load Balancer: Configure → Load Balancing

Render:
1. Create second instance of same service
2. Use Render Load Balancer (auto-configured)

Docker (multi-instance):
```bash
# Use Docker Swarm or Kubernetes
# Nginx load balancer in front
upstream proxy_backend {
  server proxy1:3000;
  server proxy2:3000;
  server proxy3:3000;
}

server {
  listen 80;
  location / {
    proxy_pass http://proxy_backend;
    proxy_set_header Host $host;
  }
}
```

---

## Backups & Disaster Recovery

**No backups needed.** The proxy is stateless:
- No database
- No configuration files stored
- No user data
- Only environment variables (secrets stored in Railway/Render/Docker)

**Disaster recovery:**
1. If entire deployment deleted: clone repo and redeploy (5 minutes)
2. If environment variables lost: restore from team documentation (every API key should be backed up in a secrets vault)

**Recommended backup strategy:**
- Store all API keys in password manager (1Password, Bitwarden, etc.)
- Document which key belongs to which service in a shared wiki
- Test API key rotation quarterly

---

## Maintenance Tasks

### Daily
- [ ] Check health endpoint: `curl http://your-proxy/health`
- [ ] Verify no errors in logs (filter for ERROR and WARN)

### Weekly
- [ ] Review memory usage graph
- [ ] Check error rate < 1%
- [ ] Verify all configured services are responding

### Monthly
- [ ] Test API key rotation (if any keys expire soon)
- [ ] Review proxy logs for patterns (which services used most, any issues)
- [ ] Update dependencies: `npm audit fix`

### Quarterly
- [ ] Rotate PROXY_AUTH_TOKEN
- [ ] Rotate API keys (or verify they don't expire)
- [ ] Test disaster recovery (redeploy from scratch)

### Annually
- [ ] Review all 10 upstream services for API changes
- [ ] Update services.json if any APIs changed auth format
- [ ] Update README with new examples or clarifications
- [ ] Review security audit, rerun tests

---

## Troubleshooting

### Proxy won't start

**Check:**
1. Is services.json valid JSON? `cat services.json | jq .`
2. Are there syntax errors in index.js? `npm start` shows line numbers
3. Is PORT already in use? `lsof -i :3000` (on local machine)

**Fix:**
1. Validate JSON and JavaScript syntax
2. Kill process on PORT: `kill -9 $(lsof -t -i:3000)`
3. Restart: `npm start`

### Requests timeout

**Check:**
1. Is upstream API responding? `curl https://api.service.com`
2. Is proxy CPU spiked? Check Railway/Render dashboard
3. Is network connectivity OK? `ping 8.8.8.8`

**Fix:**
1. If upstream slow: nothing to do (pass through delay)
2. If proxy slow: scale up dyno or restart
3. If network bad: check Rails/Render infrastructure status

### SSL/TLS certificate errors

**Check:**
1. Are you using https://? Proxy should be accessed via `https://your-proxy.railway.app` (auto-managed by Railway/Render)
2. Are you running Docker locally? Use `http://localhost:3000` (no TLS needed internally)

**Fix:**
1. Use HTTPS for external access (Railway/Render auto-setup)
2. For Docker: place behind nginx with Let's Encrypt

---

## Cost Optimization

### Current Costs (Single Dyno)

- **Railway Starter:** ~$5/month
- **Render Free:** $0/month (auto-sleeps if unused)
- **Render Standard:** ~$12/month (always-on)
- **Docker self-hosted:** your infrastructure cost

### Cost Optimization

- Use Railway Starter (cheapest, includes 500 free hours)
- Use Render Free tier if traffic is bursty (wakes up on request)
- Monitor usage: if < 100 requests/day, Render Free is better
- If > 1M requests/month, consider self-hosted Docker + cheap VPS

---

## Support & Escalation

**User asks a question → GitHub issue**

1. Check README / Troubleshooting first
2. If not answered: ask in OpenClaw Discord
3. If technical bug: post GitHub issue with logs

**We (maintainers) respond within 48 hours on GitHub issues.**

---

**Maintained by:** Kaara Works
**Last Updated:** 2026-03-13
