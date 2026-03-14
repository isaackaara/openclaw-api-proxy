/**
 * openclaw-api-proxy
 * Zero-knowledge API proxy for AI agents.
 * Agents call this proxy with a service name; the proxy injects the real API key
 * from environment variables and forwards the request. Keys never appear in agent context.
 *
 * MIT License
 */

const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");
const path = require("path");
const fs = require("fs");
const https = require("https");

const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// Auto-generate a secure token if none is set.
// This means a fresh deploy is always auth-guarded - never open by accident.
// The generated token is printed to Railway logs on startup so the user can copy it.
let PROXY_AUTH_TOKEN = process.env.PROXY_AUTH_TOKEN || null;
if (!PROXY_AUTH_TOKEN) {
  PROXY_AUTH_TOKEN = crypto.randomBytes(32).toString("hex");
  console.warn("======================================================");
  console.warn("PROXY_AUTH_TOKEN was not set. A temporary token has");
  console.warn("been generated for this session:");
  console.warn(`  ${PROXY_AUTH_TOKEN}`);
  console.warn("Add PROXY_AUTH_TOKEN to your Railway environment variables");
  console.warn("to make this token permanent across restarts.");
  console.warn("======================================================");
}

// Load service registry
const servicesPath = path.join(__dirname, "services.json");
const SERVICES = JSON.parse(fs.readFileSync(servicesPath, "utf8"));

// Body parsing for /api/* routes
app.use("/api", express.json({ limit: "10mb" }));

// Optional: request logger
app.use((req, res, next) => {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${req.method} ${req.path}`);
  next();
});

// Optional bearer token auth guard
// /health and /services are exempt so Railway's healthcheck (no auth header) passes
app.use((req, res, next) => {
  if (!PROXY_AUTH_TOKEN) return next();
  if (req.path === "/health" || req.path === "/services") return next();
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (token !== PROXY_AUTH_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
});

// Health check
app.get("/health", (req, res) => {
  const services = Object.keys(SERVICES).map((name) => ({
    name,
    configured: !!process.env[SERVICES[name].keyEnv],
  }));
  const nangoConfigured = !!(
    process.env.NANGO_SECRET_KEY &&
    process.env.NANGO_CONNECTION_ID &&
    process.env.NANGO_PROVIDER_CONFIG_KEY
  );
  const nangoSheetsConfigured = !!process.env.NANGO_SECRET_KEY;
  res.json({
    status: "ok",
    services,
    gmail: {
      configured: nangoConfigured,
      endpoints: [
        "POST /api/gmail/drafts/create",
        "POST /api/gmail/drafts/send",
        "POST /api/gmail/messages/send",
        "GET  /api/gmail/messages",
        "GET  /api/gmail/messages/:id",
        "DELETE /api/gmail/messages/:id",
      ],
    },
    "google-sheets": {
      configured: nangoSheetsConfigured,
      note: "Uses Nango (provider: google, connectionId: isaac-google) - token auto-fetched and cached 55 min",
      endpoint: "GET|POST /proxy/google-sheets/spreadsheets/...",
    },
  });
});

// List available services
app.get("/services", (req, res) => {
  const list = Object.entries(SERVICES).map(([name, cfg]) => ({
    name,
    baseUrl: cfg.baseUrl,
    keyConfigured: !!process.env[cfg.keyEnv],
  }));
  res.json(list);
});

// --------------------------------------------------------------------------
// QB OAuth: token cache (in-memory, service-keyed) - QB tokens valid 3600s
// --------------------------------------------------------------------------
const _oauthTokenCache = {};

/**
 * Fetch (or return cached) QB access token using stored refresh token.
 * Refreshes 5 min before expiry (TTL = expires_in - 300s).
 * On failure throws; caller should return 503.
 */
async function getOAuthAccessToken(serviceName, config) {
  const oauthConf = config.oauth;
  const cached = _oauthTokenCache[serviceName];
  if (cached && cached.expiresAt > Date.now()) {
    return cached.accessToken;
  }

  const clientId = process.env[oauthConf.clientIdEnv];
  const clientSecret = process.env[oauthConf.clientSecretEnv];
  const refreshToken = process.env[config.keyEnv];

  if (!clientId || !clientSecret || !refreshToken) {
    throw new Error(
      `QB OAuth: missing env vars - need ${oauthConf.clientIdEnv}, ${oauthConf.clientSecretEnv}, ${config.keyEnv}`
    );
  }

  return new Promise((resolve, reject) => {
    const body = `grant_type=${oauthConf.grantType}&refresh_token=${encodeURIComponent(refreshToken)}`;
    const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
    const tokenUrl = new URL(oauthConf.tokenUrl);

    const options = {
      hostname: tokenUrl.hostname,
      port: 443,
      path: tokenUrl.pathname,
      method: "POST",
      headers: {
        Authorization: `Basic ${credentials}`,
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body),
        Accept: "application/json",
      },
    };

    const req = https.request(options, (resp) => {
      let data = "";
      resp.on("data", (chunk) => (data += chunk));
      resp.on("end", () => {
        try {
          const parsed = JSON.parse(data);
          if (!parsed.access_token) {
            return reject(
              new Error(`QB OAuth: no access_token in response (HTTP ${resp.statusCode}): ${data.slice(0, 200)}`)
            );
          }
          const expiresIn = parsed.expires_in || 3600;
          const ttl = (expiresIn - 300) * 1000; // refresh 5 min early
          _oauthTokenCache[serviceName] = {
            accessToken: parsed.access_token,
            expiresAt: Date.now() + ttl,
          };
          console.log(`[QB OAuth] Refreshed access token, expires in ${expiresIn}s`);
          resolve(parsed.access_token);
        } catch (e) {
          reject(new Error(`QB OAuth: failed to parse response: ${data.slice(0, 200)}`));
        }
      });
    });

    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

// --------------------------------------------------------------------------
// Nango: token cache (per provider:connectionId) - Google tokens valid 60 min
// --------------------------------------------------------------------------
const _nangoTokenCache = {};

async function getNangoTokenFor(provider, connectionId) {
  const NANGO_SECRET = process.env.NANGO_SECRET_KEY;
  if (!NANGO_SECRET) throw new Error("NANGO_SECRET_KEY not configured");

  const cacheKey = `${provider}:${connectionId}`;
  const cached = _nangoTokenCache[cacheKey];
  if (cached && cached.expiresAt > Date.now()) {
    return cached.token;
  }

  return new Promise((resolve, reject) => {
    const reqPath = `/connection/${connectionId}?provider_config_key=${provider}&force_refresh=false`;
    const options = {
      hostname: "api.nango.dev",
      port: 443,
      path: reqPath,
      method: "GET",
      headers: { Authorization: `Bearer ${NANGO_SECRET}` },
    };

    const req = https.request(options, (resp) => {
      let data = "";
      resp.on("data", (chunk) => (data += chunk));
      resp.on("end", () => {
        try {
          const parsed = JSON.parse(data);
          const token = parsed?.credentials?.access_token;
          if (!token) {
            return reject(
              new Error(`Nango: no access_token for ${provider}:${connectionId} (status ${resp.statusCode})`)
            );
          }
          // Cache for 55 min (Google tokens valid 60 min)
          _nangoTokenCache[cacheKey] = { token, expiresAt: Date.now() + 55 * 60 * 1000 };
          resolve(token);
        } catch (e) {
          reject(new Error(`Nango: failed to parse response: ${data.slice(0, 200)}`));
        }
      });
    });

    req.on("error", reject);
    req.end();
  });
}

// --------------------------------------------------------------------------
// Nango: get current OAuth access token for Gmail (backward-compat wrapper)
// --------------------------------------------------------------------------
async function getNangoToken() {
  const CONNECTION_ID = process.env.NANGO_CONNECTION_ID;
  const PROVIDER_CONFIG_KEY = process.env.NANGO_PROVIDER_CONFIG_KEY || "google";

  if (!CONNECTION_ID) {
    throw new Error("NANGO_SECRET_KEY or NANGO_CONNECTION_ID not configured");
  }

  return getNangoTokenFor(PROVIDER_CONFIG_KEY, CONNECTION_ID);
}

// --------------------------------------------------------------------------
// Gmail API helper: call Gmail directly with Nango-sourced OAuth token
// --------------------------------------------------------------------------
function gmailRequest({ method, path, body, query, token }) {
  return new Promise((resolve, reject) => {
    const qs = query ? "?" + new URLSearchParams(query).toString() : "";
    const reqPath = `/gmail/v1${path}${qs}`;
    const bodyStr = body ? JSON.stringify(body) : null;

    const options = {
      hostname: "gmail.googleapis.com",
      port: 443,
      path: reqPath,
      method: method.toUpperCase(),
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    };

    if (bodyStr) {
      options.headers["Content-Length"] = Buffer.byteLength(bodyStr);
    }

    const req = https.request(options, (resp) => {
      let data = "";
      resp.on("data", (chunk) => (data += chunk));
      resp.on("end", () => {
        try {
          resolve({ status: resp.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: resp.statusCode, body: data });
        }
      });
    });

    req.on("error", reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

// Convenience: get token then call Gmail
async function nangoRequest({ method, path, body, query }) {
  const token = await getNangoToken();
  return gmailRequest({ method, path, body, query, token });
}

// --------------------------------------------------------------------------
// RFC 2822 email builder -> base64url encoded "raw" field for Gmail API
// --------------------------------------------------------------------------
function buildRawEmail({ to, from, subject, body, bodyHtml, replyTo, cc, bcc }) {
  // Auto-detect HTML: if body contains HTML tags and bodyHtml isn't set, treat body as HTML.
  // This handles the common agent mistake of passing HTML in `body` instead of `bodyHtml`.
  const htmlPattern = /<(html|body|div|p|table|h[1-6]|ul|ol|li|br|a|img|span|strong|em|style)[^>]*>/i;
  if (!bodyHtml && body && (htmlPattern.test(body) || /^<!DOCTYPE\s+html/i.test(body.trim()))) {
    console.log("[buildRawEmail] Auto-detected HTML in body field - treating as bodyHtml");
    bodyHtml = body;
    body = body.replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim(); // strip tags for plain-text fallback
  }

  const lines = [];
  lines.push(`From: ${from}`);
  lines.push(`To: ${to}`);
  if (cc) lines.push(`Cc: ${cc}`);
  if (bcc) lines.push(`Bcc: ${bcc}`);
  if (replyTo) lines.push(`Reply-To: ${replyTo}`);
  lines.push(`Subject: ${subject}`);
  lines.push(`MIME-Version: 1.0`);

  if (bodyHtml) {
    const boundary = `----=_Part_${Date.now()}`;
    lines.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);
    lines.push("");
    lines.push(`--${boundary}`);
    lines.push("Content-Type: text/plain; charset=UTF-8");
    lines.push("Content-Transfer-Encoding: 7bit");
    lines.push("");
    lines.push(body || "");
    lines.push(`--${boundary}`);
    lines.push("Content-Type: text/html; charset=UTF-8");
    lines.push("Content-Transfer-Encoding: 7bit");
    lines.push("");
    lines.push(bodyHtml);
    lines.push(`--${boundary}--`);
  } else {
    lines.push("Content-Type: text/plain; charset=UTF-8");
    lines.push("Content-Transfer-Encoding: 7bit");
    lines.push("");
    lines.push(body || "");
  }

  const raw = lines.join("\r\n");
  // Base64url encode (Gmail requires URL-safe base64 without padding)
  return Buffer.from(raw)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// --------------------------------------------------------------------------
// Gmail API routes
// All routes: /api/gmail/...
// --------------------------------------------------------------------------

/**
 * POST /api/gmail/drafts/create
 * Body: { to, from, subject, body, bodyHtml?, cc?, bcc?, replyTo? }
 * Returns: { draftId, threadId, message }
 */
app.post("/api/gmail/drafts/create", async (req, res) => {
  const { to, from, subject, body, bodyHtml, cc, bcc, replyTo } = req.body || {};
  if (!to || !subject) {
    return res.status(400).json({ error: "Missing required fields: to, subject" });
  }

  const raw = buildRawEmail({ to, from, subject, body, bodyHtml, cc, bcc, replyTo });

  try {
    const result = await nangoRequest({
      method: "POST",
      path: "/users/me/drafts",
      body: { message: { raw } },
    });

    if (result.status >= 200 && result.status < 300) {
      return res.status(200).json({
        success: true,
        draftId: result.body.id,
        threadId: result.body.message?.threadId,
        messageId: result.body.message?.id,
        raw: result.body,
      });
    }
    return res.status(result.status).json({ error: "Nango error", detail: result.body });
  } catch (err) {
    console.error("[gmail/drafts/create] Error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/gmail/drafts/send
 * Body: { draftId }
 * Returns: { messageId, threadId, labelIds }
 */
app.post("/api/gmail/drafts/send", async (req, res) => {
  const { draftId } = req.body || {};
  if (!draftId) {
    return res.status(400).json({ error: "Missing required field: draftId" });
  }

  try {
    const result = await nangoRequest({
      method: "POST",
      path: "/users/me/drafts/send",
      body: { id: draftId },
    });

    if (result.status >= 200 && result.status < 300) {
      return res.status(200).json({
        success: true,
        messageId: result.body.id,
        threadId: result.body.threadId,
        labelIds: result.body.labelIds,
        raw: result.body,
      });
    }
    return res.status(result.status).json({ error: "Nango error", detail: result.body });
  } catch (err) {
    console.error("[gmail/drafts/send] Error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/gmail/messages/send
 * Body: { to, from, subject, body, bodyHtml?, cc?, bcc?, replyTo? }
 * Builds and sends directly (no draft step)
 * Returns: { messageId, threadId, labelIds }
 */
app.post("/api/gmail/messages/send", async (req, res) => {
  const { to, from, subject, body, bodyHtml, cc, bcc, replyTo } = req.body || {};
  if (!to || !subject) {
    return res.status(400).json({ error: "Missing required fields: to, subject" });
  }

  const raw = buildRawEmail({ to, from, subject, body, bodyHtml, cc, bcc, replyTo });

  try {
    const result = await nangoRequest({
      method: "POST",
      path: "/users/me/messages/send",
      body: { raw },
    });

    if (result.status >= 200 && result.status < 300) {
      return res.status(200).json({
        success: true,
        messageId: result.body.id,
        threadId: result.body.threadId,
        labelIds: result.body.labelIds,
        raw: result.body,
      });
    }
    return res.status(result.status).json({ error: "Nango error", detail: result.body });
  } catch (err) {
    console.error("[gmail/messages/send] Error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/gmail/messages
 * Query: ?q=is:unread&maxResults=10&pageToken=...
 * Returns: { messages, nextPageToken, resultSizeEstimate }
 */
app.get("/api/gmail/messages", async (req, res) => {
  const { q, maxResults, pageToken, labelIds } = req.query;
  const query = {};
  if (q) query.q = q;
  if (maxResults) query.maxResults = maxResults;
  if (pageToken) query.pageToken = pageToken;
  if (labelIds) query.labelIds = labelIds;

  try {
    const result = await nangoRequest({
      method: "GET",
      path: "/users/me/messages",
      query,
    });

    if (result.status >= 200 && result.status < 300) {
      return res.status(200).json({
        success: true,
        messages: result.body.messages || [],
        nextPageToken: result.body.nextPageToken,
        resultSizeEstimate: result.body.resultSizeEstimate,
      });
    }
    return res.status(result.status).json({ error: "Nango error", detail: result.body });
  } catch (err) {
    console.error("[gmail/messages] Error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/gmail/messages/:id
 * Query: ?format=full|metadata|minimal|raw
 * Returns: full message object
 */
app.get("/api/gmail/messages/:id", async (req, res) => {
  const { id } = req.params;
  const { format } = req.query;
  const query = {};
  if (format) query.format = format;

  try {
    const result = await nangoRequest({
      method: "GET",
      path: `/users/me/messages/${id}`,
      query: Object.keys(query).length ? query : undefined,
    });

    if (result.status >= 200 && result.status < 300) {
      return res.status(200).json({ success: true, message: result.body });
    }
    return res.status(result.status).json({ error: "Nango error", detail: result.body });
  } catch (err) {
    console.error("[gmail/messages/:id] Error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/gmail/messages/:id
 * Moves message to trash (safe; use ?permanent=true to permanently delete)
 * Returns: { success: true, messageId }
 */
app.delete("/api/gmail/messages/:id", async (req, res) => {
  const { id } = req.params;
  const permanent = req.query.permanent === "true";

  try {
    let result;
    if (permanent) {
      result = await nangoRequest({
        method: "DELETE",
        path: `/users/me/messages/${id}`,
      });
    } else {
      result = await nangoRequest({
        method: "POST",
        path: `/users/me/messages/${id}/trash`,
      });
    }

    if (result.status >= 200 && result.status < 300) {
      return res.status(200).json({
        success: true,
        messageId: id,
        permanent,
        raw: result.body,
      });
    }
    return res.status(result.status).json({ error: "Nango error", detail: result.body });
  } catch (err) {
    console.error("[gmail/messages/:id DELETE] Error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

// --------------------------------------------------------------------------
// Dynamic proxy: /proxy/:service/*  (existing API key services)
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// Pre-flight check: block requests to unconfigured services BEFORE proxy forwards.
// This prevents the agent's Authorization header (proxy token) from leaking to
// upstream APIs when a service env var is missing.
// --------------------------------------------------------------------------
Object.entries(SERVICES).forEach(([serviceName, config]) => {
  app.use(`/proxy/${serviceName}`, (req, res, next) => {
    // Skip env-var check for Nango-backed or OAuth services - they check their own vars in the token middleware
    if (config.nango || config.oauth) return next();
    const apiKey = process.env[config.keyEnv];
    if (!apiKey) {
      return res.status(503).json({
        error: 'Service not configured',
        service: serviceName,
        message: `Missing environment variable: ${config.keyEnv}`,
        action: `Add ${config.keyEnv} to Railway Variables and deploy`,
        docs: 'https://github.com/isaackaara/openclaw-api-proxy#configuration'
      });
    }
    next();
  });
});

// Pre-middleware: for services with Nango OAuth config, fetch token before proxying
// nango config supports direct values (provider/connectionId) or env var references (providerEnv/connectionIdEnv)
for (const [serviceName, config] of Object.entries(SERVICES)) {
  if (!config.nango) continue;
  app.use(`/proxy/${serviceName}`, async (req, res, next) => {
    const nangoConf = config.nango;
    const provider = nangoConf.provider || (nangoConf.providerEnv && process.env[nangoConf.providerEnv]) || "google";
    const connectionId = nangoConf.connectionId || (nangoConf.connectionIdEnv && process.env[nangoConf.connectionIdEnv]);
    if (!connectionId) {
      return res.status(503).json({ error: "Nango connection not configured", service: serviceName, detail: "Set NANGO_CONNECTION_ID in Railway Variables" });
    }
    try {
      req._nangoToken = await getNangoTokenFor(provider, connectionId);
      next();
    } catch (err) {
      console.error(`[ERROR] Nango token fetch for ${serviceName}:`, err.message);
      res.status(502).json({ error: "Nango token fetch failed", service: serviceName, detail: err.message });
    }
  });
}

// Pre-middleware: for services with QB-style OAuth config, fetch access token before proxying
for (const [serviceName, config] of Object.entries(SERVICES)) {
  if (!config.oauth) continue;
  app.use(`/proxy/${serviceName}`, async (req, res, next) => {
    try {
      req._nangoToken = await getOAuthAccessToken(serviceName, config);
      next();
    } catch (err) {
      console.error(`[ERROR] QB OAuth token fetch for ${serviceName}:`, err.message);
      res.status(503).json({ error: "QB OAuth token refresh failed", service: serviceName, detail: err.message });
    }
  });
}

for (const [serviceName, config] of Object.entries(SERVICES)) {
  const { baseUrl, keyEnv, authHeader, authPrefix } = config;

  app.use(
    `/proxy/${serviceName}`,
    createProxyMiddleware({
      target: baseUrl,
      changeOrigin: true,
      pathRewrite: (path) => {
        // Strip /proxy/serviceName from the beginning
        const rewritten = path.replace(new RegExp(`^/proxy/${serviceName}`), "");
        if (serviceName === 'ynab') {
          console.log(`[pathRewrite] ${serviceName}: "${path}" -> "${rewritten}"`);
        }
        return rewritten;
      },
      on: {
        proxyReq: (proxyReq, req) => {
          // Use Nango/OAuth-fetched token (stored in req._nangoToken) or fall back to env var
          const apiKey = req._nangoToken || process.env[keyEnv];
          if (!apiKey) {
            console.warn(
              `[WARN] ${keyEnv} is not set and no OAuth/Nango token available. Request to ${serviceName} will proceed without auth.`
            );
            return;
          }
          // Remove any auth header the agent may have sent (never trust agent-supplied keys)
          proxyReq.removeHeader(authHeader);
          proxyReq.setHeader(authHeader, `${authPrefix} ${apiKey}`);
        },
        proxyRes: (proxyRes, req) => {
          // On 401 from an OAuth-backed service, clear the token cache so the next request forces a refresh
          if (proxyRes.statusCode === 401 && config.oauth && _oauthTokenCache[serviceName]) {
            console.warn(`[QB OAuth] 401 received from ${serviceName} - clearing token cache, next request will auto-refresh`);
            delete _oauthTokenCache[serviceName];
          }
        },
        error: (err, req, res) => {
          console.error(`[ERROR] Proxy error for ${serviceName}:`, err.message);
          res
            .status(502)
            .json({ error: "Proxy error", service: serviceName, detail: err.message });
        },
      },
    })
  );
}

// 404 fallback
app.use((req, res) => {
  res.status(404).json({
    error: "Not found",
    hint: "Use /proxy/:service/... for API key services. Use /api/gmail/... for Gmail via Nango. See /health for all endpoints.",
  });
});

app.listen(PORT, () => {
  console.log(`openclaw-api-proxy listening on port ${PORT}`);
  console.log(`Auth guard: ${PROXY_AUTH_TOKEN ? "enabled" : "disabled (open)"}`);
  const configured = Object.entries(SERVICES)
    .filter(([, c]) => !!process.env[c.keyEnv])
    .map(([n]) => n);
  console.log(`Configured services: ${configured.length ? configured.join(", ") : "none"}`);
  const nangoReady = !!(
    process.env.NANGO_SECRET_KEY &&
    process.env.NANGO_CONNECTION_ID &&
    process.env.NANGO_PROVIDER_CONFIG_KEY
  );
  console.log(`Gmail (Nango): ${nangoReady ? "configured" : "NOT configured"}`);
});

module.exports = app;
