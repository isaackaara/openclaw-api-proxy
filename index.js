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
app.use((req, res, next) => {
  if (!PROXY_AUTH_TOKEN) return next();
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
// Nango: get current OAuth access token for the connection
// Nango auto-refreshes expired tokens; we always get a fresh one.
// --------------------------------------------------------------------------
async function getNangoToken() {
  const NANGO_SECRET = process.env.NANGO_SECRET_KEY;
  const CONNECTION_ID = process.env.NANGO_CONNECTION_ID;
  const PROVIDER_CONFIG_KEY = process.env.NANGO_PROVIDER_CONFIG_KEY || "google";

  if (!NANGO_SECRET || !CONNECTION_ID) {
    throw new Error("NANGO_SECRET_KEY or NANGO_CONNECTION_ID not configured");
  }

  return new Promise((resolve, reject) => {
    const path = `/connection/${CONNECTION_ID}?provider_config_key=${PROVIDER_CONFIG_KEY}&force_refresh=false`;
    const options = {
      hostname: "api.nango.dev",
      port: 443,
      path,
      method: "GET",
      headers: {
        Authorization: `Bearer ${NANGO_SECRET}`,
      },
    };

    const req = https.request(options, (resp) => {
      let data = "";
      resp.on("data", (chunk) => (data += chunk));
      resp.on("end", () => {
        try {
          const parsed = JSON.parse(data);
          const token = parsed?.credentials?.access_token;
          if (!token) {
            return reject(new Error(`Nango: no access_token in response (status ${resp.statusCode})`));
          }
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
          const apiKey = process.env[keyEnv];
          if (!apiKey) {
            console.warn(
              `[WARN] ${keyEnv} is not set. Request to ${serviceName} will proceed without auth.`
            );
            return;
          }
          // Remove any auth header the agent may have sent (never trust agent-supplied keys)
          proxyReq.removeHeader(authHeader);
          proxyReq.setHeader(authHeader, `${authPrefix} ${apiKey}`);
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
