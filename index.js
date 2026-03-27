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

// --------------------------------------------------------------------------
// Google Service Account JWT auth (domain-wide delegation)
// No external dependencies - uses Node's built-in crypto module
// --------------------------------------------------------------------------
const _serviceAccountTokenCache = {};

/**
 * Base64url encode a buffer or string (no padding).
 */
function base64url(input) {
  const buf = typeof input === "string" ? Buffer.from(input) : input;
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Create a signed JWT for Google Service Account authentication.
 * @param {object} serviceAccountKey - parsed JSON key file
 * @param {string[]} scopes - OAuth scopes to request
 * @param {string} impersonateEmail - email to impersonate (domain-wide delegation)
 */
function createServiceAccountJWT(serviceAccountKey, scopes, impersonateEmail) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: serviceAccountKey.client_email,
    sub: impersonateEmail,
    scope: scopes.join(" "),
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600, // 1 hour
  };

  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  const sign = crypto.createSign("RSA-SHA256");
  sign.update(signingInput);
  const signature = sign.sign(serviceAccountKey.private_key);

  return `${signingInput}.${base64url(signature)}`;
}

/**
 * Get an access token using Google Service Account JWT.
 * Caches tokens until 2 min before expiry.
 * @param {string} impersonateEmail - email to impersonate
 * @param {string[]} scopes - OAuth scopes
 * @returns {Promise<string>} access token
 */
async function getServiceAccountToken(impersonateEmail, scopes) {
  const cacheKey = `sa:${impersonateEmail}:${scopes.join(",")}`;
  const cached = _serviceAccountTokenCache[cacheKey];
  if (cached && cached.expiresAt > Date.now()) {
    return cached.token;
  }

  const keyJson = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
  if (!keyJson) throw new Error("GOOGLE_SERVICE_ACCOUNT_KEY not configured");

  let serviceAccountKey;
  try {
    serviceAccountKey = JSON.parse(keyJson);
  } catch (e) {
    throw new Error("GOOGLE_SERVICE_ACCOUNT_KEY is not valid JSON");
  }

  if (!serviceAccountKey.private_key || !serviceAccountKey.client_email) {
    throw new Error("GOOGLE_SERVICE_ACCOUNT_KEY missing private_key or client_email");
  }

  const jwt = createServiceAccountJWT(serviceAccountKey, scopes, impersonateEmail);

  return new Promise((resolve, reject) => {
    const body = `grant_type=${encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer")}&assertion=${encodeURIComponent(jwt)}`;
    const options = {
      hostname: "oauth2.googleapis.com",
      port: 443,
      path: "/token",
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body),
      },
    };

    const req = https.request(options, (resp) => {
      let data = "";
      resp.on("data", (chunk) => (data += chunk));
      resp.on("end", () => {
        try {
          const parsed = JSON.parse(data);
          if (!parsed.access_token) {
            return reject(new Error(`Service Account token exchange failed (HTTP ${resp.statusCode}): ${data.slice(0, 300)}`));
          }
          const expiresIn = parsed.expires_in || 3600;
          // Cache until 2 min before expiry
          const ttl = (expiresIn - 120) * 1000;
          if (ttl > 0) {
            _serviceAccountTokenCache[cacheKey] = {
              token: parsed.access_token,
              expiresAt: Date.now() + ttl,
            };
          }
          console.log(`[ServiceAccount] Got access token for ${impersonateEmail}, expires in ${expiresIn}s`);
          resolve(parsed.access_token);
        } catch (e) {
          reject(new Error(`Service Account: failed to parse token response: ${data.slice(0, 200)}`));
        }
      });
    });

    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/**
 * Check if service account auth is available.
 */
function hasServiceAccount() {
  return !!process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
}

const GMAIL_SCOPES = [
  "https://mail.google.com/",
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.send",
];

const GMAIL_IMPERSONATE_EMAIL = process.env.GMAIL_IMPERSONATE_EMAIL;

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
app.use("/api", express.urlencoded({ extended: true }));

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
  if (req.path === "/health" || req.path === "/services" || req.path === "/api/contributions" || req.path === "/api/quickbooks/auth" || req.path === "/api/quickbooks/callback") return next();
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
  const directOAuthConfigured = hasGmailDirectOAuth();
  const nangoSheetsConfigured = !!process.env.NANGO_SECRET_KEY;
  const gmailAuthMethod = directOAuthConfigured
    ? "direct-oauth (refresh token)"
    : hasServiceAccount()
    ? "service-account (JWT)"
    : nangoConfigured
    ? "nango (OAuth)"
    : "NOT CONFIGURED";
  res.json({
    status: "ok",
    services,
    gmail: {
      configured: directOAuthConfigured || hasServiceAccount() || nangoConfigured,
      authMethod: gmailAuthMethod,
      directOAuth: { configured: directOAuthConfigured },
      serviceAccount: hasServiceAccount() ? { configured: true, impersonating: GMAIL_IMPERSONATE_EMAIL || "(not set)" } : { configured: false },
      nango: { configured: nangoConfigured },
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
      configured: hasServiceAccount(),
      authMethod: hasServiceAccount() ? "service-account (JWT)" : "NOT CONFIGURED",
      impersonating: GMAIL_IMPERSONATE_EMAIL || "isaac@kaara.works",
      endpoint: "GET|POST /proxy/google-sheets/spreadsheets/...",
      note: "Same service account as Gmail - permanent auth, no expiry",
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

/**
 * Fetch OAuth access token from Nango, with smart caching.
 * @param {string} provider - Nango provider config key (e.g. "google")
 * @param {string} connectionId - Nango connection ID
 * @param {boolean} forceRefresh - bypass cache and ask Nango to force-refresh
 */
async function getNangoTokenFor(provider, connectionId, forceRefresh = false) {
  const NANGO_SECRET = process.env.NANGO_SECRET_KEY;
  if (!NANGO_SECRET) throw new Error("NANGO_SECRET_KEY not configured");

  const cacheKey = `${provider}:${connectionId}`;

  if (!forceRefresh) {
    const cached = _nangoTokenCache[cacheKey];
    if (cached && cached.expiresAt > Date.now()) {
      return cached.token;
    }
  }

  return new Promise((resolve, reject) => {
    const reqPath = `/connection/${connectionId}?provider_config_key=${provider}&force_refresh=${forceRefresh ? 'true' : 'false'}`;
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
          // Use Nango's reported expiry if available, otherwise fall back to 55 min
          const expiresAt = parsed?.credentials?.expires_at;
          let cacheTTL;
          if (expiresAt) {
            // Cache until 2 min before expiry (safety margin)
            cacheTTL = new Date(expiresAt).getTime() - Date.now() - 2 * 60 * 1000;
            if (cacheTTL < 0) cacheTTL = 0; // already expired, don't cache
          } else {
            cacheTTL = 55 * 60 * 1000; // fallback: 55 min
          }

          if (cacheTTL > 0) {
            _nangoTokenCache[cacheKey] = { token, expiresAt: Date.now() + cacheTTL };
          } else {
            // Token is expired or about to expire - don't cache
            delete _nangoTokenCache[cacheKey];
          }

          const hasRefresh = !!(parsed?.credentials?.refresh_token);
          if (!hasRefresh) {
            console.warn(`[Nango] WARNING: No refresh_token for ${provider}:${connectionId}. Token will not auto-refresh. Re-authorize at app.nango.dev.`);
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

/**
 * Clear cached Nango token for a provider:connectionId pair.
 * Used when a downstream API returns 401 to force a fresh token on retry.
 */
function clearNangoTokenCache(provider, connectionId) {
  const cacheKey = `${provider}:${connectionId}`;
  if (_nangoTokenCache[cacheKey]) {
    console.log(`[Nango] Clearing cached token for ${cacheKey}`);
    delete _nangoTokenCache[cacheKey];
  }
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

// --------------------------------------------------------------------------
// Gmail Direct OAuth: refresh token flow (same pattern as QB/YNAB)
// Priority: Direct OAuth > Service Account (JWT) > Nango (OAuth)
// --------------------------------------------------------------------------
const _gmailDirectTokenCache = {};

/**
 * Check if direct Gmail OAuth credentials are configured.
 */
function hasGmailDirectOAuth() {
  return !!(
    process.env.GMAIL_CLIENT_ID &&
    process.env.GMAIL_CLIENT_SECRET &&
    process.env.GMAIL_REFRESH_TOKEN
  );
}

/**
 * Get Gmail access token using direct OAuth refresh token.
 * Caches until 5 min before expiry.
 */
async function getGmailDirectToken(forceRefresh = false) {
  const cacheKey = "gmail-direct";
  if (!forceRefresh) {
    const cached = _gmailDirectTokenCache[cacheKey];
    if (cached && cached.expiresAt > Date.now()) {
      return cached.accessToken;
    }
  }

  const clientId = process.env.GMAIL_CLIENT_ID;
  const clientSecret = process.env.GMAIL_CLIENT_SECRET;
  const refreshToken = process.env.GMAIL_REFRESH_TOKEN;

  return new Promise((resolve, reject) => {
    const body = [
      `grant_type=refresh_token`,
      `refresh_token=${encodeURIComponent(refreshToken)}`,
      `client_id=${encodeURIComponent(clientId)}`,
      `client_secret=${encodeURIComponent(clientSecret)}`,
    ].join("&");

    const options = {
      hostname: "oauth2.googleapis.com",
      port: 443,
      path: "/token",
      method: "POST",
      headers: {
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
              new Error(`Gmail Direct OAuth: no access_token (HTTP ${resp.statusCode}): ${data.slice(0, 300)}`)
            );
          }
          const expiresIn = parsed.expires_in || 3600;
          const ttl = (expiresIn - 300) * 1000; // refresh 5 min early
          if (ttl > 0) {
            _gmailDirectTokenCache[cacheKey] = {
              accessToken: parsed.access_token,
              expiresAt: Date.now() + ttl,
            };
          }
          console.log(`[Gmail Direct OAuth] Refreshed access token, expires in ${expiresIn}s`);
          resolve(parsed.access_token);
        } catch (e) {
          reject(new Error(`Gmail Direct OAuth: failed to parse response: ${data.slice(0, 200)}`));
        }
      });
    });

    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

// Convenience: get token then call Gmail, with automatic 401 retry
// Priority: Direct OAuth > Service Account (JWT) > Nango (OAuth)
async function getGmailToken() {
  // 1. Direct OAuth (same pattern as QB/YNAB - permanent, no third-party dependency)
  if (hasGmailDirectOAuth()) {
    return { token: await getGmailDirectToken(), source: "direct-oauth" };
  }
  // 2. Service Account (JWT) - domain-wide delegation, never expires
  if (hasServiceAccount()) {
    return { token: await getServiceAccountToken(GMAIL_IMPERSONATE_EMAIL, GMAIL_SCOPES), source: "service-account" };
  }
  // 3. Nango OAuth (legacy fallback)
  return { token: await getNangoToken(), source: "nango" };
}

async function gmailAuthRequest({ method, path, body, query }) {
  const { token, source } = await getGmailToken();
  const result = await gmailRequest({ method, path, body, query, token });

  // On 401: retry with fresh token
  if (result.status === 401) {
    console.warn(`[Gmail] 401 received (source: ${source}) - retrying with fresh token`);

    if (source === "direct-oauth") {
      // Clear direct OAuth cache and force-refresh
      delete _gmailDirectTokenCache["gmail-direct"];
      try {
        const freshToken = await getGmailDirectToken(true);
        return gmailRequest({ method, path, body, query, token: freshToken });
      } catch (err) {
        console.error(`[Gmail] Direct OAuth refresh failed:`, err.message);
        return result;
      }
    } else if (source === "service-account") {
      // Clear service account cache and get a fresh token
      const cacheKey = `sa:${GMAIL_IMPERSONATE_EMAIL}:${GMAIL_SCOPES.join(",")}`;
      delete _serviceAccountTokenCache[cacheKey];
      try {
        const freshToken = await getServiceAccountToken(GMAIL_IMPERSONATE_EMAIL, GMAIL_SCOPES);
        return gmailRequest({ method, path, body, query, token: freshToken });
      } catch (err) {
        console.error(`[Gmail] Service account refresh failed:`, err.message);
        return result;
      }
    } else {
      // Nango path: clear cache, force-refresh
      const CONNECTION_ID = process.env.NANGO_CONNECTION_ID;
      const PROVIDER_CONFIG_KEY = process.env.NANGO_PROVIDER_CONFIG_KEY || "google";
      if (CONNECTION_ID) {
        clearNangoTokenCache(PROVIDER_CONFIG_KEY, CONNECTION_ID);
        try {
          const freshToken = await getNangoTokenFor(PROVIDER_CONFIG_KEY, CONNECTION_ID, true);
          return gmailRequest({ method, path, body, query, token: freshToken });
        } catch (refreshErr) {
          console.error(`[Gmail] Nango force-refresh failed:`, refreshErr.message);
          return result;
        }
      }
    }
  }

  return result;
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
    const result = await gmailAuthRequest({
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
    const result = await gmailAuthRequest({
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
    const result = await gmailAuthRequest({
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
    const result = await gmailAuthRequest({
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
    const result = await gmailAuthRequest({
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
      result = await gmailAuthRequest({
        method: "DELETE",
        path: `/users/me/messages/${id}`,
      });
    } else {
      result = await gmailAuthRequest({
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

/**
 * POST /api/gmail/messages/:id/modify
 * Modify labels on a message (e.g. archive by removing INBOX label)
 * Body: { addLabelIds: [...], removeLabelIds: [...] }
 * Returns: { success: true, message: { id, labelIds } }
 */
app.post("/api/gmail/messages/:id/modify", async (req, res) => {
  const { id } = req.params;
  const { addLabelIds, removeLabelIds } = req.body || {};

  try {
    const result = await gmailAuthRequest({
      method: "POST",
      path: `/users/me/messages/${id}/modify`,
      body: { addLabelIds: addLabelIds || [], removeLabelIds: removeLabelIds || [] },
    });

    if (result.status >= 200 && result.status < 300) {
      return res.status(200).json({
        success: true,
        message: result.body,
      });
    }
    return res.status(result.status).json({ error: "Gmail API error", detail: result.body });
  } catch (err) {
    console.error("[gmail/messages/:id/modify] Error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

// --------------------------------------------------------------------------
// QuickBooks OAuth 2.0 + API proxy
// Env vars: QUICKBOOKS_CLIENT_ID, QUICKBOOKS_CLIENT_SECRET, QUICKBOOKS_REALM_ID,
//           QUICKBOOKS_REFRESH_TOKEN
// Railway env update: RAILWAY_API_TOKEN, RAILWAY_PROJECT_ID, RAILWAY_SERVICE_ID,
//                     RAILWAY_ENVIRONMENT_ID (optional, defaults to "production")
// --------------------------------------------------------------------------

const QB_AUTH_BASE = "https://appcenter.intuit.com/connect/oauth2";
const QB_TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer";
const QB_API_BASE = "https://quickbooks.api.intuit.com";
const QB_SCOPES = "com.intuit.quickbooks.accounting";

// In-memory token cache (refreshed on demand)
let qbAccessToken = null;
let qbAccessTokenExpiry = 0;

// --------------------------------------------------------------------------
// Railway GraphQL: update environment variables on successful QB token refresh
// Required env vars: RAILWAY_API_TOKEN, RAILWAY_PROJECT_ID, RAILWAY_SERVICE_ID
// Optional: RAILWAY_ENVIRONMENT_ID (defaults to searching by name "production")
// --------------------------------------------------------------------------
async function updateRailwayEnvVars(vars) {
  const token = process.env.RAILWAY_API_TOKEN;
  const projectId = process.env.RAILWAY_PROJECT_ID;
  const serviceId = process.env.RAILWAY_SERVICE_ID;
  const environmentId = process.env.RAILWAY_ENVIRONMENT_ID;

  if (!token || !projectId || !serviceId) {
    console.warn(
      `[QB Cron] Railway env update skipped - missing RAILWAY_API_TOKEN, RAILWAY_PROJECT_ID, or RAILWAY_SERVICE_ID`
    );
    return false;
  }

  // If no explicit environment ID, fetch it by name (default: "production")
  let envId = environmentId;
  if (!envId) {
    try {
      envId = await getRailwayEnvironmentId(token, projectId, "production");
    } catch (err) {
      console.error(`[QB Cron] Could not resolve Railway environment ID:`, err.message);
      return false;
    }
  }

  const mutation = `
    mutation UpsertVariables($input: VariableCollectionUpsertInput!) {
      variableCollectionUpsert(input: $input)
    }
  `;
  const body = JSON.stringify({
    query: mutation,
    variables: {
      input: {
        projectId,
        serviceId,
        environmentId: envId,
        variables: vars,
      },
    },
  });

  return new Promise((resolve, reject) => {
    const options = {
      hostname: "backboard.railway.com",
      port: 443,
      path: "/graphql/v2",
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
    };

    const req = https.request(options, (resp) => {
      let data = "";
      resp.on("data", (chunk) => (data += chunk));
      resp.on("end", () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.errors) {
            console.error(`[QB Cron] Railway GraphQL errors:`, JSON.stringify(parsed.errors));
            return resolve(false);
          }
          console.log(`[QB Cron] Railway env vars updated:`, Object.keys(vars).join(", "));
          resolve(true);
        } catch (e) {
          console.error(`[QB Cron] Railway response parse error:`, data.slice(0, 200));
          resolve(false);
        }
      });
    });

    req.on("error", (err) => {
      console.error(`[QB Cron] Railway API request failed:`, err.message);
      resolve(false);
    });

    req.write(body);
    req.end();
  });
}

/**
 * Resolve Railway environment ID by name (e.g. "production").
 */
function getRailwayEnvironmentId(token, projectId, envName) {
  const query = `
    query GetEnvironments($id: String!) {
      project(id: $id) {
        environments { edges { node { id name } } }
      }
    }
  `;
  const body = JSON.stringify({ query, variables: { id: projectId } });

  return new Promise((resolve, reject) => {
    const options = {
      hostname: "backboard.railway.com",
      port: 443,
      path: "/graphql/v2",
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
    };

    const req = https.request(options, (resp) => {
      let data = "";
      resp.on("data", (chunk) => (data += chunk));
      resp.on("end", () => {
        try {
          const parsed = JSON.parse(data);
          const edges = parsed?.data?.project?.environments?.edges || [];
          const match = edges.find((e) => e.node.name.toLowerCase() === envName.toLowerCase());
          if (!match) return reject(new Error(`No Railway environment named "${envName}"`));
          resolve(match.node.id);
        } catch (e) {
          reject(new Error(`Railway env lookup parse error: ${data.slice(0, 200)}`));
        }
      });
    });

    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

// --------------------------------------------------------------------------
// QB daily token refresh: proactively rotate refresh token each morning
// Fires at 06:00 EAT (Africa/Nairobi = UTC+3 = 03:00 UTC)
// --------------------------------------------------------------------------

/**
 * Refresh QB tokens (both access + refresh token).
 * QB may or may not issue a new refresh token - we handle both cases.
 * On new refresh token: update Railway env vars + process.env immediately.
 * Returns { success, newRefreshToken, error }
 */
async function refreshQBTokens() {
  const ts = new Date().toISOString();
  const refreshToken = process.env.QUICKBOOKS_REFRESH_TOKEN;

  console.log(`[QB Cron] ${ts} - Starting daily token refresh`);

  if (!refreshToken) {
    const msg = "QUICKBOOKS_REFRESH_TOKEN not set - skipping refresh";
    console.error(`[QB Cron] ${ts} - ${msg}`);
    return { success: false, error: msg };
  }

  try {
    const result = await qbTokenExchange({ grantType: "refresh_token", refreshToken });

    // Always update the in-memory access token cache
    qbAccessToken = result.access_token;
    qbAccessTokenExpiry = Date.now() + (result.expires_in || 3600) * 1000;

    console.log(
      `[QB Cron] ${ts} - Access token refreshed successfully, expires in ${result.expires_in || 3600}s`
    );

    // Handle new refresh token (QB rotates these periodically)
    if (result.refresh_token && result.refresh_token !== refreshToken) {
      console.log(`[QB Cron] ${ts} - New refresh token issued by Intuit - updating Railway env vars`);
      console.log(`[QB Cron] New refresh token (first 20 chars): ${result.refresh_token.slice(0, 20)}...`);

      // Update in-process immediately so subsequent calls work without restart
      process.env.QUICKBOOKS_REFRESH_TOKEN = result.refresh_token;
      process.env.QB_REFRESH_TOKEN = result.refresh_token;

      // Persist to Railway (survives restart/redeploy)
      await updateRailwayEnvVars({
        QUICKBOOKS_REFRESH_TOKEN: result.refresh_token,
        QB_REFRESH_TOKEN: result.refresh_token,
      });

      return { success: true, newRefreshToken: result.refresh_token };
    }

    // Same refresh token returned (or not returned) - still a success
    console.log(`[QB Cron] ${ts} - Refresh token unchanged (Intuit did not rotate it)`);
    return { success: true, newRefreshToken: null };
  } catch (err) {
    const ts2 = new Date().toISOString();
    console.error(`[QB Cron] ${ts2} - Token refresh FAILED: ${err.message}`);
    return { success: false, error: err.message };
  }
}

/**
 * Schedule QB token refresh daily at 06:00 EAT (03:00 UTC).
 * Uses recursive setTimeout so the schedule self-corrects each day.
 */
function scheduleQBDailyRefresh() {
  function msUntilNextRefresh() {
    const now = new Date();
    // Next 03:00 UTC
    const next = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 3, 0, 0, 0)
    );
    if (next <= now) {
      // Already past today's 03:00 UTC - target tomorrow
      next.setUTCDate(next.getUTCDate() + 1);
    }
    return next.getTime() - now.getTime();
  }

  function scheduleNext() {
    const ms = msUntilNextRefresh();
    const nextRun = new Date(Date.now() + ms).toISOString();
    console.log(`[QB Cron] Next daily token refresh scheduled for ${nextRun} (${Math.round(ms / 60000)} min from now)`);

    setTimeout(async () => {
      await refreshQBTokens();
      scheduleNext(); // Schedule the next day's run
    }, ms);
  }

  scheduleNext();
}

/**
 * Exchange an authorization code or refresh token for QB tokens.
 * grant_type: "authorization_code" | "refresh_token"
 */
function qbTokenExchange({ grantType, code, redirectUri, refreshToken }) {
  return new Promise((resolve, reject) => {
    const clientId = process.env.QUICKBOOKS_CLIENT_ID;
    const clientSecret = process.env.QUICKBOOKS_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      return reject(new Error("QUICKBOOKS_CLIENT_ID or QUICKBOOKS_CLIENT_SECRET not set"));
    }

    const params = new URLSearchParams();
    params.set("grant_type", grantType);
    if (grantType === "authorization_code") {
      params.set("code", code);
      params.set("redirect_uri", redirectUri);
    } else {
      params.set("refresh_token", refreshToken);
    }

    const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
    const body = params.toString();

    const url = new URL(QB_TOKEN_URL);
    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "Authorization": `Basic ${basicAuth}`,
        "Content-Length": Buffer.byteLength(body),
      },
    };

    const req = https.request(options, (resp) => {
      let data = "";
      resp.on("data", (chunk) => (data += chunk));
      resp.on("end", () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) {
            return reject(new Error(`QB token error: ${parsed.error} - ${parsed.error_description || ""}`));
          }
          resolve(parsed);
        } catch (e) {
          reject(new Error(`QB token parse error: ${data.slice(0, 300)}`));
        }
      });
    });

    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/**
 * Get a valid QB access token, refreshing if needed.
 */
async function getQBAccessToken() {
  // Return cached token if still valid (with 60s buffer)
  if (qbAccessToken && Date.now() < qbAccessTokenExpiry - 60000) {
    return qbAccessToken;
  }

  const refreshToken = process.env.QUICKBOOKS_REFRESH_TOKEN;
  if (!refreshToken) {
    throw new Error("QUICKBOOKS_REFRESH_TOKEN not set. Complete OAuth flow at /api/quickbooks/auth first.");
  }

  const result = await qbTokenExchange({
    grantType: "refresh_token",
    refreshToken,
  });

  qbAccessToken = result.access_token;
  qbAccessTokenExpiry = Date.now() + (result.expires_in || 3600) * 1000;

  // If QB issued a new refresh token, persist it everywhere immediately
  if (result.refresh_token && result.refresh_token !== refreshToken) {
    const ts = new Date().toISOString();
    console.log(`[QB] ${ts} - New refresh token issued by Intuit`);
    console.log(`[QB] ${ts} - New refresh token (first 20 chars): ${result.refresh_token.slice(0, 20)}...`);
    // Update in-process so subsequent calls work without restart
    process.env.QUICKBOOKS_REFRESH_TOKEN = result.refresh_token;
    process.env.QB_REFRESH_TOKEN = result.refresh_token;
    // Persist to Railway (fire-and-forget - don't block the access token return)
    updateRailwayEnvVars({
      QUICKBOOKS_REFRESH_TOKEN: result.refresh_token,
      QB_REFRESH_TOKEN: result.refresh_token,
    }).catch((err) => console.error(`[QB] Railway env update failed:`, err.message));
  }

  return qbAccessToken;
}

/**
 * GET /api/quickbooks/auth
 * Initiates OAuth flow. Redirects browser to Intuit authorization page.
 * Query: ?redirect_uri=... (optional override; defaults to this server's callback)
 */
app.get("/api/quickbooks/auth", (req, res) => {
  const clientId = process.env.QUICKBOOKS_CLIENT_ID;
  if (!clientId) {
    return res.status(500).json({ error: "QUICKBOOKS_CLIENT_ID not configured" });
  }

  // Build redirect URI: default to this server's callback
  let host = "https://openclaw-api-proxy-production.up.railway.app";
  if (req.headers.host && req.headers["x-forwarded-proto"]) {
    host = `${req.headers["x-forwarded-proto"]}://${req.headers.host}`;
  } else if (req.headers.host && req.protocol) {
    host = `${req.protocol}://${req.headers.host}`;
  }
  const redirectUri = req.query.redirect_uri || `${host}/api/quickbooks/callback`;

  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    scope: QB_SCOPES,
    redirect_uri: redirectUri,
    state: "openclaw_qb_auth",
  });

  const authUrl = `${QB_AUTH_BASE}?${params.toString()}`;
  console.log(`[QB] OAuth redirect -> ${authUrl}`);
  res.redirect(authUrl);
});

/**
 * GET /api/quickbooks/callback
 * Handles OAuth callback from Intuit. Exchanges auth code for tokens.
 * Displays the refresh token for the operator to save.
 */
app.get("/api/quickbooks/callback", async (req, res) => {
  const { code, realmId, error, state } = req.query;

  if (error) {
    return res.status(400).json({ error: "OAuth denied", detail: error });
  }

  if (!code) {
    return res.status(400).json({ error: "Missing authorization code" });
  }

  // Build the same redirect URI used in /auth
  const host = req.headers["x-forwarded-proto"]
    ? `${req.headers["x-forwarded-proto"]}://${req.headers.host}`
    : `${req.protocol}://${req.headers.host}`;
  const redirectUri = `${host}/api/quickbooks/callback`;

  try {
    const tokens = await qbTokenExchange({
      grantType: "authorization_code",
      code,
      redirectUri,
    });

    // Cache the access token
    qbAccessToken = tokens.access_token;
    qbAccessTokenExpiry = Date.now() + (tokens.expires_in || 3600) * 1000;

    // Store refresh token in-process
    if (tokens.refresh_token) {
      process.env.QUICKBOOKS_REFRESH_TOKEN = tokens.refresh_token;
    }

    console.log(`[QB] OAuth complete! Realm: ${realmId || process.env.QUICKBOOKS_REALM_ID}`);
    console.log(`[QB] Refresh token: ${tokens.refresh_token}`);
    console.log(`[QB] Access token expires in: ${tokens.expires_in}s`);

    // Return a nice HTML page with the token info
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>QuickBooks OAuth Complete</title>
      <style>
        body { font-family: system-ui; max-width: 700px; margin: 40px auto; padding: 0 20px; }
        .token { background: #f0f0f0; padding: 12px; border-radius: 6px; word-break: break-all; font-family: monospace; font-size: 14px; }
        .success { color: #16a34a; }
        h1 { color: #1e40af; }
        .step { margin: 12px 0; padding: 8px 12px; background: #fefce8; border-left: 3px solid #eab308; }
      </style>
      </head>
      <body>
        <h1>QuickBooks OAuth Complete</h1>
        <p class="success"><strong>Authorization successful!</strong></p>
        <p><strong>Realm ID:</strong> ${realmId || process.env.QUICKBOOKS_REALM_ID || "unknown"}</p>
        <p><strong>Access token expires in:</strong> ${tokens.expires_in || 3600} seconds</p>
        <h2>Refresh Token</h2>
        <div class="token" id="rt">${tokens.refresh_token || "NOT PROVIDED"}</div>
        <br>
        <button onclick="navigator.clipboard.writeText(document.getElementById('rt').textContent).then(()=>alert('Copied!'))">Copy Refresh Token</button>
        <h2>Next Steps</h2>
        <div class="step">1. Copy the refresh token above</div>
        <div class="step">2. In Railway dashboard, update <code>QUICKBOOKS_REFRESH_TOKEN</code> env var</div>
        <div class="step">3. Also update <code>QB_REFRESH_TOKEN</code> and <code>QUICKBOOKS_API_KEY</code> if used</div>
        <div class="step">4. Redeploy or restart the service</div>
        <p><em>The token is cached in-process for now, so API calls will work until the next deploy.</em></p>
      </body>
      </html>
    `);
  } catch (err) {
    console.error("[QB callback] Error:", err.message);
    res.status(500).json({ error: "Token exchange failed", detail: err.message });
  }
});

/**
 * POST /api/quickbooks/token/refresh
 * Manually trigger QB refresh token rotation (same logic as daily cron).
 * Use this to test the cron flow or force-rotate a token before expiry.
 */
app.post("/api/quickbooks/token/refresh", async (req, res) => {
  const ts = new Date().toISOString();
  console.log(`[QB] ${ts} - Manual token refresh triggered via API`);
  const result = await refreshQBTokens();
  res.json({
    timestamp: ts,
    ...result,
    newRefreshToken: result.newRefreshToken
      ? `${result.newRefreshToken.slice(0, 20)}... (truncated for security)`
      : null,
  });
});

/**
 * GET /api/quickbooks/status
 * Check if QB is configured and tokens are valid
 */
app.get("/api/quickbooks/status", async (req, res) => {
  const configured = !!(
    process.env.QUICKBOOKS_CLIENT_ID &&
    process.env.QUICKBOOKS_CLIENT_SECRET &&
    process.env.QUICKBOOKS_REFRESH_TOKEN
  );

  if (!configured) {
    return res.json({
      status: "not_configured",
      hasClientId: !!process.env.QUICKBOOKS_CLIENT_ID,
      hasClientSecret: !!process.env.QUICKBOOKS_CLIENT_SECRET,
      hasRefreshToken: !!process.env.QUICKBOOKS_REFRESH_TOKEN,
      realmId: process.env.QUICKBOOKS_REALM_ID || null,
    });
  }

  try {
    const token = await getQBAccessToken();
    const realmId = process.env.QUICKBOOKS_REALM_ID;
    // Quick test: fetch company info
    const testResult = await new Promise((resolve, reject) => {
      const options = {
        hostname: "quickbooks.api.intuit.com",
        port: 443,
        path: `/v3/company/${realmId}/companyinfo/${realmId}`,
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
        },
      };
      const req = https.request(options, (resp) => {
        let data = "";
        resp.on("data", (chunk) => (data += chunk));
        resp.on("end", () => resolve({ status: resp.statusCode, body: data }));
      });
      req.on("error", reject);
      req.end();
    });

    res.json({
      status: testResult.status === 200 ? "ok" : "error",
      httpStatus: testResult.status,
      realmId,
      tokenCached: !!qbAccessToken,
      tokenExpiry: qbAccessTokenExpiry ? new Date(qbAccessTokenExpiry).toISOString() : null,
    });
  } catch (err) {
    res.json({
      status: "error",
      error: err.message,
      realmId: process.env.QUICKBOOKS_REALM_ID,
    });
  }
});

/**
 * Forward a single QB API request. Returns { statusCode, body (string) }.
 */
function qbApiRequest({ token, method, path, qs, bodyStr }) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: "quickbooks.api.intuit.com",
      port: 443,
      path: `${path}${qs}`,
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
        "Content-Type": "application/json",
      },
    };
    if (bodyStr) options.headers["Content-Length"] = Buffer.byteLength(bodyStr);

    const req = https.request(options, (proxyRes) => {
      let data = "";
      proxyRes.on("data", (chunk) => (data += chunk));
      proxyRes.on("end", () => resolve({ statusCode: proxyRes.statusCode, body: data }));
    });
    req.on("error", reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

/**
 * ALL /api/quickbooks/v3/*
 * Proxy requests to QuickBooks API with auto-refreshed OAuth token.
 * 401 interceptor: on 401, clear token cache, force-refresh, retry once.
 * Example: GET /api/quickbooks/v3/company/REALM/companyinfo/REALM
 */
app.all("/api/quickbooks/v3/*", async (req, res) => {
  const qbPath = req.path.replace("/api/quickbooks", "");
  const qs = Object.keys(req.query).length
    ? "?" + new URLSearchParams(req.query).toString()
    : "";
  const bodyStr = ["POST", "PUT", "PATCH"].includes(req.method) && req.body
    ? JSON.stringify(req.body)
    : null;

  function sendResult({ statusCode, body }) {
    try {
      res.status(statusCode).json(JSON.parse(body));
    } catch {
      res.status(statusCode).send(body);
    }
  }

  try {
    const token = await getQBAccessToken();
    const result = await qbApiRequest({ token, method: req.method, path: qbPath, qs, bodyStr });

    // 401 interceptor: token may have expired between cache check and QB response
    if (result.statusCode === 401) {
      const ts = new Date().toISOString();
      console.warn(`[QB proxy] ${ts} - 401 received from QB API - clearing token cache and retrying`);

      // Force cache invalidation
      qbAccessToken = null;
      qbAccessTokenExpiry = 0;

      try {
        const freshToken = await getQBAccessToken();
        const retryResult = await qbApiRequest({ token: freshToken, method: req.method, path: qbPath, qs, bodyStr });
        console.log(`[QB proxy] ${ts} - Retry after 401 returned HTTP ${retryResult.statusCode}`);
        return sendResult(retryResult);
      } catch (retryErr) {
        console.error(`[QB proxy] ${ts} - 401 retry failed: ${retryErr.message}`);
        return res.status(401).json({ error: "QB auth failed after retry", detail: retryErr.message });
      }
    }

    sendResult(result);
  } catch (err) {
    console.error("[QB proxy] Auth error:", err.message);
    res.status(503).json({ error: err.message });
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

// Pre-middleware: Google Sheets via Gmail OAuth refresh token (permanent, no service account needed)
app.use('/proxy/google-sheets', async (req, res, next) => {
  try {
    // Reuse the Gmail OAuth token - it already has spreadsheets scope from the combined auth
    const { token } = await getGmailToken();
    req._nangoToken = token;
    console.log(`[google-sheets] Using Gmail OAuth token for Sheets access`);
    next();
  } catch (err) {
    console.error(`[ERROR] Gmail OAuth token fetch for google-sheets:`, err.message);
    res.status(502).json({ error: "Gmail OAuth token fetch failed", service: "google-sheets", detail: err.message });
  }
});

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
          proxyReq.setHeader(authHeader, `${authPrefix} ${apiKey}`.trim());
        },
        proxyRes: (proxyRes, req) => {
          // On 401 from an OAuth-backed service, clear the token cache so the next request forces a refresh
          if (proxyRes.statusCode === 401 && config.oauth && _oauthTokenCache[serviceName]) {
            console.warn(`[QB OAuth] 401 received from ${serviceName} - clearing token cache, next request will auto-refresh`);
            delete _oauthTokenCache[serviceName];
          }
          // On 401 from a Nango-backed service, clear the Nango token cache
          if (proxyRes.statusCode === 401 && config.nango) {
            const nangoConf = config.nango;
            const provider = nangoConf.provider || (nangoConf.providerEnv && process.env[nangoConf.providerEnv]) || "google";
            const connectionId = nangoConf.connectionId || (nangoConf.connectionIdEnv && process.env[nangoConf.connectionIdEnv]);
            if (connectionId) {
              console.warn(`[Nango] 401 received from ${serviceName} - clearing token cache for next request`);
              clearNangoTokenCache(provider, connectionId);
            }
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

// ─── Our Kenya Contribution Form ─────────────────────────────────────────────
const OK_SHEET_ID = "1WTUD2cVVNfhx7F64Dg7_l47HumOim6rZJb3lkm8f9Fo";
const OK_ALLOWED_ORIGIN = "https://ourkenya.com";

function okCors(res) {
  res.setHeader("Access-Control-Allow-Origin", OK_ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

app.options("/api/contributions", (req, res) => {
  okCors(res);
  res.status(204).end();
});

app.post("/api/contributions", async (req, res) => {
  okCors(res);
  try {
    const { topic, why, sources, email } = req.body || {};
    if (!topic || !why) {
      return res.status(400).json({ error: "topic and why are required" });
    }
    const { token } = await getGmailToken();
    const timestamp = new Date().toISOString();
    const row = [timestamp, topic, why, sources || "", email || "", "New"];
    const sheetsUrl = `https://sheets.googleapis.com/v4/spreadsheets/${OK_SHEET_ID}/values/Submissions!A:F:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`;
    const sheetsResp = await fetch(sheetsUrl, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ values: [row] }),
    });
    if (!sheetsResp.ok) {
      const err = await sheetsResp.text();
      console.error("[contributions] Sheets error:", err);
      return res.status(502).json({ error: "sheets write failed" });
    }
    console.log(`[contributions] New submission: "${topic}" from ${email || "anonymous"}`);
    res.json({ ok: true });
  } catch (err) {
    console.error("[contributions] Error:", err.message);
    res.status(500).json({ error: "internal error" });
  }
});
// ─────────────────────────────────────────────────────────────────────────────

// 404 fallback
app.use((req, res) => {
  res.status(404).json({
    error: "Not found",
    hint: "Use /proxy/:service/... for API key services. Use /api/gmail/... for Gmail. Use /api/quickbooks/... for QuickBooks. See /health for all endpoints.",
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
  console.log(`Gmail (Direct OAuth): ${hasGmailDirectOAuth() ? "configured" : "NOT configured"}`);
  console.log(`Gmail (Service Account): ${hasServiceAccount() ? `configured${GMAIL_IMPERSONATE_EMAIL ? `, impersonating ${GMAIL_IMPERSONATE_EMAIL}` : " (set GMAIL_IMPERSONATE_EMAIL to enable impersonation)"}` : "NOT configured"}`);
  console.log(`Gmail (Nango): ${nangoReady ? "configured" : "NOT configured"}`);
  console.log(`Gmail auth priority: Direct OAuth > Service Account (JWT) > Nango (OAuth)`);

  // Start QB daily cron (06:00 EAT = 03:00 UTC)
  const qbConfigured = !!(
    process.env.QUICKBOOKS_CLIENT_ID &&
    process.env.QUICKBOOKS_CLIENT_SECRET &&
    process.env.QUICKBOOKS_REFRESH_TOKEN
  );
  if (qbConfigured) {
    scheduleQBDailyRefresh();
    console.log(`QuickBooks: daily token refresh cron ACTIVE (fires at 06:00 EAT / 03:00 UTC)`);
    const railwayConfigured = !!(process.env.RAILWAY_API_TOKEN && process.env.RAILWAY_PROJECT_ID && process.env.RAILWAY_SERVICE_ID);
    console.log(`QuickBooks: Railway env auto-update: ${railwayConfigured ? "ENABLED" : "DISABLED (set RAILWAY_API_TOKEN, RAILWAY_PROJECT_ID, RAILWAY_SERVICE_ID to enable)"}`);
  } else {
    console.log(`QuickBooks: NOT configured - cron will not start (set QUICKBOOKS_CLIENT_ID, QUICKBOOKS_CLIENT_SECRET, QUICKBOOKS_REFRESH_TOKEN)`);
  }
});

module.exports = app;
