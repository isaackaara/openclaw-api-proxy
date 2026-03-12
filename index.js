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

const app = express();
const PORT = process.env.PORT || 3000;
const PROXY_AUTH_TOKEN = process.env.PROXY_AUTH_TOKEN || null;

// Load service registry
const servicesPath = path.join(__dirname, "services.json");
const SERVICES = JSON.parse(fs.readFileSync(servicesPath, "utf8"));

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
  res.json({ status: "ok", services });
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

// Dynamic proxy: /proxy/:service/*
// All requests go through here. The proxy injects the API key header
// and strips the /proxy/:service prefix before forwarding.
for (const [serviceName, config] of Object.entries(SERVICES)) {
  const { baseUrl, keyEnv, authHeader, authPrefix } = config;

  app.use(
    `/proxy/${serviceName}`,
    createProxyMiddleware({
      target: baseUrl,
      changeOrigin: true,
      pathRewrite: { [`^/proxy/${serviceName}`]: "" },
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
    hint: "Use /proxy/:service/... to proxy requests. See /services for available services.",
  });
});

app.listen(PORT, () => {
  console.log(`openclaw-api-proxy listening on port ${PORT}`);
  console.log(`Auth guard: ${PROXY_AUTH_TOKEN ? "enabled" : "disabled (open)"}`);
  const configured = Object.entries(SERVICES)
    .filter(([, c]) => !!process.env[c.keyEnv])
    .map(([n]) => n);
  console.log(`Configured services: ${configured.length ? configured.join(", ") : "none"}`);
});

module.exports = app;

