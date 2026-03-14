#!/usr/bin/env node
/**
 * ynab-oauth-init.js
 * One-time script to get a YNAB OAuth refresh token.
 *
 * Prerequisites:
 *   1. Create a YNAB OAuth app at https://app.youneedabudget.com/settings/developer
 *   2. Set redirect URI to: http://localhost:9876/callback
 *   3. Run: YNAB_CLIENT_ID=xxx YNAB_CLIENT_SECRET=yyy node scripts/ynab-oauth-init.js
 *
 * Output: refresh_token to paste into Railway as YNAB_REFRESH_TOKEN
 */

const http = require("http");
const https = require("https");
const { exec } = require("child_process");

const CLIENT_ID = process.env.YNAB_CLIENT_ID;
const CLIENT_SECRET = process.env.YNAB_CLIENT_SECRET;
const REDIRECT_URI = "http://localhost:9876/callback";
const PORT = 9876;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error("ERROR: Missing required env vars.");
  console.error(
    "Usage: YNAB_CLIENT_ID=xxx YNAB_CLIENT_SECRET=yyy node scripts/ynab-oauth-init.js"
  );
  process.exit(1);
}

// Build the YNAB authorization URL
const authUrl =
  `https://app.youneedabudget.com/oauth/authorize` +
  `?client_id=${encodeURIComponent(CLIENT_ID)}` +
  `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
  `&response_type=code`;

// Exchange authorization code for tokens
function exchangeCode(code) {
  return new Promise((resolve, reject) => {
    const body = [
      `grant_type=authorization_code`,
      `code=${encodeURIComponent(code)}`,
      `redirect_uri=${encodeURIComponent(REDIRECT_URI)}`,
    ].join("&");

    const credentials = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");

    const options = {
      hostname: "app.youneedabudget.com",
      port: 443,
      path: "/oauth/token",
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
          resolve({ status: resp.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: resp.statusCode, body: data });
        }
      });
    });

    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

// Start local callback server
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (url.pathname !== "/callback") {
    res.writeHead(404);
    res.end("Not found");
    return;
  }

  const code = url.searchParams.get("code");
  const error = url.searchParams.get("error");

  if (error || !code) {
    res.writeHead(400, { "Content-Type": "text/html" });
    res.end(`<h2>Authorization failed: ${error || "no code returned"}</h2>`);
    console.error("Authorization failed:", error);
    server.close();
    return;
  }

  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(`
    <h2>Authorization successful!</h2>
    <p>Exchanging code for tokens... check your terminal.</p>
  `);

  console.log("\nAuthorization code received. Exchanging for tokens...");

  try {
    const result = await exchangeCode(code);

    if (result.status !== 200 || !result.body.refresh_token) {
      console.error(
        "Token exchange failed (HTTP " + result.status + "):",
        JSON.stringify(result.body, null, 2)
      );
      server.close();
      return;
    }

    const { access_token, refresh_token, token_type, expires_in } = result.body;

    console.log("\n========================================");
    console.log("SUCCESS! YNAB OAuth tokens obtained.");
    console.log("========================================\n");
    console.log("ACCESS TOKEN (expires in " + expires_in + "s, auto-refreshed by proxy):");
    console.log(access_token);
    console.log("\nREFRESH TOKEN (permanent - store this in Railway):");
    console.log(refresh_token);
    console.log("\n========================================");
    console.log("NEXT STEPS:");
    console.log("1. In Railway dashboard -> openclaw-api-proxy -> Variables:");
    console.log("   YNAB_CLIENT_ID     = " + CLIENT_ID);
    console.log("   YNAB_CLIENT_SECRET = " + CLIENT_SECRET);
    console.log("   YNAB_REFRESH_TOKEN = " + refresh_token);
    console.log("2. Delete YNAB_API_KEY from Railway Variables.");
    console.log("3. Redeploy the proxy (Railway auto-deploys on env var change).");
    console.log("4. Test: curl -H 'Authorization: Bearer <proxy_token>' \\");
    console.log("        https://openclaw-api-proxy-production.up.railway.app/proxy/ynab/v1/budgets");
    console.log("========================================\n");

    server.close();
  } catch (err) {
    console.error("Token exchange error:", err.message);
    server.close();
  }
});

server.listen(PORT, () => {
  console.log("========================================");
  console.log("YNAB OAuth Init - Starting authorization flow");
  console.log("========================================");
  console.log(`\nLocal callback server: http://localhost:${PORT}/callback`);
  console.log("\nOpening YNAB authorization page in your browser...");
  console.log("If it doesn't open automatically, visit:");
  console.log(authUrl);
  console.log("\nWaiting for authorization...");

  // Open browser (works on macOS)
  const openCmd =
    process.platform === "darwin"
      ? `open "${authUrl}"`
      : process.platform === "win32"
      ? `start "${authUrl}"`
      : `xdg-open "${authUrl}"`;

  exec(openCmd, (err) => {
    if (err) {
      console.log("\nCould not auto-open browser. Please visit the URL above manually.");
    }
  });
});

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(`\nERROR: Port ${PORT} is already in use.`);
    console.error("Kill the process using that port and try again:");
    console.error(`  lsof -ti:${PORT} | xargs kill -9`);
  } else {
    console.error("Server error:", err.message);
  }
  process.exit(1);
});
