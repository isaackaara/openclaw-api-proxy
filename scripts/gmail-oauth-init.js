#!/usr/bin/env node
/**
 * gmail-oauth-init.js
 * One-time script to get a Gmail OAuth refresh token.
 *
 * Prerequisites:
 *   1. Go to Google Cloud Console -> APIs & Services -> Credentials
 *      (Project: petrus-crm-488612 or your GCP project)
 *   2. Create an OAuth 2.0 Client ID (type: Desktop app or Web application)
 *   3. Add redirect URI: http://localhost:9877/callback
 *   4. Enable the Gmail API in APIs & Services -> Library
 *   5. Run: GMAIL_CLIENT_ID=xxx GMAIL_CLIENT_SECRET=yyy node scripts/gmail-oauth-init.js
 *
 * Output: refresh_token to paste into Railway as GMAIL_REFRESH_TOKEN
 *
 * IMPORTANT: When creating the OAuth consent screen, set the app to "Internal"
 * (if using Google Workspace) or add isaac@kaara.works as a test user.
 * The refresh token is permanent as long as the OAuth app stays in production
 * or the user remains a test user.
 */

const http = require("http");
const https = require("https");
const { exec } = require("child_process");

const CLIENT_ID = process.env.GMAIL_CLIENT_ID;
const CLIENT_SECRET = process.env.GMAIL_CLIENT_SECRET;
const REDIRECT_URI = "http://localhost:9877/callback";
const PORT = 9877;

// Full Gmail access scope - required for send, read, draft, delete operations
const SCOPES = [
  "https://mail.google.com/",
].join(" ");

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error("ERROR: Missing required env vars.");
  console.error(
    "Usage: GMAIL_CLIENT_ID=xxx GMAIL_CLIENT_SECRET=yyy node scripts/gmail-oauth-init.js"
  );
  process.exit(1);
}

// Build the Google authorization URL
// access_type=offline ensures we get a refresh_token
// prompt=consent forces the consent screen even if previously authorized
const authUrl =
  `https://accounts.google.com/o/oauth2/v2/auth` +
  `?client_id=${encodeURIComponent(CLIENT_ID)}` +
  `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
  `&response_type=code` +
  `&scope=${encodeURIComponent(SCOPES)}` +
  `&access_type=offline` +
  `&prompt=consent`;

// Exchange authorization code for tokens
function exchangeCode(code) {
  return new Promise((resolve, reject) => {
    const body = [
      `grant_type=authorization_code`,
      `code=${encodeURIComponent(code)}`,
      `redirect_uri=${encodeURIComponent(REDIRECT_URI)}`,
      `client_id=${encodeURIComponent(CLIENT_ID)}`,
      `client_secret=${encodeURIComponent(CLIENT_SECRET)}`,
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
    <h2>Gmail Authorization Successful!</h2>
    <p>Exchanging code for tokens... check your terminal.</p>
    <p>You can close this tab.</p>
  `);

  console.log("\nAuthorization code received. Exchanging for tokens...");

  try {
    const result = await exchangeCode(code);

    if (result.status !== 200 || !result.body.refresh_token) {
      console.error(
        "Token exchange failed (HTTP " + result.status + "):",
        JSON.stringify(result.body, null, 2)
      );
      if (!result.body.refresh_token && result.body.access_token) {
        console.error("\nGot access_token but no refresh_token.");
        console.error("This usually means you need to add prompt=consent to the auth URL.");
        console.error("The script already does this. Try revoking access first:");
        console.error("  https://myaccount.google.com/permissions");
        console.error("Then run this script again.");
      }
      server.close();
      return;
    }

    const { access_token, refresh_token, expires_in } = result.body;

    console.log("\n========================================");
    console.log("SUCCESS! Gmail OAuth tokens obtained.");
    console.log("========================================\n");
    console.log("ACCESS TOKEN (expires in " + expires_in + "s, auto-refreshed by proxy):");
    console.log(access_token);
    console.log("\nREFRESH TOKEN (permanent - store this in Railway):");
    console.log(refresh_token);
    console.log("\n========================================");
    console.log("NEXT STEPS:");
    console.log("1. In Railway dashboard -> openclaw-api-proxy -> Variables, set:");
    console.log("   GMAIL_CLIENT_ID     = " + CLIENT_ID);
    console.log("   GMAIL_CLIENT_SECRET = " + CLIENT_SECRET);
    console.log("   GMAIL_REFRESH_TOKEN = " + refresh_token);
    console.log("2. Railway auto-deploys on env var change.");
    console.log("3. Test with:");
    console.log('   curl -H "Authorization: Bearer <proxy_token>" \\');
    console.log("        https://openclaw-api-proxy-production.up.railway.app/api/gmail/messages?maxResults=1");
    console.log("========================================\n");

    server.close();
  } catch (err) {
    console.error("Token exchange error:", err.message);
    server.close();
  }
});

server.listen(PORT, () => {
  console.log("========================================");
  console.log("Gmail OAuth Init - Starting authorization flow");
  console.log("========================================");
  console.log(`\nLocal callback server: http://localhost:${PORT}/callback`);
  console.log("\nOpening Google authorization page in your browser...");
  console.log("If it doesn't open automatically, visit:");
  console.log(authUrl);
  console.log("\nSign in with: isaac@kaara.works");
  console.log("Grant full Gmail access when prompted.");
  console.log("\nWaiting for authorization...");

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
