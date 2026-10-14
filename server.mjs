// Standalone StudentProof demo relying party — uses the published @studentproof/sdk.
//
// What it is: a minimal third-party website showing the full walletless
// "Sign in with StudentProof" flow using the published SDK package (@studentproof/sdk):
//   buildAuthorizeUrl, generateState, createPkcePair, exchangeAuthorizationCode,
//   and verifyStudentAssertion from @studentproof/sdk/server.
// The demo never sees a wallet address, email, or proof — only a boolean.
//
// Run locally:
//   1. Provision a client for THIS demo (isolated/studentproof dev DB only):
//        DATABASE_URL="postgresql://postgres@127.0.0.1:54400/sp_phase2" \
//          node /Users/kirigawa/studentproof/scripts/provision-sdk-demo-client.mjs \
//          --allow-host 127.0.0.1 --secret-out .env.demo-secret
//   2. cp .env.example .env   (fill in values; .env is gitignored)
//   3. node server.mjs        (http://localhost:3117)
//
// Deploy to Vercel:
//   1. Set the same env vars (see .env.example) via the Vercel dashboard.
//      Set DEMO_REDIRECT_URI to https://<your-app>.vercel.app/auth/callback
//   2. `npx vercel` or push to Git. Vercel turns api/index.mjs into a serverless
//      function — no server.listen() or port needed.
//
// State is kept in HMAC-signed cookies (stateless) so it survives Vercel's
// cold-start / multi-instance model. Nothing here runs in a browser except
// plain links — the client secret never leaves this process.
import { createHash, createHmac, randomBytes } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { createServer } from "node:http";

import {
  buildAuthorizeUrl,
  createPkcePair,
  exchangeAuthorizationCode,
  generateState,
  InvalidAssertionError,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  RateLimitedError,
  StudentProofOAuthError,
  VerificationUnavailableError,
} from "@studentproof/sdk";
import { verifyStudentAssertion } from "@studentproof/sdk/server";

// ---- tiny .env loader (no dependency; KEY=VALUE lines only) ----
const ENV_FILE = new URL("./.env", import.meta.url);
if (existsSync(ENV_FILE)) {
  for (const line of readFileSync(ENV_FILE, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq > 0) process.env[trimmed.slice(0, eq).trim()] ??= trimmed.slice(eq + 1).trim();
  }
}

const CONFIG = {
  baseUrl: process.env.STUDENTPROOF_BASE ?? "http://localhost:3118",
  issuer: process.env.STUDENTPROOF_ISSUER ?? process.env.STUDENTPROOF_BASE ?? "http://localhost:3118",
  clientId: process.env.DEMO_CLIENT_ID ?? "",
  clientSecret: process.env.DEMO_CLIENT_SECRET ?? "",
  redirectUri: process.env.DEMO_REDIRECT_URI ?? "http://localhost:3117/auth/callback",
  port: Number(process.env.DEMO_PORT ?? "3117"),
};
for (const [key, value] of Object.entries({ DEMO_CLIENT_ID: CONFIG.clientId, DEMO_CLIENT_SECRET: CONFIG.clientSecret })) {
  if (!value) {
    console.error(`error: ${key} is not set. Copy .env.example to .env and fill it in (step 2 above).`);
    process.exit(1);
  }
}

// ---- HMAC-signed cookies (stateless; survives cold starts) ----
const PENDING_TTL_MS = 10 * 60 * 1000;
const SESSION_TTL_S = 3600;

function sign(payload, secret) {
  return createHmac("sha256", secret).update(payload).digest("hex");
}

function makeSignedCookie(data, secret, ttl) {
  const json = Buffer.from(JSON.stringify({ d: data, t: Date.now() })).toString("base64url");
  const sig = sign(json, secret);
  const parts = [`pkce=${json}.${sig}`, "HttpOnly", "SameSite=Lax", "Path=/"];
  if (ttl) parts.push(`Max-Age=${ttl}`);
  return parts.join("; ");
}

function parseSignedCookie(raw, secret) {
  const eq = raw.indexOf("=");
  if (eq < 0) return null;
  const val = decodeURIComponent(raw.slice(eq + 1).trim());
  const dot = val.indexOf(".");
  if (dot < 0) return null;
  const json = val.slice(0, dot);
  const sig = val.slice(dot + 1);
  if (sig !== sign(json, secret)) return null;
  try {
    const { d, t } = JSON.parse(Buffer.from(json, "base64url").toString("utf8"));
    return { data: d, createdAt: t };
  } catch {
    return null;
  }
}

function getCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0) out[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

function errorLabel(err) {
  // Map SDK error types to a short human-readable label for the demo page.
  // No secrets or internal codes are leaked — only a safe label + HTTP status.
  if (err instanceof InvalidClientError) return "invalid_client (401)";
  if (err instanceof InvalidGrantError) return "invalid_grant (400)";
  if (err instanceof InvalidRequestError) return "invalid_request (400)";
  if (err instanceof RateLimitedError) return "rate_limited (429)";
  if (err instanceof InvalidAssertionError) return "invalid_assertion";
  if (err instanceof VerificationUnavailableError) return "verification_unavailable";
  if (err instanceof StudentProofOAuthError) return `oauth_error (${err.code})`;
  return "unexpected_error";
}

const page = (title, inner) => `<!doctype html><html><head><meta charset="utf8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title></head><body style="font-family:system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem;line-height:1.6"><h1>${title}</h1>${inner}</body></html>`;

function logRequest(req, status) {
  // Diagnostics only: method + status, never query values (code/state are
  // single-use secrets), never headers/cookies.
  const rawPath = (req.url || "/").split("?", 1)[0];
  console.log(`[demo] ${req.method} ${rawPath} -> ${status}`);
}

// ---- request handler (stateless; works as a serverless function) ----
export const handler = async (req, res) => {
  const finish = (status) => logRequest(req, status);
  const origEnd = res.end.bind(res);
  res.end = (...args) => {
    finish(res.statusCode);
    return origEnd(...args);
  };
  try {
    // On Vercel (behind the edge proxy) the host arrives via x-forwarded-host.
    const host = req.headers["x-forwarded-host"] || req.headers.host || `localhost:${CONFIG.port}`;
    const proto = req.headers["x-forwarded-proto"] || "http";
    const url = new URL(req.url, `${proto}://${host}`);
    const pathname = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, "") : url.pathname;

    if (pathname === "/" && req.method === "GET") {
      const state = generateState();
      const { verifier, challenge } = await createPkcePair();
      const pkceCookie = makeSignedCookie({ state, verifier }, CONFIG.clientSecret, PENDING_TTL_MS / 1000);
      const authUrl = buildAuthorizeUrl({
        baseUrl: CONFIG.baseUrl,
        clientId: CONFIG.clientId,
        redirectUri: CONFIG.redirectUri,
        state,
        codeChallenge: challenge,
      });
      res.writeHead(200, { "content-type": "text/html", "Set-Cookie": pkceCookie });
      res.end(page("Demo shop", `<p>Student discount: 20% off. Prove your status without sharing a wallet or email.</p><p><a href="${authUrl}">Sign in with StudentProof</a></p>`));
      return;
    }

    if (pathname === "/auth/callback" && req.method === "GET") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state") ?? "";
      const err = url.searchParams.get("error");

      if (err) {
        res.writeHead(200, { "content-type": "text/html", "Set-Cookie": "pkce=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0" });
        res.end(page("Not shared", `<p>The student ${err === "access_denied" ? "denied consent" : "could not share status"} (${err}). No student data was received. <a href="/">Try again</a>.</p>`));
        return;
      }

      // Verify the signed PKCE/state cookie (CSRF + replay protection).
      const pkce = parseSignedCookie(getCookies(req).pkce ?? "", CONFIG.clientSecret);
      if (!pkce || pkce.data.state !== state || !code || Date.now() - pkce.createdAt > PENDING_TTL_MS) {
        res.writeHead(400, { "content-type": "text/html", "Set-Cookie": "pkce=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0" });
        res.end(page("Login failed", `<p>Unknown or expired login attempt (bad state). This stops login-CSRF. <a href="/">Restart</a>.</p>`));
        return;
      }

      // Server-to-server exchange + verification using the SDK.
      let assertion;
      try {
        const tokenRes = await exchangeAuthorizationCode({
          baseUrl: CONFIG.baseUrl,
          code,
          redirectUri: CONFIG.redirectUri,
          clientId: CONFIG.clientId,
          clientSecret: CONFIG.clientSecret,
          codeVerifier: pkce.data.verifier,
        });
        assertion = tokenRes.assertion;
      } catch (err) {
        res.writeHead(502, { "content-type": "text/html", "Set-Cookie": "pkce=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0" });
        res.end(page("Login failed", `<p>Code exchange failed (${errorLabel(err)}). No access granted on error paths. <a href="/">Restart</a>.</p>`));
        return;
      }

      let result;
      try {
        result = await verifyStudentAssertion({
          baseUrl: CONFIG.baseUrl,
          assertion,
          expectedAud: CONFIG.clientId,
          expectedIss: CONFIG.issuer,
        });
      } catch (err) {
        res.writeHead(502, { "content-type": "text/html" });
        res.end(page("Login failed", `<p>Assertion rejected (${errorLabel(err)}). <a href="/">Restart</a>.</p>`));
        return;
      }

      const sessionCookie = makeSignedCookie(
        { sub: result.sub, verified: result.valid },
        CONFIG.clientSecret,
        SESSION_TTL_S
      );
      res.writeHead(302, {
        location: "/me",
        "set-cookie": [
          `pkce=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
          `demo_session=${sessionCookie}`,
        ].join(", "),
      });
      res.end();
      return;
    }

    if (pathname === "/me" && req.method === "GET") {
      const session = parseSignedCookie(getCookies(req).demo_session ?? "", CONFIG.clientSecret);
      if (!session) {
        res.writeHead(302, { location: "/" });
        res.end();
        return;
      }
      const { sub, verified } = session.data;
      res.writeHead(200, { "content-type": "text/html" });
      res.end(
        page(
          "Your discount",
          verified
            ? `<p>Verified student — 20% off applied. (Subject <code>${sub.slice(0, 12)}…</code>, pairwise for this demo.)</p><p><a href="/logout">Log out</a></p>`
            : `<p>No active credential — discount not applied. Verify on StudentProof, then <a href="/">sign in again</a>.</p><p><a href="/logout">Log out</a></p>`
        )
      );
      return;
    }

    if (pathname === "/logout") {
      res.writeHead(302, {
        location: "/",
        "set-cookie": [
          "pkce=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
          "demo_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
        ].join(", "),
      });
      res.end();
      return;
    }

    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
  } catch (e) {
    console.error("[demo] unexpected error:", e instanceof Error ? e.message : String(e));
    res.writeHead(500, { "content-type": "text/plain" });
    res.end("demo error");
  }
};

// Default export for Vercel Serverless Functions (expects export default).
export { handler as default };

// Local dev: start a real HTTP server. On Vercel the function is exported.
const isVercel = process.env.VERCEL === "1" || Boolean(process.env.VERCEL_REGION);
if (!isVercel) {
  const server = createServer(handler);
  server.listen(CONFIG.port, () => console.log(`demo relying party on http://localhost:${CONFIG.port}`));
}
