// StudentProof demo relying party. Runs locally (node server.mjs) and as the
// Vercel root entrypoint — this file creates the HTTP server for both.
//
//   /               authorize URL (PKCE + state)
//   /auth/callback  exchange the code + verify the assertion
//   /me             discount gate        /logout
//
// Serverless-safe: the pending login (state + PKCE verifier) and the session
// live in HMAC-signed, httpOnly cookies instead of server memory, so any
// instance can finish the flow. Secrets come from environment variables only
// (see .env.example); locally they are loaded from .env.
import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";

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

const ENV_FILE = new URL("./.env", import.meta.url);
if (existsSync(ENV_FILE)) {
  for (const line of readFileSync(ENV_FILE, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq > 0) process.env[trimmed.slice(0, eq).trim()] ??= trimmed.slice(eq + 1).trim();
  }
}

const PENDING_TTL_SEC = 10 * 60;
const SESSION_TTL_SEC = 60 * 60;
const PENDING_COOKIE = "sp_pending";
const SESSION_COOKIE = "demo_session";

function loadConfig() {
  const env = process.env;
  const config = {
    baseUrl: env.STUDENTPROOF_BASE ?? "https://studentproof.app",
    issuer: env.STUDENTPROOF_ISSUER ?? env.STUDENTPROOF_BASE ?? "https://studentproof.app",
    clientId: env.DEMO_CLIENT_ID ?? "",
    clientSecret: env.DEMO_CLIENT_SECRET ?? "",
    redirectUri: env.DEMO_REDIRECT_URI ?? "",
    cookieSecret: env.DEMO_COOKIE_SECRET ?? "",
  };
  const missing = Object.entries({
    DEMO_CLIENT_ID: config.clientId,
    DEMO_CLIENT_SECRET: config.clientSecret,
    DEMO_REDIRECT_URI: config.redirectUri,
    DEMO_COOKIE_SECRET: config.cookieSecret,
  })
    .filter(([, value]) => !value)
    .map(([key]) => key);
  if (missing.length > 0) throw new Error(`missing env: ${missing.join(", ")}`);
  if (config.cookieSecret.length < 32) throw new Error("DEMO_COOKIE_SECRET must be at least 32 characters");
  return config;
}

// Signed cookie payloads: base64url(JSON) "." HMAC-SHA256(body).
function sign(secret, payload) {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${body}.${createHmac("sha256", secret).update(body).digest("base64url")}`;
}

function unsign(secret, token) {
  if (typeof token !== "string") return null;
  const dot = token.indexOf(".");
  if (dot <= 0) return null;
  const body = token.slice(0, dot);
  const mac = token.slice(dot + 1);
  const expected = createHmac("sha256", secret).update(body).digest("base64url");
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (typeof payload?.exp !== "number" || payload.exp * 1000 < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function readCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0) out[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

function setCookie(res, name, value, maxAge, secure) {
  const parts = [`${name}=${encodeURIComponent(value)}`, "Path=/", "HttpOnly", "SameSite=Lax", `Max-Age=${maxAge}`];
  if (secure) parts.push("Secure");
  const existing = res.getHeader("set-cookie");
  const list = Array.isArray(existing) ? existing : existing ? [existing] : [];
  res.setHeader("set-cookie", [...list, parts.join("; ")]);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function errorLabel(err) {
  if (err instanceof InvalidClientError) return "invalid_client (401)";
  if (err instanceof InvalidGrantError) return "invalid_grant (400)";
  if (err instanceof InvalidRequestError) return "invalid_request (400)";
  if (err instanceof RateLimitedError) return "rate_limited (429)";
  if (err instanceof InvalidAssertionError) return "invalid_assertion";
  if (err instanceof VerificationUnavailableError) return "verification_unavailable";
  if (err instanceof StudentProofOAuthError) return `oauth_error (${err.code})`;
  return "unexpected_error";
}

function send(res, status, title, innerHtml) {
  res.statusCode = status;
  res.setHeader("content-type", "text/html; charset=utf-8");
  res.end(
    `<!doctype html><html><head><meta charset="utf8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title></head><body style="font-family:system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem;line-height:1.6"><h1>${escapeHtml(title)}</h1>${innerHtml}</body></html>`
  );
}

function redirect(res, location) {
  res.statusCode = 302;
  res.setHeader("location", location);
  res.end();
}

async function handler(req, res) {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    console.error("[demo] configuration error:", err.message);
    return send(res, 500, "Demo misconfigured", "<p>The demo is not configured. Check the server environment variables.</p>");
  }
  const secure = config.redirectUri.startsWith("https://");
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, "") : url.pathname;
  const cookies = readCookies(req);

  if (path === "/" && req.method === "GET") {
    const state = generateState();
    const { verifier, challenge } = await createPkcePair();
    const authUrl = buildAuthorizeUrl({
      baseUrl: config.baseUrl,
      clientId: config.clientId,
      redirectUri: config.redirectUri,
      state,
      codeChallenge: challenge,
    });
    setCookie(res, PENDING_COOKIE, sign(config.cookieSecret, { state, verifier, exp: Math.floor(Date.now() / 1000) + PENDING_TTL_SEC }), PENDING_TTL_SEC, secure);
    return send(
      res,
      200,
      "Demo shop",
      `<p>Student discount: 20% off. Prove your status without sharing a wallet or email.</p><p><a href="${escapeHtml(authUrl)}">Sign in with StudentProof</a></p>`
    );
  }

  if (path === "/auth/callback" && req.method === "GET") {
    // The pending cookie is single-use: clear it on every callback.
    setCookie(res, PENDING_COOKIE, "", 0, secure);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state") ?? "";
    const err = url.searchParams.get("error");

    if (err) {
      return send(
        res,
        200,
        "Not shared",
        `<p>The student ${err === "access_denied" ? "denied consent" : "could not share status"} (${escapeHtml(err)}). No student data was received. <a href="/">Try again</a>.</p>`
      );
    }

    const pend = unsign(config.cookieSecret, cookies[PENDING_COOKIE]);
    if (!pend || !code || pend.state !== state) {
      return send(res, 400, "Login failed", `<p>Unknown or expired login attempt (bad state). This stops login-CSRF. <a href="/">Restart</a>.</p>`);
    }

    let assertion;
    try {
      ({ assertion } = await exchangeAuthorizationCode({
        baseUrl: config.baseUrl,
        code,
        redirectUri: config.redirectUri,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        codeVerifier: pend.verifier,
      }));
    } catch (e) {
      return send(res, 502, "Login failed", `<p>Code exchange failed (${errorLabel(e)}). No access granted on error paths. <a href="/">Restart</a>.</p>`);
    }

    let result;
    try {
      result = await verifyStudentAssertion({
        baseUrl: config.baseUrl,
        assertion,
        expectedAud: config.clientId,
        expectedIss: config.issuer,
      });
    } catch (e) {
      return send(res, 502, "Login failed", `<p>Assertion rejected (${errorLabel(e)}). <a href="/">Restart</a>.</p>`);
    }

    setCookie(res, SESSION_COOKIE, sign(config.cookieSecret, { sub: result.sub, verified: result.valid, exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SEC }), SESSION_TTL_SEC, secure);
    return redirect(res, "/me");
  }

  if (path === "/me" && req.method === "GET") {
    const session = unsign(config.cookieSecret, cookies[SESSION_COOKIE]);
    if (!session) return redirect(res, "/");
    return send(
      res,
      200,
      "Your discount",
      session.verified
        ? `<p>Verified student — 20% off applied. (Subject <code>${escapeHtml(String(session.sub).slice(0, 12))}…</code>, pairwise for this demo.)</p><p><a href="/logout">Log out</a></p>`
        : `<p>No active credential — discount not applied. Verify on StudentProof, then <a href="/">sign in again</a>.</p><p><a href="/logout">Log out</a></p>`
    );
  }

  if (path === "/logout") {
    setCookie(res, SESSION_COOKIE, "", 0, secure);
    return redirect(res, "/");
  }

  return send(res, 404, "Not found", "<p>Not found.</p>");
}

const port = Number(process.env.PORT ?? process.env.DEMO_PORT ?? "3117");
createServer(async (req, res) => {
  const raw = (req.url || "/").split("?", 1)[0];
  res.on("finish", () => console.log(`[demo] ${req.method} ${raw} -> ${res.statusCode}`));
  try {
    await handler(req, res);
  } catch (e) {
    console.error("[demo] unexpected error:", e instanceof Error ? e.message : String(e));
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader("content-type", "text/plain");
    }
    res.end("demo error");
  }
}).listen(port, () => console.log(`demo relying party on http://localhost:${port}`));
