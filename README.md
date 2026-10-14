# StudentProof demo relying party

A minimal third-party website proving the walletless **Sign in with StudentProof** flow end to end. Zero dependencies (Node 18+ only). It never sees a wallet address, email, or proof — only the boolean student status inside a signed assertion.

## Setup (isolated environments only)

1. Start the isolated StudentProof server (throwaway Postgres + Redis + fresh
   signing keys — see the Phase 2 report for the exact recipe; never point this
   demo at production).
2. Provision this demo as a client of that server (run from the studentproof repo):
   ```bash
   DATABASE_URL="postgresql://postgres@127.0.0.1:54400/sp_phase2" \
     node scripts/provision-sdk-demo-client.mjs \
     --allow-host 127.0.0.1 --secret-out .env.demo-secret
   ```
   The script refuses non-loopback databases. The raw secret is written once.
3. `cp .env.example .env` and set `DEMO_CLIENT_SECRET` from `.env.demo-secret`.
4. `node server.mjs` → open http://localhost:3117 → **Sign in with StudentProof**.

## Flow

`/` builds the authorize URL (`client_id`, exact `redirect_uri`, random `state`,
PKCE S256 challenge; verifier kept server-side) → student signs in on
StudentProof, consents, returns to `/auth/callback?code&state` → the demo
validates `state` (single-use, 10-minute expiry — login-CSRF protection),
exchanges the code server-to-server (client secret + verifier, form-encoded),
fetches `GET {STUDENTPROOF_BASE}/api/sdk/jwks`, verifies the Ed25519 assertion
(signature, `iss`, `aud`, claims, lifetime), then mints its own
`HttpOnly; SameSite=Lax` session. `/me` gates the discount on `verified`;
`/logout` clears it.

## Security notes

- The client secret lives only in server-side `.env` and travels only in the
  token exchange. Browser code sees links, never secrets.
- Any error at any step (bad state, failed exchange, rejected assertion, chain
  outage upstream) grants nothing — the demo fails closed.
- Assertion checks enforced: `v2` shape, known `kid` (JWKS refreshed once on
  miss, covering rotation overlap), Ed25519 signature over the
  domain-separated payload, exact `iss`/`aud`, boolean `vb`, `exp`/`iat` with
  ±60s skew.
- Pending logins and sessions are in-memory (single demo instance, fine for a
  demo; a real app persists them).

## Troubleshooting

| Symptom | Cause |
|---|---|
| `invalid_client` (401) at token exchange | wrong secret or unknown client id |
| `invalid_grant` (400) | reused/expired code, wrong redirect URI, or wrong PKCE verifier |
| `access_denied` at callback | student clicked Deny |
| `verification_required` on StudentProof | student holds no active credential |
| `temporarily_unavailable` (502) | chain read failed upstream — retry later, code not consumed |
| Login failed: bad state | stale/unknown callback — restart from `/` |
