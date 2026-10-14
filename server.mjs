// Local runner for the demo. The app itself is api/demo.mjs (same code that
// runs on Vercel); this only loads .env and serves it on DEMO_PORT.
import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";

const ENV_FILE = new URL("./.env", import.meta.url);
if (existsSync(ENV_FILE)) {
  for (const line of readFileSync(ENV_FILE, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq > 0) process.env[trimmed.slice(0, eq).trim()] ??= trimmed.slice(eq + 1).trim();
  }
}

const { default: handler } = await import("./api/demo.mjs");
const port = Number(process.env.DEMO_PORT ?? "3117");
createServer(handler).listen(port, () => console.log(`demo relying party on http://localhost:${port}`));
