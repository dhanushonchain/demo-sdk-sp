// Vercel serverless function entry point.
// Re-exports the stateful handler from server.mjs so Vercel can deploy
// it as a Node.js serverless function (no server.listen needed).
export { handler as default } from "../server.mjs";
