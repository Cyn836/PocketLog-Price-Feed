// Cloudflare Worker — paste into the dashboard "Edit code" editor.
//
// This Worker no longer scrapes anything itself (DOJI/PNJ got 520/403'd from
// the shared Cloudflare Workers egress IP range no matter what — see fetch.mjs
// in the repo for the full story). Its only two jobs now:
//
//   1. On cron, call GitHub's API to trigger the `fetch-prices.yml` workflow
//      (workflow_dispatch) — that workflow runs on a GitHub-hosted runner,
//      which isn't blocked, does the actual scraping, and writes straight to
//      this same KV namespace via the Cloudflare API.
//   2. Serve whatever's currently in KV as JSON on every HTTP request.
//
// Requires:
//   - KV binding named PRICES (Settings > Bindings -> KV Namespace binding).
//   - Secret GITHUB_TOKEN — a GitHub PAT with `actions:write` on the repo.
//   - Cron Trigger(s) (Settings > Triggers -> Cron Triggers).
//   - GITHUB_OWNER / GITHUB_REPO below match your repo.

const GITHUB_OWNER = "Cyn836";
const GITHUB_REPO = "PocketLog-Price-Feed";
const GITHUB_WORKFLOW_FILE = "fetch-prices.yml";

export default {
  async scheduled(event, env, ctx) {
    const res = await fetch(
      `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/actions/workflows/${GITHUB_WORKFLOW_FILE}/dispatches`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.GITHUB_TOKEN}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "pocketlog-price-feed-worker",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ref: "main" }),
      }
    );
    if (!res.ok) {
      console.error(`GitHub dispatch failed: HTTP ${res.status} — ${await res.text()}`);
    } else {
      console.log("Dispatched fetch-prices.yml");
    }
  },

  async fetch(request, env) {
    const data = await env.PRICES.get("data");
    if (!data) {
      return new Response(JSON.stringify({ error: "no data yet" }), {
        status: 503,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(data, { headers: { "content-type": "application/json" } });
  },
};
