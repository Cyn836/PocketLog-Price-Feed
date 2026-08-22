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
//   2. Serve KV as JSON:
//        GET /          -> the latest snapshot (key `data`), unchanged forever:
//                          every released version of the app reads this exact
//                          route and shape, so it must not drift.
//        GET /history   -> price history for charts, sliced server-side.
//
// Requires:
//   - KV binding named PRICES (Settings > Bindings -> KV Namespace binding).
//   - Secret GITHUB_TOKEN — a GitHub PAT with `actions:write` on the repo.
//   - Cron Trigger(s) (Settings > Triggers -> Cron Triggers).
//   - GITHUB_OWNER / GITHUB_REPO below match your repo.

const GITHUB_OWNER = "Cyn836";
const GITHUB_REPO = "PocketLog-Price-Feed";
const GITHUB_WORKFLOW_FILE = "fetch-prices.yml";

// ---------------------------------------------------------------------------
// KV reads, memoized per isolate
//
// Deliberately NOT the Cache API: its behaviour on a *.workers.dev subdomain is
// not something this deployment can rely on, and caching whole Responses risks
// pinning an error body. A module-scope map works everywhere — isolates are
// reused across many requests, so this collapses most repeat KV reads for free.
// Different isolates can drift by up to the TTL, which is harmless for data
// that only changes every ~15 minutes.

const memo = new Map();

async function readKV(env, key, ttlMs) {
  const hit = memo.get(key);
  if (hit && Date.now() - hit.at < ttlMs) return hit.value;
  const value = await env.PRICES.get(key, "json");
  memo.set(key, { value, at: Date.now() });
  return value;
}

// ---------------------------------------------------------------------------
// /history
//
// The stored shape is columnar — see the "Lịch sử giá" section of fetch.mjs:
//   { v, scale, t: [...], series: { <id>: { buy: [...], sell: [...] } } }
// with `t` holding epoch seconds for intraday keys and `YYYY-MM-DD` for daily.
//
// Slicing happens HERE, not on the device. The full daily blob is 110 gold ids
// × up to 1500 days; a detail screen wants one product, so shipping the whole
// thing would waste megabytes per chart open.

const INTERVALS = {
  "1h": { source: "intraday", bucketSeconds: 3600, maxAgeSeconds: 300 },
  "4h": { source: "intraday", bucketSeconds: 4 * 3600, maxAgeSeconds: 300 },
  "1d": { source: "daily", group: null, maxAgeSeconds: 3600 },
  "1w": { source: "daily", group: "week", maxAgeSeconds: 3600 },
  "1m": { source: "daily", group: "month", maxAgeSeconds: 3600 },
};

const INTRADAY_TTL_MS = 300_000;
const DAILY_TTL_MS = 3_600_000;
const INTRADAY_RETENTION_DAYS = 30;   // matches INTRADAY_TTL_SECONDS in fetch.mjs
const MAX_LIMIT = 500;

function json(body, { status = 200, maxAgeSeconds } = {}) {
  const headers = { "content-type": "application/json" };
  // Only ever attached to a 200: a cached 503/400 would be served to everyone
  // for the whole window, which is exactly the failure this feed can't afford.
  if (status === 200 && maxAgeSeconds) {
    headers["cache-control"] = `public, max-age=${maxAgeSeconds}`;
  }
  return new Response(JSON.stringify(body), { status, headers });
}

/** `YYYY-MM-DD`, `daysAgo` days before today, in the feed's timezone (Asia/Ho_Chi_Minh). */
function vnDayKey(daysAgo) {
  const date = new Date(Date.now() - daysAgo * 86400_000);
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Ho_Chi_Minh",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);
}

const VN_OFFSET_SECONDS = 7 * 3600;   // Asia/Ho_Chi_Minh, no DST

/** Midnight Asia/Ho_Chi_Minh as epoch seconds — daily stamps become uniform. */
function dayKeyToEpoch(dayKey) {
  return Math.floor(Date.parse(`${dayKey}T00:00:00+07:00`) / 1000);
}

/**
 * Flattens the columnar stores into per-timestamp rows for the requested ids only.
 * `null` means "this id had no quote at this stamp" and is carried through rather
 * than interpolated — the client decides how to render a gap.
 */
function rowsFromStores(stores, ids) {
  const rows = [];
  for (const store of stores) {
    if (!store?.t?.length) continue;
    for (let i = 0; i < store.t.length; i++) {
      const values = {};
      for (const id of ids) {
        const entry = store.series?.[id];
        values[id] = entry ? { buy: entry.buy[i] ?? null, sell: entry.sell[i] ?? null } : null;
      }
      rows.push({ stamp: store.t[i], values });
    }
  }
  return rows.sort((a, b) => a.stamp - b.stamp);
}

/** Last sample wins inside each bucket — a close, not an average. */
function bucketKeyFor(epochSeconds, interval, config) {
  if (config.source === "intraday") {
    return Math.floor(epochSeconds / config.bucketSeconds) * config.bucketSeconds;
  }
  if (config.group === null) return epochSeconds;

  // Shift into VN local time before reading calendar parts, then shift the bucket
  // start back. A daily stamp is VN midnight = 17:00 UTC the previous day, so
  // reading getUTCMonth() directly would file the 1st of a month under the
  // previous one — and the Monday of a week under the week before.
  const local = new Date((epochSeconds + VN_OFFSET_SECONDS) * 1000);
  if (config.group === "month") {
    return Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), 1) / 1000 - VN_OFFSET_SECONDS;
  }
  // Week buckets start Monday, so a partial current week collapses into one point
  // instead of splitting across two.
  const dayOfWeek = (local.getUTCDay() + 6) % 7;
  const monday = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate() - dayOfWeek);
  return monday / 1000 - VN_OFFSET_SECONDS;
}

function collapse(rows, interval, config, ids, limit) {
  const buckets = new Map();
  for (const row of rows) {
    buckets.set(bucketKeyFor(row.stamp, interval, config), row.values);
  }

  const stamps = [...buckets.keys()].sort((a, b) => a - b).slice(-limit);
  const series = {};
  for (const id of ids) series[id] = { buy: [], sell: [] };

  for (const stamp of stamps) {
    const values = buckets.get(stamp);
    for (const id of ids) {
      const point = values[id];
      series[id].buy.push(point?.buy ?? null);
      series[id].sell.push(point?.sell ?? null);
    }
  }
  return { t: stamps, series };
}

async function handleHistory(url, env) {
  const metal = url.searchParams.get("metal");
  const interval = url.searchParams.get("interval") ?? "1d";
  const config = INTERVALS[interval];

  if (metal !== "gold" && metal !== "silver") {
    return json({ error: "metal must be gold or silver" }, { status: 400 });
  }
  if (!config) {
    return json({ error: `interval must be one of ${Object.keys(INTERVALS).join(", ")}` }, { status: 400 });
  }

  const requestedLimit = Number.parseInt(url.searchParams.get("limit") ?? "200", 10);
  const limit = Math.min(Number.isFinite(requestedLimit) && requestedLimit > 0 ? requestedLimit : 200, MAX_LIMIT);

  let stores = [];
  let scale = 1000;

  if (config.source === "intraday") {
    // Enough day-keys to cover `limit` buckets, capped by how long intraday keys live.
    const daysNeeded = Math.min(
      Math.ceil((limit * config.bucketSeconds) / 86400) + 1,
      INTRADAY_RETENTION_DAYS
    );
    const keys = [];
    for (let i = daysNeeded - 1; i >= 0; i--) keys.push(`intraday:${metal}:${vnDayKey(i)}`);
    stores = (await Promise.all(keys.map((key) => readKV(env, key, INTRADAY_TTL_MS)))).filter(Boolean);
  } else {
    const store = await readKV(env, `history:${metal}`, DAILY_TTL_MS);
    if (store) {
      // Daily stamps are date strings; normalize to epoch seconds so every interval
      // this endpoint serves has the same `t` type on the client.
      stores = [{ ...store, t: store.t.map(dayKeyToEpoch) }];
    }
  }

  if (stores.length) scale = stores[0].scale ?? 1000;

  const idsParam = url.searchParams.get("ids");
  const ids = idsParam
    ? idsParam.split(",").map((id) => id.trim()).filter(Boolean)
    : [...new Set(stores.flatMap((store) => Object.keys(store.series ?? {})))];

  if (ids.length === 0) {
    return json({ interval, scale, t: [], series: {} }, { maxAgeSeconds: config.maxAgeSeconds });
  }

  const { t, series } = collapse(rowsFromStores(stores, ids), interval, config, ids, limit);
  return json({ interval, scale, t, series }, { maxAgeSeconds: config.maxAgeSeconds });
}

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
    const url = new URL(request.url);

    if (url.pathname === "/history") return handleHistory(url, env);

    // Every other path keeps the pre-existing behaviour byte-for-byte, including
    // the 503 body: released app versions hit `/` and only `/`.
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
