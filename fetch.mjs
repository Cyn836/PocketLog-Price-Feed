// Fetches gold/silver/world-spot prices from the same dealer sources as
// Money/Services/InvestServiceHelper.swift and pushes them to a Cloudflare KV
// namespace via the Cloudflare API — the Worker only *serves* that KV value,
// it no longer fetches anything itself (its outbound requests get 520/403'd
// by DOJI/PNJ from the shared Cloudflare Workers egress IP range; a GitHub
// Actions runner IP isn't blocked, so the actual scraping happens here).
//
// Runs on `workflow_dispatch`, triggered by the Worker's cron on a schedule —
// see .github/workflows/fetch-prices.yml.
//
// Each item carries its own `updatedAt`. Every run reads whatever's already
// in KV first and merges freshly fetched items on top by `id`: a dealer that
// fetched successfully gets its data + updatedAt bumped to now; a dealer that
// failed just keeps its last-known entry (old data, old updatedAt) instead of
// disappearing from the feed.

import { createDecipheriv } from "node:crypto";
import https from "node:https";
import tls from "node:tls";
import { normalize, typeCode } from "./lib/metalBrandKey.mjs";
import * as scraper from "./lib/silverTableScraper.mjs";
import { luongPerUnit as silverLuongPerUnit, luongPerKg, isPlausible, logRejected } from "./lib/silverUnitNormalizer.mjs";

const BROWSER_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

async function fetchHTML(url) {
  const res = await fetch(url, { headers: { "User-Agent": BROWSER_UA } });
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return res.text();
}

async function fetchJSON(url, init) {
  const res = await fetch(url, init);
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return res.json();
}

// baotinmanhhai.vn's server doesn't send its intermediate certificate in the
// TLS handshake — curl/macOS tolerate that (cached/AIA-fetched elsewhere),
// but Node's fetch validates strictly and fails with UNABLE_TO_VERIFY_LEAF_
// SIGNATURE. Supplying the missing intermediate (GlobalSign RSA OV SSL CA
// 2018, publicly downloadable from GlobalSign's own repository) alongside
// Node's default trust store fixes the chain without disabling verification.
const globalSignRsaOvSslCa2018 = `-----BEGIN CERTIFICATE-----
MIIETjCCAzagAwIBAgINAe5fIh38YjvUMzqFVzANBgkqhkiG9w0BAQsFADBMMSAw
HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFs
U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xODExMjEwMDAwMDBaFw0yODEx
MjEwMDAwMDBaMFAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52
LXNhMSYwJAYDVQQDEx1HbG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKdaydUMGCEAI9WXD+uu3Vxoa2uP
UGATeoHLl+6OimGUSyZ59gSnKvuk2la77qCk8HuKf1UfR5NhDW5xUTolJAgvjOH3
idaSz6+zpz8w7bXfIa7+9UQX/dhj2S/TgVprX9NHsKzyqzskeU8fxy7quRU6fBhM
abO1IFkJXinDY+YuRluqlJBJDrnw9UqhCS98NE3QvADFBlV5Bs6i0BDxSEPouVq1
lVW9MdIbPYa+oewNEtssmSStR8JvA+Z6cLVwzM0nLKWMjsIYPJLJLnNvBhBWk0Cq
o8VS++XFBdZpaFwGue5RieGKDkFNm5KQConpFmvv73W+eka440eKHRwup08CAwEA
AaOCASkwggElMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0G
A1UdDgQWBBT473/yzXhnqN5vjySNiPGHAwKz6zAfBgNVHSMEGDAWgBSP8Et/qC5F
JK5NUPpjmove4t0bvDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6
Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjMwNgYDVR0fBC8wLTAroCmgJ4Yl
aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+
MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5j
b20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBAJmQyC1fQorUC2bbmANz
EdSIhlIoU4r7rd/9c446ZwTbw1MUcBQJfMPg+NccmBqixD7b6QDjynCy8SIwIVbb
0615XoFYC20UgDX1b10d65pHBf9ZjQCxQNqQmJYaumxtf4z1s4DfjGRzNpZ5eWl0
6r/4ngGPoJVpjemEuunl1Ig423g7mNA2eymw0lIYkN5SQwCuaifIFJ6GlazhgDEw
fpolu4usBCOmmQDo8dIm7A9+O4orkjgTHY+GzYZSR+Y0fFukAj6KYXwidlNalFMz
hriSqHKvoflShx8xpfywgVcvzfTO3PYkz6fiNJBonf6q8amaEsybwMbDqKWwIX7e
SPY=
-----END CERTIFICATE-----`;

function postJSONWithExtraCA(url, body, extraCA) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = https.request(
      url,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) },
        ca: [...tls.rootCertificates, extraCA],
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error(`${url} -> HTTP ${res.statusCode}`));
            return;
          }
          try {
            resolve(JSON.parse(data));
          } catch (err) {
            reject(err);
          }
        });
      }
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

/** Coerces a value that may be a native number or numeric string into a Number. */
function numericValue(raw) {
  if (typeof raw === "number") return raw;
  if (typeof raw === "string") {
    const n = Number(raw);
    return Number.isNaN(n) ? null : n;
  }
  return null;
}

/** "141.000" ("." as digit-group separator) as thousands of VND -> full VND. */
function pnjThousandVNDPrice(raw) {
  const digits = raw.replace(/\D/g, "");
  if (!digits) return null;
  return Number(digits) * 1000;
}

/** "12.960" / "1.774" as millions of VND (3-decimal convention) -> full VND. */
function goldMillionVNDPrice(raw) {
  const cleaned = raw.replace(",", ".").trim();
  const value = Number(cleaned);
  if (Number.isNaN(value)) return null;
  return value * 1_000_000;
}

/** Trailing size phrase after the last " - ", e.g. "Bạc ... - 1 lượng" -> "1 lượng". */
function packagingLabel(name) {
  const idx = name.lastIndexOf(" - ");
  if (idx === -1) return null;
  const tail = name.slice(idx + 3).trim();
  return tail || null;
}

/** "BẠC THƯƠNG HIỆU PHÚ QUÝ" -> "Phú Quý"; otherwise title-cased as-is. */
function prettifyBrandGroup(raw) {
  const stripped = raw.replace(/^\s*BẠC\s+THƯƠNG\s+HIỆU\s+/i, "").trim();
  const base = stripped || raw;
  return base
    .toLowerCase()
    .replace(/(^|\s)\S/g, (c) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Exclusion lists (InvestServiceHelper.swift:688-734)

const excludedGoldProductNames = {
  btmc: new Set(["qua mung ban vi vang bao tin minh chau", "vang he thong", "vang mieng sjc"]),
  doji: new Set(["vang mieng sjc"]),
  phuquy: new Set(["vang mieng sjc"]),
  pnj: new Set(["pnj", "sjc"]),
};

function isExcludedGoldProduct(brandSlug, name) {
  const excluded = excludedGoldProductNames[brandSlug];
  return excluded ? excluded.has(normalize(name)) : false;
}

const excludedSilverProductNamePrefixes = [
  "bac 999 tren 1500 luong",
  "bac 999 (mieng-thanh-thoi)",
  "bac 999 (mieng - thanh - thoi)",
];

function isExcludedSilverProduct(name) {
  const normalized = normalize(name);
  return excludedSilverProductNamePrefixes.some((prefix) => normalized.startsWith(prefix));
}

// ---------------------------------------------------------------------------
// Gold fetchers

const sjcGoldBrandSlug = "sjc";
const dojiGoldBrandSlug = "doji";
const pnjGoldBrandSlug = "pnj";
const btmcGoldBrandSlug = "btmc";
const baoTinManhHaiGoldBrandSlug = "baotinmanhhai";
const kimNganPhucGoldBrandSlug = "kimnganphuc";
const miHongGoldBrandSlug = "mihong";
const ngocThamGoldBrandSlug = "ngoctham";
const phuQuyGoldBrandSlug = "phuquy";
const huyThanhGoldBrandSlug = "huythanh";

async function fetchSJCGoldBrands() {
  const html = await fetchHTML("https://baomoi.com/tien-ich-gia-vang-sjc.epi");
  const idMarker = html.indexOf("__NEXT_DATA__");
  if (idMarker === -1) return [];
  const scriptEndIdx = html.indexOf("</script>", idMarker);
  if (scriptEndIdx === -1) return [];
  const jsonStartIdx = html.indexOf(">", idMarker);
  if (jsonStartIdx === -1 || jsonStartIdx > scriptEndIdx) return [];
  const jsonString = html.slice(jsonStartIdx + 1, scriptEndIdx);

  let nextData;
  try {
    nextData = JSON.parse(jsonString);
  } catch {
    return [];
  }
  const entries = nextData?.props?.pageProps?.resp?.data?.content?.entries ?? [];
  return entries
    .filter((entry) => entry.buy > 0)
    .map((entry) => ({
      id: typeCode(sjcGoldBrandSlug, entry.name),
      name: entry.name,
      buy: entry.buy,
      sell: entry.sell ?? 0,
      currency: "VND",
      brand: "SJC",
    }));
}

const dojiTablePriceAESKeyHex = "7a4b8c3d1e9f2a5b6c0d4e8f3a7b1c5d9e2f6a0b4c8d3e7f1a5b9c2d6e0f4a8b";

function dojiDecryptTablePrice(base64) {
  const raw = Buffer.from(base64, "base64");
  if (raw.length <= 16) return null;
  const key = Buffer.from(dojiTablePriceAESKeyHex, "hex");
  const iv = raw.subarray(0, 16);
  const ciphertext = raw.subarray(16);
  try {
    const decipher = createDecipheriv("aes-256-cbc", key, iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    return null;
  }
}

let dojiTableRowsPromise = null;

/** Shared by gold and silver — one table carries both (`type: "G"`/`"S"`), fetched/decrypted once. */
function fetchDojiTableRows() {
  if (!dojiTableRowsPromise) {
    dojiTableRowsPromise = (async () => {
      const envelope = await fetchJSON("https://banggia.doji.vn/api/TablePrice/GetTablePrice");
      const decrypted = dojiDecryptTablePrice(envelope.data);
      if (!decrypted) throw new Error("DOJI: decrypt failed");
      return JSON.parse(decrypted.toString("utf8"));
    })();
  }
  return dojiTableRowsPromise;
}

async function fetchDojiGoldBrands() {
  const rows = await fetchDojiTableRows();
  return rows
    .filter((row) => row.type === "G" && row.isActive === true)
    .filter((row) => !isExcludedGoldProduct(dojiGoldBrandSlug, row.materialName))
    .filter((row) => row.priceDojiBuyIn > 0)
    .map((row) => ({
      id: typeCode(dojiGoldBrandSlug, row.materialName),
      name: row.materialName,
      buy: row.priceDojiBuyIn * 1000,
      sell: (row.priceDojiSellOut ?? 0) * 1000,
      currency: "VND",
      brand: "DOJI",
    }));
}

async function fetchPNJGoldBrands() {
  const response = await fetchJSON("https://edge-cf-api.pnj.io/ecom-frontend/v3/get-gold-price");
  const items = [];
  for (const location of response.locations ?? []) {
    for (const entry of location.gold_type ?? []) {
      if (isExcludedGoldProduct(pnjGoldBrandSlug, entry.name)) continue;
      const buy = pnjThousandVNDPrice(entry.gia_mua);
      if (!(buy > 0)) continue;
      const sell = pnjThousandVNDPrice(entry.gia_ban) ?? 0;
      items.push({
        id: typeCode(pnjGoldBrandSlug, entry.name),
        name: entry.name,
        buy,
        sell,
        currency: "VND",
        brand: "PNJ",
      });
    }
  }
  return items;
}

// btmc.vn itself 520/522's from the shared Cloudflare egress range but is
// fine from a GitHub Actions runner — however its own chart page prices
// per-chỉ, not per-lượng like every other dealer here. giavang.org mirrors
// BTMC's counter prices per-lượng (states "Đơn vị: x1000đ/lượng" on-page),
// grouped under a "Thương phẩm" heading (VRTL / Quà Mừng Vàng / Vàng SJC /
// Vàng BTMC / Vàng Thị Trường) that repeats via rowspan — carry it forward
// as a prefix so ids stay unique and readable.
async function fetchBTMCGoldBrands() {
  const html = await fetchHTML("https://giavang.org/trong-nuoc/bao-tin-minh-chau/");
  const items = [];
  let currentCategory = "";
  for (const row of scraper.rows(html)) {
    let productName, buyCell, sellCell;
    if (row.cells.length === 4) {
      [currentCategory, productName, buyCell, sellCell] = row.cells;
    } else if (row.cells.length === 3) {
      [productName, buyCell, sellCell] = row.cells;
    } else {
      continue;
    }
    // "Vàng SJC" counter price at BTMC just mirrors SJC's own dealer price —
    // already counted under the SJC fetcher, so skip it here.
    if (normalize(currentCategory).includes("vang sjc")) continue;

    const buy = scraper.price(buyCell);
    const sell = scraper.price(sellCell);
    if (buy === null || sell === null || !(buy > 0)) continue;
    const name = `${currentCategory} - ${productName}`;
    items.push({
      id: typeCode(btmcGoldBrandSlug, name),
      name,
      buy: buy * 1000,
      sell: sell * 1000,
      currency: "VND",
      brand: "Bảo Tín Minh Châu",
    });
  }
  return items;
}

async function fetchBaoTinManhHaiGraphQL(query) {
  return postJSONWithExtraCA("https://baotinmanhhai.vn/api/graphql", { query }, globalSignRsaOvSslCa2018);
}

async function fetchBaoTinManhHaiGoldBrands() {
  const response = await fetchBaoTinManhHaiGraphQL(
    "query { goldRates { items { code name buy_price sell_price } } }"
  );
  const items = response?.data?.goldRates?.items ?? [];
  return items
    .filter((item) => item.buy_price > 0 && !normalize(item.name).startsWith("bac"))
    .map((item) => ({
      id: typeCode(baoTinManhHaiGoldBrandSlug, item.name),
      name: item.name,
      buy: item.buy_price,
      sell: item.sell_price <= 1 ? 0 : item.sell_price,
      currency: "VND",
      brand: "Bảo Tín Mạnh Hải",
    }));
}

async function fetchKimNganPhucRows(url) {
  const html = await fetchHTML(url);
  return scraper.rows(html);
}

function walkKimNganPhucRows(rows, { keepSilver }) {
  const items = [];
  let lastBuy = null;
  let lastSell = null;
  for (const row of rows) {
    if (row.cells.length === 0) continue;
    const name = row.cells[0];

    if (row.cells.length >= 2) {
      const buy = goldMillionVNDPrice(row.cells[1]);
      if (buy === null) continue;
      const sell = row.cells.length >= 3 ? goldMillionVNDPrice(row.cells[2]) ?? 0 : 0;
      lastBuy = buy;
      lastSell = sell;
    } else if (row.cells.length !== 1) {
      continue;
    }

    const isSilver = normalize(name).startsWith("bac");
    if (keepSilver !== isSilver) continue;
    if (lastBuy === null || lastSell === null || !(lastBuy > 0)) continue;

    items.push({ name, buy: lastBuy, sell: lastSell });
  }
  return items;
}

async function fetchKimNganPhucGoldBrands() {
  const rows = await fetchKimNganPhucRows("https://kimnganphuc.vn/gia-vang");
  return walkKimNganPhucRows(rows, { keepSilver: false }).map(({ name, buy, sell }) => ({
    id: typeCode(kimNganPhucGoldBrandSlug, name),
    name,
    buy,
    sell,
    currency: "VND",
    brand: "Kim Ngân Phúc",
  }));
}

async function fetchMiHongGoldBrands() {
  const entries = await fetchJSON("https://api.mihong.vn/v1/gold-prices?market=domestic");
  return entries
    .filter((entry) => entry.buyingPrice > 0)
    .map((entry) => {
      const name = entry.code === "SJC" ? "Vàng miếng SJC" : `Vàng ${entry.code}`;
      return {
        id: typeCode(miHongGoldBrandSlug, name),
        name,
        buy: entry.buyingPrice,
        sell: entry.sellingPrice,
        currency: "VND",
        brand: "Mi Hồng",
      };
    });
}

async function fetchNgocThamGoldBrands() {
  const json = await fetchJSON("https://ngoctham.com/ajax/proxy_banggia.php");
  const rows = json?.chitiet ?? [];
  const items = [];
  for (const row of rows) {
    const name = row.loaivang;
    if (!name) continue;
    const buy = numericValue(row.giamua);
    const sell = numericValue(row.giaban);
    if (buy === null || sell === null || !(buy > 0)) continue;
    const hideBuy = numericValue(row.chihiengiamua) === 1;
    const hideSell = numericValue(row.chihiengiaban) === 1;
    items.push({
      id: typeCode(ngocThamGoldBrandSlug, name),
      name,
      buy: hideBuy ? 0 : buy,
      sell: hideSell ? 0 : sell,
      currency: "VND",
      brand: "Ngọc Thẩm",
    });
  }
  return items;
}

async function fetchPhuQuyGoldBrands() {
  const response = await fetchJSON(
    "https://be.phuquy.com.vn/jewelry/product-payment-service/api/sync-price-history/get-sync-table-history"
  );
  const rows = response?.data ?? [];
  return rows
    .filter((row) => row.type === 1)
    .filter((row) => !isExcludedGoldProduct(phuQuyGoldBrandSlug, row.productTypeName))
    .filter((row) => row.priceIn > 0)
    .map((row) => ({
      id: typeCode(phuQuyGoldBrandSlug, row.productTypeName),
      name: row.productTypeName,
      buy: row.priceIn,
      sell: row.priceOut,
      currency: "VND",
      brand: "Phú Quý",
    }));
}

async function fetchHuyThanhGoldBrands() {
  const html = await fetchHTML("https://huythanhjewelry.vn/gia-vang-hom-nay");
  const items = [];
  for (const row of scraper.rows(html)) {
    if (row.cells.length !== 3) continue;
    const name = row.cells[0];
    const buy = scraper.price(row.cells[1]);
    const sell = scraper.price(row.cells[2]);
    if (buy === null || sell === null || !(buy > 0)) continue;
    items.push({
      id: typeCode(huyThanhGoldBrandSlug, name),
      name,
      buy,
      sell,
      currency: "VND",
      brand: "Huy Thanh",
    });
  }
  return items;
}

async function fetchGoldBrands() {
  const fetchers = [
    fetchSJCGoldBrands,
    fetchDojiGoldBrands,
    fetchPNJGoldBrands,
    fetchBTMCGoldBrands,
    fetchBaoTinManhHaiGoldBrands,
    fetchKimNganPhucGoldBrands,
    fetchMiHongGoldBrands,
    fetchNgocThamGoldBrands,
    fetchPhuQuyGoldBrands,
    fetchHuyThanhGoldBrands,
  ];
  const results = await Promise.allSettled(fetchers.map((fn) => fn()));
  const merged = [];
  results.forEach((result, i) => {
    if (result.status === "fulfilled") {
      merged.push(...result.value);
    } else {
      console.warn(`[gold] ${fetchers[i].name} failed: ${result.reason?.message ?? result.reason}`);
    }
  });
  const seen = new Set();
  return merged
    .filter((item) => (seen.has(item.id) ? false : (seen.add(item.id), true)))
    .sort((a, b) => a.brand.localeCompare(b.brand) || a.name.localeCompare(b.name));
}

// ---------------------------------------------------------------------------
// Silver fetchers

const dojiSilverBrandSlug = "doji";
const phuQuySilverBrandSlug = "phuquy";
const ancaratSilverBrandSlug = "ancarat";
const baoTinManhHaiSilverBrandSlug = "baotinmanhhai";
const kimNganPhucSilverBrandSlug = "kimnganphuc";

async function fetchDojiSilverBrands() {
  const rows = await fetchDojiTableRows();
  const items = [];
  for (const row of rows) {
    if (row.type !== "S" || row.isActive === false) continue;
    const name = row.materialName;
    if (isExcludedSilverProduct(name)) continue;
    if (!(row.priceDojiBuyIn > 0)) continue;

    const unitLuong = silverLuongPerUnit(name) ?? 1;
    const buy = (row.priceDojiBuyIn * 1000) / unitLuong;
    const sell = ((row.priceDojiSellOut ?? 0) * 1000) / unitLuong;
    if (!isPlausible(buy)) {
      logRejected("DOJI", name, `giá/lượng ${Math.round(buy)} ngoài dải hợp lý`);
      continue;
    }
    items.push({
      id: typeCode(dojiSilverBrandSlug, name),
      name,
      buy: Math.round(buy),
      sell: Math.round(sell),
      brand: "DOJI",
      packaging: packagingLabel(name) ?? "Vnđ/Lượng",
    });
  }
  return items;
}

async function fetchPhuQuySilverPriceFallback() {
  const ts = Math.floor(Date.now() / 1000);
  const response = await fetchJSON(
    `https://giabac.vn/SilverInfo/GetGoldPriceChartFromSQLData?days=7&type=L&t=${ts}`,
    { headers: { "User-Agent": "Mozilla/5.0" } }
  );
  const buy = response.LastBuyPrices?.at(-1);
  const sell = response.LastSellPrices?.at(-1);
  if (buy === undefined || sell === undefined) throw new Error("giabac.vn chart: cannot parse");
  return { buy, sell };
}

async function scrapePhuQuySilverBrands() {
  const html = await fetchHTML("https://giabac.vn/");
  const items = [];
  let currentGroup = "Phú Quý";
  for (const row of scraper.rows(html)) {
    if (row.isGroupHeading) {
      currentGroup = prettifyBrandGroup(row.cells[0]);
      continue;
    }
    if (row.cells.length < 4) continue;
    const [name, unit] = row.cells;
    const rawBuy = scraper.price(row.cells[2]);
    const rawSell = scraper.price(row.cells[3]);
    if (rawBuy === null || rawSell === null || !(rawBuy > 0)) continue;

    const divisor = normalize(unit).includes("kg") ? luongPerKg : 1;
    const buy = rawBuy / divisor;
    const sell = rawSell / divisor;
    if (!isPlausible(buy)) {
      logRejected("Phú Quý", name, `giá/lượng ${Math.round(buy)} ngoài dải hợp lý`);
      continue;
    }
    items.push({
      id: typeCode(phuQuySilverBrandSlug, name),
      name,
      buy: Math.round(buy),
      sell: Math.round(sell),
      brand: currentGroup,
      packaging: unit,
    });
  }
  return items;
}

async function fetchPhuQuySilverBrands() {
  try {
    const scraped = await scrapePhuQuySilverBrands();
    if (scraped.length > 0) return scraped;
  } catch (err) {
    console.warn(`[silver] scrapePhuQuySilverBrands failed: ${err.message}`);
  }
  try {
    const price = await fetchPhuQuySilverPriceFallback();
    logRejected("Phú Quý", "toàn bảng", "parse HTML thất bại, dùng chart endpoint");
    return [
      {
        id: typeCode(phuQuySilverBrandSlug, "Bạc miếng Phú Quý 999 1 lượng"),
        name: "Bạc miếng Phú Quý 999 1 lượng",
        buy: price.buy,
        sell: price.sell,
        brand: "Phú Quý",
        packaging: "Vnđ/Lượng",
      },
    ];
  } catch {
    return [];
  }
}

async function fetchAncaratSilverBrands() {
  const html = await fetchHTML("https://giabac.ancarat.com/");
  const items = [];
  let isInBullionGroup = false;
  for (const row of scraper.rows(html)) {
    if (row.isGroupHeading) {
      const heading = normalize(row.cells[0]);
      isInBullionGroup = heading.includes("tich tru") && heading.includes("dang phat hanh");
      continue;
    }
    if (!isInBullionGroup || row.cells.length < 3) continue;
    const name = row.cells[0];
    const rawSell = scraper.price(row.cells[1]);
    const rawBuy = scraper.price(row.cells[2]);
    if (rawSell === null || rawBuy === null) continue;

    if (isExcludedSilverProduct(name)) continue;
    if (!(rawBuy > 0)) {
      logRejected("Ancarat", name, "không có giá mua (phụ kiện/hộp đựng)");
      continue;
    }
    const normalized = normalize(name);
    if (normalized.includes("vang") && normalized.includes("bac")) {
      logRejected("Ancarat", name, "combo vàng + bạc, không quy được về giá bạc/lượng");
      continue;
    }
    const unitLuong = silverLuongPerUnit(name);
    if (!unitLuong) {
      logRejected("Ancarat", name, "không đọc được khối lượng trong tên");
      continue;
    }

    const buy = rawBuy / unitLuong;
    const sell = rawSell / unitLuong;
    if (!isPlausible(buy)) {
      logRejected("Ancarat", name, `giá/lượng ${Math.round(buy)} ngoài dải hợp lý`);
      continue;
    }
    items.push({
      id: typeCode(ancaratSilverBrandSlug, name),
      name,
      buy: Math.round(buy),
      sell: Math.round(sell),
      brand: "Ancarat",
      packaging: packagingLabel(name),
    });
  }
  return items;
}

async function fetchBaoTinManhHaiSilverBrands() {
  const response = await fetchBaoTinManhHaiGraphQL(
    "query { goldRates { items { code name buy_price sell_price unit } } }"
  );
  const items = response?.data?.goldRates?.items ?? [];
  const result = [];
  for (const item of items) {
    if (!normalize(item.name).startsWith("bac") || !(item.buy_price > 0)) continue;
    const isPerKg = (item.unit ?? "").toLowerCase().includes("kg");
    const divisor = isPerKg ? luongPerKg : 1;
    const buy = item.buy_price / divisor;
    const sell = (item.sell_price <= 1 ? 0 : item.sell_price) / divisor;
    if (!isPlausible(buy)) {
      logRejected("Bảo Tín Mạnh Hải", item.name, `giá/lượng ${Math.round(buy)} ngoài dải hợp lý`);
      continue;
    }
    result.push({
      id: typeCode(baoTinManhHaiSilverBrandSlug, item.name),
      name: item.name,
      buy: Math.round(buy),
      sell: Math.round(sell),
      brand: "Bảo Tín Mạnh Hải",
      packaging: item.unit ?? null,
    });
  }
  return result;
}

async function fetchKimNganPhucSilverBrands() {
  const rows = await fetchKimNganPhucRows("https://kimnganphuc.vn/gia-vang");
  const raw = walkKimNganPhucRows(rows, { keepSilver: true });
  const items = [];
  for (const { name, buy, sell } of raw) {
    const unitLuong = silverLuongPerUnit(name);
    if (!unitLuong) {
      logRejected("Kim Ngân Phúc", name, "không đọc được khối lượng trong tên");
      continue;
    }
    const perLuongBuy = buy / unitLuong;
    const perLuongSell = sell / unitLuong;
    if (!isPlausible(perLuongBuy)) {
      logRejected("Kim Ngân Phúc", name, `giá/lượng ${Math.round(perLuongBuy)} ngoài dải hợp lý`);
      continue;
    }
    items.push({
      id: typeCode(kimNganPhucSilverBrandSlug, name),
      name,
      buy: Math.round(perLuongBuy),
      sell: Math.round(perLuongSell),
      brand: "Kim Ngân Phúc",
      packaging: packagingLabel(name),
    });
  }
  return items;
}

async function fetchSilverBrands() {
  const fetchers = [
    fetchDojiSilverBrands,
    fetchPhuQuySilverBrands,
    fetchAncaratSilverBrands,
    fetchBaoTinManhHaiSilverBrands,
    fetchKimNganPhucSilverBrands,
  ];
  const results = await Promise.allSettled(fetchers.map((fn) => fn()));
  const merged = [];
  results.forEach((result, i) => {
    if (result.status === "fulfilled") {
      merged.push(...result.value);
    } else {
      console.warn(`[silver] ${fetchers[i].name} failed: ${result.reason?.message ?? result.reason}`);
    }
  });
  const seen = new Set();
  return merged.filter((item) => (seen.has(item.id) ? false : (seen.add(item.id), true)));
}

// ---------------------------------------------------------------------------
// World spot (TradingView scanner + USD/VND forex)

const ouncesToLuongFactor = 37.5 / 31.1034768;

const tradingViewSymbols = { gold: "TVC:GOLD", silver: "TVC:SILVER" };

async function fetchUsdToVndSellRate() {
  const json = await fetchJSON("https://open.er-api.com/v6/latest/VND");
  if (json.result !== "success") throw new Error("open.er-api.com: not success");
  const rateVndPerUnit = json.rates?.USD;
  if (!(rateVndPerUnit > 0)) throw new Error("open.er-api.com: missing USD rate");
  return 1 / rateVndPerUnit;
}

async function fetchTradingViewClosePrices(tickers) {
  const json = await fetchJSON("https://scanner.tradingview.com/cfd/scan", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: "https://www.tradingview.com",
      Referer: "https://www.tradingview.com/",
      "User-Agent": BROWSER_UA,
    },
    body: JSON.stringify({ symbols: { tickers, query: { types: [] } }, columns: ["close"] }),
  });
  const byTicker = {};
  for (const row of json.data ?? []) {
    byTicker[row.s] = row.d?.[0] ?? null;
  }
  return byTicker;
}

function worldMetalPrice(usdPerOz, usdToVnd) {
  const vndPerOz = usdPerOz * usdToVnd;
  const vndPerLuong = vndPerOz * ouncesToLuongFactor;
  return { usdPerOz, vndPerOz, vndPerChi: vndPerLuong / 10, vndPerLuong };
}

async function fetchWorldPrices() {
  const [usdToVnd, closes] = await Promise.all([
    fetchUsdToVndSellRate(),
    fetchTradingViewClosePrices([tradingViewSymbols.gold, tradingViewSymbols.silver]),
  ]);
  const goldUsd = closes[tradingViewSymbols.gold];
  const silverUsd = closes[tradingViewSymbols.silver];
  if (!(goldUsd > 0) || !(silverUsd > 0)) {
    throw new Error(`TradingView: missing close price (gold=${goldUsd}, silver=${silverUsd})`);
  }
  return { gold: worldMetalPrice(goldUsd, usdToVnd), silver: worldMetalPrice(silverUsd, usdToVnd) };
}

// ---------------------------------------------------------------------------
// Cloudflare KV (REST API — https://api.cloudflare.com/client/v4)

const CF_ACCOUNT_ID = process.env.CF_ACCOUNT_ID;
const CF_KV_NAMESPACE_ID = process.env.CF_KV_NAMESPACE_ID;
const CF_API_TOKEN = process.env.CF_API_TOKEN;

function kvUrl(key) {
  return `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/storage/kv/namespaces/${CF_KV_NAMESPACE_ID}/values/${key}`;
}

async function readKV(key) {
  const res = await fetch(kvUrl(key), {
    headers: { Authorization: `Bearer ${CF_API_TOKEN}` },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`KV read ${key} -> HTTP ${res.status}`);
  return res.json();
}

async function writeKV(key, value, { expirationTtl } = {}) {
  const url = expirationTtl ? `${kvUrl(key)}?expiration_ttl=${expirationTtl}` : kvUrl(key);
  const res = await fetch(url, {
    method: "PUT",
    headers: { Authorization: `Bearer ${CF_API_TOKEN}`, "Content-Type": "text/plain" },
    body: JSON.stringify(value),
  });
  if (!res.ok) throw new Error(`KV write ${key} -> HTTP ${res.status}: ${await res.text()}`);
}

/** By-id merge: fresh data wins per id, ids missing from `fresh` keep their old entry. */
function mergeById(previousItems, freshItems) {
  const merged = new Map((previousItems ?? []).map((item) => [item.id, item]));
  for (const item of freshItems) merged.set(item.id, item);
  return [...merged.values()];
}

// ---------------------------------------------------------------------------
// Lịch sử giá (cho biểu đồ trong app)
//
// Key `data` ở trên chỉ là snapshot mới nhất, bị ghi đè mỗi lần chạy — không đủ để
// vẽ chart. Nên có thêm hai tầng, cả hai đều là key RIÊNG: bản app đang phát hành
// chỉ đọc `data`, nên không bao giờ thấy các key này.
//
//   intraday:<metal>:<YYYY-MM-DD>  mẫu ~15 phút, TTL 30 ngày  -> phục vụ nến 1h/4h
//   history:<metal>                giá đóng mỗi ngày, 1500 mốc -> phục vụ 1d/1w/1m
//
// Cả hai lưu dạng cột (`t` + `series[id].buy/sell`) thay vì mảng object: 110 mã vàng
// × 1500 ngày mà lưu object thì blob phình lên hàng chục MB, chạm giới hạn 25MB/value.

const SCALE = 1000;
const DAILY_MAX_POINTS = 1500;
const INTRADAY_MIN_GAP_MS = 15 * 60 * 1000;
const INTRADAY_TTL_SECONDS = 30 * 86400;

// Giá vàng/bạc là chuyện của thị trường VN, nên mốc ngày phải theo giờ VN chứ không
// phải UTC — runner của GitHub Actions chạy ở UTC, lệch 7 tiếng.
const vnDateFormatter = new Intl.DateTimeFormat("en-CA", {
  timeZone: "Asia/Ho_Chi_Minh",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
});

/** `YYYY-MM-DD` theo giờ Asia/Ho_Chi_Minh. */
function vnDate(date) {
  return vnDateFormatter.format(date);
}

function emptyStore() {
  return { v: 1, scale: SCALE, t: [], series: {} };
}

/**
 * Thêm một mốc vào cuối chuỗi cột. Mã mới xuất hiện giữa đường được pad `null` cho
 * toàn bộ mốc trước đó, mã lần này thiếu cũng pad `null` — nhờ vậy mọi mảng luôn
 * dài bằng `t`, và app chỉ cần zip theo index.
 *
 * `sell: 0` là sentinel "dealer không công bố giá bán" (xem các scraper ở trên) nên
 * phải giữ nguyên số 0, KHÔNG được quy về `null` — hai thứ này khác nghĩa.
 */
function appendSnapshot(store, stamp, items) {
  const index = store.t.length;
  store.t.push(stamp);

  for (const item of items) {
    let entry = store.series[item.id];
    if (!entry) {
      entry = { buy: [], sell: [] };
      store.series[item.id] = entry;
    }
    while (entry.buy.length < index) {
      entry.buy.push(null);
      entry.sell.push(null);
    }
    entry.buy.push(Math.round(item.buy / SCALE));
    entry.sell.push(Math.round(item.sell / SCALE));
  }

  for (const entry of Object.values(store.series)) {
    while (entry.buy.length <= index) {
      entry.buy.push(null);
      entry.sell.push(null);
    }
  }

  return store;
}

/** Cắt cửa sổ trượt, và bỏ hẳn mã đã rỗng sạch sau khi cắt (dealer ngừng bán). */
function trimStore(store, maxPoints) {
  const excess = store.t.length - maxPoints;
  if (excess <= 0) return store;

  store.t = store.t.slice(excess);
  for (const [id, entry] of Object.entries(store.series)) {
    entry.buy = entry.buy.slice(excess);
    entry.sell = entry.sell.slice(excess);
    if (entry.buy.every((value) => value === null)) delete store.series[id];
  }
  return store;
}

/**
 * Một điểm intraday mỗi ~15 phút. Cái gate này là điểm chốt chi phí: gói KV free cho
 * 1000 writes/ngày, nếu append mỗi lần cron thì tần suất cron quyết định hạn mức
 * (cron 5 phút -> 576 writes chỉ riêng intraday). Có gate thì trần là 96
 * writes/metal/ngày bất kể cron dày cỡ nào.
 */
async function appendIntraday(metal, items, dayKey, nowMs) {
  const key = `intraday:${metal}:${dayKey}`;
  const store = (await readKV(key)) ?? emptyStore();
  const last = store.t[store.t.length - 1];
  if (last != null && nowMs - last * 1000 < INTRADAY_MIN_GAP_MS) return false;

  appendSnapshot(store, Math.floor(nowMs / 1000), items);
  // TTL thay cho việc xoá tay: key hết hạn tự động, không tốn write nào để dọn.
  await writeKV(key, store, { expirationTtl: INTRADAY_TTL_SECONDS });
  return true;
}

/** Một điểm mỗi ngày, ghi ở lần chạy đầu tiên sau khi ngày VN đổi -> 1 write/ngày. */
async function appendDaily(metal, items, dayKey) {
  const key = `history:${metal}`;
  const store = (await readKV(key)) ?? { ...emptyStore(), lastDate: null };
  if (store.lastDate === dayKey) return false;

  appendSnapshot(store, dayKey, items);
  store.lastDate = dayKey;
  trimStore(store, DAILY_MAX_POINTS);
  await writeKV(key, store);
  return true;
}

// ---------------------------------------------------------------------------
// main

async function main() {
  if (!CF_ACCOUNT_ID || !CF_KV_NAMESPACE_ID || !CF_API_TOKEN) {
    throw new Error("Missing CF_ACCOUNT_ID / CF_KV_NAMESPACE_ID / CF_API_TOKEN env vars");
  }

  const nowIso = new Date().toISOString();
  const previous = (await readKV("data")) ?? { gold: [], silver: [], world: null };

  const [gold, silver, world] = await Promise.allSettled([
    fetchGoldBrands(),
    fetchSilverBrands(),
    fetchWorldPrices(),
  ]);

  if (gold.status === "rejected") console.error(`[gold] fetchGoldBrands failed: ${gold.reason}`);
  if (silver.status === "rejected") console.error(`[silver] fetchSilverBrands failed: ${silver.reason}`);
  if (world.status === "rejected") console.error(`[world] fetchWorldPrices failed: ${world.reason}`);

  const freshGold = (gold.status === "fulfilled" ? gold.value : []).map((item) => ({
    ...item,
    updatedAt: nowIso,
  }));
  const freshSilver = (silver.status === "fulfilled" ? silver.value : []).map((item) => ({
    ...item,
    updatedAt: nowIso,
  }));

  const mergedGold = mergeById(previous.gold, freshGold).sort(
    (a, b) => a.brand.localeCompare(b.brand) || a.name.localeCompare(b.name)
  );
  const mergedSilver = mergeById(previous.silver, freshSilver);

  const worldPrices =
    world.status === "fulfilled"
      ? {
          gold: { ...world.value.gold, updatedAt: nowIso },
          silver: { ...world.value.silver, updatedAt: nowIso },
        }
      : previous.world ?? null;

  if (mergedGold.length === 0 && mergedSilver.length === 0) {
    console.error("Both gold and silver feeds are empty (fresh + previous) — aborting without writing KV");
    process.exit(1);
  }

  await writeKV("data", { gold: mergedGold, silver: mergedSilver, world: worldPrices });

  console.log(
    `Wrote KV — ${mergedGold.length} gold, ${mergedSilver.length} silver, world=${worldPrices ? "ok" : "missing"}`
  );

  // Sau `data`, và trong try/catch riêng: history là tính năng phụ (biểu đồ trong app),
  // còn `data` là thứ mọi bản app đang phát hành phụ thuộc vào. Một lỗi khi ghi history
  // không được phép làm run này fail và kéo theo feed chính.
  try {
    const now = new Date();
    const dayKey = vnDate(now);
    const nowMs = now.getTime();
    const wrote = [];

    for (const [metal, items] of [
      ["gold", mergedGold],
      ["silver", mergedSilver],
    ]) {
      if (items.length === 0) continue;
      if (await appendIntraday(metal, items, dayKey, nowMs)) wrote.push(`intraday:${metal}`);
      if (await appendDaily(metal, items, dayKey)) wrote.push(`history:${metal}`);
    }

    console.log(wrote.length ? `History — wrote ${wrote.join(", ")}` : "History — nothing due, skipped");
  } catch (err) {
    console.error(`History write failed (feed itself is fine): ${err}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
