// Port of `SilverTableScraper` (Money/Services/InvestServiceHelper.swift:600-673).
// Minimal HTML table reader for server-rendered dealer pages with no API.

const ENTITY_MAP = {
  "&amp;": "&",
  "&nbsp;": " ",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#39;": "'",
};

function decodeEntities(raw) {
  let text = raw;
  for (const [entity, replacement] of Object.entries(ENTITY_MAP)) {
    text = text.split(entity).join(replacement);
  }
  if (text.includes("&#")) {
    text = text.replace(/&#(\d+);/g, (_, code) => String.fromCodePoint(Number(code)));
  }
  return text;
}

function stripTags(raw) {
  const text = decodeEntities(raw.replace(/<[^>]+>/g, " "));
  return text.replace(/\s+/g, " ").trim();
}

function cellsIn(rowBody) {
  const regex = /<t[dh][^>]*>(.*?)<\/t[dh]>/gis;
  const cells = [];
  let match;
  while ((match = regex.exec(rowBody)) !== null) {
    const text = stripTags(match[1]);
    if (text) cells.push(text);
  }
  return cells;
}

/** `{ cells, isGroupHeading }` per `<tr>` — a single-cell row is a group heading. */
export function rows(html) {
  const regex = /<tr[^>]*>(.*?)<\/tr>/gis;
  const result = [];
  let match;
  while ((match = regex.exec(html)) !== null) {
    const cells = cellsIn(match[1]);
    result.push({ cells, isGroupHeading: cells.length === 1 });
  }
  return result;
}

/** Parses "2,155,000" / "57.466.523" / "_" (placeholder for "no quote", returns 0). Null if empty. */
export function price(raw) {
  const digits = raw.replace(/\D/g, "");
  if (!digits) return raw === "" ? null : 0;
  return Number(digits);
}
