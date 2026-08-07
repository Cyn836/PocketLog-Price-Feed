// Port of `MetalQuantityTier` (Money/Services/InvestServiceHelper.swift:418-558).
// Only the pieces this feed actually needs: `denominations()`, used by
// `silverUnitNormalizer.luongPerUnit()` to convert package-total prices to per-lượng.

import { normalize } from "./metalBrandKey.mjs";

export const Unit = {
  chi: { gramsPerUnit: 3.75 },
  luong: { gramsPerUnit: 37.5 },
};

const NUMBER_PATTERN = "(\\d+(?:[.,]\\d+)?)";
const UNIT_PATTERN = "(kilo|kg|gram|luong|chi|l)";

const NOISE_PATTERNS = [
  /\(\s*[\d.,]+\s*ban\s*\)/g,
  /[\d.,]+\s*%/g,
  /\b\d+k\b/g,
  /\b(999|9999|99|925|916|985|980|950|750|680|650|610|585|580|416|410|375|333)\b/g,
];

function stripNoise(name) {
  let out = name;
  for (const pattern of NOISE_PATTERNS) {
    out = out.replace(pattern, " ");
  }
  return out;
}

function grams(numberStr, unitStr) {
  const value = Number(numberStr.replace(",", "."));
  if (!(value > 0)) return null;
  switch (unitStr) {
    case "kilo":
    case "kg":
      return value * 1000;
    case "gram":
      return value;
    case "luong":
    case "l":
      return value * Unit.luong.gramsPerUnit;
    case "chi":
      return value * Unit.chi.gramsPerUnit;
    default:
      return null;
  }
}

function quantityMatches(cleaned) {
  const regex = new RegExp(`${NUMBER_PATTERN}\\s*${UNIT_PATTERN}\\b`, "g");
  const results = [];
  let match;
  while ((match = regex.exec(cleaned)) !== null) {
    const g = grams(match[1], match[2]);
    if (g !== null) results.push(g);
  }
  return results;
}

/** Every denomination named in the product, ascending, in `unit`. Empty when the name states no size. */
export function denominations(rawName, unit) {
  const cleaned = stripNoise(normalize(rawName));
  const values = new Set(quantityMatches(cleaned).map((g) => g / unit.gramsPerUnit));
  return [...values].sort((a, b) => a - b);
}

/** "Bạc 999 trên 1500 lượng" — the quote applies only above this amount. */
export function threshold(rawName, unit) {
  const cleaned = stripNoise(normalize(rawName));
  const regex = new RegExp(`\\btren\\s+${NUMBER_PATTERN}\\s*${UNIT_PATTERN}\\b`);
  const match = regex.exec(cleaned);
  if (!match) return null;
  const g = grams(match[1], match[2]);
  return g === null ? null : g / unit.gramsPerUnit;
}
