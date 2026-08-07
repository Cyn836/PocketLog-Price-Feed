// Port of `SilverUnitNormalizer` (Money/Services/InvestServiceHelper.swift:564-598).

import { denominations, Unit } from "./metalQuantityTier.mjs";

export const gramsPerLuong = 37.5;
export const luongPerKg = 1000 / gramsPerLuong;

const minPerLuong = 1_000_000;
const maxPerLuong = 4_000_000;

export function isPlausible(perLuong) {
  return perLuong >= minPerLuong && perLuong <= maxPerLuong;
}

/** Weight of one unit of a product, in lượng, read out of its name. Null when the name states no size. */
export function luongPerUnit(productName) {
  const values = denominations(productName, Unit.luong);
  return values.length > 0 ? values[0] : null;
}

export function logRejected(source, name, reason) {
  console.warn(`[SilverFeed] ${source}: dropped "${name}" — ${reason}`);
}
