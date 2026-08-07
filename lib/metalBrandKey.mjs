// Port of `MetalBrandKey` (Money/Services/InvestServiceHelper.swift:375-409).
// Must stay byte-for-byte identical to the Swift version — the `id` this produces
// has to match `BrandDetails.code` already stored in users' saved positions.

const VIETNAMESE_FOLD_MAP = {
  à: "a", á: "a", ả: "a", ã: "a", ạ: "a",
  ă: "a", ằ: "a", ắ: "a", ẳ: "a", ẵ: "a", ặ: "a",
  â: "a", ầ: "a", ấ: "a", ẩ: "a", ẫ: "a", ậ: "a",
  è: "e", é: "e", ẻ: "e", ẽ: "e", ẹ: "e",
  ê: "e", ề: "e", ế: "e", ể: "e", ễ: "e", ệ: "e",
  ì: "i", í: "i", ỉ: "i", ĩ: "i", ị: "i",
  ò: "o", ó: "o", ỏ: "o", õ: "o", ọ: "o",
  ô: "o", ồ: "o", ố: "o", ổ: "o", ỗ: "o", ộ: "o",
  ơ: "o", ờ: "o", ớ: "o", ở: "o", ỡ: "o", ợ: "o",
  ù: "u", ú: "u", ủ: "u", ũ: "u", ụ: "u",
  ư: "u", ừ: "u", ứ: "u", ử: "u", ữ: "u", ự: "u",
  ỳ: "y", ý: "y", ỷ: "y", ỹ: "y", ỵ: "y",
  đ: "d",
};

/** Diacritic + case fold, then `đ` -> `d` (NOT covered by NFD stripping — see Swift's own note). */
export function normalize(raw) {
  const trimmed = raw.trim();
  const lower = trimmed.toLowerCase();
  let out = "";
  for (const ch of lower) {
    out += VIETNAMESE_FOLD_MAP[ch] ?? ch;
  }
  // NFD-normalize + strip remaining combining marks for any diacritic not in the map above.
  return out.normalize("NFD").replace(/[̀-ͯ]/g, "");
}

export function slug(raw) {
  const normalized = normalize(raw);
  let out = "";
  let lastWasSeparator = false;
  for (const ch of normalized) {
    if (/[a-z0-9]/i.test(ch)) {
      out += ch;
      lastWasSeparator = false;
    } else if (!lastWasSeparator && out.length > 0) {
      out += "_";
      lastWasSeparator = true;
    }
  }
  return out.replace(/_+$/, "");
}

export function typeCode(brandSlug, productName) {
  return `${brandSlug}.${slug(productName)}`;
}
