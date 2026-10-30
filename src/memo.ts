export function payoutIdToMemoHex(payoutId: string): string {
  return Buffer.from(payoutId, "utf8").toString("hex");
}

/** ZIP-321 memo query value: UTF-8 id as unpadded base64url. */
export function payoutIdToMemoBase64Url(payoutId: string): string {
  return Buffer.from(payoutId, "utf8").toString("base64url");
}

export function memoBase64UrlToPayoutId(memo: string): string {
  return Buffer.from(memo, "base64url").toString("utf8");
}

/** UTF-8 memo from a raw string or a 512-byte hex field (null-padded on chain). */
export function memoFieldToUtf8(memo: string): string {
  const trimmed = memo.trim();
  if (!trimmed) return "";
  if (/^[0-9a-f]+$/i.test(trimmed) && trimmed.length % 2 === 0) {
    const bytes = Buffer.from(trimmed, "hex");
    const end = bytes.indexOf(0);
    return bytes.subarray(0, end === -1 ? bytes.length : end).toString("utf8");
  }
  const end = trimmed.indexOf("\0");
  return end === -1 ? trimmed : trimmed.slice(0, end);
}
