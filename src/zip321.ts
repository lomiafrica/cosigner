import { payoutIdToMemoBase64Url } from "./memo.js";

const TRANSPARENT = /^(t1|t3|tm)/i;
const SHIELDED = /^(u1|utest|uregtest|zs|ztestsapling|zregtestsapling)/i;
const AMOUNT = /^\d+(?:\.\d{1,8})?$/;

export type Zip321Payment = {
  address: string;
  amount: string;
  memo: string;
  message?: string;
};

export function addressAllowsMemo(address: string): boolean {
  const value = address.trim();
  if (TRANSPARENT.test(value)) return false;
  return SHIELDED.test(value);
}

export function assertZip321Amount(amount: string): void {
  if (!AMOUNT.test(amount)) {
    throw new Error(`invalid ZIP-321 amount: ${amount}`);
  }
  if (Number(amount) > 21_000_000) {
    throw new Error(`ZIP-321 amount exceeds 21000000 ZEC: ${amount}`);
  }
}

export function buildZip321Uri(input: {
  address: string;
  amount: string;
  resourceId: string;
  message?: string;
}): string {
  const address = input.address.trim();
  if (!address) throw new Error("ZIP-321 address is required");
  if (address.includes("/")) {
    throw new Error("ZIP-321 address must not contain slashes");
  }
  assertZip321Amount(input.amount);
  if (!addressAllowsMemo(address)) {
    throw new Error("ZIP-321 memo requires a shielded or unified address");
  }
  const memo = payoutIdToMemoBase64Url(input.resourceId);
  if (Buffer.from(input.resourceId, "utf8").length > 512) {
    throw new Error("ZIP-321 memo exceeds 512 bytes");
  }
  const parts = [`amount=${input.amount}`, `memo=${memo}`];
  if (input.message?.trim()) {
    parts.push(`message=${encodeURIComponent(input.message.trim())}`);
  }
  return `zcash:${address}?${parts.join("&")}`;
}

export function parseZip321Uri(uri: string): Zip321Payment {
  const trimmed = uri.trim();
  if (!trimmed.startsWith("zcash:")) {
    throw new Error("ZIP-321 URI must start with zcash:");
  }
  if (trimmed.startsWith("zcash://")) {
    throw new Error("ZIP-321 URI must not use zcash://");
  }
  const body = trimmed.slice("zcash:".length);
  const q = body.indexOf("?");
  if (q <= 0) throw new Error("ZIP-321 URI is missing query parameters");
  const address = body.slice(0, q);
  const query = body.slice(q + 1);
  const params = new URLSearchParams(query);
  const amount = params.get("amount");
  const memo = params.get("memo");
  if (!address || !amount || !memo) {
    throw new Error("ZIP-321 URI requires address, amount, and memo");
  }
  assertZip321Amount(amount);
  if (!addressAllowsMemo(address)) {
    throw new Error("ZIP-321 memo requires a shielded or unified address");
  }
  const message = params.get("message") ?? undefined;
  return { address, amount, memo, message };
}
