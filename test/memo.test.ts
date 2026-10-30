import assert from "node:assert/strict";
import { test } from "node:test";
import { payoutIdToMemoHex } from "../src/memo.js";

test("payout id memo is utf8 hex and round-trips", () => {
  const payoutId = "11111111-1111-4111-8111-111111111111";
  const hex = payoutIdToMemoHex(payoutId);
  assert.equal(Buffer.from(hex, "hex").toString("utf8"), payoutId);
});
