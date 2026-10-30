import assert from "node:assert/strict";
import { test } from "node:test";
import {
  memoBase64UrlToPayoutId,
  payoutIdToMemoBase64Url,
} from "../src/memo.js";
import {
  addressAllowsMemo,
  buildZip321Uri,
  parseZip321Uri,
} from "../src/zip321.js";

const UA =
  "uregtest1ma4nrsg5fn6ucrguedj7k08tyk48tsaru4m8f02syrwgdgfap5zhkwkwvuzcegtecwk29m7e3u6hgvcwuc7sx802egc3dem4z532w6cd5978uau9n8h3c2gg9shjxpwevs8nu4qmadtew6qcztdn4cyx3a7pqqa0576nm9gquvjfw3sng5e57fupnvmxmpgkyq7y62gc2rccvjetucj";

test("ZIP-321 memo is unpadded base64url of the resource id", () => {
  const id = "11111111-1111-4111-8111-111111111111";
  const memo = payoutIdToMemoBase64Url(id);
  assert.equal(memo.includes("="), false);
  assert.equal(memoBase64UrlToPayoutId(memo), id);
  assert.ok(Buffer.from(id, "utf8").length <= 512);
});

test("ZIP-321 URI round-trips address amount and memo", () => {
  const resourceId = "ea4a24c6-dd17-4233-8b8e-734cf7b085ed";
  const uri = buildZip321Uri({
    address: UA,
    amount: "0.001",
    resourceId,
    message: "Agent payment request",
  });
  assert.equal(uri.startsWith("zcash://"), false);
  const parsed = parseZip321Uri(uri);
  assert.equal(parsed.address, UA);
  assert.equal(parsed.amount, "0.001");
  assert.equal(memoBase64UrlToPayoutId(parsed.memo), resourceId);
});

test("ZIP-321 rejects transparent address with memo", () => {
  assert.equal(addressAllowsMemo("tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU"), false);
  assert.throws(() =>
    buildZip321Uri({
      address: "tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU",
      amount: "1",
      resourceId: "x",
    }),
  );
});

test("ZIP-321 round-trips a sapling zregtestsapling address", () => {
  const sapling = "zregtestsapling1w8k5k9k7j6h5g4f3d2s1a0saplingreceiveaddr";
  const resourceId = "33333333-3333-4333-8333-333333333333";
  const uri = buildZip321Uri({
    address: sapling,
    amount: "0.001",
    resourceId,
  });
  const parsed = parseZip321Uri(uri);
  assert.equal(parsed.address, sapling);
  assert.equal(parsed.amount, "0.001");
  assert.equal(memoBase64UrlToPayoutId(parsed.memo), resourceId);
  assert.equal(addressAllowsMemo(sapling), true);
});
