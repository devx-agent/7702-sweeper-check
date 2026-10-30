import test from "node:test"; import assert from "node:assert/strict";
import { checkDelegation, summarize } from "../src/index.js";
const fake = (body, status = 200) => async (url) => ({ ok: status < 300, status, json: async () => ({ ...body, _url: url }) });
test("rejects bad address", async () => { await assert.rejects(checkDelegation("0x12", { fetch: fake({}) })); });
test("calls /api/basic and summarizes", async () => {
  const r = await checkDelegation("0x75E732608bc17b23d01f01728562ee844196dcc3", { fetch: fake({ address: "0x75e7", delegated_on: ["base"], chains: [{ name: "Base", delegated: true, delegate: "0xabc" }], full_report: "https://x/v1/check?address=0x75e7" }) });
  assert.match(r._url, /\/api\/basic\?address=0x75e732608bc17b23d01f01728562ee844196dcc3$/);
  const s = summarize(r); assert.match(s, /delegation found on 1 chain/); assert.match(s, /DELEGATED -> 0xabc/); assert.match(s, /0.01 USDC/);
});
test("no delegation summary", () => { assert.match(summarize({ delegated_on: [], chains: [] }), /No EIP-7702 delegation/); });
