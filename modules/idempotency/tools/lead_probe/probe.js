// SPDX-License-Identifier: MIT
//
// The evidence behind the idempotency card's `**Ahead:**` correctness claim:
// @node-idempotency/core 1.1.0 (the most used Idempotency-Key library on npm,
// 64k downloads a month) reserves a key with `onRequest` and completes it
// with `onResponse`; there is no third call. A request whose handler throws
// never reaches `onResponse` (the express adapter records only through
// `response.send`), so the key stays IN_PROGRESS and every retry is refused
// as "in progress" (409) until the 24 h TTL runs out -- the request can never
// be completed. This module releases the reservation when the handler fails
// (test "a handler that fails releases the reservation: the retry runs, it
// is not a 409").
//
//   modules/idempotency/tools/lead_probe/run.sh
//
// 2026-10-23, core 1.1.0: retry after 0 s / 2 s: REQUEST_IN_PROGRESS; TTL 86400000 ms.
const { Idempotency } = require("@node-idempotency/core");
const { MemoryStorageAdapter } = require("@node-idempotency/storage-adapter-memory");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const idem = new Idempotency(new MemoryStorageAdapter(), {});
  const req = () => ({ headers: { "idempotency-key": "k1" }, body: { amount: 5 }, path: "/pay", method: "POST" });
  console.log("api:", Object.getOwnPropertyNames(Idempotency.prototype).filter((n) => n.startsWith("on")).join(", "));
  console.log("ttl ms:", idem.options.cacheTTLMS);
  // First request: reserved; the handler throws, so onResponse never runs.
  const first = await idem.onRequest(req());
  console.log("first:", first === undefined ? "reserved, handler runs and throws" : "unexpected replay");
  let stuck = 0;
  for (const wait of [0, 2000]) {
    await sleep(wait);
    try {
      const r = await idem.onRequest(req());
      console.log(`retry after ${wait} ms:`, r === undefined ? "runs" : "replay");
    } catch (e) {
      console.log(`retry after ${wait} ms:`, e.code);
      if (e.code === "REQUEST_IN_PROGRESS") stuck += 1;
    }
  }
  process.exit(stuck === 2 ? 0 : 1);
})();
