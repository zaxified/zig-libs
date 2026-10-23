# `idempotency` verification instruments

| tool | role |
|---|---|
| `lead_probe/` | The evidence behind the card's `**Ahead:**` line: fetches `@node-idempotency/core` 1.1.0 with `storage` and `storage-adapter-memory` 1.0.5 (pinned, sha512-checked against the npm registry's `dist.integrity`; no install, no package scripts) into `.zig-cache/idem-lead-probe/node_modules` and runs `probe.js` with bun: a request reserved by `onRequest` whose handler throws, then two retries. |

```bash
modules/idempotency/tools/lead_probe/run.sh
```

Needs `curl`, `openssl`, `bun`. Last run 2026-10-23 (bun 1.3.12): both retries `REQUEST_IN_PROGRESS`, TTL 86 400 000 ms.
