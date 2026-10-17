# `security-headers` verification instruments

One oracle, a real browser; run by hand, its answers frozen in
`src/browser_oracle_vectors.zig` and replayed by `src/browser_oracle_test.zig` in the
module's own lane, with no Chrome and no bun (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-security-headers`: starts the driver. In `serve` mode (the driver runs it): one `http.Server` + `router` + this middleware per configuration on 127.0.0.1:18720+, serving a test page and its subresources, logging every response head. |
| `browser_oracle.js` | bun: serves another origin's page (`:18811`), starts headless `google-chrome`, loads each configuration's page, then frames it, embeds its image and opens it from the other origin over the DevTools protocol; compares Chrome's behaviour and log with each header's specified effect and writes the vectors. |
| `bench.zig` + `go_bench/` | `zig build bench-security-headers`: comparative benchmark against unrolled/secure v1.17.0, the source of the maturity card's `**Performance:**` line (CONVENTIONS.md §9 kind 3). Header work only (no HTTP stack): ours `apply`/`applyStatic`/`applyCspNonce` on a reused `ResponseWriter`, Go `Secure.Process` into a header-map-only writer; 64 responses per op. Counts (headers + name + value bytes) must agree or the run fails. Needs `go` with unrolled/secure in its module cache (`go_bench/go.sum` pins it; `GOPROXY=off`, `GOTOOLCHAIN=local`). Not run by any lane. |

```bash
zig build interop-security-headers               # re-take, write src/browser_oracle_vectors.zig
zig build interop-security-headers -- --check    # re-take, compare with the committed file
```

Needs `bun` (on PATH or in `~/.bun/bin`) and `google-chrome`. Loopback only; ports
18691 (DevTools), 18720+ and 18811 must be free.

**What the replay holds** (2026-10-05, Chrome 154.0.8037.97): seven configurations;
for each, what ran (inline / same-origin / text/plain script), whether the inline style
and the data: image applied, the Referer a same-origin fetch carried, whether another
origin could frame the page, load its image, keep its `window.open` handle -- all
equal to what the headers are specified to cause; no complaint from Chrome about any
real configuration, and complaints about the malformed control (so silence is
evidence, not a deaf listener). And the header set the middleware answered with,
byte for byte.

**Benchmark result** (2026-10-17, x86-64, `BENCH_ROUNDS=5`, ReleaseFast; ours/Go by wall time, 64 responses per op):

| workload | ours ns | Go ns | ours/Go | what both sides do |
|---|---:|---:|---:|---|
| `apply_default` | 7279 | 261362 | 0.028 | the 9-header default set: ours `apply`, Go `Process` |
| `apply_static` | 2470 | 253998 | 0.010 | same set; ours `applyStatic` (comptime), Go has no comptime path and repeats `Process` |
| `csp_nonce` | 70436 | 101296 | 0.695 | helmet default CSP, fresh nonce in script-src and style-src: ours `applyCspNonce`, Go `$NONCE` |

Result counts agree (19072, 19072, 21568). Largest spread 23.6% (a shared, noisy machine; an earlier run with 3 rounds gave 0.026 / 0.010 / 0.661). Ours leaves `Origin-Agent-Cluster` and `X-Download-Options` off in these rows because unrolled/secure cannot emit them. `csp_nonce` is dominated by the `getrandom` call on both sides.

card: **Performance:** ref 0.01–0.70× unrolled/secure v1.17.0 · fastest ? (measured 2026-10-17)
