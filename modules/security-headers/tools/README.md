# `security-headers` verification instruments

One oracle, a real browser; run by hand, its answers frozen in
`src/browser_oracle_vectors.zig` and replayed by `src/browser_oracle_test.zig` in the
module's own lane, with no Chrome and no bun (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-security-headers`: starts the driver. In `serve` mode (the driver runs it): one `http.Server` + `router` + this middleware per configuration on 127.0.0.1:18720+, serving a test page and its subresources, logging every response head. |
| `browser_oracle.js` | bun: serves another origin's page (`:18811`), starts headless `google-chrome`, loads each configuration's page, then frames it, embeds its image and opens it from the other origin over the DevTools protocol; compares Chrome's behaviour and log with each header's specified effect and writes the vectors. |

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
