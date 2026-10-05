# `cors` verification instruments

One oracle, a real browser; run by hand, its answers frozen in
`src/browser_oracle_vectors.zig` and replayed by `src/browser_oracle_test.zig` in
the module's own lane, with no Chrome and no bun (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-cors`: starts the driver. In `serve` mode (the driver runs it): one `http.Server` + `router` + this middleware per configuration on 127.0.0.1:18700+, logging every request and the head answered to it. |
| `browser_oracle.js` | bun: serves two blank pages (origins `http://127.0.0.1:18601`, `:18602`), starts headless `google-chrome`, and over the DevTools protocol runs every request shape as `fetch()` from each page against each configuration; compares Chrome's verdict with the policy model and writes the vectors. |

```bash
zig build interop-cors                 # re-take, write src/browser_oracle_vectors.zig
zig build interop-cors -- --check      # re-take, compare with the committed file
```

Needs `bun` (on PATH or in `~/.bun/bin`) and `google-chrome`. Loopback only, no
network; ports 18601-18602, 18690 (DevTools) and 18700+ must be free.

**The policy model** (`want` in the driver) is the Fetch Standard's CORS checks
applied to the configuration: the origin must be granted (`*` never with
credentials), a credentialed fetch needs `allow_credentials`, a preflighted
request needs its method byte for byte in `allowed_methods` and every
non-safelisted header in `allowed_headers`, an actual request's method must be
allowed (this module's gate), and a response header is readable when exposed
(`*` only without credentials). The static posture has no gate of its own, so
only the browser's checks apply to its constant grant.

**What the replay holds** (2026-10-05, Chrome 154.0.8037.97): 504 fetches, every
one with Chrome's verdict equal to the model's; the requests Chrome sent, minus
the headers that carry its identity and version (`User-Agent`, `sec-*`, `Accept*`,
...), and the status and `Access-Control-*`/`Vary` fields the middleware
answered. Fixed ports keep the frozen requests stable across runs.
