# `router` verification instruments

One oracle; its answers are frozen in `src/chi_vectors.zig` and replayed by
`src/chi_oracle_test.zig` in the module's own lane, with no Go (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-router`: runs `go_chi_oracle` and writes (or with `--check` compares) the vectors. The interop lane runs it with `--check`. |
| `bench.zig` + `go_bench/` | `zig build bench-router`: comparative benchmark against go-chi/chi v5.3.2, the source of the maturity card's `**Performance:**` line (CONVENTIONS.md §9 kind 3). One API-shaped table (25 routes) and 32 requests (hits, 404, 405); `lookup` = `Static(routes).match` vs chi `Mux.Match`, `serve` = request bytes → response bytes through `http.Server.serveStream` + `Router` vs `http.ReadRequest` + chi `ServeHTTP` (that one measures both HTTP stacks too). Counts must agree or the run fails. Needs the same chi module cache as the oracle. Not run by any lane. 2026-10-07, x86-64: lookup 0.54, serve 0.17 (ours/chi). |
| `go_chi_oracle/` | go-chi/chi v5.3.2 (MIT, the module's reference) as a black box through its public API: seeded route tables (static, `{name}`, in-segment shapes, regexp constraints, `*`; every fourth table holds every shape at one position) and requests, chi's status / matched pattern / captures / `Allow` per request; plus a crafted table of the documented divergences. No chi source read. |

```bash
zig build interop-router              # re-take, write src/chi_vectors.zig
zig build interop-router -- --check   # re-take, compare with the committed file
```

Needs Go 1.26.0 with `github.com/go-chi/chi/v5` in the module cache, fetched once with network
(`cd modules/router/tools/go_chi_oracle && GOTOOLCHAIN=go1.26.0 go mod download`; CI:
`scripts/lib/ci-environment.sh interop`), and `zig` on PATH.

**What the replay holds** (2026-10-07): 60 tables, 3,600 requests (1,570 matched, 1,275 not
found, 755 wrong method) answered exactly as chi answers — status, matched pattern, every capture;
on a 405 chi's `Allow` methods are a subset of ours (ours is the union over every candidate). The
tables draw static segments, `{name}`, seven in-segment shapes and five regexp-constrained ones
(`{p:[0-9]+}`, `{p:[a-z]+}`, `{p:[0-9]+}.json`, `v{p:[0-9]+}`, `{p:[a-c]+}-{q}`); the requests stay
where the two semantics coincide (no empty capture, each delimiter at most once per segment).
Eight crafted divergences (EMPTY, SPLIT, ANCHOR) pin this module's own answer and that chi still
answers otherwise. Teeth: inverting the precedence between sibling patterns fails 14 generated
requests; skipping the constraint check fails 411; one flipped vector fails `--check`.
