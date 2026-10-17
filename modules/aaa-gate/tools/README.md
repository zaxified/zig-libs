# `aaa-gate` verification instruments

| tool | role |
|---|---|
| `bench.zig` + `go_bench/` | `zig build bench-aaa-gate`: comparative benchmark against labstack/echo v5.4.0 `middleware.KeyAuth`, the source of the maturity card's `**Performance:**` line (CONVENTIONS.md §9 kind 3). Layer: router + middleware + rendered response over 64 pre-parsed requests per op, no sockets, no head parsing; every row also runs through a no-middleware twin and the verdict is the net of the two. Status sums must agree with echo's or the run fails. Needs `go` with echo v5.4.0 and golang.org/x/time v0.15.0 in its module cache (`go_bench/go.sum` pins them; `GOPROXY=off`, `GOTOOLCHAIN=local`). Not run by any lane. |

```bash
BENCH_ROUNDS=7 zig build bench-aaa-gate    # all rows; arguments filter by name
```

## What is compared

Both sides, same policy: three configured 26-byte keys (the same strings as bearer tokens and as API keys), no audit hook (echo has none), one route `GET /` with a trivial handler.

| row | request | ours | echo |
|---|---|---|---|
| `bearer_ok` | `Authorization: Bearer <valid>` | `.bearer` | `header:Authorization:Bearer ` |
| `bearer_denied` | `Authorization: Bearer <on no list>` -> 401 | `.bearer` | same |
| `api_key_header_ok` | `X-Api-Key: <valid>` | `.api_key` | `header:X-Api-Key` |
| `api_key_query_ok` | `GET /?api_key=<valid>` | `.api_key` + `api_key_query_param` | `query:api_key` |
| `no_credential` | none -> 401 | `.bearer` | `header:Authorization:Bearer ` |

echo leaves the comparison to the caller's `Validator`. **The verdict compares like for like** (owner decision 2026-10-17): the Go validator gives aaa-gate's guarantee — only SHA-256 digests of the configured credentials kept, the presented value hashed and compared against every digest with `subtle.ConstantTimeCompare`, no early exit, so neither length nor content leaks. Every row also prints `<row>_raw`: echo with the validator its documentation shows as secure (`ConstantTimeCompare` against the raw keys, first match returns — leaks the key length and keeps the secrets in memory). That row is information only. This machine (i7-7920HQ) has no SHA-NI, so the software SHA-256 is most of either side's gate cost; with the raw validator echo skips it, which is the whole of the `_raw` gap.

The 401 answers differ and are in the number: ours `Unauthorized\n` text/plain with `WWW-Authenticate: Bearer`; echo's default error handler builds a `map`, wraps the error and encodes `{"message":"Unauthorized"}` with `encoding/json` (no challenge header for KeyAuth). The denied rows therefore flatter ours (the Go cost is mostly the error path, not the key check).

`basic_ok` / `basic_denied`: HTTP Basic (`.basic`, three users) against `middleware.BasicAuthWithConfig` with the same two validators (hashed `user:password` digests for the verdict, raw `ConstantTimeCompare` of user and password for `_raw`).

## Benchmark result

2026-10-17, x86-64 (i7-7920HQ, no SHA-NI), `BENCH_ROUNDS=5`, ReleaseFast, a shared and noisy machine; wall time per op of 64 requests, ours/echo. `gross` = router + middleware + response; `net` = (with - without middleware) per side, the verdict.

| row | ours ns | echo ns | gross | net | echo raw-key: net (info) |
|---|---:|---:|---:|---:|---:|
| `bearer_ok` | 33642 | 83500 | 0.403 | 0.834 | 1.928 |
| `bearer_denied` | 39530 | 156400 | 0.253 | 0.299 | 0.325 |
| `api_key_header_ok` | 32248 | 80039 | 0.403 | 0.865 | 2.128 |
| `api_key_query_ok` | 30805 | 97330 | 0.317 | 0.488 | 0.745 |
| `no_credential` | 18137 | 137120 | 0.132 | 0.111 | 0.111 |
| `basic_ok` | 40317 | 91717 | 0.440 | 0.804 | 1.005 |
| `basic_denied` | 46550 | 201829 | 0.231 | 0.254 | 0.259 |

Without middleware: ours ~8.8 µs, echo ~53 µs per op. Status sums agree on both sides; ours is also checked against the expected status before any timing. Largest spread 16.8% (noisy machine; the verdict rows sit well under 1.1x).

card: **Performance:** ref 0.11–0.87× labstack/echo v5.4.0 · fastest ? (measured 2026-10-17)

**Reading.** At equal guarantees the gate costs ~0.8x echo's. Against echo's raw-key validator the header success rows are ~2x: the gap is one software SHA-256 per request (~300 ns without SHA-NI) — the price of keeping no secret in memory and leaking no length, which the raw validator does not pay. The denied rows sit far below echo because echo's 401 goes through its JSON error handler; the query row because echo parses a `url.Values` per request.
