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

echo leaves the comparison to the caller's `Validator`; the Go side uses the one its own documentation shows as secure: `subtle.ConstantTimeCompare` against each of the three keys, returning on the first match. Ours hashes the presented value (SHA-256) and compares digests against all three without early exit, so neither length nor content leaks (`ConstantTimeCompare` leaks the length). That is the module's design and it is in the number.

The 401 answers differ and are in the number: ours `Unauthorized\n` text/plain with `WWW-Authenticate: Bearer`; echo's default error handler builds a `map`, wraps the error and encodes `{"message":"Unauthorized"}` with `encoding/json` (no challenge header for KeyAuth). The denied rows therefore flatter ours (the Go cost is mostly the error path, not the key check).

TODO `basic_ok` / `basic_denied` (HTTP Basic against `middleware.BasicAuth`, validator with `subtle.ConstantTimeCompare` on user and password): `aaa-gate` has no HTTP Basic in this tree yet. Add a wire builder in `bench.zig`, a `lookup`/validator case in `go_bench/main.go`.

## Benchmark result

2026-10-17, x86-64, `BENCH_ROUNDS=7`, ReleaseFast, a shared and noisy machine; wall time per op of 64 requests, ours/echo. `gross` = router + middleware + response; `net` = (with - without middleware) per side, the verdict.

| row | ours ns | echo ns | gross | net | ours without / echo without |
|---|---:|---:|---:|---:|---|
| `bearer_ok` | 31995 | 71660 | 0.446 | **1.569** | 8711 / 56823 |
| `bearer_denied` | 39284 | 147259 | 0.267 | 0.325 | 8935 / 53772 |
| `api_key_header_ok` | 32406 | 64448 | 0.503 | **2.370** | 9021 / 54580 |
| `api_key_query_ok` | 31332 | 85575 | 0.366 | 0.706 | 9425 / 54534 |
| `no_credential` | 17763 | 140510 | 0.126 | 0.101 | 9171 / 55111 |

Status sums agree on both sides (12800 = 64 x 200 for the success rows and every `_plain` twin, 25664 = 64 x 401 for the two denied rows); ours is also checked against the expected status before any timing. Largest spread 40.9% on a `_plain` twin (OVER 5%: the net of the success rows moves by +-50% between runs; two earlier runs at the head-parsing layer, 3 and 7 rounds, gave 1.43 / 1.52 / 0.66 and 4.39 / 2.36 / 0.81 for `bearer_ok`/`api_key_header_ok`/`api_key_query_ok`, so the direction is stable and the size is not).

card: **Performance:** ref 0.10–2.37× labstack/echo v5.4.0 · fastest ? (measured 2026-10-17)

**Reading.** Two rows are over the 1.1x line: the success rows with a header lookup (`bearer_ok`, `api_key_header_ok`). The gate's own cost there is about 360 ns per request against about 100 to 250 ns for echo's raw compare. Hypothesis from reading the path (not profiled): every call hashes the presented value with SHA-256 (`src/root.zig:752`, one block compress), takes and releases the gate lock with two atomic operations (`:764`, used in `verify` `:603` and `verifyApiKey` `:632`), and compares all three digests without early exit (`:758`) -- a fixed price for not leaking length or content, which echo's validator does not pay (it returns on the first match; 26-byte `ConstantTimeCompare` is a few ns). The denied and no-credential rows pay the same hash but sit far below echo because echo's 401 goes through its JSON error handler. The query row is under 1.1x because echo's `QueryParams` allocates and parses a `url.Values` per request, which ours does not.
