# `websocket` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test.

The frozen three-implementation corpus in `src/connection.zig` came from:

| file | step |
|---|---|
| `cases.py` | the shared case table (valid and adversarial client frames) |
| `oracle_python.py` | runs the cases through `websockets` 15.0.1 → `out_python.json`, `cases.json` |
| `oracle_go_main.go` | runs the same cases against `coder/websocket` and `gorilla/websocket` over loopback: `go run oracle_go_main.go <cases.json> <out_go.json>` |
| `report.py` | merges both → `merged.json` |
| `emit_zig.py` | writes the Zig table → `corpus.zig.txt` |

Scratch goes to `$WS_WORK` (default `.zig-cache/websocket-capture`, run from the
repo root). The Go program needs a `go.mod` requiring the two libraries at the
versions it prints.

## The opening handshake, differentially (not covered by the corpus above)

The three-implementation corpus above is entirely post-handshake data frames fed to a
`Connection`; it never drives the handshake itself. `oracle_handshake.py` +
`verify_response_probe.zig` do: they diff the module's `handshake.verifyResponse`
(client side) and `handshake.acceptHandshake` (server side) against python-websockets
15.0.1's (BSD-3-Clause, verified via `pip show websockets`) `ClientProtocol`/
`ServerProtocol` over the same fixed case table. It builds and runs the Zig side and
diffs it against python-websockets' verdicts (`CONVENTIONS.md` §9).

```bash
scripts/lib/capped zig build-exe --cache-dir <scratch>/zc \
  -femit-bin=<scratch>/verify_response_probe \
  --dep websocket --dep http -Mmain=modules/websocket/tools/verify_response_probe.zig \
  --dep http -Mwebsocket=modules/websocket/src/root.zig \
  --dep netaddr --dep datefmt --dep tlsclient --dep crc32 --dep b64ct --dep proxyproto --dep tlsserver -Mhttp=modules/http/src/root.zig \
  -Mb64ct=modules/b64ct/src/root.zig \
  -Mcrc32=modules/crc32/src/root.zig \
  --dep x509 --dep p256 --dep p384 --dep p521 --dep rsa --dep tlsresume --dep ct25519 --dep mlkem -Mtlsclient=modules/tlsclient/src/root.zig \
  --dep entropy -Mmlkem=modules/mlkem/src/root.zig \
  -Mentropy=modules/entropy/src/root.zig \
  --dep entropy -Mct25519=modules/ct25519/src/root.zig \
  --dep aesgcm -Mtlsresume=modules/tlsresume/src/root.zig \
  --dep aes192 -Maesgcm=modules/aesgcm/src/root.zig \
  -Maes192=modules/aes192/src/root.zig \
  --dep montint --dep aescbc --dep aes192 --dep b64ct --dep keycodec -Mrsa=modules/rsa/src/root.zig \
  --dep b64ct --dep aescbc --dep aes192 -Mkeycodec=modules/keycodec/src/root.zig \
  -Maescbc=modules/aescbc/src/root.zig \
  -Mmontint=modules/montint/src/root.zig \
  --dep entropy -Mp521=modules/p521/src/root.zig \
  --dep entropy -Mp384=modules/p384/src/root.zig \
  -Mp256=modules/p256/src/root.zig \
  --dep rsa --dep slhdsa --dep p521 --dep p256 --dep netaddr -Mx509=modules/x509/src/root.zig \
  -Mnetaddr=modules/netaddr/src/root.zig \
  -Mslhdsa=modules/slhdsa/src/root.zig \
  -Mdatefmt=modules/datefmt/src/root.zig \
  -Mchachapoly=modules/chachapoly/src/root.zig \
  -Mcrc32c=modules/crc32c/src/root.zig \
  --dep p256 --dep chachapoly --dep entropy --dep p521 --dep aesgcm --dep p384 --dep ct25519 --dep mlkem -Mhpke=modules/hpke/src/root.zig \
  --dep netaddr --dep crc32c -Mproxyproto=modules/proxyproto/src/root.zig \
  --dep rsa --dep ct25519 --dep p256 --dep p384 --dep p521 --dep mlkem --dep montint -Mtls13=modules/tls13/src/root.zig \
  --dep tls13 --dep aesgcm --dep chachapoly --dep netaddr --dep x509 --dep rsa --dep keycodec --dep tlsresume --dep p521 --dep hpke -Mtlsserver=modules/tlsserver/src/root.zig
modules/websocket/tools/oracle_handshake.py <scratch>/verify_response_probe
```

The case table holds 10 cases (6 client-side `verifyResponse`, 4 server-side
`acceptHandshake`); the script exits 0 iff every case agrees. Nine agree. The tenth, the
`Origin: https://evil.example` row, is a *known, deliberate* divergence: `acceptHandshake`'s
`Origin` allow-list (SPEC.md "Server-side `Origin` check") rejects it with
`error.OriginNotAllowed` (the Origin's host does not match `Host: h`), while python-websockets'
bare `ServerProtocol` has no origin policy of its own, so the script reports one MISMATCH for it
(the comment on that row in `verify_response_probe.zig` explains why). Needs
`pip install websockets==15.0.1`.

## The live oracle: `interop.zig` + `go_oracle/`

`zig build interop-websocket` (a program, not a test; `check-interop` compiles it) builds
`go_oracle` — github.com/coder/websocket v1.8.15 and github.com/gorilla/websocket v1.5.3 through
their public APIs, pinned by `go_oracle/go.mod`/`go.sum`, `GOPROXY=off` — and runs three families
over loopback: this module's client against both Go servers, both Go clients against this
module's server (`http.Server` + `respondUpgraded` + `Conn`, 16 KiB buffers), and fixed raw
handshakes and frames sent to all three servers. Expectations are `agree`, `stricter` (the
card's `**Ahead:**` rows) or `differs` (documented); anything else is a SURPRISE and exit 1.
Verdicts: `.zig-cache/interop-websocket/verdicts.tsv`.

`-- --capture` rewrites `src/testdata/interop/*.bin`: the bytes the Go libraries sent after the
handshake in the scenarios without 1 MiB of plain payload, replayed hermetically by
`src/interop_replay_test.zig`.

## Fastest in the field: `go_bench/gorilla/`, `rust_fast_bench/`

`zig build bench-websocket` also times gorilla/websocket v1.5.3 (`go_bench/gorilla`, same module
cache) and denoland/fastwebsockets 0.10.0 + snapview/tungstenite 0.30.0 (`rust_fast_bench`,
`cargo build --release --offline`, versions pinned with `=`, `Cargo.lock` committed; their
dependency closure was read before the first build — build scripts, proc macros, the code paths
run). `BENCH_FAST=0` skips these three sides.
