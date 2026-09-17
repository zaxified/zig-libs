# `bolt8` verification instruments

Three instruments, run by hand. None is wired into `zig build`: `fetch-oracle.sh` +
`oracle_main.go` need a **foreign toolchain** (Go, plus network to fetch lnd's source and
the Go module proxy). `zig build test-bolt8` must require none of it (`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. This is the differential-oracle kind: no data is committed, only the recipe
and the two peers it pairs.

Figures below were measured on 2026-09-17 against the tree as it stands (Zig 0.16.0,
Go 1.26.0).

## Paired against lnd's own `brontide`

| tool | question it answers |
|---|---|
| `fetch-oracle.sh` | Fetches lnd's `brontide`/`keychain` straight from `lightningnetwork/lnd@master` (never vendored — keeps this module's clean-room `NOTICE` true) and builds `oraclebin`. |
| `oracle_main.go` | The Go side of the interop peer (`-role init\|resp`), plus three wire-level adversaries: `evil-resp` (forged Act Two), `evil-init` (forged Act One), `truncate` (49/50 Act Two bytes then silence). |
| `peer.zig` | THIS module's side, driven only through `@import("bolt8")`'s public API (`Secp256k1DH`, `Initiator`/`Responder`, `Transport`, `act.Act1/2/3`). Raw `read`/`write` on fd 0/1 (`std.os.linux`), deliberately no `std.Io`, so the harness itself is never the thing under test. |
| `pair.sh` | Pairs the two binaries over two FIFOs (held open read-write in the parent so neither side blocks in `open(2)`). |

```bash
W=~/workspace/zig-libs/.zig-cache/o1-bolt8   # scratch, never /tmp
mkdir -p "$W/oracle"
bash <repo>/modules/bolt8/tools/fetch-oracle.sh "$W/oracle"
( cd "$W/oracle" && GOCACHE="$W/go-cache" GOMODCACHE="$W/gomod" go build -o oraclebin . )

zig build-exe -O ReleaseFast --dep bolt8 \
    --cache-dir "$W/zc" -femit-bin="$W/interop" \
    -Mmain=<repo>/modules/bolt8/tools/peer.zig \
    --dep noise --dep k256 -Mbolt8=<repo>/modules/bolt8/src/root.zig \
    --dep chachapoly -Mnoise=<repo>/modules/noise/src/root.zig \
    -Mchachapoly=<repo>/modules/chachapoly/src/root.zig \
    -Mk256=<repo>/modules/k256/src/root.zig

cd "$W"
TMPDIR="$PWD" ZIG="$PWD/interop" GO="$PWD/oracle/oraclebin" \
    bash <repo>/modules/bolt8/tools/pair.sh init 1100   # our initiator  <-> brontide responder
TMPDIR="$PWD" ZIG="$PWD/interop" GO="$PWD/oracle/oraclebin" \
    bash <repo>/modules/bolt8/tools/pair.sh resp 1100   # brontide initiator <-> our responder
```

**Measured 2026-09-17:** both directions complete the full three-act `Noise_XK`
handshake and exchange **1100 messages each way** (payload lengths 0..65535 on the
same ladder both sides derive deterministically), every one decrypting back to the
exact bytes the other side sent — `zig-role=init zig_exit=0 go_exit=0` and
`zig-role=resp zig_exit=0 go_exit=0`.

The two wire-level forgeries were also run against the real binaries: `evil-resp`
(brontide-role adversary sends a well-formed-looking but unverifiable Act Two to our
initiator) and `evil-init` (adversary sends a forged Act One to our responder) both
make this module fail closed with `error.DecryptionFailed` — the MAC check catches a
forged act it cannot possibly have derived, in both handshake directions. `truncate`
(49 of 50 Act Two bytes, then silence, no EOF) makes our side block on the raw
`read(2)` loop until the wrapping `timeout` kills it — expected for a harness with no
transport-level EOF signal, not a module defect (the same shape `pair.sh`'s own
`timeout 25` wrapper exists for).

**Licence, checked at the source fetched by `fetch-oracle.sh`:** lnd's `LICENSE`
(`lightningnetwork/lnd@master/LICENSE`) is MIT. `go mod tidy` additionally pulls
`github.com/btcsuite/btcd/btcec/v2` (ISC — its own `LICENSE` in `$GOMODCACHE`) and
`github.com/decred/dcrd/dcrec/secp256k1/v4` (ISC) and `golang.org/x/crypto` /
`golang.org/x/sys` (BSD-3-Clause, the Go team's standard licence) — all permissive.
None of it is vendored; `fetch-oracle.sh` re-fetches fresh every run.
