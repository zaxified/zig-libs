# `drand` verification instruments

Six instruments. None is wired into `zig build`: each is run by
hand and prints what it found. They are here rather than in `src/` because each
needs a foreign toolchain — a Python, a Go, and in most cases the live network — which
a module must never require (`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runners and per-finding probes were deleted on
2026-09-17; what they found is pinned by tests in `src/` or filed as open findings.

## Where this module's vectors come from, and how to refresh them

⚠ Read this before running `fetch.py`. `modules/drand` has **no `testdata/` and
no generated vector file**: the quicknet `/info` document and the round
documents are inline string literals in `src/root.zig` and `src/verify.zig`.
`fetch.py` and `gen_vectors.py` are the recipe that produced them and the way to
refresh them — the output is pasted in by hand, deliberately, because a vector
that changes without a human reading the diff is a vector nobody checked.

    python3 fetch.py live/          # hits api.drand.sh, writes live/*.json
    python3 gen_vectors.py live/    # turns those into Zig literals on stdout

## What each one is for

| tool | question it answers | why this tool and not a test |
|---|---|---|
| `chainhash.py` | Does each chain's advertised hash actually match the fields it publishes? | The module reads the chain hash from `/info` and trusts it; nothing in the module derives it. A re-derivation catches a swapped field or a substituted document. |
| `ch2.py` | Which encoding reproduces the published hash? | The search that *found* the formula `chainhash.py` uses. Kept so that formula rests on a reproducible experiment rather than on someone having read drand's Go. |
| `fetch.py` | What does the live network currently serve? | Fixtures for the vectors above, from two chains and ~60 rounds. |
| `gen_vectors.py` | — | Formats what `fetch.py` captured as Zig literals. |
| `go/main.go` | Does an independently written BLS12-381 client (drand's own `crypto`/`kyber`) verify the same live rounds this module verifies? | The differential oracle CONVENTIONS.md §9 asks for: a foreign implementation driven through its own public API over the same wire-format documents. |
| `verify_driver.zig` | What does THIS module's own `parseInfo`/`parseRound`/`verifyRound` make of those same documents? | The other half of the differential — talks to `drand` only through its public exports, never copies module source. |

## O1 differential oracle — adopted 2026-09-17

Audit disposition O1 asked to adopt the audit's `gooracle/main.go` into `tools/`,
per `CONVENTIONS.md` §9's "differential oracle" kind. `cpu.go` was confirmed to be a
benchmark helper (`cpuNs`, used only by a CPU-timing loop) and left out per the
disposition; `chainhash.go` duplicates what `chainhash.py`/`ch2.py` already do here
and was left out too, to avoid keeping the same question twice.

**Licence, checked at the source fetched by `go get`/`go mod tidy`:**
`github.com/drand/drand/v2` is dual MIT/Apache-2.0 (`LICENSE-MIT`/`LICENSE-APACHE` in
`$GOMODCACHE/github.com/drand/drand/v2@v2.1.7/`). `github.com/drand/kyber` — which
`crypto.Scheme` needs for every scheme, including quicknet's — is MPL-2.0
(`$GOMODCACHE/github.com/drand/kyber@v1.3.2/LICENSE`: "Mozilla Public License
Version 2.0"). Both are fine here: this repo's licence policy restricts copyleft in
code the repo **distributes**; `go/main.go` is FETCHED into `$GOMODCACHE` and RUN, never
vendored into this tree or shipped with it — the same shape as `modules/poseidon/tools/`
running GPL-3.0 circomlibjs and `modules/uci/tools/` running LGPL libuci. (An earlier
pass read the licence-policy bar as "no copyleft, fetched or not" and stopped here;
that was a misreading, corrected 2026-09-17.)

```bash
W=~/workspace/zig-libs/.zig-cache/o1-drand    # scratch, never /tmp
mkdir -p "$W"
python3 <repo>/modules/drand/tools/fetch.py "$W"     # writes quicknet{,_t}_{info,rounds}.json
                                                      # into $W — NOT committed, NOT adopted

mkdir -p "$W/go" && cp <repo>/modules/drand/tools/go/{main.go,go.mod} "$W/go/"
( cd "$W/go" && export GOCACHE="$W/go-cache" GOMODCACHE="$W/gomod" && \
  go mod tidy && go build -o oracle . )    # go.sum is resolved here, not committed

zig build-exe -O ReleaseFast --dep drand \
    --cache-dir "$W/zc" -femit-bin="$W/verify_driver" \
    -Mmain=<repo>/modules/drand/tools/verify_driver.zig \
    --dep bls12_381 --dep tlock -Mdrand=<repo>/modules/drand/src/root.zig \
    --dep bls12_381 --dep entropy -Mtlock=<repo>/modules/tlock/src/root.zig \
    -Mbls12_381=<repo>/modules/bls12_381/src/root.zig \
    -Mentropy=<repo>/modules/entropy/src/root.zig

GOCACHE="$W/go-cache" GOMODCACHE="$W/gomod" "$W/go/oracle" "$W/quicknet_info.json" "$W/quicknet_rounds.json"
"$W/verify_driver" "$W/quicknet_info.json" "$W/quicknet_rounds.json"
```

**Measured 2026-09-17:** both oracles agree exactly, on both chains fetched fresh —

```
GO oracle:  60/60 live quicknet rounds verified (rejected 0)
ZIG oracle: 60/60 live rounds verified (rejected 0)
GO oracle:  5/5 live quicknet rounds verified (rejected 0)     # quicknet-t
ZIG oracle: 5/5 live rounds verified (rejected 0)
```
