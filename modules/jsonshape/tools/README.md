# jsonshape — tools

## The compliance suite (`src/testdata/cts.json`)

The module's external anchor (`CONVENTIONS.md` §9): the official JSONPath
Compliance Test Suite, byte for byte, read by `src/cts_test.zig`, which pins its
number of cases. BSD-2-Clause (its `LICENSE` read; the GitHub API says
`NOASSERTION`), attribution in `../NOTICE`. To refresh it, take `cts.json` of a
chosen commit and update the commit in `../NOTICE`, the digest below and the counts
in `src/cts_test.zig`:

    curl -sSf -o modules/jsonshape/src/testdata/cts.json \
      https://raw.githubusercontent.com/jsonpath-standard/jsonpath-compliance-test-suite/20ebdcce5008c8a777ee9c80ad853ecf606950b5/cts.json
    sha256sum modules/jsonshape/src/testdata/cts.json
    # f4ab5e3d3c17b40bf59cb0fa94425790b1401eb30c35a54902a119c65c851d36

## The benchmark

`bench.zig` is `zig build bench-jsonshape`, the program behind the card's
`**Performance:**` line; its header says what each row pairs. Other sides:
`go_bench` (theory/jsonpath v0.12.2, ohler55/ojg v1.28.9, both MIT) and
`rust_bench` (serde_json_path 0.7.2, jsonpath-rust 1.0.12, both MIT). They come
from the Go and cargo module caches, fetched once with:

    go mod download github.com/theory/jsonpath@v0.12.2 github.com/ohler55/ojg@v1.28.9
    cargo fetch --manifest-path modules/jsonshape/tools/rust_bench/Cargo.toml

What was read before the first compile: the licences; every non-test Go file of
theory/jsonpath and of ojg's `jp` swept for `os/exec`, `net`, cgo, `init()` and
`go:generate` (nothing but two `stringer` lines, which do not run in a build; ojg's
`jp` imports `unsafe`); in the cargo tree every `build.rs` of the JSONPath crates'
dependencies (`pest_stack_guard`, `stacker`, `psm`, `zmij`: target and `rustc`
version checks, an assembler call for stacker's own stack switching) and a grep for
`std::process` and `std::net` (one `Command` in a `pest_meta` test). The crates'
source beyond the entry points used here was not read: serde_json_path and
jsonpath-rust are established crates, and their tree comes from crates.io under
the `Cargo.lock` kept here.

A row is left out for a side that disagrees on the nodes or does not have the
function: ojg's `jp` is not an RFC 9535 implementation (no `search`/`match` under
those semantics, no nested filter in this form), so `bench.zig` marks those rows
`ojg = false`. Its other rows are compared only where its count agrees.
