# `bn254` tools

Recipes for committed data and the second implementation that anchors them (`CONVENTIONS.md`
§9): run by hand, never by a test.

| file | produces | needs |
|---|---|---|
| `gen_precompile_vectors.py` | `src/precompile_vectors.zig` (`python3 modules/bn254/tools/gen_precompile_vectors.py > modules/bn254/src/precompile_vectors.zig`; fixed seed, a rerun reproduces it byte for byte) | `python3`, standard library only. An independent affine BN254 implementation over our own inputs; ecPairing truth values hold by construction. Replaced go-ethereum's LGPL-3.0 `bn256*.json` tables on 2026-10-26 |
| `bench.zig` + `go_bench/` | the card's `**Performance:**` ratio (`zig build bench-bn254`, always ReleaseFast) | `go` 1.26.x and gnark-crypto v0.19.2 (+ bitset v1.24.4, x/sys v0.50.0) in the Go module cache; run offline (`GOPROXY=off`). Pure Go (no cgo, no build-time code); `go.sum` committed |
