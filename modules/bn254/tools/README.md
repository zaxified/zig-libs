# `bn254` tools

Recipes for committed data and the second implementation that anchors them (`CONVENTIONS.md`
§9): run by hand, never by a test.

| file | produces | needs |
|---|---|---|
| `gen_precompile_vectors.py` | `src/precompile_vectors.zig` (`python3 modules/bn254/tools/gen_precompile_vectors.py > modules/bn254/src/precompile_vectors.zig`; fixed seed, a rerun reproduces it byte for byte) | `python3`, standard library only. An independent affine BN254 implementation over our own inputs; ecPairing truth values hold by construction. Replaced go-ethereum's LGPL-3.0 `bn256*.json` tables on 2026-10-26 |
