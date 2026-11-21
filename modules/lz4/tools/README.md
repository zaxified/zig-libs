# lz4 — tools

Instruments that check this module against the reference LZ4 (CONVENTIONS.md §9). The reference
is run as installed programs, never vendored: the `lz4` CLI (v1.10.0 was used) and python3 with
python-lz4 (4.4.5, linking the system liblz4).

| File | What |
|---|---|
| `capture-goldens.sh` | Recipe for `src/testdata/`: generates five inputs from a fixed seed, compresses them with the lz4 CLI under ten flag sets (default, linked 64 KB with content size and block checksums, `-12`, `--fast=9`, legacy `-l`, stored blocks) and writes `goldens.zig` (SHA-256 and length of each input). `src/golden_test.zig` replays them. Needs `lz4`, `python3`. |
| `interop.zig` | `zig build interop-lz4 [-- --quick]`: for every shape of `src/shapes.zig`, our frames through `lz4 -d` and `lz4.frame.decompress`; CLI frames (nine flag sets) and python-lz4 frames and blocks through ours; our blocks through `LZ4_decompress_safe`; then 6000 mutated blocks and frames whose verdicts must agree with liblz4's, except for the two documented divergences (0 offset; the optional end-of-block rules), which it counts and classifies. Needs `lz4`, `python3` with `lz4`. |
| `dict_oracle.py`, `dict_cli.zig` | Dictionary oracle: our dictionary blocks and frames (linked and independent) against python-lz4 `dict=` and `lz4 -D`, both directions; `dict_cli.zig` is the file driver the script runs (build line in the script's header). Measured 2026-11-21: every verdict True. |
| `bench.zig` | `zig build bench-lz4`: `compressBlock`/`decompressBlock` over 64 KiB pieces of three 8 MiB payloads against `lz4 -b1 -B65536` on the same files; prints MB/s, the ratio and the compressed sizes. Needs `lz4`. |
