# codespan_bench

Two binaries. `oracle` (`src/bin/oracle.rs`) is the codespan side of the differential fuzz
`zig build interop-diagnostics` (`../interop.zig`; input/output format in its header). The default
one is the reference side of `zig build bench-diagnostics` (`../bench.zig`): times
codespan-reporting 0.13.1 (Apache-2.0; "rich" style, `Chars::ascii()`, no colour,
`term::emit_to_io_write` into a reused `Vec<u8>`) and annotate-snippets 0.12.17
(MIT OR Apache-2.0; `Renderer::plain()`) through their public APIs, on the
corpus and the diagnostics the Zig program writes to `.zig-cache/bench-diagnostics/`.

- Both crates are pinned exactly in `Cargo.toml`, `Cargo.lock` is committed; the
  build is `cargo build --release --locked --offline` with
  `CARGO_TARGET_DIR=.zig-cache/bench-diagnostics/target` (run by `bench.zig`;
  `cargo fetch` once for the registry). The crates built are anstyle, termcolor,
  unicode-width, codespan-reporting, annotate-snippets: none has a `build.rs` or
  is a proc-macro (swept 2026-10-20; `serde`/`syn` in the lock file belong to
  codespan's optional `serialization` feature and are not built).
- Usage and the output format are in the header of `src/main.rs`.
- Not a test and not part of any lane; delete-and-rebuild is cheap.
