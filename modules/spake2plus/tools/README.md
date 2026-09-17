# `spake2plus` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test. Moved here on
2026-09-17 from a private `~/.cache` directory, where they were the only copy.

| file | produces | needs |
|---|---|---|
| `capture_w0w1.cc` | `src/bssl_w0w1_vectors.zig` | a C++ compiler and a BoringSSL build (commit in the vectors' header), kept outside this repo |

Build and run command: the file's header.
