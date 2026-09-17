# `signal` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test. Moved here on
2026-09-17 from a private `~/.cache` directory, where they were the only copy.

| file | produces | needs |
|---|---|---|
| `libsignal_dump.rs` | `src/interop_vectors.zig` | a throwaway libsignal checkout at the commit named in that file; this driver is appended to `rust/protocol/src/ratchet/keys.rs` there |

⚠ libsignal is AGPL-3.0. The checkout stays outside this repository; only our
driver (MIT) and the numbers it prints are here. See `../NOTICE`.
