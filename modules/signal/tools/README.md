# `signal` tools

Recipes for committed data and the second implementation that anchors them (`CONVENTIONS.md`
§9): run by hand or by the `interop` lane, never by a test.

| file | produces | needs |
|---|---|---|
| `pqxdh-kdf-check.py` | the `pqxdh_kdf` block of `src/interop_vectors.zig`; `--check` diffs it against the pin | `python3`, standard library only. **Keep it**: Signal publishes no byte-exact PQXDH vectors, so this independent implementation is the only anchor for the KDF chain. Moved from `scripts/gen/` on 2026-09-18 |
| `interop.zig` | nothing -- runs `pqxdh-kdf-check.py --check` as `zig build interop-signal` (the tag's `interop` lane) | `python3` |
| `gen_xeddsa_kat.py` | `src/xeddsa_kat_vector.zig` (`python3 modules/signal/tools/gen_xeddsa_kat.py > modules/signal/src/xeddsa_kat_vector.zig`; a rerun reproduces it byte for byte) | `python3`, standard library only. An independent Edwards25519/XEdDSA implementation signing our own sign-1 key in both variants. Replaced libsignal's GPLv3 test vector on 2026-10-26 |
| `libsignal_dump.rs` | `src/interop_vectors.zig` | a throwaway libsignal checkout at the commit named in that file; this driver is appended to `rust/protocol/src/ratchet/keys.rs` there |

`libsignal_dump.rs` moved here on 2026-09-17 from a private `~/.cache` directory, where it was
the only copy.

⚠ libsignal is AGPL-3.0. The checkout stays outside this repository; only our
driver (MIT) and the numbers it prints are here. See `../NOTICE`.
