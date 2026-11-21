# wipealloc — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-21** — **NEW (additive API):** `SecureAllocator`, a locked, guard-paged allocator for key material (libsodium `sodium_malloc`, OpenSSL `OPENSSL_secure_malloc`): one mapping per block between two `PROT_NONE` pages, `mlock` (`Lock` best-effort / required / off) and `MADV_DONTDUMP`, a per-allocator random canary checked on `free` (panics when overwritten), the pages zeroed and unmapped on `free`, `resize`/`remap` refused. `WipingAllocator` is unchanged.
- **2026-11-18** — New module: `WipingAllocator`, the allocator that zeroes every block on `free` and refuses `resize`/`remap`, extracted from five identical private copies (xmlenc, xmldsig, wireguard `wipe.zig`, bbs and minisign `burn.zig`; security-triage row xmlenc:338). Tests: the child sees an all-zero block, resize/remap refused, `realloc` growth and shrink wipe the old block and keep the data, aligned and zero-length frees, an `ArrayList` leaves no secret in a `FixedBufferAllocator`'s bytes. Mutation: 8/8 killed. Surveyed (scope `core`) and panic-swept, which the consumed modules depending on it require.
