# `wipealloc` — specification

## Maturity

**Grade:** *(written by `zig build gen-catalog` — never by hand)*

**Scope:** unsurveyed

**Audit:** review none · mutation none · src ?

**Hardening:** fuzz n/a — no input parsing, nothing to fuzz · ct n/a — the wipe's data-independent loop is not a secret-dependent branch (keyword review, 2026-11-18)

**Performance:** not measured

**Evidence:** model — the contract is checkable by a spying child allocator (tests)

**Known defects:** none recorded

**Downstream consumer:** no

## What this module is, and what it is not

`WipingAllocator` is a 60-line `std.mem.Allocator` adapter: `alloc` forwards,
`free` calls `std.crypto.secureZero` over the whole block before `rawFree`,
`resize` returns `false`, `remap` returns `null`. It was five identical private
copies (xmlenc, xmldsig, wireguard `wipe.zig`, bbs `burn.zig`, minisign
`burn.zig`) until the 2026-11 security triage (row xmlenc:338) asked for one.

Reference behaviour: OpenSSL `OPENSSL_clear_free` and libsodium `sodium_free`
cleanse a block before releasing it; neither offers an in-place shrink that
skips the cleanse, which is what refusing `resize`/`remap` reproduces.

**Not here, by design:**

- **`mls`'s `Wiper`** (`modules/mls/src/group.zig`) is a different allocator, not a
  copy: it forwards *grow-in-place* `resize` to the child (growing hands nothing
  back) and refuses only shrinks and remaps, because it sits under an
  `ArenaAllocator` whose last chunk is extended in place. It stays private.
- **Stack burns** (`burn.stack`, `burn.run`): per module, `burn.zig` is copied on
  purpose (CONVENTIONS §2.1 D3: each module's stack probe measures its own frames).
- Test spies (`ScanAllocator`, `Spy`, `DirtyAllocator`) in other modules observe or
  corrupt memory; they do not wipe.

## Constant-time contract

No secret-dependent branch or address: the wipe is a volatile byte-store loop
over `memory.len`, a public length. The module makes no timing claim beyond that.

## Limits and refusals

- `resize` is always refused, `remap` always returns null (a caller's `realloc`
  therefore always copies). Pinned by "resize and remap are refused…" and
  "realloc moves through alloc + copy + free…".
- The adapter must outlive every block and must not move (the vtable points at it).
- Cost: one volatile store per byte on `free` (`std.crypto.secureZero`); a module
  that wants vector-width wipes can link `fastmem` for the whole binary.

## Anchoring

Expected values: the spy child's view of the block (all zero), the data after a
`realloc`, the bytes of a backing buffer after an `ArrayList` grew and was freed.
Our own reading of the contract.

**Anchor grade:** class C · oracle n/a

## What is deliberately not done

- **No allocation tracking, no quarantine, no guard pages** (libsodium's `sodium_malloc`
  does these): this wipes on free and nothing else. **Never.**
- **No in-place growth** (`mls`'s variant): **not now**; a second allocator type in
  this module if a second consumer needs it.

## Open

No survey and no mutation run yet (card entries `unsurveyed`, `mutation none`).
