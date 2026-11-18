# `wipealloc` — specification

## Maturity

**Grade:** *(written by `zig build gen-catalog` — never by hand)*

**Scope:** core — OpenSSL 4.1 `OPENSSL_clear_free` and libsodium 1.0.22 `sodium_free` (surveyed 2026-11-18)

**Audit:** review none · mutation 2026-11-18 (8/8, 0 eq) · src 587079bec2c92279

**Hardening:** fuzz n/a — no input parsing, nothing to fuzz · ct n/a — the wipe's data-independent loop is not a secret-dependent branch (keyword review, 2026-11-18) · panic 2026-11-18 (every pub entry point read: no `assert`, `unreachable`, `@panic` or `.?` in the module; every failure is the child's `null`)

**Performance:** not measured

**Evidence:** model — a spying child allocator observes every block the adapter hands back
**Model:** src/root.zig:Spy

**Known defects:** none recorded

**Downstream consumer:** no

## Compared with

Surveyed 2026-11-18 per `SURVEY-PLAYBOOK.md`; stars and activity as of that date. Docs and READMEs only; no source copied.

| Project | Language | Licence | Stars | Last release / push | What a user notices against this module |
|---|---|---|--:|---|---|
| [openssl/openssl](https://github.com/openssl/openssl) — **reference** | C | Apache-2.0 | 31.5k | 4.1.0 (push 2026-11-18) | `OPENSSL_clear_free` cleanses a block then frees it; `OPENSSL_secure_malloc` adds a locked, guard-paged secure heap. Same wipe-on-give-back, no allocator adapter: the caller frees by hand. |
| [jedisct1/libsodium](https://github.com/jedisct1/libsodium) | C | ISC | 14.1k | 1.0.22 (2026-04-09) | `sodium_malloc`/`sodium_free`: guard pages, canary, `mlock`, wipe on free. More protection per block; no `realloc`, so a growing buffer is the caller's copy. |
| [RustCrypto/utils](https://github.com/RustCrypto/utils) (`zeroize`) | Rust | Apache-2.0 OR MIT *(inferred)* | 0.7k | push 2026-11-17 | `Zeroizing<Vec<u8>>` wipes the vector's contents on drop *(inferred from the crate's docs)*; a wrapper type, not an allocator, so third-party containers do not benefit. |

**Where we are ahead:** a drop-in `std.mem.Allocator`, so every std container and arena that takes an allocator wipes its growth copies without code changes. **Where we are behind:** no guard pages, no `mlock`, no canary (→ Backlog).

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

## Backlog / deferred

- (survey 2026-11-18) **Locked, guard-paged secure heap** (`sodium_malloc`, `OPENSSL_secure_malloc`) — **not now**, a separate allocator; effort medium; no consumer asks.
- (survey 2026-11-18) **In-place growth variant** (what `mls`'s private `Wiper` does under its arena) — **not now**; see above.

## Open

No survey yet (scope `unsurveyed`) and no independent review (`review none`).

Mutation 2026-11-18 (whole module, schemata, ReleaseSafe): 8 mutants — child allocation dropped, alignment lost on `alloc` and on `free`, `resize` returning true, `remap` returning a pointer, the wipe skipped, the wipe one byte short, `rawFree` skipped — 8 killed, 0 equivalent, 0 survivors (two killed by the child allocator's own alignment checks).
