# wipealloc

**An allocator adapter that wipes what it gives back.** `WipingAllocator`
forwards `alloc` to a child allocator; `free` overwrites the whole block with
`std.crypto.secureZero` first, and `resize`/`remap` are refused, so a growing or
shrinking buffer goes through alloc + copy + `free` and the old block is wiped
too. Put it under an `ArrayList`, an `ArenaAllocator` or a parser that holds
key material, so no earlier, smaller copy stays behind in a freed heap block.

- **Status:** extract — five identical private copies (xml-encryption,
  xml-signature, WireGuard control plane, BBS, minisign) became this one module.
- **Model after:** OpenSSL `OPENSSL_clear_free` and libsodium `sodium_free`
  (wipe on every give-back).
- **Platform:** any. **Role:** util. **Concurrency:** reentrant (exactly as
  thread-safe as the child). **Allocation:** none of its own.

```zig
const wipealloc = @import("wipealloc");

var wiper = wipealloc.WipingAllocator.init(gpa);
const a = wiper.allocator(); // `wiper` must outlive every block and must not move
var secret_buf: std.ArrayList(u8) = .empty;
defer secret_buf.deinit(a);   // every grown-out block and the last one are zeroed
```

Why it matters: in Debug and ReleaseSafe `Allocator.free` already poisons the
block (`0xaa`); in ReleaseFast that memset compiles away and the wiper is what
stands between a freed block and unrelated code.

`SecureAllocator` is the heavier form for a handful of keys (libsodium's `sodium_malloc`): each block in its own
mapping between two guard pages, `mlock`ed, with a canary in front of it, zeroed and unmapped on `free`.

```zig
var secure = try wipealloc.SecureAllocator.init(.best_effort);
const key = try secure.allocator().alloc(u8, 32);
defer secure.allocator().free(key);
```

Not a stack-burn helper (that is each module's private `burn.zig`, per
CONVENTIONS §2.1 D3) and not a wiping arena: `mls` keeps its own `Wiper`
because it forwards grow-in-place resizes (see SPEC).

Provenance: original work of the zig-libs authors (MIT). The wipe-on-free
pattern is common knowledge (OpenSSL, libsodium); no third-party source was
translated, so no NOTICE entry (root [`NOTICE`](../../NOTICE) §0).
