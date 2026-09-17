# ripemd160

RIPEMD-160 (ISO/IEC 10118-3) — the hash Bitcoin uses to shrink a SHA-256
public-key digest to 20 bytes for P2PKH/P2WPKH/P2SH addresses. `std` has no
RIPEMD-160; this module fills that gap with a `std.crypto.hash`-shaped API
(`init`/`update`/`final`, one-shot `hash`) plus a ready-made `hash160`
convenience.

- **Model after:** the public RIPEMD-160 specification (Dobbertin/Bosselaers/
  Preneel, 1996; ISO/IEC 10118-3); streaming shape mirrors
  `std.crypto.hash.md5.Md5` (the closest std hash structurally — both use
  little-endian length padding).
- **Platform:** any (pure computation, no OS calls). **Role:** util.
  **Concurrency:** reentrant — `Ripemd160` is a plain value type, no shared
  state. **Allocation:** none.

Provenance: original work of the zig-libs authors (MIT); the algorithm is a
public spec (merger doctrine — no NOTICE entry needed, see CONVENTIONS.md
§5). No third-party source consulted or copied. The test vectors are the
public spec's; `tools/` is our own tooling that cross-checks them against
Python `hashlib` and the `openssl` CLI run as black-box oracles.

## API

```zig
const ripemd160 = @import("ripemd160");
const Ripemd160 = ripemd160.Ripemd160;

pub const digest_length = 20;
pub const block_length = 64;

// one-shot
var out: [20]u8 = undefined;
Ripemd160.hash("abc", &out, .{});

// streaming
var h = Ripemd160.init(.{});
h.update("ab");
h.update("c");
h.final(&out);

// Bitcoin hash160 = RIPEMD160(SHA256(x))
ripemd160.hash160(pubkey_bytes, &out);
```

## Notes

- **Little-endian length padding.** Like MD5 (and unlike SHA-1/SHA-2), the
  64-bit bit-length suffix is written little-endian. Getting this backwards
  is the classic RIPEMD/MD5-family implementation bug — it only diverges
  from the correct digest once a message is long enough for the low length
  byte to matter, so a single short KAT can't catch it. This module's tests
  include the official million-`'a'` stress vector specifically to exercise
  that path.
- **`hash160`** composes this module's `Ripemd160` with
  `std.crypto.hash.sha2.Sha256` — no reimplementation of SHA-256.
- **`final()` is single-use.** It does not clear or reset `Self` — a second
  `final()` call, an `update()` after `final()`, or reusing a struct without
  a fresh `init()` all return a well-defined but almost certainly not the
  digest you want. Same shape as `std.crypto.hash.md5.Md5` and the rest of
  `std.crypto.hash`: call `init()` again for the next message rather than
  recycling a finished one.

## Verify

```
zig build test-ripemd160
```
