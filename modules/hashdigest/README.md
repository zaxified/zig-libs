# hashdigest

Streaming SHA-256 helpers — one-shot, incremental, and **file** hashing that is
correct on size-0 virtual files (`/proc`, `/sys`).

- **Status:** `extract` — from axp `axp-core/src/digest.zig` (`sha256Hex`,
  `matches`) + `axp-core/src/task.zig` (`sha256FileHex`, read-to-EOF loop).
- **Model after:** Go `crypto/sha256` streaming. Thin over
  `std.crypto.hash.sha2.Sha256` — no custom crypto.
- **Platform:** any (file path uses `std.Io`). **Role:** util.
  **Concurrency:** one-shot fns pure; `Hasher` single-owner. **Allocation:** none.

Provenance: extracted from axp (Apache-2.0, relicensed MIT by the copyright
holder); the construction is the public SHA-256 standard, so no NOTICE
entry (own code over std).

## API

```zig
const hd = @import("hashdigest");

var hex: [hd.hex_len]u8 = undefined;      // hex_len == 64
hd.sha256Hex(&hex, "abc");                // lowercase hex
const h = hd.sha256HexBuf("abc");         // -> [64]u8
_ = hd.matches("abc", &hex);              // content-address check (no panic on junk)

var hasher = hd.Hasher.init();            // incremental
hasher.update("ab");
hasher.update("c");
hasher.finalHex(&hex);

// file hashing that trusts EOF, not stat().size (works on /proc/*)
if (hd.sha256File(io, "/proc/cpuinfo", &hex)) |n| { _ = n; }
```
