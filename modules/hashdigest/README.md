# hashdigest

Streaming digest helpers — one-shot, incremental, and **file** hashing that is
correct on size-0 virtual files (`/proc`, `/sys`). SHA-256 has dedicated
shortcuts; a runtime-selectable `Algorithm` (SHA-2 family, SHA-3, BLAKE2b-256,
BLAKE3) goes through `hex`/`MultiHasher`/`hashFile`.

- One-shot (`sha256Hex`, `matches`), incremental,
  and read-to-EOF file hashing (`sha256File`).
- **Model after:** Go `crypto/sha256` streaming. Thin over
  `std.crypto.hash` and the sibling `sha2` module; BLAKE2b-256 is this module's own vectorised form, tested byte-for-byte against std.
- **Platform:** any (file path uses `std.Io`). **Role:** util.
  **Concurrency:** one-shot fns pure; `Hasher` single-owner. **Allocation:** none.

Provenance: original work of the zig-libs authors (MIT); modeled after Go
`crypto/sha256` streaming ergonomics. The constructions are public standards
(SHA-2, SHA-3, RFC 7693 BLAKE2b, BLAKE3). On x86-64 SHA-2 comes from the sibling
`sha2` module, whose compression function is CRYPTOGAMS assembly (BSD-style
licence, in `modules/sha2/NOTICE`; a binary that includes `sha2` carries it);
everything else is `std.crypto` or `src/blake2b.zig` (written from the RFC, std's
streaming layout). The benchmark drivers in `tools/` (`c_bench/foreign_bench.c`,
`go_bench/`) are our own code that runs OpenSSL, libsodium and Go `crypto` as
black-box oracles for timing. Test data: `src/testdata/golden.tsv`, `sums.txt` and
`blake3_vectors.tsv` are produced by `tools/gen_golden.py`. golden.tsv: deterministic
messages (byte i = i*31+7 mod 256) hashed with Python `hashlib` as a black box.
sums.txt: GNU coreutils 9.7 (`gnusha256sum`, ...) and uutils coreutils 0.10
(`sha256sum`, ...) over files named for those messages, tool and version on each
block's comment line. blake3_vectors.tsv: a slice of `test_vectors/test_vectors.json`
from BLAKE3-team/BLAKE3 at commit `f55849f89cd85083c1c9daa2c5de20766f309c00`, CC0-1.0
(alternatively Apache-2.0), both MIT-compatible; origin URL on the file's first line.

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

// any algorithm, chosen at runtime (`hd.Algorithm`)
var out: [hd.max_hex_len]u8 = undefined;
const sha512_hex = try hd.hex(.sha512, "abc", &out);      // slice of `out`
var mh = hd.MultiHasher.init(.blake3);
mh.update("abc");
const blake_hex = try mh.finalHex(&out);
_ = try hd.hashFile(.sha3_256, io, "/proc/cpuinfo", &out); // ?u64 bytes read

// checksum files (`sha256sum -c`, `b2sum --tag`, ...): GNU and BSD-tag lines
var it = hd.checksum.Iterator.init(text);
while (try it.next()) |entry| { _ = entry; }     // BadLine / UnknownTag per bad line
const sum = hd.checksum.verifyAll(io, dir, .sha256, text, .{});   // ok/mismatch/unreadable/unsafe_name/malformed
_ = sum.allOk();

// extendable output and keyed / derived BLAKE3
var long: [100]u8 = undefined;
hd.xof(.shake256, "abc", &long);                 // any output length
hd.blake3Keyed(&key32, "msg", &long);            // keyed hash (MAC)
hd.blake3DeriveKey("my app v1 session", ikm, &long);
```

`blake2b256` runs on this module's own row-vectorised BLAKE2b-256 (`src/blake2b.zig`) when the build has AVX2 (std's otherwise),
byte-identical to `std.crypto.hash.blake2.Blake2b256` (tested on every length 0..600
and random chunkings). On x86-64 SHA-2 comes from the sibling `sha2` module, elsewhere from std (measured, SPEC Performance). `verifyAll` refuses absolute and `..` names and non-regular files unless told otherwise. Checksum-file parsing is fuzzed (`HASHDIGEST_FUZZ=<runs>`).
