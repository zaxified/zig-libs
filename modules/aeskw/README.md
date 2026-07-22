# aeskw

**RFC 3394 AES Key Wrap.** std ships no key-wrap primitive; this module extracts the
canonical implementation that had previously accreted three times independently in this repo
(`jwe`'s `A128KW`/`A256KW`, `dnp3`'s SAv2 session-key wrap, `xmlenc`'s `kw-aes128`/`kw-aes256`
unwrap) into one place. No allocation, no deps, no panics — every buffer is caller-supplied.

- **Model after:** RFC 3394 (AES Key Wrap).
- **Platform:** any. **Role:** crypto primitive. **Concurrency:** reentrant (no shared state, no
  allocation). **Deps:** none (`std.crypto.core.aes` only).

Provenance: original work of the zig-libs authors (MIT), implemented directly from the RFC 3394
text — an open IETF specification, not a copyrightable work. See `SPEC.md` for the full
design/threat-model breakdown and how this relates to the three in-repo mirrors it supersedes.

## Usage

```zig
const aeskw = @import("aeskw");

const kek = [_]u8{ /* 16 bytes (AES-128) or 32 bytes (AES-256) */ };
const key_data = [_]u8{ /* 8-byte-multiple, >= 16 bytes */ };

var wrapped: [key_data.len + 8]u8 = undefined;
const ct = try aeskw.wrap(&kek, &key_data, &wrapped); // ct.len == key_data.len + 8

var recovered: [key_data.len]u8 = undefined;
const pt = try aeskw.unwrap(&kek, ct, &recovered); // error.Unauthentic on wrong KEK / tamper
```

`aeskw.default_iv` exposes the RFC 3394 §2.2.3.1 default integrity-check IV
(`A6A6A6A6A6A6A6A6`) directly, for callers that want it (e.g. to assert against before wiring
a KEK from a new source).

## API

```zig
pub const default_iv: [8]u8;

pub const Error = error{
    InvalidLength,       // plaintext/ciphertext not an 8-byte multiple, or below the RFC minimum
    BufferTooSmall,       // out too small for the result
    UnsupportedKeyLength, // kek.len is neither 16 (AES-128) nor 32 (AES-256)
    Unauthentic,          // unwrap: integrity check failed (wrong KEK or corrupted ciphertext)
};

pub fn wrap(kek: []const u8, plaintext: []const u8, out: []u8) Error![]u8;
pub fn unwrap(kek: []const u8, ciphertext: []const u8, out: []u8) Error![]u8;
```

`wrap`: `plaintext.len` must be a multiple of 8 and `>= 16`; writes `plaintext.len + 8` bytes to
`out` and returns that slice. `unwrap`: `ciphertext.len` must be a multiple of 8 and `>= 24`;
writes `ciphertext.len - 8` bytes to `out` and returns that slice, or fails with
`error.Unauthentic` — in which case `out`'s scratch region is zeroed before returning, so a
failed unwrap never leaks partially-recovered, KEK-derived plaintext. The KEK width (16 vs. 32
bytes) is read from `kek.len` at each call — there's no separate AES-128/AES-256 selection
argument or comptime variant; a 24-byte (AES-192) KEK returns `error.UnsupportedKeyLength` (see
`SPEC.md` — a real `std.crypto.core.aes` gap in Zig 0.16, not a design choice).

## Tests

`zig build test-aeskw` (headless; green in Debug and `-Doptimize=ReleaseFast`). Anchors: RFC
3394 §4.1 (128-bit KEK / 128-bit key), §4.3 (256-bit KEK / 128-bit key), §4.5 (256-bit KEK /
192-bit key, the odd-block-count n=3 case), and §4.6 (256-bit KEK / 256-bit key, n=4) — each
byte-exact in both the wrap and unwrap directions; unwrap integrity-failure coverage (wrong KEK,
single-bit-corrupted ciphertext) each proven `error.Unauthentic` with an all-zeroed `out` and a
same-shape correct-KEK positive control; length/KEK-width validation with positive controls at
the exact 16-/24-byte boundaries. See `SPEC.md` for the full breakdown.

## Deferred (not implemented)

- **RFC 5649** (AES Key Wrap with Padding, for key data that isn't an 8-byte multiple) — no
  in-repo consumer needs it; see `SPEC.md` "Scope" for why adding it later is additive, not a
  breaking change to this module's `wrap`/`unwrap`.
