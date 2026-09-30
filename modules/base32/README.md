# base32

RFC 4648 Base32 (§6) and Base32 with Extended Hex Alphabet (§7): the encoding
of TOTP/HOTP shared secrets, DNSSEC NSEC3 names and many human-typed keys. Zig
`std` has no base32.

Decoding is strict by default: bytes outside the alphabet, wrong padding,
impossible lengths and non-canonical trailing bits are each a distinct typed
error. Leniency is opt-in through `DecodeOptions` (optional/forbidden padding,
case-insensitive input, whitespace skipping) because authenticator secrets are
usually typed lowercase, unpadded and grouped by spaces. No allocation in the
core; caller-supplied buffers throughout.

```zig
const base32 = @import("base32");

var buf: [64]u8 = undefined;
const text = try base32.encode(&buf, "foobar", .{});                  // "MZXW6YTBOI======"
const bare = try base32.encode(&buf, "foobar", .{ .pad = false });    // "MZXW6YTBOI"

var raw: [base32.decodedLenUpperBound(64)]u8 = undefined;
const n = try base32.decode(&raw, "jbsw y3dp ehpk 3pxp", .{
    .padding = .optional, .case = .insensitive, .skip_whitespace = true,
});                                                                    // "Hello!\xde\xad\xbe\xef"
```

## API

| | |
|---|---|
| `Alphabet` | `.std` (RFC 4648 §6), `.hex` (§7) |
| `EncodeOptions` | `alphabet`, `pad` (default true), `lowercase` |
| `DecodeOptions` | `alphabet`, `padding: .required/.optional/.forbidden` (default required), `case: .upper_only/.insensitive`, `skip_whitespace` |
| `encodedLen(n, pad)`, `decodedLenUpperBound(text_len)` | buffer sizing |
| `encode(dest, src, opts)`, `decode(dest, text, opts) !usize` | caller-buffer codec |
| `encodeAlloc`, `decodeAlloc` | owning wrappers |
| `DecodeError` | `InvalidCharacter`, `InvalidPadding`, `InvalidLength`, `NonCanonical`, `BufferTooSmall` |

Not constant-time; see `SPEC.md` before feeding it long-lived secrets on a
shared host.

Provenance: clean-room from RFC 4648 (public IETF specification, §10 vectors
transcribed); further vectors captured from Python's stdlib
(`base64.b32encode`/`b32hexencode`) as a black-box oracle by
`tools/gen_kat.py`. No third-party source was consulted or copied.

## Tests

```
zig build test-base32
```
