# sealedbox

NaCl `crypto_box_seal` — **anonymous-sender** public-key encryption. Encrypt to a
recipient's X25519 public key with no sender key (a fresh ephemeral keypair per
message); the recipient cannot identify the sender.

- **Status:** `extract` — from axp `axp-core/src/sealed.zig` (enrollment path).
- **Model after:** libsodium `crypto_box_seal` / Go `nacl/box`. Thin, faithful
  wrapper over `std.crypto.nacl.SealedBox` — **no custom crypto**.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant.
  **Allocation:** none in the buffer API; `*Alloc` variants allocate the result.

Provenance: extracted from axp (Apache-2.0, relicensed MIT by the copyright
holder); the construction is the public NaCl standard, so no NOTICE entry.

## API

```zig
const sb = @import("sealedbox");

const kp = sb.KeyPair.generate(io);          // recipient keypair (X25519 / WG-compatible)

// buffer API (no allocation)
var ct: [sb.sealedLen(msg.len)]u8 = undefined; // == msg.len + sb.overhead
try sb.seal(io, &ct, msg, kp.public_key);      // io = entropy for the ephemeral key
var pt: [msg.len]u8 = undefined;
try sb.open(&pt, &ct, kp);                     // error (no panic) on tamper/short input

// allocating convenience
const ct2 = try sb.sealAlloc(gpa, io, msg, kp.public_key);  defer gpa.free(ct2);
const pt2 = try sb.openAlloc(gpa, ct2, kp);                 defer gpa.free(pt2);
```

`overhead` is 48 bytes (32-byte ephemeral pubkey + 16-byte Poly1305 tag).
