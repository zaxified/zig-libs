# lms

LMS and HSS (RFC 8554, Leighton-Micali hash-based signatures): **stateful**
post-quantum signatures whose security rests on the hash alone (SHA-256 or SHAKE256). Pure Zig over
`std.crypto`. This is the scheme NIST SP 800-208 and CNSA 2.0 approve for
firmware signing (`slhdsa` is the stateless alternative; `xmss` the other
stateful one). Small public key (60 bytes), 1.3 - 9 KB signatures, and a private
key that is a **consumable**: every signature spends one one-time leaf, and using
a leaf twice breaks the scheme.

- **Parameter sets:** LMS `H5 / H10 / H15 / H20 / H25` and LM-OTS `W1 / W2 / W4 / W8`
  over SHA-256 (n = m = 32, RFC 8554 typecodes) and RFC 9858's SHA-256/192, SHAKE256/256
  and SHAKE256/192 (n = m = 24 or 32); one hash per LMS key, any mix across HSS levels
  `L` = 1..8. A 24-byte set's SEED is the first 24 bytes of the 32-byte seed.
- **Operations:** `hssVerify` / `lmsVerify` (no allocation, `false` for anything
  malformed), key generation from a `(SEED, I)` pair (RFC 8554 Appendix A), and
  `sign`, which advances the position **before** it produces a signature and
  returns `error.KeyExhausted` at the end.
- **Model after:** RFC 8554 and RFC 9858, clean-room; validated on RFC 8554 Appendix F
  (both HSS signatures verify, and Test Case 2's public keys and signatures are
  reproduced byte for byte) and RFC 9858 Appendix A (all four cases). See `NOTICE`.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant (no globals; a bare `SecretKey` is
  caller-synchronised, `SigningKey` locks). **Deps:** none (std SHA-256).

```zig
const lms = @import("lms");

const levels = [_]lms.Level{
    .{ .lms = .sha256_m32_h10, .ots = .sha256_n32_w4 }, // top tree: generated up front
    .{ .lms = .sha256_m32_h10, .ots = .sha256_n32_w4 }, // 2^20 signatures in all
};

// SEED (secret, 32 bytes) and I (16 bytes) from a CSPRNG: there is no RNG here.
// The seed goes in by pointer and the key is built in place (`out` parameter),
// so no copy of the SEED is made on the stack.
var sk: lms.SecretKey = undefined;
try lms.SecretKey.init(&sk, gpa, &levels, &seed, id, null);
defer sk.deinit(); // wipes the seeds

var pk_buf: [lms.HssPublicKey.max_encoded_len]u8 = undefined;
const pk = sk.publicKey().encode(&pk_buf); // 60 bytes (52 for a 24-byte set): ship this
const buf = try gpa.alloc(u8, sk.signatureLength());
const sig = try sk.sign(message, buf); // advances the position FIRST; PERSIST it!

const ok = lms.hssVerify(pk, message, sig); // on the device: no allocation
```

**STATEFUL-KEY HAZARD.** `sign` mutates the key's position. Make the new position
durable *before* the signature leaves the process, never sign from a restored
backup or from two copies of the key, and partition leaves if a key must be shared.
`SigningKey` wraps `SecretKey` with a `Persist` hook called before any signature
byte exists, a lock, and a copy guard. If you cannot guarantee that discipline, use
`slhdsa`. A CNSA 2.0 signer must additionally keep key and state in an HSM; see
SPEC.md for what a software library cannot supply.

**Cost.** Key generation computes every leaf of the top tree once: `2^h` leaves of
`p * (2^w - 1)` hashes each (W8: 8 704, W4: 1 072, W2: 532, W1: 530). That is the
reason HSS exists: with a small top tree (`H5`/`H10`/`H15`) generation is quick and a
lower tree is built only when the position first enters it (`O(2^h)` hashing for one
signature in `2^h`). A single H20 or H25 tree takes hours or days here (single
thread, no hardware SHA extensions); use HSS instead. Signing needs the public
node cache (at most 2 MiB per tree, `sign.zig`).

Provenance: clean-room from RFC 8554, a public specification; no LMS/HSS source
consulted. The RFC's Appendix F test data is reproduced with attribution in
[`NOTICE`](NOTICE). It carries no condition beyond zig-libs' MIT license.
