# mls

**Messaging Layer Security (RFC 9420)** — the scalable group-messaging
complement to this repo's 1:1 `signal` module. A multi-part arc; this is
**Part 1: foundation** — the mandatory cipher suite, the labeled-crypto
primitives (`RefHash`, `ExpandWithLabel`/`DeriveSecret`,
`DeriveTreeSecret`, `SignWithLabel`/`VerifyWithLabel`,
`EncryptWithLabel`/`DecryptWithLabel`), the ratchet tree's pure integer
math, and the TLS-presentation-language wire codec RFC 9420 is written in.

**Status: Part 1 COMPLETE, entirely Sonnet-tier.** Mechanical composition
+ exact conformance to the official RFC 9420 interop test vectors — no
novel cryptography. TreeKEM, KeyPackage/LeafNode/Proposal/Commit framing,
the key schedule, and the secret tree are LATER parts; see `SPEC.md`'s
"Arc breakdown" for the full decomposition (the genuinely Fable-hard
piece, TreeKEM path/parent-hash/resolution validation, is deliberately
NOT built here).

| File | Provides |
|---|---|
| `codec.zig` | RFC 9420 §2.1 TLS-presentation-language (de)serializer: `Writer`/`Reader`, fixed-width big-endian ints, `optional<T>`, enums, and the QUIC-style variable-length-integer VECTOR length prefix (§2.1.2) that is RFC 9420's one deviation from plain RFC 8446 |
| `suite.zig` | `CipherSuite(...)` (comptime KEM+KDF+AEAD+Hash+Signature bundle); `Mls128X25519Aes128GcmSha256Ed25519` (suite `0x0001`, the mandatory-to-implement suite) |
| `crypto.zig` | `RefHash`/`make_keypackage_ref`/`make_proposal_ref` (§5.2), `ExpandWithLabel`/`DeriveSecret` (§8), `DeriveTreeSecret` (§9.1), `SignWithLabel`/`VerifyWithLabel` (§5.1.2), `EncryptWithLabel`/`DecryptWithLabel` (§5.1.3, delegates to the sibling `hpke` module's `sealBase`/`openBase`) |
| `treemath.zig` | RFC 9420 Appendix C array-based binary tree math: `left`/`right`/`parent`/`sibling`, `root`, `direct_path`, `copath`, `is_leaf`, `node_width`, `level` — a direct port of the RFC's own published Python |
| `kat_test.zig` | The official RFC 9420 interop vectors (`mlswg/mls-implementations`'s `tree-math.json`/`crypto-basics.json`), embedded and driven end-to-end |

- **Model after:** RFC 9420 (Messaging Layer Security); `treemath.zig`
  ports Appendix C's own published reference algorithm.
- **Platform:** any. **Role:** util (pure computation, no owned transport
  — a later framing part may add wire I/O). **Concurrency:** reentrant —
  every type is a plain caller-owned value.
- **Deps:** `hpke` (the sibling module supplies suite `0x0001`'s
  DHKEM(X25519, HKDF-SHA256) + AES-128-GCM machinery via `sealBase`/
  `openBase`; MLS's own `ExpandWithLabel`/`RefHash`/`SignWithLabel` are a
  SEPARATE wire encoding from HPKE's own labeling, see `crypto.zig`'s
  module doc comment).

## Import

```zig
const mls = @import("mls");
```

## API surface (Part 1)

**Cipher suite** (`suite.zig`, re-exported at `mls.suite`):

```zig
const S = mls.default_suite; // suite 0x0001, MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
S.Nh; // 32 (KDF/hash output width)
S.Nk; // 16 (AEAD key width)
S.Nn; // 12 (AEAD nonce width)
S.Nx; // 64 (Ed25519 signature width)
```

**Labeled crypto** (`crypto.zig`, re-exported flat on `mls`):

```zig
// RFC 9420 §8
const secret = try mls.DeriveSecret(S, epoch_secret, "encryption");
var out: [32]u8 = undefined;
try mls.ExpandWithLabel(S, secret, "derived", context_bytes, &out);

// RFC 9420 §5.2
const kp_ref = try mls.make_keypackage_ref(S, encoded_key_package);

// RFC 9420 §5.1.2 — Ed25519 signing is DETERMINISTIC (RFC 8032)
const sig = try mls.SignWithLabel(S, signature_key_pair, "FramedContentTBS", content);
try mls.VerifyWithLabel(S, signature_public_key, "FramedContentTBS", content, sig);

// RFC 9420 §5.1.3 — delegates to hpke.sealBase/openBase
var ct: [pt.len + S.Aead.tag_length]u8 = undefined;
const enc = try mls.EncryptWithLabel(S, kem_public_key, io, "UpdatePathNode", context_bytes, pt, &ct);
var out_pt: [pt.len]u8 = undefined;
try mls.DecryptWithLabel(S, enc, kem_key_pair, "UpdatePathNode", context_bytes, &ct, &out_pt);
```

**Tree math** (`treemath.zig`):

```zig
const treemath = mls.treemath;
const n_leaves: usize = 4;
treemath.root(n_leaves); // 3
treemath.left(1); // 0
treemath.parent(0, n_leaves); // 1
treemath.sibling(0, n_leaves); // 2
var path_buf: [treemath.max_path_len]usize = undefined;
const path = try treemath.direct_path(0, n_leaves, &path_buf); // [1, 3]
```

**Codec** (`codec.zig`) — the wire (de)serializer every later part builds
on:

```zig
const codec = mls.codec;
var buf: [256]u8 = undefined;
var w = codec.Writer.init(&buf);
try w.writeU16(0x0001); // a CipherSuite id
try w.writeVector(some_bytes); // opaque foo<V>
const out = w.finish();

var r = codec.Reader.init(out);
const suite_id = try r.readU16();
const bytes = try r.readVector(); // aliases `out`, no copy
```

## Verify

```sh
zig build test-mls --summary all
zig build test-mls --summary all -Doptimize=ReleaseFast
```

35 tests, all real, no skip guards — including the two KAT tests that
drive the complete official RFC 9420 `tree-math.json` (all 10 published
tree sizes, 1 through 512 leaves, every node's `root`/`left`/`right`/
`parent`/`sibling`) and `crypto-basics.json` (suite `0x0001`'s
`ref_hash`/`derive_secret`/`derive_tree_secret`/`expand_with_label`/
`sign_with_label`/`encrypt_with_label`) end-to-end through the real
implementation. Green in Debug and ReleaseFast.

## Provenance

Clean-room from RFC 9420 (public IETF specification) plus a direct port
of Appendix C's own published reference algorithm (`treemath.zig`). KAT
vectors are official `mlswg/mls-implementations` interop test data. See
`NOTICE` for the exact source commit/fetch date.
