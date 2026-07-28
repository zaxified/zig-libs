# mls

**Messaging Layer Security (RFC 9420)** — the scalable group-messaging
complement to this repo's 1:1 `signal` module. A multi-part arc.
**Part 1: foundation** — the mandatory cipher suite, the labeled-crypto
primitives (`RefHash`, `ExpandWithLabel`/`DeriveSecret`,
`DeriveTreeSecret`, `SignWithLabel`/`VerifyWithLabel`,
`EncryptWithLabel`/`DecryptWithLabel`), the ratchet tree's pure integer
math, and the TLS-presentation-language wire codec RFC 9420 is written
in. **Part 2: TreeKEM (ratchet tree, resolution, parent-hash,
UpdatePath)** — the ratchet tree's data structures (`LeafNode`/
`ParentNode`/`Node`/`RatchetTree`), wire codec, leaf-signature
verification, tree hash, and the mechanical tree-shape edits, PLUS the
five algorithmically-hard TreeKEM cores (`resolution`/`parentHash`/
`validateParentHashes`/`processUpdatePath`/`applyUpdatePath`) —
implemented and pinned byte-exact against the official mlswg interop
vectors — see `SPEC.md`'s "Part 2 — TreeKEM" section.

**Status: Part 1 COMPLETE, entirely Sonnet-tier. Part 2 COMPLETE** — the
data/codec/tree-hash/tree-editing pieces are Sonnet-tier (mechanical
composition + exact conformance to the official RFC 9420 interop test
vectors); the five Fable-tier tree-algorithm cores are implemented and
KAT-pinned (all 14 trees' resolutions, 275 single-byte parent-hash tamper
rejections, 62 UpdatePath processings across 328 receiver views, and 62
merges reproducing `tree_hash_after`) behind `gate.treekem_core_implemented`
(now `true`). KeyPackage/LeafNode-validation/Credential (Part 3), the key
schedule (Part 4), and Proposal/Commit/framing (Part 5) are LATER parts;
see `SPEC.md`'s "Arc breakdown" for the full decomposition.

| File | Provides |
|---|---|
| `codec.zig` | RFC 9420 §2.1 TLS-presentation-language (de)serializer: `Writer`/`Reader`, fixed-width big-endian ints, `optional<T>`, enums, and the QUIC-style variable-length-integer VECTOR length prefix (§2.1.2) that is RFC 9420's one deviation from plain RFC 8446 |
| `suite.zig` | `CipherSuite(...)` (comptime KEM+KDF+AEAD+Hash+Signature bundle); `Mls128X25519Aes128GcmSha256Ed25519` (suite `0x0001`, the mandatory-to-implement suite) |
| `crypto.zig` | `RefHash`/`make_keypackage_ref`/`make_proposal_ref` (§5.2), `ExpandWithLabel`/`DeriveSecret` (§8), `DeriveTreeSecret` (§9.1), `SignWithLabel`/`VerifyWithLabel` (§5.1.2), `EncryptWithLabel`/`DecryptWithLabel` (§5.1.3, delegates to the sibling `hpke` module's `sealBase`/`openBase`) |
| `treemath.zig` | RFC 9420 Appendix C array-based binary tree math: `left`/`right`/`parent`/`sibling`, `root`, `direct_path`, `copath`, `is_leaf`, `node_width`, `level` — a direct port of the RFC's own published Python |
| `kat_test.zig` | Part 1's official RFC 9420 interop vectors (`mlswg/mls-implementations`'s `tree-math.json`/`crypto-basics.json`), embedded and driven end-to-end |
| `wire_lists.zig` | Part 2's shared variable-length-vector encode/decode helpers |
| `tree.zig` | Part 2's `LeafNode`/`ParentNode`/`Node`/`RatchetTree` (§7.1/§7.2/§12.4.3.3), wire codec, leaf-signature verification, `addLeaf`/`updateLeaf`/`removeLeaf` (§7.7/§12.1.1-3) |
| `treehash.zig` | Part 2's RFC 9420 §7.8 tree hash (real, recursive, KAT'd byte-exact) |
| `treekem.zig` | Part 2's `HPKECiphertext`/`UpdatePathNode`/`UpdatePath` (§7.6) + the five Fable cores (`resolution`/`parentHash`/`validateParentHashes`/`processUpdatePath`/`applyUpdatePath`), implemented and KAT-pinned |
| `gate.zig` | Part 2's `treekem_core_implemented` switch — now `true` (the five cores are implemented; the gated TreeKEM KATs run) |
| `kat_treekem_test.zig` | Part 2's official RFC 9420 interop vectors (`tree-validation.json`/`tree-operations.json`/`treekem.json`), driven byte-exact against the five cores |

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

## API surface (Part 2 — TreeKEM)

**RatchetTree** (`tree.zig`, allocator-owning — see that file's module
doc comment):

```zig
const tree = mls.tree;
var r = mls.codec.Reader.init(wire_bytes); // the `ratchet_tree` extension's bytes
var rt = try tree.RatchetTree.decode(allocator, &r);
defer rt.deinit();

rt.nLeaves();
try rt.addLeaf(new_leaf_node); // §12.1.1 Add — takes ownership of new_leaf_node
try rt.updateLeaf(sender_index, new_leaf_node); // §12.1.2 Update
try rt.removeLeaf(removed_index); // §12.1.3 Remove + §7.7 truncation

const encoded = try rt.encode(allocator); // trims trailing blanks, §12.4.3.3
defer allocator.free(encoded);

// §7.2/§5.1.2 leaf signature verification
const leaf = rt.nodes[0].?.leaf;
try leaf.verifySignature(S, allocator, group_id, 0);
```

**Tree hash** (`treehash.zig`, real, RFC 9420 §7.8):

```zig
const treehash = mls.treehash;
const root_hash = try treehash.rootHash(S, allocator, &rt);
const hash_of_node_5 = try treehash.treeHash(S, allocator, &rt, 5);
```

**TreeKEM** (`treekem.zig`): the §7.6 wire structs plus the five cores —
`resolution` (§4.1), `parentHash`/`validateParentHashes` (§7.9), and the
`UpdatePath` walk `processUpdatePath` (private-side secret derivation +
`commit_secret`) / `applyUpdatePath` (public-side merge):

```zig
const treekem = mls.treekem;
var r2 = mls.codec.Reader.init(update_path_bytes);
var up = try treekem.UpdatePath.decode(allocator, &r2);
defer up.deinit(allocator);

// receiver derives commit_secret + path secrets from the UpdatePath
const processed = try treekem.processUpdatePath(S, allocator, &rt, receiver, sender_index, up, group_context);
// commit_secret == path_secret[n+1] (RFC §12.4.2); byte-exact vs treekem.json

// every member merges the public tree state (blank direct path, adopt keys,
// recompute parent hashes, enforce the committer leaf's parent-hash validity)
try treekem.applyUpdatePath(arena_allocator, &rt, sender_index, up);
```

## Verify

```sh
zig build test-mls --summary all
zig build test-mls --summary all -Doptimize=ReleaseFast
```

46 tests, all running (the `gate.treekem_core_implemented`-gated TreeKEM
tests now execute). Coverage includes Part 1's `tree-math.json`/
`crypto-basics.json` KATs (see below); Part 2's `tree-validation.json`
(tree hash + leaf signatures + resolution for every node across 14
suite-`0x0001` trees, plus `validateParentHashes` accepting all 14 and
rejecting all 275 single-byte parent-hash tampers, byte-exact); the FULL
`tree-operations.json` (Add/Update/Remove tree-editing, byte-exact tree
bytes + both tree hashes, 5 vectors); and the whole `treekem.json`
(`processUpdatePath` reproducing `commit_secret` + first path secret for
all 62 UpdatePaths across 328 receiver views, and `applyUpdatePath`
merging each of the 62 to reproduce `tree_hash_after`, all byte-exact).
Green in Debug and ReleaseFast.

## Provenance

Clean-room from RFC 9420 (public IETF specification) plus a direct port
of Appendix C's own published reference algorithm (`treemath.zig`). KAT
vectors are official `mlswg/mls-implementations` interop test data. See
`NOTICE` for the exact source commit/fetch date.
