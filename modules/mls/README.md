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
vectors — see `SPEC.md`'s "Part 2 — TreeKEM" section. **Part 4: key
schedule + secret tree** — RFC 9420 §8's epoch chain, §8.1's
`GroupContext`, §8.4's `psk_secret`, §8.5's exporter, §6.1's
`confirmation_tag`/`membership_tag`, and §9's secret tree with its
per-leaf sender ratchets and out-of-order window — pinned byte-exact
against the official `key-schedule`/`psk_secret`/`secret-tree` vectors,
see `SPEC.md`'s "Part 4" section. **Part 5: message framing** — all of
RFC 9420 §6 (`FramedContent`, `AuthenticatedContent`, the §6.1 signature
and its two tags, §6.2's `PublicMessage`, §6.3's `PrivateMessage` with
content and sender-data encryption, `MLSMessage`), the §12.1 `Proposal`
and §12.4 `Commit` wire formats framing carries, the §10 `KeyPackage`
wire format an `Add` carries, and §8.2's transcript hashes — pinned
byte-exact against the official `messages`/`message-protection`/
`transcript-hashes` vectors, see `SPEC.md`'s "Part 5" section.
**Part 6: joining a group** — RFC 9420 §12.4.3's `GroupInfo`, §12.4.3.1's
`Welcome`/`GroupSecrets` with both encryption layers, §12.4.3.3's
`ratchet_tree`/`external_pub` extensions and the tree-hash binding, and
the joiner's own procedure (`join`) — pinned byte-exact against the
official `welcome` vector, see `SPEC.md`'s "Part 6" section.
**Part 7: the group state machine** — `Group(S)`, the state a member
carries between epochs plus the receiving half of an epoch transition:
§12.2's proposal-list validation, §12.3's application order, §12.4.2's
whole Commit-processing procedure, and §12.4.3.1's join run to completion
(`fromWelcome`). Plus §8.3's external initialization. Anchored against the
official `passive-client-*` vectors — whole recorded sessions replayed
Commit by Commit with the `epoch_authenticator` compared at every step,
including one 200-Commit session — see `SPEC.md`'s "Part 7" section.

**Status: Part 1 COMPLETE, entirely Sonnet-tier. Part 2 COMPLETE** — the
data/codec/tree-hash/tree-editing pieces are Sonnet-tier (mechanical
composition + exact conformance to the official RFC 9420 interop test
vectors); the five Fable-tier tree-algorithm cores are implemented and
KAT-pinned (all 14 trees' resolutions, 275 single-byte parent-hash tamper
rejections, 62 UpdatePath processings across 328 receiver views, and 62
merges reproducing `tree_hash_after`) behind `gate.treekem_core_implemented`
(now `true`). **Part 4 COMPLETE** (Sonnet-tier) — including §8.3's
external initialization, which Part 7 added. **Part 5 COMPLETE**
(Sonnet-tier) — and it closed §8.2, the other gap Part 4 had left open.
**Part 6 COMPLETE for the Welcome path** (Sonnet-tier). **Part 7 COMPLETE
for the FOLLOWER** (Sonnet-tier) — and it is the first part of this arc
whose vectors did NOT match on the first run: replaying recorded sessions
found three real defects in Parts 1/2/4 (a fixed 512-byte label scratch
that overflowed for any realistically sized group, an over-constrained PSK
width that rejected legal 14-byte input, and an `unmerged_leaves` insert
that did not keep §7.1's required sort order) plus one specification
misreading, RFC 9420 §7.5's rule that members added by the same Commit are
excluded from the `UpdatePath` resolutions. See `SPEC.md`'s "Part 7".
Part 3 (KeyPackage/LeafNode VALIDATION + Credential) and §12.4.3.2's
external Commits remain; see `SPEC.md`'s "Arc breakdown".
What this module can do today: produce and consume real MLS messages other
implementations accept byte-for-byte, JOIN a group from a `Welcome`, and
FOLLOW that group through Commits — validated against recorded sessions
from another implementation, one of them 200 Commits long. A passive client
is complete. What it cannot: SPEAK — there is no Commit, proposal or
`Welcome` CREATION (no sender half of §7.5 anywhere in the module) — nor
accept `PrivateMessage` handshakes, join by external Commit, or decide
whether a KeyPackage or LeafNode should be admitted (§10.1/§7.3).

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
| `keyschedule.zig` | Part 4's §8 epoch chain (`joinerSecret`/`welcomeSecret`/`epochSecret`/`deriveEpoch`), §8.1 `GroupContext`, §8.4 `PreSharedKeyId`/`pskSecret`, §8.5 `mlsExporter`, `externalKeyPair`, §6.1 `confirmationTag`/`membershipTag` (+ constant-time verifiers) |
| `secrettree.zig` | Part 4's §9 secret tree (`nodeSecret`/`ratchetBaseSecret`), §9.1 `Ratchet` + the generation-indexed out-of-order `Window`, §6.3.2 `senderDataKeys` |
| `kat_keyschedule_test.zig` | Part 4's official interop vectors `key-schedule.json` + `psk_secret.json`, driven per-stage byte-exact |
| `kat_secrettree_test.zig` | Part 4's official `secret-tree.json`, driven byte-exact both forward (`Ratchet`) and out-of-order (`Window`) |
| `keypackage.zig` | Part 5's §10 `KeyPackage`/`KeyPackageTBS` WIRE FORMAT + self-signature (`verifySignature`/`sign`). §10.1's validation rules are Part 3's and are NOT here |
| `content.zig` | Part 5's §12.1 `Proposal` (all seven types) + §12.4 `Commit`/`ProposalOrRef` — wire shape only; no proposal-list validity, no commit processing |
| `framing.zig` | Part 5's whole of §6: `Sender`/`FramedContent`/`AuthenticatedContent`, §6.1 sign+verify, §6.2 `PublicMessage` + `protectPublic`/`unprotectPublic`, §6.3 `PrivateMessage` + `protectPrivate`/`decryptSenderData`/`decryptContent`/`parsePrivateContent`, `MLSMessage` |
| `transcript.zig` | Part 5's §8.2 `confirmedTranscriptHash`/`interimTranscriptHash`/`advance` — the gap Part 4 named and could not fill |
| `kat_messages_test.zig` | Parts 5+6's official `messages.json`, every embedded field decode→re-encode byte-exact (including §12.4.3.1's `Welcome`/`GroupInfo`/`GroupSecrets` and §12.4.3.3's bare `ratchet_tree`) |
| `kat_framing_test.zig` | Part 5's official `message-protection.json` (protect/unprotect byte-exact both directions) + `transcript-hashes.json` (§8.2) |
| `welcome.zig` | Part 6's §12.4.3 `GroupInfo` (+ `sign`/`verifySignature`), §12.4.3.1 `GroupSecrets`/`EncryptedGroupSecrets`/`Welcome`, `welcomeKeyNonce`/`encryptGroupInfo`/`decryptGroupInfo`, `encryptGroupSecrets`/`decryptGroupSecrets`, `join`, and §12.4.3.3's `ratchetTree`/`externalPub`/`verifyTreeHash` |
| `kat_welcome_test.zig` | Part 6's official `welcome.json`, the whole join staged per layer — plus the vector's `encrypted_group_info` reproduced in the SEND direction |
| `group.zig` | Part 7's `Group(S)` — the group STATE plus the receiving half of an epoch transition: `fromWelcome` (§12.4.3.1 run to completion), `processCommit` (§12.2 validation, §12.3 ordering, §12.4.2's whole procedure), `epochAuthenticator`/`groupContext`, and §8.4 PSK resolution over application-supplied and remembered-resumption keys |
| `kat_passive_test.zig` | Part 7's official `passive-client-welcome`/`-handling-commit`/`-random` vectors — recorded sessions replayed Commit by Commit against `epoch_authenticator`, plus the assertions guarding each file's reduction |

- **Model after:** RFC 9420 (Messaging Layer Security); `treemath.zig`
  ports Appendix C's own published reference algorithm.
- **Platform:** any. **Role:** util (pure computation, no owned transport;
  Part 5's framing returns BYTES to send and takes bytes received — MLS
  does not specify a transport, so owning one here would be an invention).
  **Concurrency:** reentrant — every type is a plain caller-owned value.
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

## API surface (Part 4 — key schedule + secret tree)

**Epoch key schedule** (`keyschedule.zig`, RFC 9420 §8). The allocator is
there because a `GroupContext` has no size bound — it is serialized, and it
is fed to the KDF as a label context:

```zig
const ks = mls.keyschedule;

const gc: ks.GroupContext = .{
    .cipher_suite = S.id,
    .group_id = group_id,
    .epoch = epoch,
    .tree_hash = tree_hash,                       // from treehash.rootHash
    .confirmed_transcript_hash = confirmed_transcript_hash,
    .extensions = &.{},
};
const encoded_gc = try gc.encodeAlloc(allocator);
defer allocator.free(encoded_gc);

// psk_secret from the Commit's PreSharedKey proposals (§8.4), or all-zero
const psk = try ks.pskSecret(S, allocator, psks); // `&.{}` => ks.zeroSecret(S)

var secrets = try ks.deriveEpoch(S, allocator, init_secret_prev, commit_secret, psk, encoded_gc);
defer secrets.wipe(); // §9.2

secrets.encryption_secret;   // -> the secret tree, below
secrets.init_secret;         // -> the NEXT epoch's deriveEpoch
secrets.epoch_authenticator; // §8.7, for out-of-band comparison

const external_pub = ks.externalKeyPair(S, secrets.external_secret).public_key;
try ks.mlsExporter(S, secrets.exporter_secret, "my-app label", context, out);

// §6.1, over structures Part 5 assembles (framing.membershipTag)
const tag = ks.confirmationTag(S, secrets.confirmation_key, confirmed_transcript_hash);
try ks.verifyConfirmationTag(S, secrets.confirmation_key, confirmed_transcript_hash, received_tag);
```

**Secret tree and sender ratchets** (`secrettree.zig`, RFC 9420 §9). A
sender walks a `Ratchet` forward; a receiver uses a `Window`, which
tolerates reordering, refuses replays, and bounds how far an
unauthenticated generation can make it ratchet:

```zig
const st = mls.secrettree;

// sender: leaf 3's application ratchet
const base = try st.ratchetBaseSecret(S, secrets.encryption_secret, n_leaves, 3, .application);
var ratchet = st.Ratchet(S).init(base);
defer ratchet.wipe();
const kn = try ratchet.current(); // kn.key, kn.nonce for ratchet.generation
try ratchet.advance();

// receiver: same base, tolerant of out-of-order delivery
var window = st.Window(S, 32).init(base);
defer window.wipe();
window.max_forward_jump = 256;              // default 1024
const kn2 = try window.get(generation);     // consumed: a second get() fails
// error.GenerationConsumed / .GenerationTooFarAhead

// §6.3.2 sender-data keys, bound to a sample of the message ciphertext
const sd = try st.senderDataKeys(S, secrets.sender_data_secret, ciphertext);
```

## API surface (Part 5 — message framing)

**Sending** (`framing.zig`, RFC 9420 §6). Both `protect*` calls return
freshly allocated wire bytes; wrap them in an `MLSMessage` to put them on
the network:

```zig
const fr = mls.framing;

const fc: fr.FramedContent = .{
    .group_id = group_id,
    .epoch = epoch,
    .sender = .{ .member = my_leaf_index },
    .authenticated_data = &.{},
    .body = .{ .proposal = .{ .remove = 2 } },   // or .commit / .application
};

// §6.2 — signed, MAC'd, not encrypted. Refuses application content
// (error.ApplicationContentMustBeEncrypted), per §6's MUST.
const pub_bytes = try fr.protectPublic(S, allocator, .{
    .signature_key_pair = my_signature_key,
    .membership_key = secrets.membership_key,
    .group_context = encoded_gc,
    .content = fc,
    .confirmation_tag = null,        // required iff `fc` is a commit
});
defer allocator.free(pub_bytes);

// §6.3 — encrypted. The reuse guard MUST be freshly random per message
// (§6.3.1); this module never owns a randomness policy.
const priv_bytes = try fr.protectPrivate(S, allocator, .{
    .signature_key_pair = my_signature_key,
    .group_context = encoded_gc,
    .content = fc,
    .key_nonce = kn,                 // from secrettree.Ratchet.current()
    .generation = ratchet.generation,
    .reuse_guard = my_fresh_random_4_bytes,
    .sender_data_secret = secrets.sender_data_secret,
    .padding_len = 0,
});
defer allocator.free(priv_bytes);
```

**Receiving.** A `PublicMessage` unprotects in one call; a `PrivateMessage`
is genuinely two-phase, because §6.3.2's sender data names the key §6.3.1's
content needs, and the lookup between them is yours:

```zig
var r = mls.codec.Reader.init(received);
const msg = try fr.MLSMessage.decode(allocator, &r);
defer msg.deinit(allocator);

switch (msg) {
    .public_message => {
        // checks BOTH §6.2 MUSTs: membership_tag and the signature
        const pm = try fr.unprotectPublic(S, allocator, bare_bytes, sender_pub, secrets.membership_key, encoded_gc);
        defer pm.deinit(allocator);
        _ = pm.content.body;
    },
    .private_message => |pm| {
        const sd = try fr.decryptSenderData(S, allocator, pm, secrets.sender_data_secret);
        // YOUR job: check sd.leaf_index names a non-blank leaf (§6.3.2),
        // then pick that leaf's handshake/application Window.
        const kn2 = try window.get(sd.generation);
        const plaintext = try fr.decryptContent(S, allocator, pm, kn2, sd.reuse_guard);
        defer allocator.free(plaintext);
        const ac = try fr.parsePrivateContent(allocator, pm, plaintext, sd.leaf_index);
        defer ac.deinit(allocator);
        try fr.verifyFramedContent(S, allocator, sender_pub, ac, encoded_gc);
    },
    .key_package, .welcome, .group_info => {},
}
```

**Transcript hashes** (`transcript.zig`, RFC 9420 §8.2) — what feeds the
next epoch's `GroupContext.confirmed_transcript_hash`:

```zig
const th = try mls.transcript.advance(S, allocator, interim_prev, commit_ac);
th.confirmed;  // -> GroupContext.confirmed_transcript_hash, and the
               //    confirmation_tag's MAC input
th.interim;    // -> the NEXT epoch's interim_prev
// epoch 0 seeds both with the ZERO-LENGTH string, not a zero digest:
// mls.transcript.empty_transcript_hash
```

**Proposal references** (§5.2) — what a Commit puts in a by-reference
`ProposalOrRef`:

```zig
const ref = try fr.proposalRef(S, allocator, proposal_authenticated_content);
```

## API surface (Part 6 — joining a group)

**Joining** (`welcome.zig`, RFC 9420 §12.4.3/§12.4.3.1). One call runs the
whole receiving procedure: find this client's slot, HPKE-open the
`GroupSecrets`, derive `welcome_secret`, decrypt and verify the
`GroupInfo`, enter §8's chain at `joiner_secret`, and check the
`confirmation_tag` against the `confirmation_key` it just derived.

```zig
var r = mls.codec.Reader.init(received_welcome);
const msg = try mls.framing.MLSMessage.decode(allocator, &r);
defer msg.deinit(allocator);

// §5.2 over YOUR encoded KeyPackage — what names your slot in the Welcome
const my_ref = try mls.make_keypackage_ref(S, my_encoded_key_package);

var joined = try mls.welcome.join(S, allocator, .{
    .welcome = msg.welcome,
    .key_package_ref = &my_ref,
    .init_key_pair = my_init_key_pair,      // private half of KeyPackage.init_key
    // §12.4.3: the signature_key of the tree leaf at GroupInfo.signer.
    // Resolving it needs the tree, so it is YOURS to supply.
    .signer_key = signer_leaf_signature_key,
    .psks = &.{},                            // resolved in GroupSecrets order
});
defer joined.deinit(allocator);

joined.secrets;                    // every §8 secret for the epoch
joined.group_info.group_context;   // the signed GroupContext
joined.interim_transcript_hash;    // §8.2, for the NEXT epoch
joined.group_secrets.path_secret;  // §12.4.3.1, if the Commit reset your path
```

**The tree** (§12.4.3.3). A `GroupInfo` may carry the whole ratchet tree in
a `ratchet_tree` extension, or the tree may arrive out of band. Either way
the tree hash is what binds it to the signed `GroupContext`, so check it:

```zig
var t = try joined.group_info.ratchetTree(allocator);  // error.ExtensionNotFound if absent
defer t.deinit();
try mls.welcome.verifyTreeHash(S, allocator, &t, joined.group_info.group_context);
// still YOURS: treekem.validateParentHashes, §7.3 leaf validation,
// finding your own leaf, installing private keys from path_secret.
const external_pub = try joined.group_info.externalPub();  // §12.4.3.2, wire read only
```

**Sending a Welcome.** The two layers are separate calls, because the
committer owns the group state that assembles them:

```zig
const egi = try mls.welcome.encryptGroupInfo(S, allocator, welcome_secret, encoded_group_info);
defer allocator.free(egi);
// NOTE the context argument: the whole `egi` blob, which is what binds
// each per-member ciphertext to this one GroupInfo (§12.4.3.1).
const ct = try mls.welcome.encryptGroupSecrets(S, allocator, io, recipient_init_key, egi, encoded_group_secrets);
```

## API surface (Part 7 — the group state machine)

`Group(S)` is the first type in this module that OWNS state. Everything
else takes bytes and keys and returns bytes and keys; this holds the tree,
the transcript hashes, the epoch secrets and this member's private path
secrets, and advances all of them across a Commit.

```zig
const S = mls.default_suite;
const G = mls.Group(S);

// §12.4.3.1: enter the group. Unlike `welcome.join`, this needs no signer
// key from the caller — it resolves `GroupInfo.signer` out of the ratchet
// tree itself, and verifies the tree hash and the parent-hash chain first.
var g = try G.fromWelcome(allocator, .{
    .welcome_msg = welcome_bytes,          // whole MLSMessage(Welcome)
    .key_package_msg = my_key_package_msg, // whole MLSMessage(KeyPackage)
    .init_priv = init_priv,
    .encryption_priv = encryption_priv,
    .ratchet_tree = null,                  // or §12.4.3.3's out-of-band tree
    .external_psks = &.{},
});
defer g.deinit();

// §12.4.2: follow the group. `proposal_msgs` are the proposals seen during
// the current epoch, so the Commit's by-reference `ProposalOrRef`s can be
// resolved; ones it does not reference are ignored.
try g.processCommit(.{
    .commit_msg = commit_bytes,
    .proposal_msgs = proposals,
    .external_psks = &.{},
});

// The value every other member of the group also holds for this epoch.
const auth = g.epochAuthenticator();
```

Also available: `g.groupContext()` (a no-allocation view for the current
epoch), `g.groupContextAlloc(allocator)` (the encoded form §6.1 and §8
consume), `g.epoch`, `g.my_leaf_index`, `g.treeSize()`, and
`g.policy` (`mls.GroupPolicy` — the two §12.2 rules RFC 9420 defers to "the
application", defaulting ON).

**What it refuses, by name.** `error.PrivateHandshakeNotSupported` — a
Commit or proposal framed as a `PrivateMessage`; driving the §9 secret tree
per epoch is not this object's job. `error.GroupPoisoned` — a previous
`processCommit` failed after the tree was already mutated, so the object is
unusable rather than silently half-applied.

**What it does not do:** CREATE Commits, proposals or Welcomes (there is no
sender half of §7.5 anywhere in this module), join by external Commit
(§12.4.3.2), or apply §7.3/§10.1 admission rules (Part 3) — it checks only
the leaf properties §12.4.2 names in its own bullets.

RFC 9420 §8.3's external initialization lives in `keyschedule.zig`, since it
is a key-schedule entry point rather than group state:

```zig
// The joiner's half (§12.4.3.2 would carry `kem_output` in an ExternalInit).
const ext = try mls.externalInitSender(S, group_external_pub, io);
// The existing members' half.
const init_secret = try mls.externalInitReceiver(S, ext.kem_output, group_external_key_pair);
```

Note its anchoring honestly: no upstream MLS vector covers §8.3, so unlike
every other derivation in `keyschedule.zig` it is pinned by a
sender/receiver round trip plus RFC 9180's own KATs one layer down, not by
a byte-exact interop vector.

## Verify

```sh
zig build test-mls --summary all
zig build test-mls --summary all -Doptimize=ReleaseFast
```

All tests run (the `gate.treekem_core_implemented`-gated TreeKEM
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
Part 4 adds `key-schedule.json` (every stage of a five-epoch chain, each
Table 4 secret, the encoded `GroupContext` in both directions,
`external_pub`, and the exporter), `psk_secret.json` (chains of 0 through
10 PSKs), and `secret-tree.json` (1/8/32-leaf trees, both ratchets of every
leaf at every published generation, driven forward AND out-of-order, plus
§6.3.2's sender-data keys) — all byte-exact.
Part 5 adds `messages.json` (every embedded entry's §12.1 proposal bodies,
§12.4 `Commit`, §10 `KeyPackage` and §6 `MLSMessage` wire formats, decode →
re-encode byte-exact), `message-protection.json` (`PrivateMessage` for all
three content types and `PublicMessage` for the two handshake types,
unprotected AND re-protected byte-exact — stronger than that vector's own
round-trip procedure, see `SPEC.md`; application content as a
`PublicMessage` is checked to be REFUSED, per §6), and
`transcript-hashes.json` (§8.2's two hashes plus the Commit's own
`confirmation_tag`) — all byte-exact.
Part 6 adds `welcome.json` (the whole §12.4.3.1 join with real keys, staged
per layer, plus the vector's own `encrypted_group_info` reproduced in the
SEND direction — stronger than that vector's stated receive-only
procedure) and extends `messages.json` to §12.4.3.1's `Welcome`/
`GroupInfo`/`GroupSecrets` and §12.4.3.3's bare `ratchet_tree`, decode →
re-encode byte-exact. The per-member HPKE layer is round-trip only in the
SEND direction and says so: HPKE draws a fresh ephemeral keypair per
encryption and the vector publishes only the resulting public `kem_output`.
Part 7 adds the three `passive-client-*.json` vectors — whole recorded
sessions from another implementation, replayed Commit by Commit with the
`epoch_authenticator` compared at every step: 8 recorded joins spanning both
§12.4.3.3 tree sources and both PSK cases, 13 two-Commit sessions each
injecting an external PSK, and one session of 200 consecutive Commits that
grows the group until an `UpdatePath` spans seven levels. Each file's
reduction (see `NOTICE`) is guarded by assertions on the coverage it rests
on, so a future re-filter that drops a case fails rather than passing
quietly.
Green in Debug and ReleaseFast.

## Provenance

Clean-room from RFC 9420 (public IETF specification) plus a direct port
of Appendix C's own published reference algorithm (`treemath.zig`). KAT
vectors are official `mlswg/mls-implementations` interop test data. See
`NOTICE` for the exact source commit/fetch date.
