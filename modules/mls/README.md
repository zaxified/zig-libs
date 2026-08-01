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
**Part 8: creating Commits** — the sender half of everything Part 7 could
only receive: §11's group creation, §12.1's proposal creation, §7.4/§7.5's
`UpdatePath` GENERATION (`treekem.stageUpdatePath`/`sealUpdatePath`),
§12.4.1's Commit creation, §12.4.3.1's `Welcome` production, and §10's
`KeyPackage` construction. Anchored where creation can be anchored at all:
an `UpdatePath` generated from a `treekem.json` vector's own
`path_secret[0]` reproduces that vector's node public keys, `commit_secret`
and committer-leaf `parent_hash` byte-exact, and is then opened by every one
of that vector's recorded members — see `SPEC.md`'s "Part 8" section, which
states per test what is anchored and what is a round trip.

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
excluded from the `UpdatePath` resolutions — which Part 8 then found had
been applied one step too far, to §4.1.2's filtered direct path as well.
See `SPEC.md`'s "Part 7".
**Part 8 COMPLETE for regular Commits** (Sonnet-tier) — and building the
SEND half found three problems on the RECEIVE side that 200 replayed
Commits could not reach, because a passive client never generates anything:
a §7.5 MISREADING Part 7 had introduced (applying the same-Commit-Add
exclusion to §4.1.2's filtered direct path and not only to the resolution,
which produces trees that fail §7.9.2's parent-hash validity), a joiner's
path-secret chain that consumed a derivation step at nodes the committer had
filtered out, and a member with no way to adopt the private key of an Update
it had published itself. Every upstream vector passes under either reading
of §7.5, so only creating Commits could expose it. See `SPEC.md`'s
"Part 8".
Part 9 then added §12.4.3.2's external Commits, in both directions. Part 3
(the rest of §7.3/§10.1 VALIDATION + Credential) and §11.2/§11.3
(reinit/branch) remain; see `SPEC.md`'s "Arc breakdown".
What this module can do today: produce and consume real MLS messages other
implementations accept byte-for-byte, CREATE a group, JOIN one from a
`Welcome`, FOLLOW it through Commits — validated against recorded sessions
from another implementation, one of them 200 Commits long — and now SPEAK:
create proposals, create Commits with a full `UpdatePath`, and produce the
`Welcome` and `GroupInfo` that go with them. A two-way client is complete.
Both ways INTO a group are built: by invitation (§12.4.3.1's `Welcome`) and
by §12.4.3.2's external Commit, which needs nobody already inside to be
online.
What it cannot: send or accept `PrivateMessage` handshakes, follow through
on a `ReInit` (§11.2) or branch (§11.3), or apply the §10.1/§7.3
admission rules that need a clock, a credential authority or an extension
registry — the two §7.3 rules that need only the leaf and the tree ARE
applied, in both directions.

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
| `treekem.zig` | Part 2's `HPKECiphertext`/`UpdatePathNode`/`UpdatePath` (§7.6) + the five Fable cores (`resolution`/`parentHash`/`validateParentHashes`/`processUpdatePath`/`applyUpdatePath`), implemented and KAT-pinned — plus Part 8's SENDER half of §7.5 (`stageUpdatePath`/`sealUpdatePath`) |
| `gate.zig` | Part 2's `treekem_core_implemented` switch — now `true` (the five cores are implemented; the gated TreeKEM KATs run) |
| `kat_treekem_test.zig` | Part 2's official RFC 9420 interop vectors (`tree-validation.json`/`tree-operations.json`/`treekem.json`), driven byte-exact against the five cores |
| `keyschedule.zig` | Part 4's §8 epoch chain (`joinerSecret`/`welcomeSecret`/`epochSecret`/`deriveEpoch`), §8.1 `GroupContext`, §8.4 `PreSharedKeyId`/`pskSecret`, §8.5 `mlsExporter`, `externalKeyPair`, §6.1 `confirmationTag`/`membershipTag` (+ constant-time verifiers) |
| `secrettree.zig` | Part 4's §9 secret tree (`nodeSecret`/`ratchetBaseSecret`), §9.1 `Ratchet` + the generation-indexed out-of-order `Window`, §6.3.2 `senderDataKeys` |
| `kat_keyschedule_test.zig` | Part 4's official interop vectors `key-schedule.json` + `psk_secret.json`, driven per-stage byte-exact |
| `kat_secrettree_test.zig` | Part 4's official `secret-tree.json`, driven byte-exact both forward (`Ratchet`) and out-of-order (`Window`) |
| `keypackage.zig` | Part 5's §10 `KeyPackage`/`KeyPackageTBS` WIRE FORMAT + self-signature (`verifySignature`/`sign`), plus Part 8's `create` (assemble and sign one). §10.1's validation rules are Part 3's and are NOT here |
| `content.zig` | Part 5's §12.1 `Proposal` (all seven types) + §12.4 `Commit`/`ProposalOrRef` — wire shape only; no proposal-list validity, no commit processing |
| `framing.zig` | Part 5's whole of §6: `Sender`/`FramedContent`/`AuthenticatedContent`, §6.1 sign+verify, §6.2 `PublicMessage` + `protectPublic`/`unprotectPublic`, §6.3 `PrivateMessage` + `protectPrivate`/`decryptSenderData`/`decryptContent`/`parsePrivateContent`, `MLSMessage` |
| `transcript.zig` | Part 5's §8.2 `confirmedTranscriptHash`/`interimTranscriptHash`/`advance` — the gap Part 4 named and could not fill |
| `kat_messages_test.zig` | Parts 5+6's official `messages.json`, every embedded field decode→re-encode byte-exact (including §12.4.3.1's `Welcome`/`GroupInfo`/`GroupSecrets` and §12.4.3.3's bare `ratchet_tree`) |
| `kat_framing_test.zig` | Part 5's official `message-protection.json` (protect/unprotect byte-exact both directions) + `transcript-hashes.json` (§8.2) |
| `welcome.zig` | Part 6's §12.4.3 `GroupInfo` (+ `sign`/`verifySignature`), §12.4.3.1 `GroupSecrets`/`EncryptedGroupSecrets`/`Welcome`, `welcomeKeyNonce`/`encryptGroupInfo`/`decryptGroupInfo`, `encryptGroupSecrets`/`decryptGroupSecrets`, `join`, and §12.4.3.3's `ratchetTree`/`externalPub`/`verifyTreeHash` |
| `kat_welcome_test.zig` | Part 6's official `welcome.json`, the whole join staged per layer — plus the vector's `encrypted_group_info` reproduced in the SEND direction |
| `group.zig` | Part 7's `Group(S)` — the group STATE plus the receiving half of an epoch transition: `fromWelcome` (§12.4.3.1 run to completion), `processCommit` (§12.2 validation, §12.3 ordering, §12.4.2's whole procedure), `epochAuthenticator`/`groupContext`, and §8.4 PSK resolution — plus Part 8's SENDING half on the same object: `create` (§11), `createProposal`/`updateLeaf` (§12.1), `createCommit` (§12.4.1, which also builds the §12.4.3.1 `Welcome` and a signed `GroupInfo`) |
| `kat_passive_test.zig` | Part 7's official `passive-client-welcome`/`-handling-commit`/`-random` vectors — recorded sessions replayed Commit by Commit against `epoch_authenticator`, plus the assertions guarding each file's reduction |
| `kat_commit_test.zig` | Part 8's harness: an `UpdatePath` GENERATED from `treekem.json`'s own recorded `path_secret[0]`, compared byte-exact against that vector and then opened by its recorded members; plus Commits created on group states restored from the `passive-client-*` sessions |

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

`error.RemovedFromGroup` is the one that is not a refusal: the Commit is
valid and it removes THIS client. §12.4.2's closing note asks a removed
member to stop sending and to "promptly delete its group state and secret
tree" — not to advance an epoch, which it could not do in any case, since
no `UpdatePath` ciphertext is addressed to the leaf §12.3 just blanked. The
group is left at the previous epoch and unpoisoned, so the same note's "keep
the secret tree for a short time to decrypt late messages" stays open to the
caller; `deinit` is the caller's to call, and should be soon.

**What it does not do:** send or accept `PrivateMessage` handshakes, follow
through on a `ReInit` (§11.2) or branch (§11.3), or apply the §7.3/§10.1
admission rules that
need a clock, a credential authority or an extension registry (Part 3) — the
two that need only the leaf and the tree are applied, see
`mls.GroupPolicy`.

## API surface (Part 8 — speaking)

The sender half lives on the same `Group(S)`, because a committer has to
land in the state its receivers land in.

```zig
// §10: publish a KeyPackage. Keep all three private halves — the init and
// encryption keys are what `fromWelcome` later needs, and the signature
// key signs everything this client ever sends.
const kp = try mls.createKeyPackage(S, arena, .{
    .signature_key_pair = sig_kp,
    .init_key = init_kp.public_key,
    .encryption_key = enc_kp.public_key,
    .credential = .{ .basic = "alice" },
    .capabilities = caps,
    .lifetime = .{ .not_before = not_before, .not_after = not_after },
});
const kp_msg = try (mls.MLSMessage{ .key_package = kp }).encodeAlloc(arena);

// §11: create a one-member group. `io` supplies the single random value
// §11 calls for; §8.2's epoch-0 confirmed transcript hash is the
// ZERO-LENGTH string, which this object represents exactly.
var g = try G.create(allocator, .{
    .io = io,
    .group_id = group_id,
    .key_package_msg = kp_msg,
    .encryption_priv = enc_kp.secret_key,
});
defer g.deinit();

// §12.1: publish a proposal. Nothing is applied — a proposal only takes
// effect through a Commit, so KEEP these bytes: they are what the
// committer passes as `.by_reference` and what receivers pass as
// `proposal_msgs`.
const prop = try g.createProposal(allocator, .{
    .signature_key_pair = sig_kp,
    .proposal = .{ .add = their_key_package },
});

// §12.4.1: commit. Order in `proposals` is observable (§12.1.1 places Adds
// at successive blank leaves in list order; §8.4's PSK chain is
// position-dependent); §12.3's APPLICATION order is fixed and unrelated.
const c = try g.createCommit(allocator, .{
    .io = io,
    .signature_key_pair = sig_kp,
    .proposals = &.{
        .{ .by_value = .{ .add = their_key_package } },
        .{ .by_reference = someone_elses_proposal_msg },
    },
    .external_psks = psks,
});
defer c.deinit(allocator);
// c.commit      -> MLSMessage(PublicMessage), send to every member
// c.welcome     -> MLSMessage(Welcome) for the members this Commit added
// c.group_info  -> MLSMessage(GroupInfo) for the DS to cache (external joins)
// ...and `g` has ALREADY advanced into the epoch it just created.
```

To rotate this member's own leaf key without committing, build the Update's
`LeafNode` with `g.updateLeaf(.{ .signature_key_pair = ..., .encryption_key_pair = ... })`
and send it as a proposal: the group retains the private half and swaps it
in when whichever Commit applies that Update arrives, which it must, because
§12.3 applies Updates before the `UpdatePath` is decrypted.

`createCommit` populates the path by default (§12.4: "By default, the path
field of a Commit MUST be populated"). `omit_path_when_allowed = true` asks
for §12.4's "partial" Commit — honoured only when the list covers at least
one proposal and none of them is a path-required type.

**What it refuses:** the same `error.GroupPoisoned` contract as
`processCommit` — but every §12.2 refusal and every Add's KeyPackage
signature check happens BEFORE the tree is touched, so a rejected proposal
list leaves the group usable.

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

## API surface (Part 9 — joining without an invitation)

RFC 9420 §12.4.3.2. A newcomer with nothing but a published `GroupInfo`
adds *itself* to the group — no existing member has to be online, and
nobody issues an Add on its behalf. The `GroupInfo` must carry an
`external_pub` extension, which is what `createCommit`'s
`include_external_pub = true` puts there, and it is good for exactly one
external join because that join changes the epoch.

```zig
var joined = try mls.Group(S).joinByExternalCommit(gpa, allocator, .{
    .io = io,
    .group_info_msg = published_group_info,   // MLSMessage(GroupInfo), public
    .key_package_msg = my_key_package_msg,    // identity half of my new leaf
    .signature_key_pair = my_sig,
    // §12.2's whitelist also admits a Remove (the "resync" flavor: drop an
    // old appearance of myself) and PreSharedKeys. Nothing else.
    .proposals = &.{},
});
defer joined.group.deinit();
defer joined.messages.deinit(allocator);
// joined.group is already IN the new epoch.
// joined.messages.commit goes to every member; .welcome is always null.
```

Existing members feed those bytes to the same `processCommit` they use for
any other Commit — the `new_member_commit` sender type is handled inside.

```zig
try alice.processCommit(.{ .commit_msg = joined.messages.commit });
// alice.epochAuthenticator() == joined.group.epochAuthenticator()
```

**What the joiner can and cannot check.** It verifies the tree against the
signed `tree_hash`, the parent-hash chain and the `GroupInfo` signature. It
cannot verify the `GroupInfo`'s `confirmation_tag` — that needs the epoch's
`confirmation_key`, which is exactly what a non-member lacks. A forged tag
is not absorbed silently: it changes the joiner's transcript, so every
member rejects the resulting Commit and the joiner ends up in an epoch of
one rather than in the group holding state nobody else holds.

**What it refuses, by name.** `error.ExternalPubUnavailable` — the
`GroupInfo` carries no `external_pub`, so §8.3 has nothing to encapsulate
to. `error.MissingExternalInit` / `MultipleExternalInit` /
`MultipleRemoveInExternalCommit` / `ProposalNotAllowedInExternalCommit` /
`ProposalByReferenceInExternalCommit` — §12.2's whitelist and §12.4.3.2's
by-reference ban, enforced by BOTH the sender and every receiver.
`error.UnexpectedMembershipTag` / `ExternalCommitRequiresPath` — §6.2 and
§12.4.3.2's framing requirements.

**Anchoring, stated honestly.** There is no upstream external-commit test
vector, so this is round-trip-anchored: what makes the round trip worth
something is that the two directions meet at an `epoch_authenticator`
neither of them transports, having reached it by opposite halves of §8.3
and via a leaf index that appears nowhere on the wire. See `SPEC.md`'s
"Part 9".

**Resumption PSKs in an external join.** A group entered this way has no
epoch history, so `ExternalJoinParams.resumption_psks` is how the caller
hands in prior-epoch `resumption_psk` values it kept out of band — the
resync case, where this client was in this group before. The library checks
the width (`KDF.Nh`) and that a `PreSharedKeyID` resolves only against an
entry naming the same `usage`, `psk_group_id` and `psk_epoch`; it cannot
check that the value is genuine, and a wrong one costs a failed join rather
than a compromised group, because every member resolves the same id from its
own history and rejects the Commit. Without the list, a resumption
`PreSharedKeyID` is still `error.PskNotAvailable`.

Note that §12.4.3.2's suggestion to gate the resync flavor on a `reinit` PSK
proposal cannot be followed literally — §12.1.4 and §11.2 make that proposal
invalid outside a reinitialization, and this module rejects it
(`error.ResumptionPskUsageNotAllowed`). Use usage `application`; it
demonstrates presence in a prior epoch identically. See `SPEC.md`'s "Part 9".

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
Part 8 drives `treekem.json` in the SEND direction as well: a generation
seeded from each update path's own recorded `path_secret[0]` reproduces that
vector's node public keys, its `commit_secret` and its committer-leaf
`parent_hash` byte-exact, and the `UpdatePath` it then seals is opened by
every one of that vector's recorded members with their recorded private
keys, landing on the recorded plaintexts. A negative control drives the same
generation from a path secret one bit off and requires every anchored field
to differ. Beyond that, creation is round-trip tested against this module's
own (externally anchored) receive path — including Commits created on group
states restored from the `passive-client-*` sessions, the 200-Commit one
included. `SPEC.md`'s "Part 8" states which is which per test.
Green in Debug and ReleaseFast.

## Provenance

Clean-room from RFC 9420 (public IETF specification) plus a direct port
of Appendix C's own published reference algorithm (`treemath.zig`). KAT
vectors are official `mlswg/mls-implementations` interop test data. See
`NOTICE` for the exact source commit/fetch date.
