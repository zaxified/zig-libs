# mls — SPEC

See `README.md` for the consumer-facing API summary and Provenance note.

## What this is, in one paragraph

RFC 9420 Messaging Layer Security: a scalable-group-messaging protocol
built around TreeKEM (a ratchet tree of HPKE keypairs, one per group
member, that lets the whole group agree on a shared epoch secret in
O(log n) messages per membership change instead of Signal-style pairwise
sessions). This module (`mls`) is a multi-part arc; **Part 1** builds only
the FOUNDATION every later part needs: the mandatory cipher suite
(`suite.zig`), the seven labeled-crypto primitives RFC 9420 §5/§8/§9.1
define (`crypto.zig`), the ratchet tree's pure integer math
(`treemath.zig`), and the TLS-presentation-language wire codec
(`codec.zig`). Part 1 deliberately builds NO group state, NO TreeKEM
key-derivation-along-a-path, NO KeyPackage/Proposal/Commit message types,
and NO key schedule — those are later parts (see "Arc breakdown" below).
**Part 2** (TreeKEM) and **Part 4** (key schedule + secret tree) have since
landed; between them the module now covers the whole cryptographic spine of
an epoch — given a ratchet tree and a transcript, every key the epoch uses
is derivable and interop-verified. What is still missing before a client
can send or receive anything is Part 3's `KeyPackage` and Part 5's
Proposal/Commit/framing.

## Design & invariants

**`codec.zig`'s ONE deviation from plain RFC 8446 is load-bearing for the
whole arc.** RFC 9420 §2.1 states it uses the TLS presentation language
verbatim except for vector length headers: instead of a fixed `uint8`/
`uint16`/`uint32` length prefix sized by declared min/max
(`opaque foo<0..255>`), MLS uses a QUIC-style variable-length integer
(§2.1.2, borrowed from RFC 9000 §16, with RFC 9420 additionally requiring
— matching RFC 9000's own requirement — the encoder to always use the
SMALLEST prefix that fits). Every later part's KeyPackage/LeafNode/
Proposal/Commit/framing wire formats are `opaque foo<V>`-shaped, so
`codec.Writer`/`Reader` getting this byte-exact here is a correctness
precondition for everything downstream, not just this part's own use of
it (`crypto.zig`'s `KDFLabel`/`SignContent`/`EncryptContext` framing).
Verified against RFC 9420 §2.1.2's own three worked examples
(`0x9d7f3e7d` → 494878333, `0x7bbd` → 15293, `0x25` → 37) plus explicit
non-minimal-encoding and truncated-input rejection tests.

**Two label-framing systems that look similar but are NOT the same
construction.** `hpke.suite.labeledExtract`/`labeledExpand` (RFC 9180 §4)
prepend `"HPKE-v1" || suite_id` to every derivation; MLS's `KDFLabel`/
`SignContent`/`EncryptContext` (RFC 9420 §8/§5.1.2/§5.1.3) prepend
nothing of the sort — they're MLS's own wire structs (`length ||
opaque label<V> || opaque context<V>`, etc.), assembled via
`codec.Writer` and fed DIRECTLY into `KDF.Expand`/the signature scheme.
`crypto.zig`'s `ExpandWithLabel`/`DeriveSecret`/`SignWithLabel`/
`VerifyWithLabel` never call into `hpke.suite`'s labeling at all — only
`EncryptWithLabel`/`DecryptWithLabel` hand off to `hpke` wholesale (RFC
9420 §5.1.3 literally says "SealBase and OpenBase are defined in Section
6.1 of [RFC9180]"), and even then MLS's `EncryptContext` framing becomes
HPKE's `info` parameter — HPKE then applies ITS OWN "HPKE-v1"+suite_id
labeling around that on top. The two layers compose; verifying this
required tracing RFC 9420 §5.1.3's definition against RFC 9180 §6.1's
`SealBase`/`OpenBase` signatures by hand (both take `info` as an opaque
byte string, so MLS's pre-encoded `EncryptContext` slots in exactly
where HPKE expects a caller-supplied `info`).

**`RefHash` streams; `ExpandWithLabel`/`SignWithLabel`/`EncryptWithLabel`
assemble a bounded scratch buffer (implementation detail, not a spec
requirement) — same asymmetry `hpke.suite.labeledExtract`/
`labeledExpand` already has, for the identical reason.** `RefHash`'s
`value` argument is an entire encoded `KeyPackage`/`AuthenticatedContent`
in real use with no realistic upper bound, so it hashes incrementally
(`Hash.update` per varint-prefixed field) and needs no buffer at all. The
other five functions each need ONE CONTIGUOUS byte slice to hand to
`Hkdf.expand`/`Ed25519.sign`/HPKE's `info` (all three re-process their
input as a whole, not incrementally), so they assemble their
`KDFLabel`/`SignContent`/`EncryptContext` into a fixed 512-byte
`label_scratch_len` stack buffer (matching `hpke.suite.labeledExpand`'s
own 512-byte constant) and return `error.LabelTooLong` rather than
silently truncating or panicking on overflow. Every label/context/content
this Part or the KAT vectors use is a handful to a few dozen bytes, so
512 is comfortable headroom; a LATER part deriving a secret from a
multi-kilobyte `GroupContext` (with extensions) may need a larger bound
or a caller-supplied scratch slice instead — tracked below in Backlog,
not a gap for anything this Part actually exercises.

**`treemath.zig` returns `null`, never panics, where the RFC's own Python
raises an exception.** RFC 9420 Appendix C's reference `left`/`right`
raise on a leaf node, `parent`/`sibling` raise on the root — this port
returns `?usize` at exactly those points instead, because a later part
calls these with node indices that arrive over the wire (an
attacker-controlled tree size or index is untrusted input, and a panic on
untrusted input is a denial-of-service bug this repo's fuzz-safety
convention forbids). `direct_path`/`copath` take a caller-supplied `out:
[]usize` buffer and return `error.BufferTooShort` rather than allocating
or assuming a bound — `max_path_len = 64` is published as the safe size
for any tree this module can index (`usize` node indices already cap
`n_leaves` well below any tree Appendix C's algorithm would need a
deeper-than-64 path for).

**Ed25519 signing is deterministic (RFC 8032) — `SignWithLabel` calls
`std.crypto.sign.Ed25519.KeyPair.sign(msg, null)` with `noise = null`,
never hedged/randomized signing.** This is a stronger-than-required KAT
property the vector format doesn't ask for explicitly (the task brief
expected only a verify-round-trip, appropriate for a RANDOMIZED scheme
like ECDSA) — because Ed25519 is deterministic, `kat_test.zig` re-signs
the vector's own `(priv, label, content)` and checks the produced
signature is byte-IDENTICAL to the vector's published `signature` field,
which is a strictly stronger check than "verifies successfully" (a buggy
sign that happened to produce a different-but-still-valid signature would
pass a verify-only check but fail this one).

## Arc breakdown (Part 1 done; later parts, tier-tagged)

Honest tiering per the task brief: this Part is **100% Sonnet** —
mechanical composition (wire encoding, HKDF/Ed25519/HPKE calls exactly as
specified, integer-arithmetic tree math ported from the RFC's own
pseudocode) with an authoritative byte-exact conformance oracle (the
official interop vectors) for every function. Nothing here required a
novel security-property judgment call the way, say, TreeKEM's
parent-hash validation logic does (see Part 2 below).

| Part | Scope | Tier | RFC-vector components |
|---|---|---|---|
| **1 (this part)** | Cipher suite, labeled crypto, tree math, codec | **Sonnet** | `tree-math.json`, `crypto-basics.json` |
| **2 — TreeKEM** | `LeafNode`/`ParentNode`/`Node`/`RatchetTree` + wire codec + tree-shape edits (§7.1/§7.2/§7.7/§12.1.1-3) + tree-hash (§7.8) — Sonnet, DONE. `resolution` (§4.1), `parentHash`+chain validation (§7.9), path-secret-derivation-and-UpdatePath (§7.4-§7.6) — **IMPLEMENTED + KAT-pinned 2026-07-16, Fable**. Whole part **COMPLETE**. | Split tier: the data/codec/tree-hash/tree-editing is mechanical (Sonnet, KAT'd byte-exact); the five cores are the genuinely hard piece the task brief flags — subtle recursive tree-validation logic with real security consequences if wrong (a forged parent-hash or a wrong resolution set can let a malicious member inject an unauthorized key into another member's derived path) — the "hardest TIER, not crypto-only" bar this repo's Fable pool applies, now pinned byte-exact | `tree-operations.json` (real), `tree-validation.json` (tree-hash/leaf-signature + resolution + parent-hash accept/tamper), `treekem.json` (`processUpdatePath` + `applyUpdatePath`) — all byte-exact, gate now `true`; see "Part 2 — TreeKEM" below |
| **3 — LeafNode / KeyPackage / Credential** | §5.3 credentials, §7.2/§7.3 `LeafNode` content + validation (`leaf_node_validation.json`), `KeyPackage` (§10) wire format + validation | **Sonnet** — mostly `codec.zig`-shaped serialization plus signature verification (`SignWithLabel`/`VerifyWithLabel` from THIS part) over well-specified structs; the validation RULES (§7.3's numbered list) are mechanical checks, not novel crypto | `key-package-validation.json`, `leaf-node-validation.json` |
| **4 — Key Schedule + Secret Tree** | §8's full `init_secret_[n-1] → ... → init_secret_[n]` chain, §8.1 `GroupContext`, §8.4 `psk_secret`, §8.5 exporter, §6.1's two MACs, §9 Secret Tree + sender ratchets, §6.3.2 sender-data keys — **DONE 2026-07-28**, whole part **COMPLETE** except §8.2 (transcript hashes, needs Part 5) and §8.3 (external init, needs Part 6) | **Sonnet** — pure composition of `ExpandWithLabel`/`DeriveSecret` (already built) over a well-specified derivation graph. One correction to the original note below: Figure 22 pins the ORDER unambiguously, but Figure 24 (§8.4's PSK chain) does NOT — it contradicts its own prose on the Extract argument order, and only the vector settles it | `key-schedule.json`, `secret-tree.json`, `psk_secret.json` — all byte-exact; see "Part 4" below |
| **5 — Proposal / Commit / framing** | §11-§12 Proposal types, Commit processing, `PublicMessage`/`PrivateMessage` framing + the membership/confirmation MACs | **Sonnet** — mechanical message-type composition over Parts 1-4's primitives, EXCEPT the Commit-processing state machine's interaction with TreeKEM (applying a Commit's proposals correctly against the ratchet tree) which leans on Part 2's resolution logic being right | `messages.json`, `commit-processing` vectors |
| **6 — External Commit / PSK / Reinit / Sub-group ops** | §12.4.3 external Commit, §8's `psk_secret` injection (§13), §16's reinit/branch | **Sonnet**, lowest priority — genuinely-used-but-optional MLS features; defer until a real consumer needs them (this repo's std/dedup consumer-check convention) | — |

**Where TreeKEM/Fable lands, restated plainly:** it's Part 2, specifically
the path-secret-derivation-along-the-copath + parent-hash-chain
validation logic — NOT the crypto primitives (HPKE seal/open is already
done, here, via `EncryptWithLabel`/`DecryptWithLabel`; HKDF derivation is
already done, via `ExpandWithLabel`/`DeriveTreeSecret`) but the TREE
ALGORITHM binding them together correctly under adversarial tree state
(a malicious member's LeafNode, a stale/forked view of the tree, a
resolution set computed over unmerged leaves). This matches the task
brief's own expectation exactly.

## Part 2 — TreeKEM (2026-07-16)

**Files:** `tree.zig` (`LeafNode`/`ParentNode`/`Node`/`RatchetTree`, wire
codec, leaf-signature verification, `addLeaf`/`updateLeaf`/`removeLeaf`),
`treehash.zig` (`treeHash`/`rootHash`), `treekem.zig` (`HPKECiphertext`/
`UpdatePathNode`/`UpdatePath` wire structs, plus the five now-implemented
cores `resolution`/`parentHash`/`validateParentHashes`/
`processUpdatePath`/`applyUpdatePath`), `gate.zig`
(`treekem_core_implemented = true`), `wire_lists.zig`
(shared variable-length-vector encode/decode helpers, factored out of
`tree.zig` so `treekem.zig`'s `UpdatePathNode`/`UpdatePath` reuse the
same shape), `kat_treekem_test.zig` (the KAT harness).

**Design choice: allocator-owned, unlike Part 1.** `codec.zig`'s
`Writer`/`Reader` are zero-allocation (Part 1's primitives are fixed-size
or caller-bounded). A `RatchetTree` is inherently a dynamic collection —
member count varies at runtime — so `tree.zig`'s `decode` functions take
an allocator and own their sub-slices, the same convention the sibling
`ssh` module's `messages.readString`/`readNameList(gpa, r)` already
established for this repo. `encodedLen()`/`encode()` pairs (mirroring
`codec.varint.encodedLen`/`.encode`) let every struct size its own
destination buffer by pure arithmetic — no scratch buffer, no growable
writer — since every field bottoms out in an already-in-memory byte slice
or fixed-width int (`wire_lists.zig`'s module doc comment).

**`treeHash` (§7.8) implemented for real, not stubbed** — the task brief
explicitly left this as a judgment call ("prefer implementing it, it's not
the hard part"), and it is indeed mechanical recursive hashing over
already-real `LeafNode`/`ParentNode` encodings, with no adversarial-tree-
state judgment call the way VALIDATING a tree (`treekem.zig`'s stubs)
needs. Byte-exact against all 14 suite-`0x0001` entries of
`tree-validation.json`'s `tree_hashes` field, every node index (300+
checks), ungated.

**Tree-shape editing (`addLeaf`/`updateLeaf`/`removeLeaf`, §7.7/
§12.1.1-§12.1.3) implemented for real, not stubbed** — also a deliberate
judgment call: applying an Add/Update/Remove PROPOSAL to a tree (find-or-
extend a blank leaf; blank a direct path; truncate a now-empty right
subtree) is mechanical index bookkeeping built on `treemath.zig`'s
already-real `direct_path`, with no resolution/parent-hash ALGORITHM
involved — distinct from the four Fable cores (which are specifically
about which KEYS a path secret gets encrypted to and how a key's
provenance is cryptographically proven, not about which array slots move
where). Byte-exact against all 5 suite-`0x0001` entries of
`tree-operations.json` (`tree_hash_before`/`tree_after` bytes/
`tree_hash_after`, all three fields checked, ungated).

One real bug this KAT caught during scaffolding: `removeLeaf`'s
truncation loop originally sliced the tree's right subtree at
`nodes[left_idx+1..]`, confusing the LEFT CHILD's array index
(`treemath.left(root)` — the root of the left subtree, sitting in the
MIDDLE of that subtree's own index span) with the left subtree's
BOUNDARY (`2*left_idx+1` — see `tree.zig`'s `removeLeaf` doc comment for
the derivation). `tree-operations.json`'s one `remove` vector whose
truncation crosses more than one tree-size halving (16 leaves → 8 leaves)
caught this immediately (`tree_hash_after` mismatched even though the
byte-trimmed `tree_after` output happened to still match, since Part 1's
`encode`'s OWN trailing-blank-trim independently arrived at the same
final byte count) — exactly the kind of bug a byte-exact KAT is supposed
to catch that a "does it look right" review would not.

**KAT sourcing.** `mlswg/mls-implementations`, same repo/license posture
as Part 1's `NOTICE` entry documents (no explicit OSS license, public
interop conformance DATA not copyrightable expression). Fetched
2026-07-16 from `main` (repo HEAD `cfd450286d1bfd9cd2519b95c80f9771f94a5b1a`,
same commit Part 1 cites — the repo hadn't moved). Per-file last-modified
commits: `tree-validation.json` → `9ea691fee9464aaeee9eadf9757963f1be88f5dd`
(2023-02-20), `tree-operations.json` → `89134d5de0222bd99598ba5849003d2e85e63116`
(2025-11-30), `treekem.json` → `112c2d3960a558663280a1bbb18258766fea9d0d`
(2023-03-01). **Filtered to cipher suite `0x0001` BEFORE embedding**
(unlike Part 1's `crypto-basics.json`, embedded verbatim and filtered at
test-time) — the unfiltered files are 1.3 MB/51 KB/1.97 MB (7 cipher
suites); filtering to suite `0x0001` alone (this module's only wired
suite) shrinks them to 115 KB/49 KB/164 KB (14/5/11 entries respectively)
before `@embedFile`, avoiding a 3.4 MB `@embedFile` + `std.json` parse of
mostly-irrelevant-suite data on every test run. Filtered with `jq -c
'[.[] | select(.cipher_suite==1)]'`, entry ORDER within each file
preserved from upstream.

**What's gated vs. real, and why:**

- `tree-validation.json`: tree-hash (all node indices) and leaf-signature
  verification (all 161 suite-`0x0001` leaves across the 14 trees) —
  REAL, ungated, byte-exact/verify-exact. `resolution`/
  `validateParentHashes` checks — GATED (need the Fable cores).
- `tree-operations.json`: the WHOLE vector (Add/Update/Remove application
  + resulting tree bytes + both tree hashes) — REAL, ungated (see above).
  Uses a MINIMAL test-local `Proposal`/`KeyPackage` parser
  (`kat_treekem_test.zig`'s `applyProposal`/`LocalProposalType`) rather
  than a public `tree.zig` API — full `KeyPackage`/`Proposal` types are
  Part 3/5's job per the Arc breakdown table above; this Part only needs
  to pull a `LeafNode`/leaf-index out of the wire bytes to drive
  `RatchetTree.addLeaf`/`updateLeaf`/`removeLeaf`.
- `treekem.json`: driven in full behind the (now-`true`) gate — THE vector
  that proves the path-secret+resolution+UpdatePath logic. `processUpdatePath`
  reproduces each update path's `commit_secret` + first path secret across
  all 62 update paths / 328 receiver views (under the provisional
  GroupContext, `tree_hash = tree_hash_after`), and `applyUpdatePath`
  merges each of the 62 to reproduce `tree_hash_after` — all byte-exact.
  The gated tests followed this repo's `bn254`/`df-elect`/`pping` gate-flag
  precedent while stubbed; the gate is now flipped and they run.

**The five cores** (`treekem.zig`), each with its own rich doc-contract
citing exact RFC §-refs and wire facts — see that file directly rather
than duplicating the contracts here (SPEC.md's non-overlap rule,
`CONVENTIONS.md` §5):

- `resolution(allocator, tree, index) Error![]usize` — §4.1.
- `parentHash(comptime S, allocator, tree, index) Error![S.Hash.digest_length]u8` — §7.9.
- `validateParentHashes(comptime S, allocator, tree) Error!void` — §7.9.2.
- `processUpdatePath(comptime S, allocator, tree, receiver: PrivateLeafState, sender_leaf_index, update_path, group_context) Error!ProcessedUpdatePath` — §7.4/§7.5/§7.6 (receiver side; yields `commit_secret`).
- `applyUpdatePath(allocator, tree, sender_leaf_index, update_path) Error!void` — §7.5 (public-side merge).

`group_context` is accepted as ALREADY-ENCODED bytes rather than a typed
`GroupContext` — that type is Part 4's (Key Schedule) job per the Arc
breakdown table; Part 2 doesn't build it just to pass a parameter through.

## Part 4 — Key Schedule + Secret Tree (2026-07-28)

**Files:** `keyschedule.zig` (RFC 9420 §8's epoch chain, §8.1's
`GroupContext`, §8.4's `PreSharedKeyID`/`PSKLabel`/`psk_secret`, §8.5's
`MLS-Exporter`, `external_pub`, and §6.1's `confirmation_tag`/
`membership_tag`), `secrettree.zig` (§9's secret tree, §9.1's sender
ratchets and the out-of-order `Window`, §6.3.2's sender-data key/nonce),
`kat_keyschedule_test.zig`, `kat_secrettree_test.zig`. Two small additions
to Part 1's files were needed and are described below.

### What it is verified against

| Vector | Drives | Checked |
|---|---|---|
| `key-schedule.json` | `GroupContext.encode`/`decode`, `joinerSecret`, `welcomeSecret`, `epochSecret`, `deriveEpoch`, `externalKeyPair`, `mlsExporter` | Every stage of a five-epoch chain, per stage and per Table 4 row, byte-exact — including the encoded `GroupContext` itself, in both directions |
| `psk_secret.json` | `PreSharedKeyId.encode`, `PskLabel`, `pskSecret` | Chains of 0 through 10 PSKs, byte-exact, including the empty-list case (§8.4's all-zero `psk_secret_[0]`) |
| `secret-tree.json` | `nodeSecret`, `ratchetBaseSecret`, `Ratchet`, `Window`, `senderDataKeys` | 1/8/32-leaf trees; every named generation of both ratchets of every leaf, byte-exact, driven twice (forward through `Ratchet`, in reverse through `Window`) |

Every vector matched on the first run — no stage needed adjusting, and no
vector was edited. The harness's teeth were then confirmed the only way
that means anything: one byte was flipped in each of the three files
(`key-schedule.json`'s epoch-0 `joiner_secret`, `secret-tree.json`'s leaf-0
generation-0 `application_key`, `psk_secret.json`'s one-PSK `psk_secret`)
and each produced a failure naming that exact stage; the files were then
restored and re-verified by SHA-256 against the fetched originals (hashes
recorded in `NOTICE`).

### The one genuine ambiguity in §8, and how it was resolved

RFC 9420 §8.4 specifies the PSK chain's second Extract twice, and the two
specifications disagree:

- the **prose** says `psk_secret_[i] = KDF.Extract(psk_input_[i-1],
  psk_secret_[i-1])` — i.e. salt = `psk_input`, IKM = `psk_secret`;
- **Figure 24** draws `psk_secret_[i-1]` entering that Extract from the
  TOP, and §8's own figure legend states that the top argument is the salt
  — i.e. the opposite assignment.

`pskSecret` follows the prose. This is not a coin flip: the alternative was
implemented and run, and `psk_secret.json` rejects it (the `psk_secret`
stage diverges while every other stage still passes). Recorded here because
the next reader of Figure 24 will have the same doubt.

Note that the KAT is what makes this decidable at all — both readings
produce well-distributed output, and no round-trip or self-consistency test
could tell them apart.

### Changes to Part 1's files

- **`crypto.kdfLabelLen` + `crypto.ExpandWithLabelScratch`** (new). Part 1's
  Backlog predicted that a `GroupContext` with extensions would outgrow
  `ExpandWithLabel`'s fixed 512-byte scratch, and the key schedule is that
  consumer: it feeds an encoded `GroupContext` in as `Context` twice per
  epoch. Rather than widening the constant to some new arbitrary number,
  the caller can now size the scratch exactly. `ExpandWithLabel` is
  unchanged for everyone else — it simply delegates. This closes that
  Backlog item.
- **`suite.CipherSuite.Mac` / `.Nm`** (new). RFC 9420 §17.1's text under
  Table 7: the non-GREASE suites use HMAC with the suite's hash as their
  MAC. Derived from `Hash`, never independently declared, so a suite's
  `confirmation_tag` can't drift from its transcript hash.

### The out-of-order window is policy, not spec

§9.2 says only that members "MAY keep unconsumed values around for some
reasonable amount of time". `secrettree.Window` makes that concrete with
two limits that exist for security rather than memory, and are exposed as
parameters rather than buried:

- **consume-once**: `get` erases the key/nonce it returns, so a replayed
  message fails `error.GenerationConsumed` instead of decrypting twice;
- **bounded forward jump** (`max_forward_jump`, default 1024): the
  generation is an unauthenticated `uint32` read off the wire, so an
  unbounded ratchet-forward would let four bytes buy four billion KDF
  invocations.

Capacity is a compile-time parameter and the ring is fixed-size — no
allocator, so retained-key memory is a constant the caller can reason about
rather than attacker-driven growth.

### Scope boundary, stated precisely

Two of §8's subsections are NOT implemented, and the reason in both cases
is a missing input rather than a missing algorithm:

- **§8.2 transcript hashes** hash an encoded `AuthenticatedContent`
  (`ConfirmedTranscriptHashInput`/`InterimTranscriptHashInput`), which is a
  Part 5 framing structure. The upstream vector for it
  (`transcript-hashes.json`) supplies a serialized `AuthenticatedContent`
  and therefore cannot be driven before Part 5 either.
- **§8.3 external initialization** needs an HPKE `SetupBaseS`/`SetupBaseR`
  context (the sibling `hpke` module exposes `sealBase`/`openBase` but not
  a bare setup returning a `Context`), and is only reachable through Part
  6's external-commit flow.

Both are named in `keyschedule.zig`'s module doc comment so the omission is
discoverable from the code, not only from here. `confirmation_tag` and
`membership_tag` themselves ARE implemented — they consume Part 4's keys —
but their inputs are assembled by Part 5, so they take already-encoded
bytes.

## Threat model

- **`codec.Reader` on hostile input.** Every `read*` function is bounds-
  checked against the buffer's actual length regardless of what a length
  prefix inside the buffer claims — a `readVector` whose varint claims
  more bytes than remain fails `error.BufferTooShort`, never an
  out-of-bounds read. `readEnum`/`readPresence` never call
  `@enumFromInt`/switch in a way that's reachable-UB on an unrecognized
  tag — see `codec.zig`'s `readEnum` doc comment on requiring a
  non-exhaustive (`_,`) enum, the convention this repo's other
  wire-format enums (`dtls.messages.HandshakeType`, `hpke.suite.KemId`)
  already follow.
- **Scratch-buffer overflow on an oversized label/context.** `LabelTooLong`
  is a typed error, never a panic/truncation — see Design's scratch-buffer
  paragraph above. An application binding attacker-controlled data
  directly into a `context`/`content` argument (unusual, but not
  impossible — e.g. an application-defined MLS extension) gets a clean
  error rather than a buffer overrun.
- **`treemath.zig` on an attacker-controlled tree size / node index.**
  Every function is pure arithmetic with no allocation and no panic path
  reachable from an out-of-range `x`/`n_leaves` input on its own —
  `left`/`right`/`parent`/`sibling` return `null` rather than indexing
  into anything; `direct_path`/`copath` are the only functions that can
  fail (`error.BufferTooShort` on an undersized `out`), and that failure
  is a caller-buffer-sizing issue, not a function of the (attacker-
  supplied) tree shape itself misbehaving. Note: this module does NOT
  itself validate that a given `x` is actually `< node_width(n_leaves)`
  for the caller's tree — passing an out-of-range `x` produces
  arithmetically well-defined but MEANINGLESS results (no panic, no OOB
  memory access, just a wrong-but-bounded answer); range-checking `x`
  against the caller's actual tree is the CALLER's responsibility (a
  later part's ratchet-tree state owns that invariant), matching this
  file's "pure integer math, no I/O, no validation policy" scope.
- **Ed25519/HPKE key material.** This module generates no keys of its own
  beyond what a caller passes in (`SignWithLabel`/`EncryptWithLabel` take
  an already-constructed `KeyPair`/`PublicKey`) — key generation, storage,
  and rotation are entirely the caller's (a later part's KeyPackage
  lifecycle) responsibility, mirroring `hpke`'s own scoping.
- **A forged `generation` on an inbound message (Part 4).** The generation
  in a `SenderData` is a `uint32` that has not been authenticated at the
  point the receiver must use it to find a key. `secrettree.Window` bounds
  the resulting work with `max_forward_jump` (default 1024) — without it,
  four attacker-chosen bytes would buy up to 2^32 KDF invocations per
  message. Rejection is `error.GenerationTooFarAhead`, cheap and typed.
- **Replay of a captured message (Part 4).** `Window.get` erases each
  key/nonce as it hands it out, so a generation can be served at most once;
  a replay gets `error.GenerationConsumed`. This is stronger than §9.2
  requires (which speaks only of deleting consumed values) and is what
  turns the deletion schedule into an actual anti-replay property rather
  than only a forward-secrecy one.
- **MAC comparison (Part 4).** `verifyConfirmationTag`/`verifyMembershipTag`
  compare with `std.crypto.timing_safe.eql`, never `std.mem.eql` — both
  tags arrive from the network. Length is checked before the compare so a
  short tag cannot alias into a partial match.
- **Key material lifetime (Part 4).** `EpochSecrets.wipe`, `Ratchet.wipe`,
  `Window.wipe` and `KeyNonce.wipe` use `std.crypto.secureZero`, and
  `Ratchet.advance` overwrites the secret it derived from in place rather
  than dropping it — a ratchet that could be rewound would defeat §9.2's
  point. Calling `wipe` at the right moment is still the caller's decision;
  this module provides the mechanism, not the schedule.
- **`EncryptWithLabel`'s randomness source.** Takes `io: std.Io` and draws
  a fresh ephemeral KEM keypair per call via `hpke.sealBase` (never an
  injected/fixed ephemeral in the real entry point) — the KAT's
  `DecryptWithLabel`-only check against the vector's fixed `kem_output`
  doesn't exercise this randomness at all, so `kat_test.zig` separately
  round-trips `EncryptWithLabel`→`DecryptWithLabel` through the real
  `io`-backed path to confirm the non-deterministic entry point itself
  works, not just the deterministic-input decrypt half.

## Backlog

- **Scratch-buffer size (512 bytes) — RESOLVED 2026-07-28** by the second
  of the two options this item listed: `crypto.ExpandWithLabelScratch` takes
  a caller-supplied slice and `crypto.kdfLabelLen` sizes it exactly, while
  `ExpandWithLabel` keeps the fixed-buffer convenience for the bounded
  callers. `keyschedule.zig` uses it for the two `GroupContext`-carrying
  derivations; a regression test drives a 4 KB context through both entry
  points and asserts the fixed one refuses rather than truncates.
- **The secret tree's non-power-of-two tree shape is not vector-covered.**
  `secrettree.nodeSecret` walks `treemath`'s truncated tree, which is what
  §9 requires ("the same structure as the group's ratchet tree"), but
  `secret-tree.json` only publishes trees of 1, 8 and 32 leaves — all
  powers of two. The truncated-tree path is therefore reasoned-correct (it
  reuses Part 1's already-vector-pinned `treemath`) rather than
  externally anchored. A later part that builds a real group of, say, 5
  members exercises it for free.
- **Part 2 (TreeKEM) vector fetch/audit — DONE 2026-07-16**, see "Part 2 —
  TreeKEM" above (was previously listed here as not-yet-done).
- **`treemath.zig`'s `common_ancestor_semantic`/`common_ancestor_direct`**
  (RFC 9420 Appendix C also publishes these) are NOT implemented here —
  not required by `tree-math.json`'s published fields (`root`/`left`/
  `right`/`parent`/`sibling` only) and not needed until a later part's
  actual TreeKEM resolution logic wants them; add then, following the
  same direct-port approach.
- **Part 2's five Fable cores are DONE 2026-07-16** —
  `resolution`/`parentHash`/`validateParentHashes`/`processUpdatePath`/
  `applyUpdatePath` (`treekem.zig`) are implemented and the gate
  (`gate.treekem_core_implemented`) is `true`. `tree-validation.json`'s
  resolution/parent-hash-chain checks and the whole `treekem.json` vector
  (`kat_treekem_test.zig`) now run byte-exact. NB: the in-repo harness had
  two owner-fixed defects the Fable pass correctly refused to hack around
  (it proved correctness via a scratch driver instead) — the gated
  `processUpdatePath` test seeded `group_context = ""`/empty path secrets
  (every decrypt fails `AuthenticationFailed` regardless of correctness),
  and the parent-hash negative control indexed `tampered[0]` on the root's
  zero-length hash (an OOB panic); both were rewritten to the official
  `test-vectors.md` procedure (provisional GroupContext with
  `tree_hash = tree_hash_after`; tamper only non-empty hashes) with every
  assertion kept byte-exact.
- **`ParentNode.unmerged_leaves` sorted-increasing invariant (RFC 9420
  §7.1) is not decode-time validated** — `tree.zig`'s `ParentNode.decode`
  accepts any order; a later part (or the Fable pass's
  `validateParentHashes`) may want to check this explicitly if a vector
  ever exercises a violation (none of Part 2's KATs do).
