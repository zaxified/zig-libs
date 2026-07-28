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
**Part 2** (TreeKEM), **Part 4** (key schedule + secret tree) and **Part 5**
(message framing, RFC 9420 §6 + §8.2) have since landed. With Part 5 the
module can produce and consume real MLS messages that other implementations
accept byte-for-byte: a Proposal, a Commit or application data, framed and
signed as a `PublicMessage` or fully encrypted as a `PrivateMessage`. What
is still missing before this is a CLIENT is Part 3's KeyPackage/LeafNode
validation and Part 6's join flow (`Welcome`/`GroupInfo`), plus the
group-state object that would tie an epoch's tree, transcript and key
schedule together — none of which is a wire format, all of which is policy
and state machinery over what Parts 1-5 already compute.

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
| **3 — LeafNode / KeyPackage / Credential VALIDATION** | §5.3 credentials, §7.2/§7.3 `LeafNode` content + validation (`leaf_node_validation.json`), `KeyPackage` (§10) validation. NOTE: §10's WIRE FORMAT was taken by Part 5 (`keypackage.zig`) because §12.1.1's `Add` cannot be decoded without it; what remains for Part 3 is §10.1's and §7.3's admission RULES | **Sonnet** — mostly `codec.zig`-shaped serialization plus signature verification (`SignWithLabel`/`VerifyWithLabel` from THIS part) over well-specified structs; the validation RULES (§7.3's numbered list) are mechanical checks, not novel crypto | `key-package-validation.json`, `leaf-node-validation.json` |
| **4 — Key Schedule + Secret Tree** | §8's full `init_secret_[n-1] → ... → init_secret_[n]` chain, §8.1 `GroupContext`, §8.4 `psk_secret`, §8.5 exporter, §6.1's two MACs, §9 Secret Tree + sender ratchets, §6.3.2 sender-data keys — **DONE 2026-07-28**, whole part **COMPLETE** except §8.3 (external init, needs Part 6); §8.2's transcript hashes were the other gap and Part 5 closed them (`transcript.zig`) | **Sonnet** — pure composition of `ExpandWithLabel`/`DeriveSecret` (already built) over a well-specified derivation graph. One correction to the original note below: Figure 22 pins the ORDER unambiguously, but Figure 24 (§8.4's PSK chain) does NOT — it contradicts its own prose on the Extract argument order, and only the vector settles it | `key-schedule.json`, `secret-tree.json`, `psk_secret.json` — all byte-exact; see "Part 4" below |
| **5 — Message framing** | ALL of §6 (`FramedContent`/`AuthenticatedContent`/§6.1 TBS+auth/§6.2 `PublicMessage`+`membership_tag`/§6.3 `PrivateMessage`+§6.3.1 content encryption+§6.3.2 sender data/`MLSMessage`), the §12.1 `Proposal` and §12.4 `Commit` WIRE FORMATS framing carries, the §10 `KeyPackage` wire format `Add` carries, and §8.2's transcript hashes — **DONE 2026-07-29**, whole part **COMPLETE**. Commit PROCESSING (§12.2/§12.3/§12.4.1/§12.4.2) is explicitly NOT here — see "Part 5" below for where that boundary falls and why | **Sonnet** — mechanical composition over Parts 1/2/4's primitives with an authoritative byte-exact oracle for every path. No new cryptography: every derivation it performs was already built and vector-pinned by an earlier part | `messages.json`, `message-protection.json`, `transcript-hashes.json` — all byte-exact; see "Part 5" below |
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

When Part 4 landed, two of §8's subsections were not implemented, in both
cases for a missing input rather than a missing algorithm:

- **§8.2 transcript hashes** hash an encoded `AuthenticatedContent`
  (`ConfirmedTranscriptHashInput`/`InterimTranscriptHashInput`), which is a
  Part 5 framing structure. The upstream vector for it
  (`transcript-hashes.json`) supplies a serialized `AuthenticatedContent`
  and therefore could not be driven before Part 5 either.
  **CLOSED 2026-07-29 by Part 5** — `transcript.zig`, vector-pinned; see
  "Part 5" below. It is a separate file rather than an addition to
  `keyschedule.zig` only because `framing.zig` imports `keyschedule.zig`,
  so §8.2 living there would be an import cycle.
- **§8.3 external initialization** needs an HPKE `SetupBaseS`/`SetupBaseR`
  context (the sibling `hpke` module exposes `sealBase`/`openBase` but not
  a bare setup returning a `Context`), and is only reachable through Part
  6's external-commit flow. **STILL OPEN.**

Both were named in `keyschedule.zig`'s module doc comment so the omission
was discoverable from the code, not only from here; that comment now points
at `transcript.zig` for §8.2 and still names §8.3. `confirmation_tag` and
`membership_tag` themselves were implemented in Part 4 — they consume Part
4's keys — but their inputs are assembled by Part 5, so they take
already-encoded bytes, and `framing.membershipTag` is the function that
assembles the `AuthenticatedContentTBM` for them.

## Part 5 — Message framing (2026-07-29)

**Files:** `framing.zig` (all of RFC 9420 §6), `content.zig` (§12.1's seven
`Proposal` types + §12.4's `Commit`/`ProposalOrRef`), `keypackage.zig`
(§10's `KeyPackage`/`KeyPackageTBS` wire format), `transcript.zig` (§8.2),
`kat_messages_test.zig`, `kat_framing_test.zig`. One addition to Part 2's
`wire_lists.zig` (`encodeVarVecAny`) was needed and is described below.

### §6's actual subsection structure

Worth stating because it is smaller than the section's reputation suggests
— §6 has exactly three subsections and one sub-subsection pair:

| Section | Contents |
|---|---|
| §6 (body) | `ProtocolVersion`, `ContentType`, `SenderType`, `Sender`, `WireFormat`, `FramedContent`, `MLSMessage`, `AuthenticatedContent` |
| §6.1 Content Authentication | `FramedContentTBS`, `MAC`, `FramedContentAuthData` |
| §6.2 Encoding and Decoding a Public Message | `PublicMessage`, `AuthenticatedContentTBM`, `membership_tag` |
| §6.3 Encoding and Decoding a Private Message | `PrivateMessage` |
| §6.3.1 Content Encryption | `PrivateMessageContent`, `PrivateContentAAD`, the reuse guard, the padding MUST |
| §6.3.2 Sender Data Encryption | `SenderData`, `SenderDataAAD`, `ciphertext_sample` |

`Proposal` and `Commit` are NOT in §6 — they are §12.1 and §12.4, and §6
only references them from `FramedContent`'s `select`. They are implemented
here anyway (as `content.zig`) because a framing layer that cannot decode
them can decode nothing but application data. §10's `KeyPackage` follows for
the same reason one level down: §12.1.1's `Add` is `struct { KeyPackage
key_package; }`.

### What it is verified against

| Vector | Drives | Checked |
|---|---|---|
| `message-protection.json` | `protectPublic`/`unprotectPublic`, `protectPrivate`/`decryptSenderData`/`decryptContent`/`parsePrivateContent`, `signFramedContent`/`verifyFramedContent`, `membershipTag`, and Part 4's `secrettree` ratchets underneath | `PrivateMessage` for all three content types and `PublicMessage` for the two handshake types, byte-exact **in both directions** — plus the §6 refusal of application content as a `PublicMessage`, which is why that pairing is absent rather than untested. See below |
| `transcript-hashes.json` | `transcript.confirmedTranscriptHash`/`interimTranscriptHash`/`advance`, `AuthenticatedContent.encode`/`decode`, and Part 4's `verifyConfirmationTag` | Both §8.2 hashes byte-exact, the `AuthenticatedContent` re-encode byte-exact, and the Commit's own `confirmation_tag` verified against the confirmed hash it produces |
| `messages.json` | Every §12.1 proposal body, §12.4 `Commit`, §10 `KeyPackage`, and the §6 `MLSMessage` wire formats | decode → re-encode byte-exact for all 13 embedded fields per entry |

Every vector matched on the first run — no stage needed adjusting, no
vector was edited, and no code was changed in response to a divergence
because there was none. That is a weaker statement than it looks (this part
introduces no new cryptography; every derivation under it was pinned by
Parts 1/2/4 first), but it does mean the §6 wire shapes and the two TBS/TBM
framings were read correctly off the RFC the first time.

### The protect direction is pinned byte-exact, which upstream does not ask for

`message-protection.json`'s own procedure only requires a ROUND-TRIP in the
send direction: "verify that protecting the raw value ... produces a
PublicMessage that verifies". That is because a generic implementation
picks a random reuse guard (§6.3.1 requires it) and an arbitrary padding
length (§6.3.1 leaves it to the application), so its output cannot be
compared against the vector's bytes.

Both choices are recoverable from the vector itself, though:

- the **reuse guard** and the **generation** fall out of the decrypted
  `SenderData` (§6.3.2);
- the **padding length** is the decrypted plaintext length minus the
  encoded body and `FramedContentAuthData`.

Feed those back in and the whole construction is deterministic — Ed25519 is
(RFC 8032, and this module passes no hedging noise), AES-GCM is given
key/nonce/AAD, and HMAC/HKDF always are. So `kat_framing_test.zig`
reproduces `proposal_pub`, `commit_pub`, `proposal_priv`, `commit_priv` and
`application_priv` byte-for-byte. This matters: a round-trip test passes
happily with a systematically wrong `FramedContentTBS` (sign and verify
with the same wrong bytes and nothing complains), and byte-exactness does
not.

The one thing the harness does NOT claim byte-exactness for is the four
`MLSMessage` header bytes in front of each protected message — `protect*`
returns a bare `PublicMessage`/`PrivateMessage`, so the harness derives the
header length by re-encoding the decoded message and asserting the vector
ends with it, rather than assuming a constant.

### Where the boundary falls, stated precisely

Implemented: every wire structure in §6, §12.1, §12.4 and §10, plus §8.2.

NOT implemented, and not stubbed either:

- **§12.2 proposal-list validity / §12.3 application order / §12.4.1
  Creating a Commit / §12.4.2 Processing a Commit.** `content.zig` decodes
  a `Commit`; nothing in this part decides whether its proposal list is
  legal, applies it to a ratchet tree, or advances an epoch. That is a
  state machine over Part 2's tree editing and Part 4's key schedule, and
  it needs a group-state object this module does not have yet.
- **§10.1 KeyPackage validation and §7.3 LeafNode validation.**
  `keypackage.zig` has the struct and its self-signature check — a pure
  function of the bytes — and none of the admission rules (lifetime
  freshness, capability/extension consistency, `leaf_node_source ==
  key_package`, init-key/encryption-key distinctness, uniqueness within a
  Commit). Those stay Part 3's.
- **`Welcome` / `GroupInfo`.** `framing.MLSMessage.decode` returns
  `error.WireFormatNotInThisPart` for wire formats 3 and 4 — a NAMED
  refusal, deliberately distinct from the `error.Malformed` an unregistered
  value gets, so a caller can tell "not built yet" from "not a thing".
- **Key lookup and member validation.** `unprotect*` hands back a decoded,
  signature-verified `AuthenticatedContent` and the `SenderData.leaf_index`
  it decrypted. Checking that the index names a non-blank leaf (§6.3.2's
  closing MUST) needs a `RatchetTree`; choosing which leaf's ratchet and
  which generation to try needs a per-leaf `secrettree.Window`. Both are
  the caller's, and `framing.zig`'s doc comment says so.
- **Randomness.** §6.3.1 requires a fresh random four-byte reuse guard per
  message; `ProtectPrivateParams.reuse_guard` is a caller input. Same
  posture as `keyschedule.PreSharedKeyId.psk_nonce` — this module never
  owns a randomness policy.

### Three §6 details that are easy to get wrong, and are load-bearing

1. **The signature covers the wire format.** `FramedContentTBS` begins
   `version || wire_format`, so the same `FramedContent` produces a
   different signature for a `PublicMessage` than for a `PrivateMessage`.
   That is what stops a handshake message being lifted out of its encrypted
   envelope and replayed in the clear. There is deliberately no "sign once,
   encode either way" entry point.
2. **The GroupContext is in the TBS for `member`/`new_member_commit` only.**
   §6.1's `select` gives `external`/`new_member_proposal` an empty struct.
   Always appending it would reject legitimate external proposals; never
   appending it would accept a member's signature from the wrong epoch.
   `Sender.tbsIncludesGroupContext()` is the single place that decision
   lives, and `framedContentTbsAlloc` returns `error.MissingGroupContext`
   rather than silently producing a shorter TBS.
3. **The reuse guard is XORed into the nonce, not appended to it** — into
   the FIRST four bytes, leaving the rest of the key-schedule nonce
   untouched (§6.3.1's figure). `applyReuseGuard` is involutive and is used
   by both directions, so protect and unprotect cannot disagree about it.

Additionally, §8.2's `InterimTranscriptHashInput` is `struct { MAC
confirmation_tag; }` — one `opaque<V>` field — so the tag enters that hash
LENGTH-PREFIXED, not raw. Dropping that one varint produces a
perfectly plausible 32-byte hash that no other implementation agrees with;
`transcript.zig` has an explicit test contrasting the two constructions.

### Why §8.2 needs two hashes rather than one

A Commit's `confirmation_tag` is a MAC over the confirmed transcript hash
that that same Commit produces (§6.1). A single running hash that also
covered the tag would therefore require the tag to compute the hash the tag
is computed over. §8.2 breaks the circularity by cutting the update in two
at exactly the signature boundary: `ConfirmedTranscriptHashInput` stops at
`signature`, and `InterimTranscriptHashInput` is nothing but the tag. This
is why `transcript.confirmedInputEncode` is not simply
`AuthenticatedContent.encode` — there is a test asserting the former is a
strict prefix of the latter, differing by exactly the trailing tag.

### The addition to Part 2's files

- **`wire_lists.encodeVarVecAny`** (new). `wire_lists.encodeVarVec`
  declares `codec.Error!void`, which every Part 2 element type satisfies.
  `content.ProposalOrRef` does not: it can bottom out in a `tree.LeafNode`
  or a `KeyPackage`, whose `encode` can fail with `error.Malformed` (a
  `select`-guarded field missing) and whose error set includes
  `OutOfMemory`. Rather than widening the existing helper's declared error
  set — which would change the contract every current caller relies on —
  the new one has an inferred error set and an otherwise identical body.

### Teeth

Each of the three new vectors was corrupted by ONE byte, the suite re-run,
and the failure confirmed to name the diverging stage; then restored and
re-verified by SHA-256 against the fetched originals (hashes in `NOTICE`):

| Corruption | Failure |
|---|---|
| `messages.json` entry 0's `public_message_commit`, 2nd hex digit | `'public_message_commit (§6.2)' re-encode diverged at entry 0 (want 428 bytes, got 428)` |
| `message-protection.json` suite-1 `application`, 3rd hex digit | `'application_priv -> application body' diverged (want 42 bytes, got 42)` |
| `message-protection.json` suite-1 `membership_key`, 3rd hex digit | `'proposal_pub membership_tag (§6.2)' failed: MacMismatch` |
| `transcript-hashes.json` suite-1 `interim_transcript_hash_before`, 3rd hex digit | `'confirmed_transcript_hash_after' diverged (want 32 bytes, got 32)` |

The membership-key case is why both harnesses name the stage on an ERROR as
well as on a byte mismatch: every iteration of an `inline for` shares one
source line, so a bare `error.MacMismatch` would not have said which
content type or which of the two tags produced it.

Beyond the vectors, three in-file negative controls exist because a
positive-only harness would pass without them: a tampered ciphertext byte
must fail the content AEAD; a wrong reuse guard must fail it too (proving
the XOR is actually reaching the nonce); and the Commit's `confirmation_tag`
must NOT verify against the interim hash or the previous interim hash
(proving §8.2's two same-width hashes are not being confused).

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

- **`kat_treekem_test.zig` still carries a test-local `KeyPackage` parser.**
  It predates `keypackage.zig` (Part 5) and was written only to reach
  `tree-operations.json`'s Add proposals. Switching it to
  `keypackage.KeyPackage` would delete duplicated parsing and give that
  vector a second consumer; left alone in this pass to avoid touching a
  passing Part 2 KAT for a cosmetic win. `tree.decodeExtensionList`'s doc
  comment names this.
- **`content.zig` has no standalone `Add`/`Update`/`Remove`/`PreSharedKey`/
  `ExternalInit`/`GroupContextExtensions` types** — each §12.1 body is a
  `Proposal` union arm holding the type it wraps (`Add` is a `KeyPackage`,
  `Remove` is a `u32`, …), since none of those RFC structs has a second
  field. The consequence is that `kat_messages_test.zig` drives the bare
  `*_proposal` vector fields through the WRAPPED types, prepending the
  §17.4 type value where the vector has none. If a future extension
  proposal type needs a real struct, that is when to split them out.
- **`framing.zig` exposes no single `unprotectPrivate`.** Decryption is
  genuinely two-phase (§6.3.2's sender data names the key that §6.3.1's
  content needs), and the key lookup between the phases is the caller's, so
  the three stages are exposed separately rather than behind a callback.
  Revisit if a group-state object in a later part makes the lookup
  internal.

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
