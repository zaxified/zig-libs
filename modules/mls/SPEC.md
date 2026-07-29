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
**Part 2** (TreeKEM), **Part 4** (key schedule + secret tree), **Part 5**
(message framing, RFC 9420 §6 + §8.2) and **Part 6**'s Welcome path
(§12.4.3/§12.4.3.1/§12.4.3.3) have since landed. With Part 5 the module can
produce and consume real MLS messages that other implementations accept
byte-for-byte: a Proposal, a Commit or application data, framed and signed
as a `PublicMessage` or fully encrypted as a `PrivateMessage`. With Part 6
it can also ENTER a group from a `Welcome`, arriving at the same epoch
secrets and transcript hashes as every existing member. What is still
missing before this is a CLIENT is Part 3's KeyPackage/LeafNode validation,
the external-Commit join (§12.4.3.2/§8.3 — see "Part 9"),
and the group-state object that would tie an epoch's tree, transcript and
key schedule together so the module could FOLLOW a group after joining —
none of which is a wire format, all of which is policy and state machinery
over what Parts 1-6 already compute.

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
| **4 — Key Schedule + Secret Tree** | §8's full `init_secret_[n-1] → ... → init_secret_[n]` chain, §8.1 `GroupContext`, §8.4 `psk_secret`, §8.5 exporter, §6.1's two MACs, §9 Secret Tree + sender ratchets, §6.3.2 sender-data keys — **DONE 2026-07-28**, whole part **COMPLETE** except §8.3 (external init — Part 6 established that the `hpke` dependency it needs is already satisfied, so this is unbuilt work rather than a blocker); §8.2's transcript hashes were the other gap and Part 5 closed them (`transcript.zig`), and Part 6 added the joiner's entry point into the same chain (`deriveEpochFromJoiner`) | **Sonnet** — pure composition of `ExpandWithLabel`/`DeriveSecret` (already built) over a well-specified derivation graph. One correction to the original note below: Figure 22 pins the ORDER unambiguously, but Figure 24 (§8.4's PSK chain) does NOT — it contradicts its own prose on the Extract argument order, and only the vector settles it | `key-schedule.json`, `secret-tree.json`, `psk_secret.json` — all byte-exact; see "Part 4" below |
| **5 — Message framing** | ALL of §6 (`FramedContent`/`AuthenticatedContent`/§6.1 TBS+auth/§6.2 `PublicMessage`+`membership_tag`/§6.3 `PrivateMessage`+§6.3.1 content encryption+§6.3.2 sender data/`MLSMessage`), the §12.1 `Proposal` and §12.4 `Commit` WIRE FORMATS framing carries, the §10 `KeyPackage` wire format `Add` carries, and §8.2's transcript hashes — **DONE 2026-07-29**, whole part **COMPLETE**. Commit PROCESSING (§12.2/§12.3/§12.4.1/§12.4.2) is explicitly NOT here — see "Part 5" below for where that boundary falls and why | **Sonnet** — mechanical composition over Parts 1/2/4's primitives with an authoritative byte-exact oracle for every path. No new cryptography: every derivation it performs was already built and vector-pinned by an earlier part | `messages.json`, `message-protection.json`, `transcript-hashes.json` — all byte-exact; see "Part 5" below |
| **6 — Joining a group (Welcome), then external Commit / reinit** | §12.4.3's `GroupInfo`/`GroupInfoTBS`, §12.4.3.1's `Welcome`/`GroupSecrets`/`EncryptedGroupSecrets` + both encryption layers + the joiner's procedure, §12.4.3.3's `ratchet_tree`/`external_pub` extensions and the tree-hash binding, and §8's chain entered at `joiner_secret` — **DONE 2026-07-29**, the WELCOME path **COMPLETE**. §12.4.3.2 external Commits + §8.3 external init landed later, in Part 9; §11.2/§11.3 reinit/branch remain | **Sonnet** — no new cryptography at all: the group-info layer is a plain AEAD under a key `keyschedule.zig` already derived, and the per-member layer is `crypto.EncryptWithLabel` unchanged. The judgment calls were scope ones, not crypto ones | `welcome.json` + `messages.json`'s Part 6 fields — byte-exact; see "Part 6" below |
| **7 — Group state machine** | `Group(S)`: the state a member carries between epochs, §12.2's proposal-list validation, §12.3's application order, §12.4.2's whole Commit-processing procedure, and §12.4.3.1's join run to completion (`fromWelcome`) — **DONE 2026-07-29**, COMPLETE for the FOLLOWER. Also §8.3 external init, which Part 6 listed as unbuilt. NOT here: Commit/proposal CREATION (no sender half of §7.5), `PrivateMessage` handshakes, §12.4.3.2 external Commits, §11.2/§11.3 reinit/branch | **Sonnet** — still no new cryptography, but the first part of this arc whose vectors did NOT match on the first run. Three coding defects in Parts 1/2/4 and one specification MISREADING surfaced here and nowhere else; see "Part 7" below | `passive-client-welcome.json`, `passive-client-handling-commit.json`, `passive-client-random.json` — whole recorded sessions replayed Commit by Commit against `epoch_authenticator`; see "Part 7" below |
| **8 — Creating Commits** | The sender half of everything Part 7 could only receive: §11 group creation, §12.1 proposal creation, §7.4/§7.5's `UpdatePath` GENERATION (`treekem.stageUpdatePath`/`sealUpdatePath`), §12.4.1's Commit creation, §12.4.3.1's `Welcome` production, and §10's `KeyPackage` construction — **DONE 2026-07-29**, COMPLETE for REGULAR Commits. Also the two §7.3 rules that need only the leaf and the tree, applied in both directions. NOT here: §12.4.3.2 external Commits (the stated boundary — see "Part 8"), `PrivateMessage` handshakes, §11.2/§11.3, committer-chosen leaf content | **Sonnet** — no new cryptography; the mirror image of Part 7 over Parts 1-6's primitives. The judgement calls were about what can be ANCHORED when the output has three random inputs, and about which half of §7.3 belongs here. Building the send half found three RECEIVE-side problems that 200 replayed Commits could not reach — including a §7.5 misreading Part 7 introduced and no upstream vector can see | `treekem.json` driven in the SEND direction (a generation seeded from the vector's own `path_secret[0]` reproduces its node public keys, `commit_secret` and committer-leaf `parent_hash` byte-exact, then faces its recorded members); Commits created on states restored from `passive-client-handling-commit.json`/`passive-client-random.json`. See "Part 8" for what is anchored and what is a round trip |

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
- `resolutionExcluding(allocator, tree, index, excluded) Error![]usize` — §4.1 narrowed by §7.5's same-Commit-Add exclusion. For the CIPHERTEXT lists only, never for the §4.1.2 filter — see `filteredDirectPath`.
- `filteredDirectPath(allocator, tree, leaf_node_index) Error![]FdpEntry` — §4.1.2, a property of the tree alone.
- `processUpdatePath(comptime S, allocator, tree, receiver: PrivateLeafState, sender_leaf_index, update_path, group_context, added_this_commit) Error!ProcessedUpdatePath` — §7.4/§7.5/§7.6 (receiver side; yields `commit_secret`).
- `applyUpdatePath(allocator, tree, sender_leaf_index, update_path) Error!void` — §7.5 (public-side merge).
- `stageUpdatePath(comptime S, allocator, tree, sender_leaf_index, params: StageParams(S)) !Staged(S)` — Part 8: §7.4's derivation + §7.5's first block (sender side; mutates the tree, returns the signed leaf and every path secret).
- `sealUpdatePath(comptime S, allocator, io, tree, staged, group_context, added_this_commit) !UpdatePath` — Part 8: §7.5's second block (encrypt to the copath resolutions). Split from `stageUpdatePath` because the `group_context` it needs contains the tree hash the first half produces.

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
| `messages.json` | Every §12.1 proposal body, §12.4 `Commit`, §10 `KeyPackage`, and the §6 `MLSMessage` wire formats | decode → re-encode byte-exact for every embedded field per entry. **Part 6 widened this**: the four fields Part 5 projected away (`mls_welcome`/`mls_group_info`/`ratchet_tree`/`group_secrets`) are now embedded and driven too, so the filter is a plain entry prefix — see `NOTICE` item 6 |

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
- **`Welcome` / `GroupInfo`.** Part 5 refused wire formats 3 and 4 with a
  NAMED `error.WireFormatNotInThisPart`, deliberately distinct from the
  `error.Malformed` an unregistered value gets, so a caller could tell "not
  built yet" from "not a thing". **Part 6 supplied them and the error is
  gone** — `framing.MLSMessage.decode` now handles all five §17.2 wire
  formats, so it had no reachable return site left. See "Part 6" below.
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

## Part 6 — Joining a group (2026-07-29)

**Files:** `welcome.zig` (RFC 9420 §12.4.3, §12.4.3.1, §12.4.3.3),
`kat_welcome_test.zig`. Two additions elsewhere: `keyschedule
.deriveEpochFromJoiner` (§8 entered one step lower) and the two new
`MLSMessage` arms in `framing.zig`.

### Where the RFC actually puts this, because the brief for this part got it wrong

There is no top-level "Welcome" section. Everything lives under §12.4.3
("Adding Members to the Group"), which is itself a sub-subsection of §12.4
("Commit"):

| Section | Contents |
|---|---|
| §12.4.3 (body) | `GroupInfo`, `GroupInfoTBS` — NOT in a numbered subsection of their own |
| §12.4.3.1 Joining via Welcome Message | `PathSecret`, `GroupSecrets`, `EncryptedGroupSecrets`, `Welcome`, the `welcome_key`/`welcome_nonce` derivation, and the twelve-step receiving procedure |
| §12.4.3.2 Joining via External Commits | `ExternalPub`, the external-Commit rules — **built, see Part 9** (this row read "NOT in scope" while Part 6 was the newest part) |
| §12.4.3.3 Ratchet Tree Extension | the `optional<Node> ratchet_tree<V>` encoding and its closing tree-hash MUST |

The two supporting facts that are elsewhere: §17.2 assigns `mls_welcome` =
3 and `mls_group_info` = 4, and §17.3 assigns `ratchet_tree` = 0x0002 and
`external_pub` = 0x0004.

### The construction, and the one binding that is easy to drop

A Welcome must be readable by several new members at once while the
`GroupInfo` inside it — kilobytes, once it carries a ratchet tree — is
identical for all of them. §12.4.3.1 therefore splits it: the `GroupInfo`
is AEAD-sealed once under a key derived from the new epoch's
`welcome_secret`, and the `joiner_secret` that key comes from is
HPKE-sealed per member to each new member's `KeyPackage.init_key`.

The binding between the halves is that the per-member
`EncryptWithLabel(init_key, "Welcome", ...)` takes the ENTIRE
`encrypted_group_info` blob as its **context**. Dropping it changes
nothing observable in a round-trip test — sender and receiver would simply
both omit it — but it is what stops a delivery service from pairing one
member's sealed `GroupSecrets` with a different group's `GroupInfo`.
`kat_welcome_test.zig` has a dedicated negative control for exactly this:
flip one byte of the context, leave the sealed `GroupSecrets` untouched,
and the HPKE open must fail.

### What makes taking `joiner_secret` on trust sound

A joiner cannot recompute `joiner_secret`: it has neither the previous
epoch's `init_secret` nor the Commit's `commit_secret`, which is precisely
why §8's chain has to be enterable one step lower (`deriveEpochFromJoiner`;
`deriveEpoch` is now literally `joinerSecret` followed by it, so the two
paths cannot drift). What redeems the trust is the ORDER of the remaining
steps: derive the epoch from that `joiner_secret` and the signed
`GroupContext`, then verify the `GroupInfo`'s `confirmation_tag` with the
`confirmation_key` just derived. A committer who sent a `joiner_secret`
belonging to a different epoch produces a `confirmation_key` that does not
verify the tag it also signed. `join` runs the steps in that order and
fails closed.

### What it is verified against

| Vector | Drives | Checked |
|---|---|---|
| `welcome.json` | `Welcome`/`GroupInfo`/`GroupSecrets` codecs, `findSecret` (and therefore §5.2's `MakeKeyPackageRef`), `decryptGroupSecrets`, `welcomeSecret`, `welcomeKeyNonce`, `encryptGroupInfo`/`decryptGroupInfo`, `GroupInfo.verifySignature`, `deriveEpochFromJoiner`, `verifyConfirmationTag`, `interimTranscriptHash`, and `join` end to end | Every layer staged and byte-exact in the RECEIVE direction, plus the vector's own `encrypted_group_info` reproduced in the SEND direction (below). The one-call `join` is then required to agree with the hand-staged path field by field |
| `messages.json` (widened) | `Welcome`/`GroupInfo`/`GroupSecrets` wire codecs, the bare §12.4.3.3 `ratchet_tree`, `GroupInfo.extension`/`ratchetTree`/`externalPub` | decode → re-encode byte-exact; plus a cross-check that the `ratchet_tree` EXTENSION body inside `mls_group_info` is byte-identical to the vector's independently-generated standalone `ratchet_tree` field |

Both matched on the first run — no stage needed adjusting, no vector was
edited, and no code was changed in response to a divergence because there
was none.

### One layer is byte-exact in the send direction and one cannot be

`welcome.json`'s stated procedure is receive-only: decrypt, verify the
signature, recompute the `confirmation_tag`. This harness goes past that
where it legitimately can, and says plainly where it cannot.

- **The group-info layer IS reproducible.** §12.4.3.1 derives its key and
  nonce deterministically from `welcome_secret` and specifies no associated
  data, and AES-GCM under a fixed key and nonce is a function. So once
  `joiner_secret` has been recovered from the HPKE layer, re-sealing the
  decrypted `GroupInfo` must produce the vector's own
  `encrypted_group_info` byte for byte — and it does. A receive-only check
  passes with a `welcome_secret` derivation that is wrong in the same way
  in both directions; this cannot.
- **The per-member HPKE layer is NOT.** HPKE draws a fresh ephemeral KEM
  keypair per encryption and the vector publishes only the resulting
  `kem_output`, which is the ephemeral PUBLIC key. Recovering the private
  half is the discrete log. That layer is receive-direction only against
  this vector, and round-trip only in `welcome.zig`'s own test.
- **The `GroupInfo` SIGNATURE is likewise verify-only** against these
  bytes: the vector publishes `signer_pub` and no private key. Signing is
  exercised against a self-produced signature in `welcome.zig`.

### Received bytes are used, never a re-encode

Two steps consume a serialization of fields the decoded `GroupInfo` also
holds: the signature (over `GroupInfoTBS`) and the key schedule (over
`GroupContext`). Re-encoding either would make an encoder that differs
from the sender's by one varint fail a valid signature — or, far worse,
derive an epoch nobody else in the group derived — while every round-trip
test in the module still passed. `GroupInfo.decode` therefore records the
two raw byte ranges (`GroupInfo.raw`) from the reader's own consumption,
and both steps use them. `keyschedule.GroupContext`'s doc comment had
already named this hazard as the reason `joinerSecret`/`epochSecret` take
`[]const u8`; this is the field that supplies them. The teeth table below
includes a case that flips a byte in the raw plaintext specifically to
prove the verification reads received bytes.

### Where the boundary falls, stated precisely

**In.** `GroupInfo`/`GroupInfoTBS` + sign/verify; `PathSecret`/
`GroupSecrets`/`EncryptedGroupSecrets`/`Welcome` codecs; both encryption
layers in both directions; `findSecret`; the PSK-list identity check; the
epoch derivation from `joiner_secret`; the `confirmation_tag` check; §8.2's
interim hash for the joined epoch; the `ratchet_tree`/`external_pub`
extension accessors; `verifyTreeHash`; both new `MLSMessage` arms.

**Out, and why.**

- **§12.4.3.2 external Commits and §8.3 external initialization.** SCOPED
  OUT — and it is worth recording that the reason they were scoped out no
  longer holds. This batch was briefed on the understanding that §8.3's
  `ExternalInit` needs HPKE's `SetupBaseS`/`SetupBaseR` context setup and
  that the sibling `hpke` module exported only the single-shot
  `sealBase`/`openBase` wrappers. It exports the whole RFC 9180 §5.1 setup
  layer — `hpke.setupBaseS`/`setupBaseR`/`Setup`/`Context.exportSecret` —
  so the dependency is satisfied. What remains is the work itself: §8.3 is
  two functions (`SetupBaseS` then `Context.export("MLS 1.0 external init
  secret", KDF.Nh)`, plus the receiver mirror over `SetupBaseR`), and
  §12.4.3.2 on top of it additionally needs the commit processing this
  module does not have. Neither has an upstream interop vector, so both
  would land round-trip-anchored only — which is why neither was bolted
  onto a batch whose whole claim is byte-exact external anchoring. The
  `ExternalPub` extension a `GroupInfo` carries for this purpose IS read
  here (a joiner must be able to parse a `GroupInfo` that has one);
  nothing uses it yet.
- **The `passive-client-*.json` vectors.** These replay a whole recorded
  session — join, then apply a Commit per epoch and match an
  `epoch_authenticator` each time. They need §12.2 proposal-list validity,
  §12.3 application order and §12.4.2 commit processing, none of which
  exist in this module. Attempting them would have meant either a
  half-built commit processor or a harness that skipped the epochs, and
  a finished, vector-pinned Welcome is worth more than either. They are
  not fetched or embedded (see `NOTICE` item 7).
- **§12.4.3.1's tree-integrity block beyond the tree hash.** The
  parent-hash chain is Part 2's `treekem.validateParentHashes` (present,
  but running it is a caller step because it needs the tree) and per-leaf
  validation is §7.3, which is Part 3's and absent. `verifyTreeHash` is the
  one check this part owns, because it is what binds a tree to the SIGNED
  `GroupContext` and therefore the precondition for the other two meaning
  anything.
- **Installing the joiner's private keys from `path_secret`.** The
  `path_secret` is decoded and returned; deriving node keys up the tree
  from it needs a mutable group-state object this module deliberately does
  not have — the same call `framing.zig` makes about `SenderData
  .leaf_index`.
- **Group-id uniqueness, and §12.4.3.1's closing reinit/branch rules.**
  Both are checks against state outside this module (the client's other
  groups; the previous group's last Commit).

### The PSK-list check is stricter than "resolve what you have"

§12.4.3.1 says to error if a `PreSharedKeyID` in the `GroupSecrets` is one
the client does not hold. `join` goes slightly further: the caller passes
its resolved PSKs and `join` requires them to be the SAME list in the SAME
order, compared by encoded bytes. §8.4's chain is position-dependent, so a
caller that silently resolved a subset, a superset or a permutation would
derive a `psk_secret` nobody else in the group has — and would then fail
the `confirmation_tag` check with no indication of why. `error.PskMismatch`
names it at the point it happens. Comparing encoded bytes rather than
field-by-field means a future `PreSharedKeyID` arm cannot be added and
silently skipped by the comparison.

### Teeth

Each new vector was corrupted by ONE byte, the suite re-run, and the
failure confirmed to name the diverging stage; then restored and
re-verified by SHA-256 against the fetched originals (hashes in `NOTICE`):

| Corruption | Failure |
|---|---|
| `welcome.json` suite-1 `welcome`, last hex digit (inside `encrypted_group_info`) | `'GroupSecrets HPKE open (§12.4.3.1)' failed: DecryptionFailed` — and note WHICH layer names it: the group-info blob is the per-member layer's `EncryptWithLabel` context, so corrupting it breaks the HPKE open first |
| `welcome.json` suite-1 `signer_pub`, last hex digit | `'GroupInfo signature (§12.4.3 GroupInfoTBS)' failed: SignatureVerificationFailed` |
| `messages.json` entry 3's `group_secrets`, the `optional<PathSecret>` presence octet | `'group_secrets (§12.4.3.1)' failed to decode at entry 3: Malformed` |

A fourth attempt is worth recording as a NEGATIVE result: flipping the last
data byte of `messages.json`'s `group_secrets` (inside a `psk_nonce`)
changed nothing, because a decode → re-encode check cannot see a payload
byte change — it decodes and re-encodes identically. That is not a hole in
this harness so much as a restatement of what `messages.json` is for (a
wire-format anchor; see `kat_messages_test.zig`'s doc comment), and it is
why the corruption that DOES bite is a length/presence octet.

Beyond the vectors, `welcome.zig` and `kat_welcome_test.zig` carry negative
controls a positive-only harness would pass without: an unknown
`KeyPackageRef` must be `error.NoMatchingKeyPackage` rather than a decrypt
attempt against `secrets[0]`; a `Welcome` naming another cipher suite must
be refused before any decryption; a caller with no PSKs must not be able to
join a Welcome that names one; a correctly-signed `GroupInfo` carrying a
`confirmation_tag` from a different epoch must fail; one flipped bit of
`joiner_secret` must be caught by the CONFIRMATION TAG specifically (not by
a signature or an AEAD — that is the check proving the joiner's epoch is
pinned to the group's); a `GroupContext` with a bumped epoch must derive a
different `confirmation_key`; and a tree whose root hash is not the signed
`tree_hash` must fail `verifyTreeHash`.

## Part 7 — The group state machine (2026-07-29)

`group.zig` — `Group(S)`, the object that turns Parts 1-6's codecs and
derivations into a client that can FOLLOW a group: RFC 9420 §12.2 (proposal
list validation), §12.3 (applying a proposal list), §12.4.2 (processing a
Commit), and §12.4.3.1's joining procedure run all the way to a usable
state. Plus §8.3's external initialization in `keyschedule.zig`, which Part
6 listed as unbuilt.

### What it is verified against

The three official `passive-client-*.json` vectors, which are a different
kind of evidence from everything else this module embeds. Every other vector
pins one derivation, one codec or one message — it proves a FUNCTION is
right. These replay a whole recorded session: a client is added to a real
group by another implementation, then follows that group through a sequence
of Commits made by other members, with the `epoch_authenticator` compared at
every single step.

| Vector | What it drives | Result |
|---|---|---|
| `passive-client-welcome.json` | 8 recorded joins (suite `0x0001`), spanning both §12.4.3.3 tree sources and both PSK cases. **No Commits at all** — its `epochs` array is empty in every entry | green |
| `passive-client-handling-commit.json` | 13 recorded sessions of 2 Commits each, every one injecting an external PSK; the epochs span empty, single and multi-proposal Commits, including one carrying an Add, a Remove, two PSKs and a GroupContextExtensions together | green |
| `passive-client-random.json` | ONE recorded session of **200 consecutive Commits**, growing the group until an `UpdatePath` spans seven levels | green |

The `epoch_authenticator` is `DeriveSecret(epoch_secret, "authentication")`,
and `epoch_secret` depends on the `GroupContext` — hence on the tree hash
and on the entire transcript — and on the previous epoch's `init_secret`.
There is no way for the state machine to resynchronize: one wrong bit
anywhere makes that epoch and every later one wrong. A session that reaches
epoch 200 has had 200 independent chances to fail.

**None of these matched on the first run.** That is the first time in this
arc that has happened, and it is the whole reason the part was worth doing:
four separate defects were hiding behind vectors that were all too small to
expose them. See "What the replays found" below.

### Where the RFC actually puts commit processing, because the brief for this part was incomplete

The brief named §12.2, §12.3 and §12.4.2 as "the neighbourhood", and those
three are indeed the spine — §12.2's validity rules, §12.3's fixed
application order, §12.4.2's eleven ordered bullets. They are correct as far
as they go.

But the single rule that decides whether a Commit can be processed AT ALL is
in **§7.5**, which the brief did not mention and which contains no other
Commit-processing text:

> Any new member (from an Add proposal) added in the same Commit MUST be
> excluded from this resolution.

A member added by the same Commit that carries the `UpdatePath` must not
receive the path secrets through it — it gets its state from the `Welcome`
instead. So the committer builds one fewer ciphertext than "the resolution
of the copath node" suggests.

> **Correction, Part 8.** This section originally continued: "and, because
> the §4.1.2 filter is defined in terms of resolution EMPTINESS, a copath
> subtree containing only same-Commit additions drops out of the filtered
> direct path entirely, making the whole `UpdatePath` one node shorter."
> That second half is wrong, and Part 8 removed it —
> `treekem.filteredDirectPath` no longer takes an excluded set at all.
> §7.5 places the exclusion inside the ENCRYPTION step, applying it to "this
> resolution", while the loop is over §4.1.2's filtered direct path, which
> is defined purely on the tree. The node stays and carries an
> `UpdatePathNode` with zero ciphertexts. Dropping it instead leaves it
> blank, which puts the new member's leaf into the resolution of a blank
> node and breaks §7.9.2's `P.unmerged_leaves ∩ subtree(C) == resolution(C)
> \ {D}` criterion — a tree this module's own `validateParentHashes`
> rejects. Every upstream vector passes under either reading, so the error
> was invisible until Commit CREATION made the distinguishing case
> constructible. See "Part 8".

This is not a subtle key divergence that shows up later as a wrong secret.
A receiver that misses it computes a resolution one entry too long, the
ciphertext count does not match, and the Commit is rejected outright. It is
the reason `treekem.resolutionExcluding` exists and why
`processUpdatePath`/`applyUpdatePath` now take an `added_this_commit`
argument.

### What the replays found

Four defects, each invisible to every previously embedded vector. Three are
coding bugs in Parts 1/2/4; one is a specification misreading in this part.

1. **`crypto`'s 512-byte label scratch overflowed for any realistically
   sized group — Parts 1/6, real bug.** `EncryptWithLabel`'s `Context` and
   `SignWithLabel`'s `Content` have no upper bound in RFC 9420's own uses of
   them: §12.4.3.1 seals each member's `GroupSecrets` with the WHOLE
   `encrypted_group_info` as the context (which contains the ratchet tree),
   §7.5 opens each `UpdatePathNode` under the serialized `GroupContext`,
   `GroupInfoTBS` contains a `GroupContext` plus the `ratchet_tree`
   extension, and `FramedContentTBS` for a Commit contains a whole
   `UpdatePath`. All four are kilobytes for a real group. `welcome.json`'s
   group was small enough to fit; the passive-client groups are not, and
   every one of them failed. Fixed by mirroring the existing
   `kdfLabelLen`/`ExpandWithLabelScratch` precedent:
   `crypto.encryptContextLen` + `EncryptWithLabelScratch`/
   `DecryptWithLabelScratch`, and `crypto.signContentLen` +
   `SignWithLabelAlloc`/`VerifyWithLabelAlloc`, with every call site that
   can see an unbounded argument (and that already allocates its TBS buffer)
   switched over.
   **A second defect was hiding behind the first:**
   `welcome.decryptGroupSecrets` mapped every error from
   `DecryptWithLabel` to `error.DecryptionFailed`, so a buffer-size bug was
   reported as a wrong-key one. Sizing the scratch exactly makes
   `error.LabelTooLong` unreachable there, so the surviving `catch` can only
   mean a genuine AEAD/decap failure.
2. **`keyschedule.PreSharedKey.secret` was width-constrained to `[Nh]u8` —
   Part 4, real bug.** RFC 9420 §8.4's first step is
   `psk_extracted = KDF.Extract(0, psk)`: the PSK is HKDF *input keying
   material*, which has no required width. The passive-client vectors'
   external PSKs are **14 bytes**, and were rejected outright.
   `psk_secret.json`'s suite-`0x0001` entries all happen to be 32 bytes,
   which is exactly why no earlier vector caught it. Now `[]const u8`.
3. **`ParentNode.withAppendedUnmerged` appended instead of inserting in
   sorted position — Part 2, real bug.** RFC 9420 §7.1: "The entries in the
   unmerged_leaves vector MUST be sorted in increasing order." Appending is
   correct only while leaves are added strictly rightward, which is all Part
   2 could produce. An Add that reuses a blank leaf to the LEFT of an
   existing unmerged leaf breaks the invariant, and the damage is silent
   until a `resolution` — which reads the list in order — hands a path
   secret to the wrong node or a tree hash diverges.
4. **§7.5's same-Commit-Add exclusion, described above — a misreading, not a
   bug.** The first implementation applied §12.3's order literally and
   computed resolutions over the post-Add tree. Worth recording how it was
   resolved, because the wrong fix was very plausible: the observed
   ciphertext counts `[1, 1, 3]` were ALSO consistent with "the Add must not
   reuse a leaf vacated by a Remove in the same Commit, so extend the tree
   instead". That hypothesis was implemented, and it failed differently (the
   filtered direct path became one node too LONG), which is what sent the
   search back to the RFC until §7.5's sentence turned up. §12.1.1's
   leftmost-blank-leaf placement is unchanged and DOES reuse a
   just-vacated leaf — the recorded sessions confirm it. **Part 8 then
   found that the fix had been applied one step too far** — to §4.1.2's
   filter as well as to the resolution — see the correction box above.

### The three orderings that are load-bearing

`processCommit` is deliberately one function following §12.4.2's bullets in
order, with each step commented by its bullet, because splitting it up is
how the order drifts. Three places in it produce perfectly well-formed
32-byte secrets when wrong:

1. **Two different `GroupContext`s in one function.** The Commit's signature
   and `membership_tag` are verified against the OLD context (the epoch the
   sender was in); the key schedule consumes the NEW one.
2. **A third, PROVISIONAL `GroupContext` for the `UpdatePath`.** §12.4.2 is
   explicit: new `epoch`, new `tree_hash` (after the proposals AND after
   merging the `UpdatePath`), but the OLD `confirmed_transcript_hash`,
   because the transcript cannot yet include the Commit being processed. It
   differs from the final context in exactly one field, and using the final
   one there derives an epoch nobody else derived.
3. **§12.3's application order is not the Commit's list order.**
   GroupContextExtensions, then Update, then Remove, then Add, then PSK.
   Applying Adds before Removes puts new members in the wrong leaves and
   every subsequent tree hash diverges.

### Where the boundary falls, stated precisely

`Group(S)` is a complete PASSIVE client and a complete FOLLOWER. It is not a
complete client, and the gaps are named rather than implied:

- **No Commit or proposal CREATION.** There is still no sender half of §7.5
  (`treekem.zig` does not generate an `UpdatePath`), and no `Welcome`
  production. This is the receiving half only.
- **No `PrivateMessage` handshakes** — `error.PrivateHandshakeNotSupported`.
  `secrettree.zig` owns §9's ratchets, but this object does not drive them
  per epoch; that has its own generation and deletion policy. The
  passive-client vectors contain only `PublicMessage`s, and
  `kat_passive_test.zig` ASSERTS that, so the boundary stays an honest one
  rather than an untested claim.
- **No §7.3/§10.1 admission validation** (Part 3). `processCommit` checks
  the leaf properties §12.4.2 names in its own bullets —
  `leaf_node_source == commit`, the committer's encryption key actually
  changing, no `UpdatePath` public key already present in the tree — and
  verifies the signature on every `LeafNode` it installs. It does not check
  lifetimes, credential acceptability or capability support.
- **No external Commits (§12.4.3.2)** — at the time of Part 7. Built in
  Part 9; see there.
- **Not atomic.** A failure after the tree is mutated poisons the object
  (`error.GroupPoisoned`) instead of rolling back. Backlog.

Two §12.2 rules are explicitly application-defined by the RFC ("multiple Add
proposals that ... represent the same client according to the application,
for example, identical signature keys"). They are implemented on the RFC's
own parenthetical reading and exposed as `group.Policy`, defaulting ON,
because the failure they prevent — a group silently containing two leaves
for one client — is not detectable afterwards.

### `fromWelcome` re-sequences the join rather than calling `welcome.join`

`welcome.join` takes the signer's public key as a PARAMETER, because Part 6
had no way to resolve a leaf index to a key. But `GroupInfo.signer` is
inside the encrypted `GroupInfo`, and so is the tree that resolves it, so a
caller holding only a Welcome cannot supply that argument without decrypting
first. Part 7 can, because it owns the tree. `fromWelcome` runs the same
steps in the same order over the same public building blocks
(`welcome.decryptGroupSecrets`/`welcomeKeyNonce`/`decryptGroupInfo`/
`verifyTreeHash`, `keyschedule.deriveEpochFromJoiner`/
`verifyConfirmationTag`, `transcript.interimTranscriptHash`) and adds the
three steps §12.4.3.1 lists that Part 6 explicitly left to the caller:
verify the tree hash, verify the parent-hash chain
(`treekem.validateParentHashes`), and find this client's own leaf. It also
checks that a re-encode of the resulting `GroupContext` equals the bytes the
key schedule just consumed — otherwise every later epoch, which uses the
re-encoded form, would silently diverge from the first.

### Memory model

One arena for retained state, the caller's allocator for scratch. This
module's decoders alias their input buffers, and a group's tree accumulates
leaves aliasing a DIFFERENT buffer per epoch (the Welcome's `GroupInfo`,
then each Commit's `UpdatePath`, then each Add's `KeyPackage`).
Deep-copying every `LeafNode` would mean a second implementation of
`tree.zig`'s decode layer, so `Group` copies each message it retains state
from into its own arena and decodes from that copy. Group state is retained
wholesale and dropped wholesale, which is how MLS treats it too. The cost is
recorded in the Backlog: the arena grows monotonically with session length.

### Teeth

Each of the three vectors was corrupted by ONE hex nibble and the failure
checked to name the stage that diverged, then restored:

- one byte inside `passive-client-welcome`'s first `welcome` blob →
  `fromWelcome failed: DecryptionFailed` (the group-info AEAD layer);
- one byte inside `passive-client-handling-commit`'s entry-0 epoch-1
  `commit` → `entry 0, epoch index 1: processCommit failed: MacMismatch`
  (the `membership_tag`, i.e. §12.4.2's second bullet, before anything is
  applied);
- one byte of the EXPECTED `epoch_authenticator` at epoch 150 of the
  200-Commit session → `entry 0, epoch index 150: epoch_authenticator
  diverged`, with the differing bytes printed.

Every diagnostic names the vector, the entry and the epoch index, because a
failure at epoch 137 of 200 that says only "slices differ" is not
actionable.

Beyond the vectors, `keyschedule.zig`'s §8.3 tests pin the export-context
string's exact bytes and the HPKE `suite_id`'s exact bytes as literals
(a round trip alone passes for ANY label both sides agree on), and check
that the derived `init_secret` is bound to the group's external key and to
the `kem_output` — including the fact that decapsulating with the wrong
private key yields a DIFFERENT secret rather than an error, since X25519
decap cannot fail on a well-formed point. What makes an external Commit safe
is therefore the `confirmation_tag`, not §8.3's exchange, and the test says
so.

## Part 8 — Creating Commits (2026-07-29)

**Files:** `treekem.zig` (`stageUpdatePath`/`sealUpdatePath` — the sender
half of §7.5, and the first consumer `treekem.zig`'s own merge machinery has
had in the send direction), `group.zig` (`Group(S).create`,
`createProposal`, `updateLeaf`, `createCommit`, `buildWelcome`, and the
shared `applyProposals`), `keypackage.zig` (`create`), `tree.zig`
(`LeafNode.sign`), `kat_commit_test.zig`.

Part 7 left a client that could join a group and follow it but not speak.
This part is the other half of every one of those verbs, and it is
deliberately the SAME object: `createCommit` and `processCommit` are two
methods on one `Group(S)`, over one tree and one transcript, because a
committer must land in exactly the state its receivers land in.

### What the RFC actually calls these, because the brief for this part was
### wrong twice

The brief for this batch located `UpdatePath` generation via
"`treemath.common_ancestor_*`, which has never had a consumer". Neither half
is right. `treemath.zig` has never contained `common_ancestor_semantic` or
`common_ancestor_direct` at all — RFC 9420 Appendix C does publish them, and
`SPEC.md`'s own Backlog has recorded them as NOT ported since Part 1. And
the operation they name already had a consumer before this part started:
Part 7's `group.commonAncestor` (a direct-path intersection, not a port of
Appendix C) has been serving §12.4.3.1's private-key installation step since
`fromWelcome` landed. That Backlog entry was stale in the other direction
too — it said the two would "arrive together or not at all" with the
group-state object, and the group-state object arrived without them.

The brief also cited §12.4.2 for Commit creation. Creation is **§12.4.1**;
§12.4.2 is processing, which Part 7 built. The distinction matters here
because the two sections are NOT mirror images: §12.4.1 has bullets §12.4.2
has no counterpart for (constructing the `GroupInfo`, deriving the per-member
path secret, building the `Welcome`), and it is the section that specifies
the ORDER in which a Commit and its Welcome are produced.

One more section disagrees with itself, and a creator has to pick a side:

> **§12.4 vs §12.4.2 on when a path is required.** §12.4.2's bullet says
> "Verify that the path value is populated if the proposals vector contains
> any Update or Remove proposals, or if it's empty." §12.4's own pseudocode
> says `pathRequiredTypes = [update, remove, external_init,
> group_context_extensions]`. §12.4 is the section that defines the "Path
> Required" column of §17.4's registry and states the rule as executable
> logic, so `applyProposals` follows §12.4 — which is also the safe
> direction to disagree in for a sender. All three `passive-client-*.json`
> sessions still replay green under the stricter rule, so the reference
> implementation that recorded them does not emit a Commit the two readings
> would classify differently.

### What it is verified against

`kat_commit_test.zig`, and the file is explicit about which of its claims
are anchored and which are round trips, because creation cannot be fully
anchored by anything:

| Claim | Kind | Against what |
|---|---|---|
| Every `node_pub[n]` of a generated `UpdatePath`, in order | **ANCHORED** | `treekem.json`'s `update_path.nodes[n].encryption_key`, byte-exact, for all 62 update paths |
| The generated `commit_secret` | **ANCHORED** | `treekem.json`'s `commit_secret`, byte-exact, all 62 |
| The committer leaf's `parent_hash` | **ANCHORED** | `treekem.json`'s `update_path.leaf_node.parent_hash`, byte-exact, all 62 |
| The per-node ciphertext COUNT, and the node COUNT | **ANCHORED** | the lengths of `update_path.nodes` and of each `encrypted_path_secret` |
| Every recorded member opens the generated `UpdatePath` and recovers its own recorded path secret and the recorded `commit_secret` | round trip through this module's decap, over the vector's tree, the vector's private keys and the vector's expected plaintexts | `treekem.json`'s `leaves_private` + `path_secrets` |
| A Commit created on a state restored from a recorded session lands a new member on the committer's `epoch_authenticator` | round trip, from an externally-produced starting state | `passive-client-handling-commit.json`, `passive-client-random.json` (after all 200 Commits) |
| Two to four `Group(S)` objects run a group through Commits in both directions and agree on epoch, tree hash, confirmed transcript hash and `epoch_authenticator` at every step | round trip | `group.zig`'s own tests |

**How the first three become anchored at all.** A Commit has three random
inputs — §7.4's `path_secret[0]`, §7.5's fresh leaf key pair, and one HPKE
ephemeral per ciphertext — so its bytes are unreproducible by construction.
But `treekem.json` publishes, per update path, the path secret each
receiving leaf decrypts at its overlap node; for the receiver whose overlap
is the FIRST node of the sender's filtered direct path, that value *is* the
sender's `path_secret[0]`. Injecting it makes `stageUpdatePath`
deterministic, and everything it derives becomes comparable with what the
implementation that recorded the vector actually produced. The seed is
located at runtime (not hardcoded), and the test fails with
`NoSeedableReceiverInVector` rather than silently degrading to a round trip
if a future re-fetch changes the shape.

Two properties make that stronger than it first looks:

- **the leaf content does not matter.** `ParentHashInput` for any node reads
  that node's key, its stored `parent_hash`, and the tree hash of a COPATH
  subtree — and no copath subtree of the sender's own direct path contains
  the sender's leaf. So a dummy committer leaf still produces the vector's
  exact parent hashes;
- **one digest pins the whole chain.** §7.9's `ParentHashInput` embeds the
  parent's own stored `parent_hash`, so a matching hash at the leaf implies
  a matching hash at every node above it, all the way to the root.

### What building the send half found on the RECEIVE side

A passive client never generates anything, so Part 7's replays exercised
every receive path and no send path. Three problems surfaced here that all
live in Part 7's code, and one change that is faithfulness rather than a
fix. Each is listed with what actually covers it, because two of them are
not visible to any upstream vector at all.

1. **§7.5's exclusion applied to the §4.1.2 FILTER, not only to the
   resolution** — a specification misreading, corrected in
   `treekem.filteredDirectPath`, which no longer takes an excluded set.
   The full argument is in that function's doc comment and in the
   correction box in "Part 7" above; the short form is that dropping the
   node leaves it blank, which puts a same-Commit-added leaf into the
   resolution of a blank node and breaks §7.9.2's third criterion.
   *Covered by* the "adding a member into the committer's OWN sibling leaf"
   scenario, whose final step is the new member JOINING — `fromWelcome`
   runs `validateParentHashes`, which returns `error.Malformed` under the
   old reading. Reverting the fix also breaks four other tests including
   `treekem.json`'s `processUpdatePath` KAT.
2. **A joiner's path-secret chain that stepped through filtered-out nodes.**
   `group.derivePathSecretsUp` walked the joiner's UNFILTERED direct path
   from the common ancestor and applied one `DeriveSecret(., "path")` per
   node. §7.4's chain runs along the committer's FILTERED direct path, so
   every node above a filtered-out one was off by a derivation step. The
   failure mode is the quiet kind: `adoptPathSecrets` validates each stored
   secret against the node's public key and silently drops the ones that do
   not match, so nothing fails at join time — it surfaces epochs later as a
   Commit the member cannot decrypt. Now skips blank nodes, which on a
   just-merged tree is exactly "the committer's filtered direct path".
   *Covered by* a purpose-built scenario: three members removed so that a
   whole copath subtree is blank, then a joiner added below it, then an
   assertion that the joiner holds a path secret for BOTH surviving nodes
   of its direct path. No recorded session reaches this shape — the first
   version of this test did not either, and the fix was verified uncovered
   before the test was written to cover it.
3. **No way to adopt the private key of one's own Update.** §12.3 applies
   Update proposals BEFORE the `UpdatePath` is decrypted, so by the time
   `processUpdatePath` runs, the updating member's leaf in the tree already
   carries the Update's NEW `encryption_key` — and the committer sealed a
   ciphertext to exactly that key. A member still holding its old private
   key fails with a bare AEAD rejection several layers down. `Group` now
   retains `pending_updates` (public key → private key, epoch-scoped) and
   swaps the key in as the Update is applied, whoever committed it.
   *Covered by* the three-member scenario, which is shaped the way it is
   (carol proposes, dave commits by reference) because that is the only
   legal shape — §12.2 forbids an Update generated by the committer. This
   is the one that fired first, and it fired as an unexplained
   `AuthenticationFailed` inside HPKE.

And the faithfulness change, labelled as such rather than as a find:

4. **§7.9.1's "next non-blank parent node" is now walked as written**
   (`nextNonBlankAncestor`), where the old code walked §4.1.2's filter
   instead. §7.9.1 gives both descriptions as one thing, and at every call
   site they provably ARE one thing: `parentHash` is only called on a leaf
   whose direct path was just merged, and the merge blanks that path and
   re-fills exactly the filtered part. **No test distinguishes the two, and
   reverting this change leaves the suite green** — that was checked, not
   assumed. It is kept because it is what the section says and because it
   stays correct if `parentHash` is ever called on a tree whose upper path
   an Update or Remove blanked, where a blank node can sit above a
   non-empty copath resolution.

### The §7.3/§10.1 boundary, decided rather than deferred

The brief asked whether §10.1/§7.3's admission rules belong here. §7.3's
list splits cleanly, and the split is the boundary:

**Stays the caller's (Part 3)** — each needs something this module does not
have. "The credential in the LeafNode is valid, as described in §5.3.1" is
an Authentication Service, i.e. an application. The `lifetime` window needs
a clock, and this module reads none (`meta.platform = .any`, no I/O in it at
all). `required_capabilities` compatibility and "the credential type is
supported by all members" are policy over an extension registry the
application owns. All of §10.1 is the same shape.

**Taken here** — each needs only the leaf and the tree, and §12.2's closing
rule makes a Commit INVALID if "after processing the Commit the ratchet tree
is invalid, in particular, if it contains any leaf node that is invalid
according to Section 7.3". A creator that skipped them would emit Commits
its own receivers must reject, which is not a defensible place for a sender
to be:

- every extension in `LeafNode.extensions` listed in
  `capabilities.extensions` (`Policy.check_leaf_extensions_supported`);
- `signature_key`/`encryption_key` unique across the group, plus
  §12.4.3.1's "the encryption key in the parent node does not appear in any
  other node of the tree" (`Policy.check_key_uniqueness`), swept once per
  epoch transition because it is a property of the finished tree and no
  earlier point can answer it.

Both default ON and both are `Policy` switches. Both run in BOTH directions,
and all three `passive-client-*.json` sessions replay green with them on —
which is itself a small piece of evidence that the reading is the same one
the reference implementation uses.

### Where the boundary fell, and where it moved to

§12.4.3.2 was NOT in Part 8, on the ground that it is a second substantial
piece rather than a few lines on top of `createCommit`, and that a
half-built external Commit next to a finished regular one would make it
impossible to tell which of the two a failing test was about. Part 9 below
builds it, in both directions at once, for exactly that reason.

### Everything else this part does NOT do

- **No `PrivateMessage` handshakes**, in either direction. Unchanged from
  Part 7: `error.PrivateHandshakeNotSupported`.
- **`createCommit` is not atomic**, on exactly the terms `processCommit` is
  not: a failure after the tree has been mutated poisons the object. The
  refusals that CAN be made cheaply happen first, though — the whole §12.2
  validation and every Add's KeyPackage signature are checked before
  `self.poisoned` is set, so the common rejection cases leave a usable
  group, and a test pins that.
- **No committer-chosen leaf content.** §7.5 allows a Commit to change the
  committer's credential, capabilities or extensions ("The application MAY
  specify other changes to the leaf node"); `createCommit` carries the
  current leaf's content over and rotates only the keys §7.5 requires.
  Supporting the rest means deep-copying caller-owned credential and
  capability data into the group's arena, which is plumbing this batch did
  not add. `treekem.StageParams` already exposes the seam for a caller that
  wants to do it by hand.
- **No `ReInit` follow-through** (§11.2) and no branching (§11.3). A
  `ReInit` proposal can be committed — §12.2's "a ReInit proposal together
  with any other proposal" rule is enforced — but nothing creates the
  successor group.

### Teeth

- **The anchored generation test has a negative control.** The same
  generation run from a path secret that is one bit off must differ from the
  vector in every anchored field — node public keys, `commit_secret` and the
  leaf's `parent_hash` — while still producing a path of the SAME length,
  since the §4.1.2 filter is a property of the tree and not of the secrets.
  Without that control, a comparison against a value the test itself
  computed would look identical to a comparison against the vector.
- **A Commit corrupted in one byte is rejected** by a receiver that
  otherwise accepts it (`MacMismatch`, §12.4.2's second bullet), and the
  receiver does not advance; the uncorrupted Commit is then accepted and
  both sides match. A `Welcome` corrupted in one byte fails
  `DecryptionFailed` and produces no member.
- **`createCommit` refuses the lists a receiver would reject** — a Remove of
  the committer, two Adds with the same signature key, an inline
  ExternalInit — and the group is still usable afterwards, which is what
  distinguishes a pre-mutation refusal from a poisoned object.
- **The zero-ciphertext `UpdatePathNode` is tested, not assumed away.** A
  one-member group adding a second member produces an `UpdatePath` whose one
  node carries NO ciphertexts, because its only copath child is the leaf
  that same Commit added and §7.5 excludes it from the resolution. That is
  the first Commit of every group's life; the test asserts the node count,
  the empty ciphertext vector, and that the joiner is nonetheless merged at
  that node via §12.4.3.1's `path_secret`.
- **Every claimed fix was sabotage-checked.** Each of the three defects
  above was re-introduced and the suite re-run, and the SPEC records which
  tests catch it. The one change no test catches (§7.9.1's wording) says so
  in the same list rather than being presented alongside the others.

## Part 9 — External Commits (2026-07-29)

RFC 9420 §12.4.3.2: the second way into a group. A newcomer turns a
published `GroupInfo` into a Commit that adds itself, and no existing
member has to be online for it. Both directions land together —
`Group(S).joinByExternalCommit` and a `new_member_commit` branch through
`processCommit` — because there is no upstream vector for either, so the
only thing that can anchor one is the other.

### What the earlier decomposition got right, and the two things it missed

The four-part decomposition recorded at the end of Part 8 held up against
the RFC and against the code. §12.2's second, whitelist-shaped procedure;
a `new_member_commit` branch with no `membership_tag` and the signature key
read out of `commit.path.leaf_node`; leaf assignment on both sides; §8.3's
`init_secret` substituted for the previous epoch's — all four are real, all
four are what the work consisted of. Every symbol it claimed already
existed does exist and has the shape it needed
(`keyschedule.externalInitSender`/`externalInitReceiver`,
`welcome.GroupInfo.externalPub`, `framing.SenderType.new_member_commit`,
`content.Proposal.external_init`, `createCommit`'s `include_external_pub`).

It missed two REQUIREMENTS, both stated in §12.4.3.2 rather than in §12.2,
and both of which a receiver has to enforce:

- **"The Commit MUST NOT include any proposals by reference, since an
  external joiner cannot determine the validity of proposals sent within
  the group."** This is not a §12.2 rule and so is not in §12.2's
  whitelist; a whitelist built from §12.2 alone accepts a by-reference
  ExternalInit. It is `error.ProposalByReferenceInExternalCommit`, checked
  per entry of the resolved list.
- **"External Commits MUST contain a path field (and is therefore a 'full'
  Commit)."** §12.4's `pathRequiredTypes` already contains `external_init`,
  so `needs_path` is true for any list that passes the whitelist and the
  two rules coincide today — but they are independent rules and only one of
  them is unconditional. Both are spelled out.

It also under-described the leaf assignment slightly. It said "the leftmost
blank leaf node in the new ratchet tree", which is §12.4.1's wording;
§12.4.2's wording for the receiving side is "add a blank leaf to the right
side of the new ratchet tree" where §12.4.1 says "expand the tree to the
right as defined in Section 7.7". These describe the same operation, and
`tree.RatchetTree.assignBlankLeaf` implements §7.7's doubling — the same
arithmetic `addLeaf` uses, deliberately, so that a group reaching a given
shape by an Add and by an external join has the same tree.

### `assignBlankLeaf` is not `addLeaf`, and the difference is load-bearing

Both hunt the leftmost blank leaf. `addLeaf` is §12.1.1's Add: it installs
a leaf and appends the new index to `unmerged_leaves` on every non-blank
ancestor, because an Add publishes a leaf no existing path secret covers.
An external Commit's sender fills its slot from its own `UpdatePath`
instead, and §7.5's merge blanks that entire direct path and rebuilds it
with EMPTY `unmerged_leaves` — so the Add bookkeeping would write state the
very next step erases. Reserving the index and touching nothing else is the
whole operation.

### One function builds both flavors of Commit

`createCommit` and `joinByExternalCommit` are one implementation
(`commitInner` plus a `CommitMode`), for the same reason §12.3's
application order is one implementation shared between sending and
receiving: §12.4.1 states its step list once and §12.4.3.2 states the
external flavor as substitutions inside it ("In principle, external Commits
work like regular Commits. However, their content has to meet a specific
set of requirements"). A second copy would be a second place for the
provisional-GroupContext ordering, the sign-then-confirm ordering and
§12.3's application order to drift — and a drift in any of them produces a
Commit that looks well-formed and that nobody can process.

The substitutions, in order: which §12.2 procedure validates the list; the
leaf index (assigned, not read from `my_leaf_index`); where the base leaf's
identity content comes from (the joiner's KeyPackage, not `ownLeaf`); the
`Sender` arm; the `init_secret`; and whether a `membership_tag` exists at
all. Everything else — §12.3's application, the path, the transcript, the
key schedule, the `GroupInfo` — is the same code.

### The joiner runs against a bootstrap group state whose secrets are zero

A non-member has none of the epoch it is committing against.
`joinByExternalCommit` builds a `Group(S)` from the `GroupInfo` — group id,
epoch, tree hash, confirmed transcript hash, extensions, tree, and the
interim transcript hash derived from the published `confirmation_tag` — and
fills `secrets` with zeroes. `commitInner` reads exactly two fields of it:
`init_secret`, which `.external` mode replaces with §8.3's, and
`membership_key`, which `.external` mode does not use because §6.2 gives
that sender no tag field. Zeroes rather than `undefined` so a mis-wired
external branch produces a deterministic, testable wrong answer instead of
stack garbage; the whole struct is overwritten with the new epoch's secrets
before the function returns.

### What the joiner cannot verify, and why that is safe

It verifies the tree against the signed `tree_hash`, the parent-hash chain,
and the `GroupInfo` signature under the signer's leaf key — the same three
checks `fromWelcome` runs, through the same function
(`verifiedTreeFromGroupInfo`, extracted so the ORDER cannot drift between
the two entry points: the signature cannot be checked before the tree is
known, and the tree cannot be trusted before its root hash is matched
against the `GroupContext` the signature covers).

It CANNOT verify the `confirmation_tag` the `GroupInfo` carries; that needs
the epoch's `confirmation_key`, which is exactly what a non-member lacks. A
forged tag is not silently absorbed, only detected later and by somebody
else: the tag feeds §8.2's `interim_transcript_hash`, so a wrong one gives
the joiner a different `confirmed_transcript_hash` for the new epoch than
every member computes, and every member rejects the Commit at §12.4.2's
`confirmation_tag` bullet. The joiner lands in an epoch of one; it never
lands in the group holding state nobody else holds.

Symmetrically, the identity in the joiner's leaf is vouched for by nothing
in this module. §12.4.3.2 says accepting an external Commit "follows the
same rules that are applied to other handshake messages", i.e. it is the
receiving application's call — the same place §7.3's credential bullet
lands.

### A reading a different implementer could reasonably make differently

§12.2's external procedure is a CLOSED list ("the list is valid if it
contains only the following proposals"), and it does not repeat the regular
procedure's "multiple PreSharedKey proposals that reference the same
PreSharedKeyID" rule. `validateExternalProposalList` follows it literally
and permits a repeated `PreSharedKeyID`: §8.4's chain is
position-dependent, both sides derive the same `psk_secret` from the same
repeated list, and correctness costs nothing. An implementer who reads
§12.2's "an individual proposal that is invalid as specified in Section
12.1" as carrying over would reject it. Nothing in this module depends on
the choice, and no vector exercises it.

### Scope, stated precisely

- **Resumption PSKs in an external join are CALLER-SUPPLIED.** A group
  entered this way starts with an empty `resumption_history`, so there is
  nothing to look a resumption `PreSharedKeyID` up in.
  `ExternalJoinParams.resumption_psks` is how a client hands in prior-epoch
  secrets it kept out of band — the resync case. The library checks that
  every entry is `KDF.Nh` wide and that a `PreSharedKeyID` resolves only
  against an entry naming the same `usage`, `psk_group_id` and `psk_epoch`;
  it cannot check that the value is genuinely that group's `resumption_psk`
  for that epoch, and says so in `ResumptionPsk`'s doc comment. A wrong one
  costs a failed join and nothing more: every member resolves the same id
  from its own history and rejects the Commit at the `confirmation_tag`.
  The group's own history is consulted FIRST, so a caller-supplied entry can
  never shadow a secret this group derived itself.
- **§12.4.3.2's advice for gating the resync flavor contradicts §12.1.4, and
  §12.1.4 wins.** §12.4.3.2's closing paragraph tells applications they may
  allow a resync Commit "only if [it] contain[s] a 'reinit' PSK proposal
  that demonstrates the joining member's presence in a prior epoch of the
  group". §12.1.4 makes a PreSharedKey proposal invalid when it names usage
  `reinit` outside §11.2's reinitialization, and §11.2 restates it as a flat
  MUST ("A PreSharedKey proposal with type resumption and usage reinit MUST
  be considered invalid"); §11.3 says the same for `branch`. An external
  Commit is not a reinitialization, so the proposal §12.4.3.2 describes is
  one every conforming receiver must reject. §12.4.3.2's paragraph is
  non-normative application advice ("can choose to") and §12.1.4's is a
  MUST, so `validatePskProposal` enforces the MUST — unconditionally, since
  neither §11.2 nor §11.3 is built here — and returns
  `error.ResumptionPskUsageNotAllowed`. The same gate is reachable with
  usage `application`, which demonstrates presence in a prior epoch exactly
  as well: only a client that held that epoch's `resumption_psk` can produce
  a Commit the members accept. This is the shape the tests exercise.
- **§12.1.4's other two conditions are enforced too**, by both §12.2
  procedures, because §12.1.4 states them about the proposal rather than
  about the list: the `psk_nonce` must be `KDF.Nh` wide
  (`error.PskNonceLength`), and unassigned `ResumptionPSKUsage` codepoints
  are NOT rejected — §12.1.4 names exactly two forbidden usages and this
  follows it literally rather than inventing a rule for values a future
  document may define.
- **A resumption `PreSharedKeyID` is matched on `psk_group_id` AND
  `psk_epoch`, not the epoch alone.** This was a live defect until
  2026-07-29: `resolvePsksFromIds` matched a resumption id against the
  group's `resumption_history` by epoch number only, so an id naming ANY
  `psk_group_id` resolved to this group's own secret for that epoch. It is
  the kind of bug no round trip can find — sender and receiver applied the
  same wrong rule to the same id, agreed on the `psk_secret`, and the Commit
  went through. What exposes it is the external-join path, where one side's
  value is caller-supplied and the other's is not; see the "naming ANOTHER
  group" test.
- **No resumption PSKs in a WELCOME.** `fromWelcome` resolves the
  `GroupSecrets` PSK list with no resumption source at all: the client has
  lived through no epoch of a group it is only now joining, and the
  `GroupInfo` naming that group has not been decrypted yet. §11.2/§11.3's
  reinit and branch flows are the ones that would need it, and neither is
  built.
- **The resync flavor is built but only partly exercised.** §12.2's "at
  most one Remove, with which the joiner removes an old version of
  themselves" is enforced, and a Remove in an external Commit is applied by
  the shared `applyProposals` before the leaf is assigned — so the joiner
  can legitimately land in the leaf its own old appearance just vacated.
  What is NOT tested is the case where the RECEIVER is the removed member.
- **§12.2's extra condition on that Remove** — "the LeafNode in the path
  field MUST meet the same criteria as would the LeafNode in an Update for
  the removed leaf ... the credential MUST present a set of identifiers
  that is acceptable to the application for the removed participant" — is
  an Authentication Service question and stays the application's, for the
  same reason §7.3's credential bullet does.
- **No committer-chosen leaf content**, unchanged from Part 8. The joiner's
  KeyPackage supplies the identity half of its leaf and §7.5 samples the
  encryption key; nothing else is settable.

### Teeth

- **The round trip is a genuine one.** Three parties — one of whom was a
  stranger a moment earlier — end on the same `epoch_authenticator`, which
  is `DeriveSecret(epoch_secret, "authentication")` and therefore
  downstream of the §8.3 secret, the tree hash, the whole transcript and a
  leaf index that appears nowhere on the wire. The two sides reach that
  secret by OPPOSITE halves of §8.3 (`SetupBaseS` on the joiner,
  `SetupBaseR` on each member), so agreement is not two copies of one
  computation. The group is then driven one further Commit BY the newcomer
  and processed by the founder, because a join that produced a state which
  cannot take another Commit would satisfy every other assertion.
- **The leftmost-blank rule is pinned by index, not by agreement.** A
  three-member group with bob removed leaves TWO blanks (leaf 1 and leaf
  3); the joiner must land at 1. This matters because sender and receiver
  call the SAME function: a leftmost→rightmost change keeps them agreeing
  and the round trip alone would pass. The other branch — a full tree,
  §7.7 expansion, "the leftmost NEW blank leaf" — is pinned in the round
  trip test.
- **The whitelist is enforced END TO END, against a hostile joiner.** The
  reject tests re-sign a real external Commit with the joiner's own
  signature key after swapping its proposal list — which is exactly what an
  attacker can do, since §6.1 verifies a `new_member_commit` with the key
  in `commit.path.leaf_node`. So a receiver cannot reject a bad list by
  signature check, and these tests reach §12.4.2's bullet 4 rather than
  failing at bullet 3. Four distinct typed errors: an Add
  (`ProposalNotAllowedInExternalCommit`), no ExternalInit
  (`MissingExternalInit`), two (`MultipleExternalInit`), two Removes
  (`MultipleRemoveInExternalCommit`), plus a by-reference proposal that
  resolves correctly and is still refused
  (`ProposalByReferenceInExternalCommit`). Each leaves the group unpoisoned
  and at its old epoch, and the unspoiled Commit is then accepted — which
  is what makes the refusals about the list and not about the fixture.
- **Both halves of "no `membership_tag`" are checked.** On the wire, a tag
  appended to the message is trailing input and `processCommit` refuses to
  decode it (`error.Malformed`) rather than ignoring it. In the struct,
  `rejectExternalCommitFraming` returns `UnexpectedMembershipTag`.
- **Mutation-tested.** Three deliberate defects were introduced and
  reverted, and the SPEC records which tests caught each:
  `assignBlankLeaf` returning the RIGHTMOST blank — caught ONLY by the
  leftmost test, with the round trip still green, which is the point of
  that test existing; `processCommit` keeping the previous epoch's
  `init_secret` instead of §8.3's — caught by all five external-Commit
  tests with `MacMismatch` at §12.4.2's `confirmation_tag` bullet; and the
  whitelist's `else` arm made permissive — caught by both whitelist tests,
  with the sender-side one showing that `joinByExternalCommit` would
  otherwise happily emit a Commit smuggling an Add.
- **One thing NO test catches, stated rather than glossed:** deleting the
  `rejectExternalCommitFraming` CALL from `processCommit`. No decode path
  can produce a `PublicMessage` with a `new_member_commit` sender and a
  non-null `membership_tag`, so the call site is unreachable through the
  public API; the guard is defensive against a future path (a
  `PrivateMessage` unprotect, a caller-built struct) and its doc comment
  says so. The function itself is tested directly.

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
- **A hostile `Welcome` (Part 6).** Everything in a Welcome arrives from
  someone the joiner has not yet authenticated. The order of `join`'s
  checks is therefore the security property, not an implementation detail:
  nothing is trusted until the `confirmation_tag` verifies under a
  `confirmation_key` the joiner derived itself from the `joiner_secret` it
  was handed and the `GroupContext` it saw signed. A `joiner_secret` for a
  different epoch, a substituted `GroupContext`, or a `GroupInfo` from
  another group all fail there. Ahead of that: the cipher suite is checked
  before any decryption; the `KeyPackageRef` lookup is a plain byte compare
  (a public hash of a public object — nothing for a timing channel to
  leak); an unknown ref is `error.NoMatchingKeyPackage` rather than a
  decrypt attempt against an arbitrary slot; and the PSK list must be
  exactly the one the caller resolved (`error.PskMismatch`). What `join`
  does NOT check, and the caller MUST, is listed in its doc comment — most
  importantly that `GroupInfo.signer` names a non-blank leaf whose
  `signature_key` is the one passed in, and the tree-integrity block.
- **A ratchet tree from an untrusted source (Part 6).** §12.4.3.3 permits
  the tree to arrive out of band precisely because `verifyTreeHash` binds
  it to the SIGNED `GroupContext`. That check is exposed as its own
  function rather than folded into `join`, because the tree may
  legitimately not be present at join time — but a caller that uses a tree
  without it has no integrity guarantee on it at all.
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
- **§8.3 external init — DONE 2026-07-29** (`keyschedule.externalInitSender`/
  `externalInitReceiver`), and honestly labelled: it is the only derivation
  in `keyschedule.zig` with no external MLS anchor, so it is pinned by a
  sender/receiver round trip plus RFC 9180's own KATs one layer down, not
  by a byte-exact interop vector. Its export-context string and HPKE
  `suite_id` are pinned as literals separately, because a round trip alone
  cannot catch a label both sides get wrong the same way.
- **External Commits (§12.4.3.2) — DONE 2026-07-29 (Part 9).** Both
  directions in one batch (`Group(S).joinByExternalCommit` and
  `processCommit`'s `new_member_commit` branch), because with no upstream
  external-commit vector the only thing that can anchor one direction is
  the other. The four-part decomposition recorded here beforehand held up;
  it missed §12.4.3.2's "MUST NOT include any proposals by reference" and
  its "MUST contain a path field", both of which are receiver-enforced
  rules that live outside §12.2. See "Part 9" for what anchors it and for
  what it deliberately leaves out (the resync case where the RECEIVER is the
  removed member). Resumption PSKs in an external join were left out here
  and closed on 2026-07-29 via `ExternalJoinParams.resumption_psks`; closing
  them turned up a §8.4 lookup defect (epoch-only matching) and a genuine
  contradiction between §12.4.3.2 and §12.1.4 — both under "Part 9" above.
- **`createCommit` cannot change the committer's leaf CONTENT.** §7.5 allows
  a Commit to carry a new credential, capabilities or extensions for the
  committer's leaf; Part 8 carries the current content over and rotates only
  the keys. The blocker is plumbing, not design: caller-owned credential and
  capability data would have to be deep-copied into the group's arena the
  way `dupExtensions` does for GroupContext extensions.
  `treekem.StageParams` already exposes the seam.
- **`passive-client-*.json` — CLAIMED and green 2026-07-29** (Part 7). All
  three replay end to end, including the 200-Commit session. See "Part 7".
- **`framing.zig` exposes no single `unprotectPrivate`.** Decryption is
  genuinely two-phase (§6.3.2's sender data names the key that §6.3.1's
  content needs), and the key lookup between the phases is the caller's, so
  the three stages are exposed separately rather than behind a callback.
  Part 7's group object did NOT make the lookup internal, because it does
  not drive the §9 secret tree per epoch — see
  `group.Error.PrivateHandshakeNotSupported`. Revisit together with that.
- **`group.processCommit` is not atomic.** A Commit that fails a check
  after the tree has been mutated leaves the object poisoned
  (`error.GroupPoisoned`) rather than rolled back. Real rollback means
  processing into a COPY of the ratchet tree and swapping on success, which
  is a memory-model change rather than a bug fix: the tree's byte fields
  alias the arena, so a copy needs either a deep clone or a second arena.
  The current behaviour fails closed and says so, which is why this is a
  backlog item and not a defect.
- **`group.Group`'s arena grows monotonically with session length.** Every
  Commit whose `UpdatePath` or Add contributes a `LeafNode` is copied into
  the group's arena and never freed, because the tree aliases those bytes
  (`tree.zig`'s stated convention). For the 200-Commit vector this is a few
  megabytes and irrelevant; for a long-lived group it is a leak in all but
  name. The fix is the same one the atomicity item needs — owning leaf
  bytes rather than aliasing them — so do both together.
- **`hpke` does not export the HPKE `suite_id`.** `Context.exportSecret`
  takes one as a parameter, but `schedule.suiteIdOf` is private, so
  `keyschedule.hpkeSuiteId` restates the `Aead` -> `aead_id` mapping in
  order to call it. `hpke.suite.suiteId` and `Kem.kem_id` ARE public, so
  only that one mapping is duplicated, and it `@compileError`s rather than
  guessing for an unregistered AEAD. The clean fix is upstream in `hpke`
  (export `suiteIdOf`, or have `Context` carry its own suite id); this
  batch was scoped out of that module.

- **Scratch-buffer size (512 bytes) — RESOLVED 2026-07-28** by the second
  of the two options this item listed: `crypto.ExpandWithLabelScratch` takes
  a caller-supplied slice and `crypto.kdfLabelLen` sizes it exactly, while
  `ExpandWithLabel` keeps the fixed-buffer convenience for the bounded
  callers. `keyschedule.zig` uses it for the two `GroupContext`-carrying
  derivations; a regression test drives a 4 KB context through both entry
  points and asserts the fixed one refuses rather than truncates.
- **§12.4's `pathRequiredTypes` and §12.4.2's own bullet disagree**, and
  this module follows §12.4 (the section that defines §17.4's "Path
  Required" registry column). §12.4.2 names only Update, Remove and an empty
  list; §12.4 adds `external_init` and `group_context_extensions`. Following
  the broader rule can only reject Commits a §12.4.2-literal implementation
  would accept — no recorded session in `passive-client-*.json` contains
  one, so the disagreement is unobservable against the vectors available. If
  it ever becomes observable, the receive side is the one to relax, not the
  send side.
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
  `right`/`parent`/`sibling` only). **This entry was stale as written, and
  is corrected 2026-07-29.** It predicted the two would arrive with the
  group-state object; the group-state object arrived in Part 7 without
  them. §12.4.3.1's private-key installation step is served by
  `group.commonAncestor`, a direct-path intersection written where it is
  used rather than a port of Appendix C, and Part 8's send side needs
  something the RFC's `common_ancestor_*` does not compute at all — "the
  lowest node OF THE COMMITTER'S FILTERED DIRECT PATH covering this leaf",
  which is `treekem.Staged.pathSecretFor`. Porting Appendix C's two
  functions is therefore now a completeness item with no consumer, not a
  prerequisite for anything.
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
