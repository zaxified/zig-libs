// SPDX-License-Identifier: MIT
//! mls — Messaging Layer Security (RFC 9420), the scalable group-messaging
//! complement to this repo's 1:1 `signal` module. A multi-part arc.
//! **Part 1: foundation** — the mandatory cipher suite, the labeled-crypto
//! primitives every later derivation composes, the ratchet tree's pure
//! integer math, and the TLS-presentation-language wire codec RFC 9420 is
//! written in — COMPLETE. **Part 2: TreeKEM — COMPLETE.** The ratchet
//! tree's data structures/wire codec/tree-hash/tree-editing plus the five
//! algorithmically-hard cores (`resolution`/`parentHash`/
//! `validateParentHashes`/`processUpdatePath`/`applyUpdatePath`,
//! `treekem.zig`) are all implemented and pinned byte-exact against the
//! official mlswg `tree-validation`/`tree-operations`/`treekem` interop
//! vectors (the `gate.treekem_core_implemented` switch is now `true`) — see
//! `SPEC.md`'s "Part 2 — TreeKEM" section for the full breakdown.
//! **Part 4: key schedule + secret tree — COMPLETE.** RFC 9420 §8's whole
//! epoch chain (`keyschedule.zig`), §8.1's `GroupContext`, §8.4's
//! `psk_secret`, §8.5's exporter, §6.1's two MACs, and §9's secret tree +
//! sender ratchets + §6.3.2 sender-data keys (`secrettree.zig`), all pinned
//! byte-exact against the official `key-schedule`/`psk_secret`/`secret-tree`
//! vectors — see `SPEC.md`'s "Part 4" section. **Part 5: message framing —
//! COMPLETE.** All of RFC 9420 §6 (`framing.zig`: `FramedContent`,
//! `AuthenticatedContent`, §6.1's `FramedContentTBS`/`FramedContentAuthData`,
//! §6.2's `PublicMessage` + `membership_tag`, §6.3's `PrivateMessage` with
//! §6.3.1's content encryption/reuse guard/padding and §6.3.2's sender-data
//! encryption, and `MLSMessage`), the two content types framing carries
//! (`content.zig`: §12.1's seven `Proposal` types, §12.4's `Commit`/
//! `ProposalOrRef`) with the §10 `KeyPackage` wire format an `Add` needs
//! (`keypackage.zig`), and **§8.2's transcript hashes** (`transcript.zig`) —
//! the one hole Part 4 deliberately left open, now closed. Pinned byte-exact
//! against the official `messages`/`message-protection`/`transcript-hashes`
//! vectors, including reproducing every protected message in
//! `message-protection.json` byte-for-byte in the SEND direction, which is
//! stronger than that vector's own stated procedure — see `SPEC.md`'s
//! "Part 5" section.
//! **Part 6: joining a group — COMPLETE for the Welcome path.** RFC 9420
//! §12.4.3's `GroupInfo`/`GroupInfoTBS`, §12.4.3.1's `PathSecret`/
//! `GroupSecrets`/`EncryptedGroupSecrets`/`Welcome` with both encryption
//! layers, §12.4.3.3's `ratchet_tree` and `external_pub` extension
//! accessors and the tree-hash binding, and the joiner's own procedure
//! (`welcome.zig`'s `join`), plus §8's chain entered one step lower at
//! `joiner_secret` (`keyschedule.deriveEpochFromJoiner`). `MLSMessage` now
//! decodes ALL five §17.2 wire formats — `error.WireFormatNotInThisPart` is
//! gone, because there is no longer a format this module refuses. Pinned
//! byte-exact against the official `welcome.json` vector, including
//! reproducing its `encrypted_group_info` in the SEND direction, which is
//! stronger than that vector's own stated procedure — see `SPEC.md`'s
//! "Part 6" section.
//! **Part 7: the group state machine — COMPLETE for the follower.**
//! `group.zig`'s `Group(S)`: the state a member carries between epochs, the
//! whole of RFC 9420 §12.4.2's Commit-processing procedure in the RFC's own
//! bullet order, §12.2's proposal-list validation, §12.3's fixed
//! application order, and §12.4.3.1's joining procedure run to completion
//! (`fromWelcome`, which resolves the `GroupInfo` signer out of the tree —
//! the step `welcome.join` has to take as a parameter). Also §8.3's
//! external initialization (`keyschedule.externalInitSender`/
//! `externalInitReceiver`), which the previous batch listed as missing.
//! Anchored against the official `passive-client-welcome`/
//! `passive-client-handling-commit`/`passive-client-random` vectors — whole
//! recorded sessions replayed Commit by Commit with the
//! `epoch_authenticator` compared at every step, including one 200-Commit
//! session. This is the strongest end-to-end evidence in the module: it is
//! the closest thing available to interoperating with another
//! implementation. Four real defects in Parts 1/2/4 surfaced only here and
//! are fixed — see `SPEC.md`'s "Part 7" section, including the correction
//! Part 8 later made to the fourth of them (§7.5's exclusion was applied
//! one step too far).
//! **Part 8: speaking — COMPLETE for regular Commits.** The sender halves
//! of everything Part 7 could only receive: RFC 9420 §11's group creation
//! (`group.Group(S).create`), §12.1's proposal creation
//! (`createProposal`/`updateLeaf`), §7.4/§7.5's `UpdatePath` GENERATION
//! (`treekem.stageUpdatePath`/`sealUpdatePath` — the sender half that
//! `treekem.zig` had never had), §12.4.1's whole Commit-creation procedure
//! and §12.4.3.1's `Welcome` production (`createCommit`, which returns the
//! Commit, the Welcome and a signed `GroupInfo` and advances the committer
//! into the epoch it just created), plus §10's `KeyPackage` construction
//! (`keypackage.create`) without which no client can be added at all.
//! §12.3's application order and §12.2's validation are now ONE
//! implementation shared by both directions, because §12.2 and §12.3 are
//! each stated once for a creator and a processor together.
//! Anchored where creation can be anchored at all — see `kat_commit_test
//! .zig`: an `UpdatePath` generated from a `treekem.json` vector's own
//! `path_secret[0]` reproduces that vector's node public keys, its
//! `commit_secret` and its committer-leaf `parent_hash` byte-exact, and is
//! then opened by every one of that vector's recorded members with their
//! recorded private keys. Commits are also created on top of group states
//! restored from the `passive-client-*.json` recorded sessions, including
//! the 200-Commit one. What is a round trip and what is anchored is stated
//! per test rather than blurred.
//! What Part 8 does NOT do: accept or send handshake messages framed as
//! `PrivateMessage` (`error.PrivateHandshakeNotSupported` — driving the §9
//! secret tree per epoch is a separate concern).
//!
//! Part 9 adds §12.4.3.2's external Commits, in both directions and in one
//! piece: `Group(S).joinByExternalCommit` turns a published `GroupInfo`
//! into a Commit that puts a stranger in the group, and `processCommit`
//! grew a `new_member_commit` branch that accepts one. §12.2's SECOND
//! (whitelist) validation procedure, §8.3's `init_secret` substitution and
//! the leftmost-blank-leaf assignment both sides must compute
//! independently are what that took. There is no upstream vector for it —
//! see `SPEC.md`'s Part 9 for what anchors it instead.
//! Part 3 (the rest of §7.3/§10.1 VALIDATION + Credential) and §11.2/§11.3
//! (reinit/branch) are what remain — see `SPEC.md`'s "Arc breakdown". Part
//! 4 landed before Part 3 because the key schedule depends on neither: it
//! consumes a tree HASH, not a `KeyPackage`; Part 5 then landed before Part
//! 3 too, and took §10's KeyPackage *wire format* with it (but none of
//! §10.1's validation rules) because §12.1.1's `Add` proposal cannot be
//! decoded without it. Part 8 took the two §7.3 rules that need nothing but
//! the leaf and the tree (`group.Policy`'s `check_leaf_extensions_supported`
//! and `check_key_uniqueness`), because §12.2 makes a Commit invalid if the
//! resulting tree breaks them — so a creator that skipped them would emit
//! Commits its own receivers must reject.
//!
//! | File | What it provides |
//! |---|---|
//! | `codec.zig` | The RFC 9420 §2.1 TLS-presentation-language (de)serializer: fixed-width big-endian ints, `optional<T>`, enums, and RFC 9420's ONE deviation from plain RFC 8446 — QUIC-style variable-length-integer VECTOR length prefixes (§2.1.2) — every later part's wire formats are built on `Writer`/`Reader` |
//! | `suite.zig` | `CipherSuite(...)`, a comptime bundle of (KEM, KDF, AEAD, Hash, Signature); `Mls128X25519Aes128GcmSha256Ed25519` (suite `0x0001`, RFC 9420's mandatory-to-implement suite) is the only one instantiated |
//! | `crypto.zig` | The seven labeled-crypto primitives RFC 9420 §5/§8/§9.1 define: `RefHash`/`make_keypackage_ref`/`make_proposal_ref`, `ExpandWithLabel`/`DeriveSecret`, `DeriveTreeSecret`, `SignWithLabel`/`VerifyWithLabel`, `EncryptWithLabel`/`DecryptWithLabel` (the last pair delegates to the sibling `hpke` module's `sealBase`/`openBase`) |
//! | `treemath.zig` | RFC 9420 Appendix C's array-based binary tree math — `left`/`right`/`parent`/`sibling`, `root`, `direct_path`, `copath`, `is_leaf`, `node_width`, `level` — a direct port of the RFC's own published Python |
//! | `kat_test.zig` | Part 1's official RFC 9420 interop vectors (`tree-math.json`/`crypto-basics.json`), embedded and driven end-to-end — see `NOTICE` for provenance |
//! | `wire_lists.zig` | Part 2's shared variable-length-vector encode/decode helpers (`Writer`/`Reader`-based, no allocator needed for `encode`/`encodedLen`) |
//! | `tree.zig` | Part 2's `LeafNode`/`ParentNode`/`Node`/`RatchetTree` (§7.1/§7.2/§12.4.3.3), wire codec, leaf-signature verification, and the mechanical (non-Fable) tree-shape edits `addLeaf`/`updateLeaf`/`removeLeaf` (§7.7/§12.1.1-3) |
//! | `treehash.zig` | Part 2's RFC 9420 §7.8 tree hash — real, recursive, KAT'd byte-exact |
//! | `treekem.zig` | Part 2's `HPKECiphertext`/`UpdatePathNode`/`UpdatePath` (§7.6) plus the five Fable cores (`resolution`/`parentHash`/`validateParentHashes`/`processUpdatePath`/`applyUpdatePath`), implemented and KAT-pinned — and Part 8's SENDER half of §7.5 (`stageUpdatePath` derives §7.4's path secrets, merges them and signs the committer's new leaf; `sealUpdatePath` encrypts them to the copath resolutions), split in two because the HPKE context the second half needs is the tree hash the first half produces |
//! | `gate.zig` | Part 2's `treekem_core_implemented` switch — now `true` (the five cores are implemented; the gated TreeKEM KATs run). Part 4 adds no gate: every line of it is real and vector-driven |
//! | `kat_treekem_test.zig` | Part 2's KAT harness: `tree-validation.json`/`tree-operations.json`/`treekem.json` driven byte-exact against the five cores (the `gate.treekem_core_implemented`-gated tests now run — resolution, parent-hash accept/tamper, UpdatePath process + merge) |
//! | `keyschedule.zig` | Part 4's RFC 9420 §8 epoch chain (`init_secret` → `joiner_secret` → `welcome_secret` → `epoch_secret` → Table 4's eight secrets + the next `init_secret`), §8.1's `GroupContext` wire format, §8.4's `PreSharedKeyID`/`PSKLabel`/`psk_secret` chain, §8.5's `MLS-Exporter`, `external_pub`, and §6.1's `confirmation_tag`/`membership_tag` |
//! | `secrettree.zig` | Part 4's RFC 9420 §9 secret tree (derived downward from `encryption_secret`), the per-leaf handshake/application sender ratchets (§9.1), a generation-indexed out-of-order `Window` with consume-once and bounded-forward-jump policy (§9.2), and §6.3.2's sender-data key/nonce |
//! | `kat_keyschedule_test.zig` | Part 4's KAT harness for `key-schedule.json` (per-STAGE, so a divergence names the failing link) + `psk_secret.json` (chains of 0 through 10 PSKs) |
//! | `kat_secrettree_test.zig` | Part 4's KAT harness for `secret-tree.json` — 1/8/32-leaf trees, each leaf's generations driven twice: forward through a bare `Ratchet` and in reverse through a `Window` |
//! | `keypackage.zig` | Part 5's RFC 9420 §10 `KeyPackage`/`KeyPackageTBS` WIRE FORMAT (plus its self-signature) — here because §12.1.1's `Add` carries one; §10.1's VALIDATION rules are Part 3's and are not in it. Part 8 adds `create`, which assembles and signs one (inner `LeafNode` first, whole structure second) — the entry point a client needs before it can be added to any group |
//! | `content.zig` | Part 5's §12.1 `Proposal` (all seven types) and §12.4 `Commit`/`ProposalOrRef`/`ProposalOrRefType` — the two non-application bodies §6's `FramedContent` selects between. Wire shape only: no §12.2 proposal-list validity, no §12.3 application order, no commit-processing state machine |
//! | `framing.zig` | Part 5's whole of §6: `WireFormat`/`ContentType`/`SenderType`/`Sender`, `FramedContent`, `AuthenticatedContent`, §6.1's `FramedContentTBS` + sign/verify, §6.2's `PublicMessage`/`AuthenticatedContentTBM`/`membership_tag` + `protectPublic`/`unprotectPublic`, §6.3's `PrivateMessage` + §6.3.1's `PrivateMessageContent`/`PrivateContentAAD`/reuse guard/padding + §6.3.2's `SenderData`/`SenderDataAAD`, and `MLSMessage` |
//! | `transcript.zig` | Part 5's RFC 9420 §8.2 — `ConfirmedTranscriptHashInput`/`InterimTranscriptHashInput` and both recurrences. Separate from `keyschedule.zig` only because `framing.zig` imports that file, so §8.2 sitting there would be an import cycle |
//! | `kat_messages_test.zig` | Parts 5+6's KAT harness for `messages.json`: every §12.1 proposal body, §12.4 `Commit`, §12.4.3.1's `GroupSecrets`, §12.4.3.3's bare `ratchet_tree`, and ALL five §17.2 `MLSMessage` wire formats, decode→re-encode byte-exact (a WIRE-format anchor — upstream states this vector's MACs may be invalid) |
//! | `welcome.zig` | Part 6's RFC 9420 §12.4.3 `GroupInfo`/`GroupInfoTBS` (+ sign/verify), §12.4.3.1's `PathSecret`/`GroupSecrets`/`EncryptedGroupSecrets`/`Welcome`, the two encryption layers (`welcomeKeyNonce`/`encryptGroupInfo`/`decryptGroupInfo` and `encryptGroupSecrets`/`decryptGroupSecrets`) and the joiner's whole procedure (`join`), plus §12.4.3.3's `ratchet_tree`/`external_pub` extension accessors and `verifyTreeHash`. §8.3's two halves live in `keyschedule.zig` and §12.4.3.2's external Commits in `group.zig`; this file supplies the `GroupInfo` they both read |
//! | `kat_welcome_test.zig` | Part 6's KAT harness for `welcome.json` — the whole §12.4.3.1 join with real keys, staged per layer (KeyPackageRef → HPKE open → welcome key → group-info AEAD → signature → confirmation tag), and reproducing the vector's `encrypted_group_info` in the SEND direction |
//! | `group.zig` | Part 7's `Group(S)` — the group STATE and the receiving half of an epoch transition: §12.4.3.1's `fromWelcome`, §12.4.2's `processCommit` (proposal resolution by §5.2 ref, §12.2 validation, §12.3's application order, the UpdatePath's provisional-GroupContext decryption, the key schedule and the `confirmation_tag`), plus §8.4 PSK resolution over application-supplied and remembered-resumption keys — and Part 8's SENDING half in the same object, because it is the same state: §11's `create`, §12.1's `createProposal`/`updateLeaf`, and §12.4.1's `createCommit` (which also produces the §12.4.3.1 `Welcome` and a signed `GroupInfo`) — and Part 9's §12.4.3.2 external Commits in BOTH directions, again in the same object: `joinByExternalCommit` (GroupInfo → external Commit + group state) and `processCommit`'s `new_member_commit` branch, sharing §12.2's second (whitelist) validation procedure and §12.4.1's leftmost-blank-leaf assignment |
//! | `kat_passive_test.zig` | Part 7's KAT harness for the three `passive-client-*.json` vectors — recorded sessions replayed Commit by Commit against `epoch_authenticator`, plus the assertions that keep each file's reduction honest |
//! | `kat_commit_test.zig` | Part 8's KAT harness: an `UpdatePath` GENERATED from a `treekem.json` vector's own `path_secret[0]`, compared byte-exact against that vector's node public keys / `commit_secret` / committer-leaf `parent_hash` and then opened by every one of its recorded members; plus Commits created on top of group states restored from the `passive-client-*.json` sessions. Each assertion is labelled anchored or round trip |
//! | `kat_framing_test.zig` | Part 5's KAT harness for `message-protection.json` (the full §6 protect/unprotect path with real keys — `PrivateMessage` for all three content types, `PublicMessage` for the two handshake types, byte-exact in BOTH directions, plus §6's refusal of application content as a `PublicMessage`) and `transcript-hashes.json` (§8.2's two hashes plus the Commit's own `confirmation_tag`) |
//!
//! **Status: Part 1 COMPLETE (Sonnet-tier). Part 2 COMPLETE (Sonnet
//! data/codec/tree-hash/tree-editing + Fable tree-algorithm cores, all
//! KAT-pinned byte-exact). Part 4 COMPLETE (Sonnet — pure composition over
//! Part 1's primitives, but with an authoritative per-stage conformance
//! oracle; the only judgment call was §8.4's Extract argument order, where
//! the RFC's prose and its Figure 24 disagree and `psk_secret.json`
//! settles it — see `keyschedule.pskSecret`'s doc comment). Part 5
//! COMPLETE (Sonnet — wire shapes plus composition of Parts 1/2/4's
//! primitives; no new cryptography, and every vector matched on the first
//! run with nothing adjusted on either side). Part 6 COMPLETE for the
//! WELCOME path (Sonnet — again no new cryptography: the two encryption
//! layers are `crypto.EncryptWithLabel` and a plain AEAD under a key
//! `keyschedule` already derived; `welcome.json` matched on the first run
//! with nothing adjusted on either side). Part 7 COMPLETE for the FOLLOWER
//! (Sonnet — no new cryptography again, but the first part of this arc
//! where the vectors did NOT match on the first run: the passive-client
//! replays found a fixed-scratch overflow that made Welcomes and Commits
//! undecryptable for any group of realistic size, an over-constrained PSK
//! width that rejected legal input, an unsorted `unmerged_leaves` insert,
//! and — the one that is a specification reading rather than a coding bug —
//! RFC 9420 §7.5's rule that members added by the same Commit are excluded
//! from the UpdatePath resolutions. Details in `SPEC.md`'s "Part 7".)
//! Part 8 COMPLETE for regular Commits (Sonnet — no new cryptography
//! again; the part is the mirror image of Part 7 over Parts 1-6's
//! primitives. Building the sender half surfaced three RECEIVER-side
//! problems that 200 replayed Commits could not reach, because a passive
//! client never generates anything: a §7.5 MISREADING Part 7 introduced —
//! applying the same-Commit-Add exclusion to §4.1.2's filtered direct path
//! and not only to the resolution, which produces trees that fail §7.9.2 —
//! plus a joiner's path-secret chain that consumed a derivation step at
//! nodes the committer had filtered out, and a member with no way to adopt
//! the private key of an Update it had published itself. Every upstream
//! vector passes under either reading of §7.5, so only creating Commits
//! could expose it. Details in `SPEC.md`'s "Part 8".)**
//! `treemath.zig` is a pure port of the RFC's own
//! reference code; `crypto.zig` composes `codec.zig` + the sibling
//! `hpke`/std.crypto primitives exactly as RFC 9420 §5/§8/§9.1 specify,
//! byte-exact against `kat_test.zig`'s embedded vectors (including a
//! stronger-than-required check for `sign_with_label`: Ed25519 is
//! deterministic, RFC 8032, so this module's own signing reproduces the
//! vector's signature bytes exactly, not merely a verify-round-trip).
//! Part 2's `tree.zig`/`treehash.zig` are similarly byte-exact against
//! `tree-validation.json`/`tree-operations.json` — see `SPEC.md` for the
//! full KAT breakdown and the real bug (`removeLeaf`'s truncation
//! boundary arithmetic) this harness caught during scaffolding.
//!
//! Consumer: a group-messaging application wanting RFC 9420 interop
//! (Matrix, MLS-based E2EE messaging, or any protocol layering on MLS's
//! group key agreement). With Part 5 the module can, for a group whose
//! state the caller maintains, PRODUCE and CONSUME real MLS messages that
//! other implementations accept byte-for-byte — a proposal, a commit or an
//! application message, signed and MAC'd or fully encrypted. With Part 6 it
//! can also ENTER such a group: given a `Welcome` addressed to one of its
//! `KeyPackage`s, `welcome.join` yields the epoch secrets, the signed
//! `GroupContext` and the transcript hashes that every existing member
//! holds, with the `confirmation_tag` checked against a `confirmation_key`
//! it derived itself.
//! With Part 7 it can FOLLOW that group: `group.Group(S)` holds the tree,
//! the transcript, the epoch secrets and this member's private path
//! secrets, and `processCommit` advances all of it across a Commit exactly
//! as §12.4.2 specifies — validated against recorded sessions produced by
//! another implementation, one of them 200 Commits long. A PASSIVE client
//! is complete.
//! With Part 8 it can SPEAK. `Group(S).create` starts a group from this
//! client's own `KeyPackage`; `createProposal` publishes a §12.1 proposal;
//! `createCommit` takes a proposal list (by value or by reference),
//! validates it, applies it, generates a full `UpdatePath`, advances the
//! key schedule, and returns the Commit, a `Welcome` for every member it
//! added and a signed `GroupInfo` — having already advanced this client
//! into the epoch it just created. A two-way client is complete: two
//! `Group(S)` objects can drive a group between them indefinitely, and a
//! group state restored from another implementation's recorded session can
//! be committed on directly.
//! Both ways into a group are now built: by invitation (§12.4.3.1's
//! `Welcome`) and by §12.4.3.2's external Commit, which needs nobody
//! already inside to be online.
//!
//! What it still cannot do: send or accept handshake messages framed as a
//! `PrivateMessage` (the §9 secret tree is built, but the group object does
//! not drive it per epoch), follow through on a `ReInit` (§11.2) or branch
//! (§11.3), and apply the §10.1/§7.3 admission rules that need a clock, a
//! credential authority or an extension registry (Part 3); the two §7.3
//! rules that need only the leaf and the tree ARE applied, in both
//! directions. See `README.md` for the current surface.
//!
//! Provenance: clean-room from RFC 9420 (a public IETF specification, not
//! copyrightable expression — see `CONVENTIONS.md` §5's merger-doctrine
//! note) plus `treemath.zig`'s direct port of RFC 9420 Appendix C's own
//! published reference algorithm (the RFC's stated intent — it publishes
//! runnable code, not just prose, specifically so implementations match
//! it exactly). The `kat_*_test.zig` harnesses embed official
//! `mlswg/mls-implementations` interop vectors — public conformance DATA,
//! not copyrightable expression, same posture as this repo's `bn254`/
//! `bls12_381` KAT sources; see `NOTICE` for the exact commit/fetch-date
//! citation anyway, out of the same caution those modules apply.

const std = @import("std");

pub const codec = @import("codec.zig");
pub const suite = @import("suite.zig");
pub const crypto = @import("crypto.zig");
pub const treemath = @import("treemath.zig");
pub const tree = @import("tree.zig");
pub const treehash = @import("treehash.zig");
pub const treekem = @import("treekem.zig");
pub const keyschedule = @import("keyschedule.zig");
pub const secrettree = @import("secrettree.zig");
pub const keypackage = @import("keypackage.zig");
pub const content = @import("content.zig");
pub const framing = @import("framing.zig");
pub const transcript = @import("transcript.zig");
pub const welcome = @import("welcome.zig");
pub const group = @import("group.zig");
pub const gate = @import("gate.zig");

// Flat re-exports of the surface most callers want.
pub const CipherSuite = suite.CipherSuite;
pub const CipherSuiteId = suite.CipherSuiteId;
pub const default_suite = suite.default;

pub const RefHash = crypto.RefHash;
pub const make_keypackage_ref = crypto.make_keypackage_ref;
pub const make_proposal_ref = crypto.make_proposal_ref;
pub const ExpandWithLabel = crypto.ExpandWithLabel;
pub const DeriveSecret = crypto.DeriveSecret;
pub const DeriveTreeSecret = crypto.DeriveTreeSecret;
pub const SignWithLabel = crypto.SignWithLabel;
pub const VerifyWithLabel = crypto.VerifyWithLabel;
pub const EncryptWithLabel = crypto.EncryptWithLabel;
pub const DecryptWithLabel = crypto.DecryptWithLabel;

pub const LeafNode = tree.LeafNode;
pub const ParentNode = tree.ParentNode;
pub const Node = tree.Node;
pub const RatchetTree = tree.RatchetTree;
pub const treeHash = treehash.treeHash;
pub const rootHash = treehash.rootHash;
pub const UpdatePath = treekem.UpdatePath;
pub const UpdatePathNode = treekem.UpdatePathNode;
pub const HPKECiphertext = treekem.HPKECiphertext;
pub const stageUpdatePath = treekem.stageUpdatePath;
pub const sealUpdatePath = treekem.sealUpdatePath;
pub const StageParams = treekem.StageParams;
pub const Staged = treekem.Staged;

pub const GroupContext = keyschedule.GroupContext;
pub const ProtocolVersion = keyschedule.ProtocolVersion;
pub const EpochSecrets = keyschedule.EpochSecrets;
pub const deriveEpoch = keyschedule.deriveEpoch;
pub const zeroSecret = keyschedule.zeroSecret;
pub const externalKeyPair = keyschedule.externalKeyPair;
pub const mlsExporter = keyschedule.mlsExporter;
pub const confirmationTag = keyschedule.confirmationTag;
pub const verifyConfirmationTag = keyschedule.verifyConfirmationTag;
pub const membershipTag = keyschedule.membershipTag;
pub const verifyMembershipTag = keyschedule.verifyMembershipTag;
pub const PreSharedKeyId = keyschedule.PreSharedKeyId;
pub const PreSharedKey = keyschedule.PreSharedKey;
pub const pskSecret = keyschedule.pskSecret;

pub const SecretTreeError = secrettree.Error;
pub const RatchetKind = secrettree.RatchetKind;
pub const ratchetBaseSecret = secrettree.ratchetBaseSecret;
pub const Ratchet = secrettree.Ratchet;
pub const Window = secrettree.Window;
pub const senderDataKeys = secrettree.senderDataKeys;

pub const KeyPackage = keypackage.KeyPackage;
pub const createKeyPackage = keypackage.create;
pub const KeyPackageCreateParams = keypackage.CreateParams;

pub const ProposalType = content.ProposalType;
pub const Proposal = content.Proposal;
pub const ProposalOrRef = content.ProposalOrRef;
pub const ProposalOrRefType = content.ProposalOrRefType;
pub const Commit = content.Commit;
pub const ReInit = content.ReInit;

pub const WireFormat = framing.WireFormat;
pub const ContentType = framing.ContentType;
pub const SenderType = framing.SenderType;
pub const Sender = framing.Sender;
pub const FramedContent = framing.FramedContent;
pub const FramedContentBody = framing.FramedContentBody;
pub const FramedContentAuthData = framing.FramedContentAuthData;
pub const AuthenticatedContent = framing.AuthenticatedContent;
pub const PublicMessage = framing.PublicMessage;
pub const PrivateMessage = framing.PrivateMessage;
pub const SenderData = framing.SenderData;
pub const MLSMessage = framing.MLSMessage;
pub const protectPublic = framing.protectPublic;
pub const unprotectPublic = framing.unprotectPublic;
pub const protectPrivate = framing.protectPrivate;
pub const decryptSenderData = framing.decryptSenderData;
pub const decryptContent = framing.decryptContent;
pub const parsePrivateContent = framing.parsePrivateContent;
pub const signFramedContent = framing.signFramedContent;
pub const verifyFramedContent = framing.verifyFramedContent;
pub const proposalRef = framing.proposalRef;

pub const confirmedTranscriptHash = transcript.confirmedTranscriptHash;
pub const interimTranscriptHash = transcript.interimTranscriptHash;
pub const advanceTranscript = transcript.advance;
pub const empty_transcript_hash = transcript.empty_transcript_hash;

pub const GroupInfo = welcome.GroupInfo;
pub const GroupSecrets = welcome.GroupSecrets;
pub const EncryptedGroupSecrets = welcome.EncryptedGroupSecrets;
pub const Welcome = welcome.Welcome;
pub const Joined = welcome.Joined;
pub const JoinParams = welcome.JoinParams;
pub const joinWelcome = welcome.join;
pub const welcomeKeyNonce = welcome.welcomeKeyNonce;
pub const encryptGroupInfo = welcome.encryptGroupInfo;
pub const decryptGroupInfo = welcome.decryptGroupInfo;
pub const encryptGroupSecrets = welcome.encryptGroupSecrets;
pub const decryptGroupSecrets = welcome.decryptGroupSecrets;
pub const verifyTreeHash = welcome.verifyTreeHash;
pub const deriveEpochFromJoiner = keyschedule.deriveEpochFromJoiner;
pub const externalInitSender = keyschedule.externalInitSender;
pub const externalInitReceiver = keyschedule.externalInitReceiver;

pub const Group = group.Group;
pub const ExternalPsk = group.ExternalPsk;
pub const GroupPolicy = group.Policy;

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    // Pure computation over caller-supplied bytes/keys, like the sibling
    // `hpke`/`signal` modules — no owned socket/transport of its own. Part
    // 5's framing layer was where wire I/O might have appeared and did not:
    // `protectPublic`/`protectPrivate` return BYTES for the caller to send,
    // and `unprotect*` takes bytes the caller received. MLS deliberately
    // does not specify a transport (RFC 9420 §2's Delivery Service is an
    // architectural role, not a protocol), so owning one here would be an
    // invention rather than an implementation.
    .role = .util,
    // No shared/global state — every type here is a plain caller-owned
    // value (`codec.Writer`/`Reader` wrap a caller-supplied buffer;
    // `suite.CipherSuite(...)` is a comptime type, not an instance).
    .concurrency = .reentrant,
    .model_after = "RFC 9420 (Messaging Layer Security); treemath.zig ports Appendix C's own published Python reference verbatim",
    .deps = .{"hpke"},
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too (the dtls/noise/tlsresume/hpke/ssh precedent this module
// follows).
test {
    _ = codec;
    _ = suite;
    _ = crypto;
    _ = treemath;
    _ = @import("kat_test.zig");
    _ = @import("wire_lists.zig");
    _ = tree;
    _ = treehash;
    _ = treekem;
    _ = keyschedule;
    _ = secrettree;
    _ = keypackage;
    _ = content;
    _ = framing;
    _ = transcript;
    _ = welcome;
    _ = group;
    _ = gate;
    _ = @import("kat_treekem_test.zig");
    _ = @import("kat_keyschedule_test.zig");
    _ = @import("kat_secrettree_test.zig");
    _ = @import("kat_messages_test.zig");
    _ = @import("kat_framing_test.zig");
    _ = @import("kat_welcome_test.zig");
    _ = @import("kat_passive_test.zig");
    _ = @import("kat_commit_test.zig");
}

test "meta.deps is exactly {\"hpke\"}" {
    try std.testing.expectEqual(@as(usize, 1), meta.deps.len);
    try std.testing.expectEqualStrings("hpke", meta.deps[0]);
}

test "meta.role is .util (no owned transport/socket in Part 1)" {
    try std.testing.expectEqual(.util, meta.role);
}

test "default_suite is RFC 9420's mandatory-to-implement suite, 0x0001" {
    try std.testing.expectEqual(CipherSuiteId.mls_128_dhkemx25519_aes128gcm_sha256_ed25519, default_suite.id);
    try std.testing.expectEqual(@as(u16, 0x0001), @intFromEnum(default_suite.id));
}
