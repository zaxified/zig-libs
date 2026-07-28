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
//! Of §8, only §8.3's external initialization is still missing (it needs
//! Part 6's external-commit flow).
//! Part 3 (LeafNode/KeyPackage VALIDATION + Credential) and Part 6
//! (external commit / Welcome / GroupInfo / reinit) are the remaining
//! parts — see `SPEC.md`'s "Arc breakdown". Part 4 landed before Part 3
//! because the key schedule depends on neither: it consumes a tree HASH,
//! not a `KeyPackage`; Part 5 then landed before Part 3 too, and took §10's
//! KeyPackage *wire format* with it (but none of §10.1's validation
//! rules) because §12.1.1's `Add` proposal cannot be decoded without it.
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
//! | `treekem.zig` | Part 2's `HPKECiphertext`/`UpdatePathNode`/`UpdatePath` (§7.6) plus the five Fable cores (`resolution`/`parentHash`/`validateParentHashes`/`processUpdatePath`/`applyUpdatePath`), implemented and KAT-pinned |
//! | `gate.zig` | Part 2's `treekem_core_implemented` switch — now `true` (the five cores are implemented; the gated TreeKEM KATs run). Part 4 adds no gate: every line of it is real and vector-driven |
//! | `kat_treekem_test.zig` | Part 2's KAT harness: `tree-validation.json`/`tree-operations.json`/`treekem.json` driven byte-exact against the five cores (the `gate.treekem_core_implemented`-gated tests now run — resolution, parent-hash accept/tamper, UpdatePath process + merge) |
//! | `keyschedule.zig` | Part 4's RFC 9420 §8 epoch chain (`init_secret` → `joiner_secret` → `welcome_secret` → `epoch_secret` → Table 4's eight secrets + the next `init_secret`), §8.1's `GroupContext` wire format, §8.4's `PreSharedKeyID`/`PSKLabel`/`psk_secret` chain, §8.5's `MLS-Exporter`, `external_pub`, and §6.1's `confirmation_tag`/`membership_tag` |
//! | `secrettree.zig` | Part 4's RFC 9420 §9 secret tree (derived downward from `encryption_secret`), the per-leaf handshake/application sender ratchets (§9.1), a generation-indexed out-of-order `Window` with consume-once and bounded-forward-jump policy (§9.2), and §6.3.2's sender-data key/nonce |
//! | `kat_keyschedule_test.zig` | Part 4's KAT harness for `key-schedule.json` (per-STAGE, so a divergence names the failing link) + `psk_secret.json` (chains of 0 through 10 PSKs) |
//! | `kat_secrettree_test.zig` | Part 4's KAT harness for `secret-tree.json` — 1/8/32-leaf trees, each leaf's generations driven twice: forward through a bare `Ratchet` and in reverse through a `Window` |
//! | `keypackage.zig` | Part 5's RFC 9420 §10 `KeyPackage`/`KeyPackageTBS` WIRE FORMAT (plus its self-signature) — here because §12.1.1's `Add` carries one; §10.1's VALIDATION rules are Part 3's and are not in it |
//! | `content.zig` | Part 5's §12.1 `Proposal` (all seven types) and §12.4 `Commit`/`ProposalOrRef`/`ProposalOrRefType` — the two non-application bodies §6's `FramedContent` selects between. Wire shape only: no §12.2 proposal-list validity, no §12.3 application order, no commit-processing state machine |
//! | `framing.zig` | Part 5's whole of §6: `WireFormat`/`ContentType`/`SenderType`/`Sender`, `FramedContent`, `AuthenticatedContent`, §6.1's `FramedContentTBS` + sign/verify, §6.2's `PublicMessage`/`AuthenticatedContentTBM`/`membership_tag` + `protectPublic`/`unprotectPublic`, §6.3's `PrivateMessage` + §6.3.1's `PrivateMessageContent`/`PrivateContentAAD`/reuse guard/padding + §6.3.2's `SenderData`/`SenderDataAAD`, and `MLSMessage` |
//! | `transcript.zig` | Part 5's RFC 9420 §8.2 — `ConfirmedTranscriptHashInput`/`InterimTranscriptHashInput` and both recurrences. Separate from `keyschedule.zig` only because `framing.zig` imports that file, so §8.2 sitting there would be an import cycle |
//! | `kat_messages_test.zig` | Part 5's KAT harness for `messages.json`: every §12.1 proposal body, §12.4 `Commit`, and the §6 `MLSMessage` wire formats, decode→re-encode byte-exact (a WIRE-format anchor — upstream states this vector's MACs may be invalid) |
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
//! run with nothing adjusted on either side).**
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
//! group key agreement). With Part 5 the module can now, for a group whose
//! state the caller maintains, PRODUCE and CONSUME real MLS messages that
//! other implementations accept byte-for-byte — a proposal, a commit or an
//! application message, signed and MAC'd or fully encrypted. What it still
//! cannot do is BE a client on its own: there is no group-state object, no
//! Welcome/GroupInfo (so no way to join a group — Part 6), and no §10.1/
//! §7.3 validation deciding whether a KeyPackage or LeafNode should be
//! admitted (Part 3). Framing hands a caller a decoded, cryptographically
//! verified `AuthenticatedContent` and a `SenderData.leaf_index`; deciding
//! that the index names a real member, and applying the proposals, is
//! still above this module. See `README.md` for the current surface.
//!
//! Provenance: clean-room from RFC 9420 (a public IETF specification, not
//! copyrightable expression — see `CONVENTIONS.md` §5's merger-doctrine
//! note) plus `treemath.zig`'s direct port of RFC 9420 Appendix C's own
//! published reference algorithm (the RFC's stated intent — it publishes
//! runnable code, not just prose, specifically so implementations match
//! it exactly). The six `kat_*_test.zig` harnesses embed official
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

pub const meta = .{
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
    _ = gate;
    _ = @import("kat_treekem_test.zig");
    _ = @import("kat_keyschedule_test.zig");
    _ = @import("kat_secrettree_test.zig");
    _ = @import("kat_messages_test.zig");
    _ = @import("kat_framing_test.zig");
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
