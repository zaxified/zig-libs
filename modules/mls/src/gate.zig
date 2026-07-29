// SPDX-License-Identifier: MIT

//! gate — the single switch enabling tests that call into TreeKEM's Fable
//! cores (`treekem.zig`'s `resolution`/`parentHash`/`validateParentHashes`/
//! `processUpdatePath`/`applyUpdatePath`). Everything else in this Part —
//! `tree.zig`'s `LeafNode`/`ParentNode`/`Node`/`RatchetTree` (encoding,
//! decoding, signature verification, `addLeaf`/`updateLeaf`/`removeLeaf`
//! tree-shape edits) and `treehash.zig`'s full recursive tree hash — is
//! fully real today and needs no gate; it is what proves the harness has
//! teeth independent of whether the TreeKEM algorithms are filled in yet
//! (`kat_treekem_test.zig`'s `tree-validation.json` signature/tree-hash
//! checks and `tree-operations.json`'s whole KAT run ungated, byte-exact,
//! against the official RFC 9420 interop vectors).
//!
//! Now `true`: `treekem.zig`'s five cores are IMPLEMENTED, and the gated
//! tests in `kat_treekem_test.zig` drive them byte-exact against the
//! official mlswg vectors — `tree-validation.json`'s resolution + parent-
//! hash-chain checks (all 14 trees, 275 single-byte parent_hash tamper
//! rejections) and the full `treekem.json` UpdatePath/path-secret/
//! commit-secret vectors (62 update paths, 328 receiver views, and 62
//! merges reproducing `tree_hash_after`).
//!
//! **This file gates Part 2 and only Part 2.** Part 4 (`keyschedule.zig`/
//! `secrettree.zig`, RFC 9420 §8/§9), Part 5 (`framing.zig`/`content.zig`/
//! `keypackage.zig`/`transcript.zig`, RFC 9420 §6/§8.2 plus the §10/§12.1/
//! §12.4 structures framing carries), Part 6 (`welcome.zig`, RFC 9420
//! §12.4.3/§12.4.3.1/§12.4.3.3), Part 7 (`group.zig`, RFC 9420 §12.2/
//! §12.3/§12.4.2) and Part 8 (§11/§12.1/§12.4.1's creation halves, in
//! `group.zig`, `treekem.zig` and `keypackage.zig`) deliberately add no
//! switch of their own: every function in them is real, so there is
//! nothing to stage. A gate constant that is always `true` for work that
//! was never staged would be exactly the "describes finished work as
//! provisional" noise this module has been keeping out.
//!
//! Parts 4-7 are additionally driven byte-exact by an official interop
//! vector throughout (`key-schedule.json`/`psk_secret.json`/
//! `secret-tree.json` for Part 4; `messages.json`/
//! `message-protection.json`/`transcript-hashes.json` for Part 5;
//! `welcome.json` plus `messages.json`'s Part 6 fields for Part 6; the
//! three `passive-client-*.json` recorded sessions for Part 7). **Part 8 is
//! the first part where that is only partly available, and the gate is NOT
//! how that is expressed** — a switch would say "unfinished", and creation
//! is finished. What is true instead is that a Commit is not a function of
//! its inputs (§7.4 samples `path_secret[0]`, §7.5 samples a leaf key pair,
//! every ciphertext draws an HPKE ephemeral), so no vector can pin its
//! bytes and there is no upstream active-client vector. `kat_commit_test
//! .zig` anchors what CAN be anchored — a generation seeded from
//! `treekem.json`'s own recorded path secret reproduces that vector's node
//! public keys, `commit_secret` and committer-leaf `parent_hash`
//! byte-exact — and labels the rest as round trips in the test names and
//! the file's doc comment, which is where a reader looks for it.
//!
//! What Parts 5-8 leave out is left out ENTIRELY rather than gated — no
//! §10.1 KeyPackage validation, no §7.3 LeafNode validation beyond the two
//! rules that need nothing but the leaf and the tree (`group.Policy`'s
//! `check_leaf_extensions_supported`/`check_key_uniqueness`) plus the
//! properties §12.4.2 names in its own bullets, and no external-Commit path
//! (§12.4.3.2 — Part 8's stated boundary; §8.3, which it needs, is built
//! and lives in `keyschedule.zig`, and so now is the Commit creation it
//! also needs). There is no half-built code behind a switch anywhere.
//!
//! **The two boundaries Parts 7-8 state as named refusals rather than
//! silence** are worth knowing about, because a caller meets them at
//! runtime: `group.Error.PrivateHandshakeNotSupported` (a Commit or
//! proposal framed as a `PrivateMessage` — the §9 secret tree exists but
//! this object does not drive it per epoch) and `group.Error.GroupPoisoned`
//! (a Commit that failed after the tree was already mutated leaves the
//! object unusable rather than silently half-applied; `createCommit` is
//! non-atomic on exactly the same terms). Neither is a gate: they are
//! permanent, documented properties of what these parts own.
//!
//! Note that Part 5's one named refusal,
//! `error.WireFormatNotInThisPart`, is GONE: Part 6 supplied the
//! `Welcome`/`GroupInfo` payloads it stood for, so
//! `framing.MLSMessage.decode` now handles every §17.2 wire format and the
//! error would have no reachable return site.
//!
//! The switch is retained (rather than deleted) so the ratchet-tree data/
//! codec/tree-hash/tree-editing layer stays independently testable should a
//! future refactor of the five cores need staging again — flipping it back
//! to `false` makes the core-driving tests report **SKIP** (via
//! `error.SkipZigTest`) while keeping every signature type-checked.
pub const treekem_core_implemented = true;
