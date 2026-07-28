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
//! `secrettree.zig`, RFC 9420 §8/§9) and Part 5 (`framing.zig`/
//! `content.zig`/`keypackage.zig`/`transcript.zig`, RFC 9420 §6/§8.2 plus
//! the §10/§12.1/§12.4 structures framing carries) deliberately add no
//! switch of their own: every function in them is real and every one is
//! driven byte-exact by an official interop vector
//! (`key-schedule.json`/`psk_secret.json`/`secret-tree.json` for Part 4;
//! `messages.json`/`message-protection.json`/`transcript-hashes.json` for
//! Part 5), so there is nothing to stage. A gate constant that is always
//! `true` for work that was never staged would be exactly the "describes
//! finished work as provisional" noise this module has been keeping out.
//!
//! What Part 5 leaves out is left out ENTIRELY rather than gated — no
//! `Welcome`/`GroupInfo` payload (`framing.MLSMessage.decode` returns
//! `error.WireFormatNotInThisPart`, a named refusal, not a stub), no §10.1
//! KeyPackage validation, no §12.2 proposal-list validity, no
//! commit-processing state machine. There is no half-built code behind a
//! switch anywhere in it.
//!
//! The switch is retained (rather than deleted) so the ratchet-tree data/
//! codec/tree-hash/tree-editing layer stays independently testable should a
//! future refactor of the five cores need staging again — flipping it back
//! to `false` makes the core-driving tests report **SKIP** (via
//! `error.SkipZigTest`) while keeping every signature type-checked.
pub const treekem_core_implemented = true;
