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
//! The switch is retained (rather than deleted) so the ratchet-tree data/
//! codec/tree-hash/tree-editing layer stays independently testable should a
//! future refactor of the five cores need staging again — flipping it back
//! to `false` makes the core-driving tests report **SKIP** (via
//! `error.SkipZigTest`) while keeping every signature type-checked.
pub const treekem_core_implemented = true;
