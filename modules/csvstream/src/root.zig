// SPDX-License-Identifier: MIT
//! csvstream — streaming RFC 4180 CSV reader that preserves byte offsets
//! (chunk + record start) so a consumer can seek back to the exact source span.
//!
//! Two layers, one coherent API:
//!   • In-memory (standalone): `LineIterator` walks a caller-owned byte slice
//!     record-by-record; `splitFields` splits one record into fields. Use these
//!     directly when you already hold the bytes.
//!   • Streaming: `StreamReader` reads a file in bounded memory (via the
//!     record-aligned `ChunkReader`) and yields the same `LineSlice` records —
//!     now with ABSOLUTE file byte offsets. It composes the in-memory layer,
//!     so both share one record model.
//!
//! Quoting is RFC 4180 (doubled `""` escape) with a deliberate "lazy quotes"
//! twist: a '\n' ALWAYS ends a record, so an unbalanced quote is a one-line
//! problem (flagged via `LineSlice.unbalanced_quote`) instead of swallowing the
//! rest of the file — which is also what makes every '\n' a safe chunk boundary.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "RFC 4180 + byte-offset-preserving streaming",
    .deps = .{},
};

const line = @import("line.zig");
const stream = @import("stream.zig");

// ── In-memory layer (usable standalone) ──────────────────────────────────────

/// One record: bytes (borrowed) + absolute byte offset + unbalanced-quote flag.
pub const LineSlice = line.LineSlice;

/// Quote-aware record iterator over an in-memory byte slice.
pub const LineIterator = line.LineIterator;

/// Split one record's bytes into fields (RFC 4180 quoting; `quote == 0`
/// disables quoting). Field slices borrow `line`, except escaped-quote fields
/// which are allocated from the passed allocator.
pub const splitFields = line.splitFields;

// ── Streaming layer (file → records with absolute offsets) ────────────────────

/// Reads a file in record-aligned chunks with bounded memory; yields absolute
/// file byte offsets. The unified reader most callers want.
pub const StreamReader = stream.StreamReader;

/// Lower-level building block under `StreamReader`: file → record-aligned byte
/// chunks. Exposed for callers who want the raw chunks (e.g. to hand each block
/// to a parallel worker).
pub const ChunkReader = stream.ChunkReader;

/// Default target chunk size (10 MiB) for `StreamReader`/`ChunkReader`.
pub const default_chunk_size = stream.default_chunk_size;

// Dark-tests aggregator: a bare `pub const` re-export does NOT pull a
// submodule's tests into the test binary — this reference does.
test {
    _ = line;
    _ = stream;
}
