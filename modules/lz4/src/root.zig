// SPDX-License-Identifier: MIT

//! lz4 — the LZ4 block format and the LZ4 frame format (`.lz4`), compress and
//! decompress, pure Zig.
//!
//! Block: `decompressBlock` into a caller's slice (its length is the output
//! budget, like liblz4's `LZ4_decompress_safe`), `compressBlock` with LZ4's
//! default fast matcher and its acceleration knob.
//!
//! Frame: `decompress` reads LZ4 frames (block and content checksums, content
//! size, linked or independent blocks, any block size), skippable frames and
//! the legacy `lz4 -l` frame, concatenated, with a decompression-bomb cap
//! (`decompressInto`: into a caller's buffer, its length the cap);
//! `compress` writes one frame with liblz4's defaults unless told otherwise.
//! Malformed input is a typed error, never a panic.
//!
//! See SPEC.md for the format, the behaviour choices and what is not done.

const std = @import("std");

pub const meta = .{
    .doc = "LZ4 block and frame (.lz4) codec: fast greedy compressor with acceleration, bounded decompressor for frames (checksums, linked blocks, skippable, legacy) and raw blocks",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "liblz4 1.10.0 (Yann Collet) and its lz4 CLI; checked against both and python-lz4",
    .deps = .{},
};

const block = @import("block.zig");
const frame = @import("frame.zig");

// ── block format ────────────────────────────────────────────────────────

pub const BlockError = block.Error;
pub const BlockOptions = block.CompressOptions;
/// Decode one block into `dst`; returns the decoded length. `dst.len` is the
/// output budget. No history: every match must stay inside `dst`.
pub const decompressBlock = block.decompress;
/// Compress `src` as one block into `dst` (`compressBlockBound(src.len)`
/// bytes always fit; with less, `error.NoSpaceLeft`).
pub const compressBlock = block.compress;
/// liblz4's `LZ4_COMPRESSBOUND(n)`: `n + n / 255 + 16`.
pub const compressBlockBound = block.compressBound;
/// The largest input `compressBlock` takes (liblz4's `LZ4_MAX_INPUT_SIZE`).
pub const max_block_input = block.max_input_size;

// ── frame format ────────────────────────────────────────────────────────

pub const DecodeError = frame.DecodeError;
pub const DecodeOptions = frame.DecodeOptions;
/// `DecodeOptions.max_output`'s default (256 MiB).
pub const default_max_output = frame.default_max_output;
/// Every frame of `src`, concatenated. Caller owns the result.
pub const decompress = frame.decompress;
/// Every frame of `src` decoded into `dst`; returns the decoded length.
/// `dst.len` caps the output (`error.OutputTooLarge` past it). No allocation.
pub const decompressInto = frame.decompressInto;

pub const EncodeError = frame.EncodeError;
pub const EncodeOptions = frame.EncodeOptions;
pub const BlockSize = frame.BlockSize;
/// One frame holding `src`. Caller owns the result.
pub const compress = frame.compress;
/// One frame into a caller's buffer; returns its length.
pub const compressInto = frame.compressInto;
/// The largest frame `compress` writes for `n` bytes with `opts`.
pub const compressBound = frame.compressBound;

/// Frame magic numbers.
pub const frame_magic = frame.magic;
pub const legacy_frame_magic = frame.legacy_magic;
pub const skippable_magic_base = frame.skippable_magic_base;

/// The input shapes the differential tests use; public only so
/// `tools/interop.zig` and `tools/bench.zig` can reach them. Not part of the API.
pub const interop_corpus = @import("shapes.zig");

test {
    _ = @import("block.zig");
    _ = @import("frame_test.zig");
    _ = @import("shapes.zig");
    _ = @import("golden_test.zig");
    _ = @import("fuzz_test.zig");
}
