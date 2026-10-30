// SPDX-License-Identifier: MIT

//! bzip2 — the .bz2 format (and the raw stream ZIP method 12 carries): a
//! compressor that emits, byte for byte, what libbzip2 1.0.8 emits at the
//! same level and work factor, and a streaming decompressor with a
//! decompression-bomb cap.
//!
//! Decoder: concatenated streams, block and stream CRCs checked, randomised
//! blocks of old encoders, memory bounded by one block (`DecompressReader`
//! is a pull `std.Io.Reader`; `decompress` the whole-buffer helper).
//! Malformed input is a typed `DecodeError`, never a panic.
//!
//! Encoder: levels 1..9 (block size 100 kB .. 900 kB), libbzip2's block
//! sort including its fallback sort and work-factor switch, MTF with
//! zero-run coding, up to six Huffman tables chosen by the same iterative
//! refinement. `StreamWriter` is a `std.Io.Writer`; `compress` the
//! whole-buffer helper. Output depends on the input only, not on how it
//! was chunked into writes.
//!
//! See SPEC.md for the format, the parity claim and what is not done, and
//! `example/main.zig` for the smallest whole round trip.

const std = @import("std");

pub const meta = .{
    .doc = "bzip2 (.bz2 and ZIP method 12): byte-exact libbzip2 1.0.8 compressor (levels 1-9) and a streaming CRC-checked decompressor with a bomb cap",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "libbzip2 1.0.8 (Julian Seward); output checked byte-for-byte against it",
    .deps = .{},
};

const decoder = @import("decoder.zig");
const encoder = @import("encoder.zig");

// ── decoding ────────────────────────────────────────────────────────────

pub const DecodeError = decoder.Error;
pub const DecodeOptions = decoder.Options;
/// `DecodeOptions.max_output`'s default (256 MiB).
pub const decoder_default_max_output = decoder.default_max_output;
/// Every stream of a byte slice. Caller owns the result.
pub const decompress = decoder.decompress;
/// From a `std.Io.Reader` to a `std.Io.Writer`, one block in memory.
pub const decompressStream = decoder.decompressStream;
/// A pull `std.Io.Reader` over the decompressed bytes.
pub const DecompressReader = decoder.DecompressReader;
/// The decoder core under both: `read(dest)` until it returns 0.
pub const Decoder = decoder.Decoder;

// ── encoding ────────────────────────────────────────────────────────────

pub const EncodeError = encoder.Error;
pub const EncodeOptions = encoder.Options;
/// A complete .bz2 stream. Caller owns the result.
pub const compress = encoder.compress;
/// `compress` into a caller's buffer; `compressBound(n)` bytes always fit.
pub const compressInto = encoder.compressInto;
/// A bound on the compressed size of `n` input bytes.
pub const compressBound = encoder.compressBound;
/// A `std.Io.Writer` that compresses into one stream.
pub const StreamWriter = encoder.StreamWriter;
/// The compressor core under both.
pub const Encoder = encoder.Encoder;

/// The CRC-32 bzip2 uses (MSB-first, not zlib's), for callers that verify
/// a stream's block CRCs themselves.
pub const crc = @import("crc.zig");

/// The input shapes the differential tests use; public only so
/// `tools/interop.zig` can reach them. Not part of the API.
pub const interop_corpus = @import("shapes.zig");

test {
    _ = @import("crc.zig");
    _ = @import("huffman.zig");
    _ = @import("blocksort.zig");
    _ = @import("roundtrip_test.zig");
    _ = @import("decoder_test.zig");
    _ = @import("golden_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("sweep_test.zig");
}
