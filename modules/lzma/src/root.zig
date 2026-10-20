// SPDX-License-Identifier: MIT

//! lzma — LZMA1, LZMA2 and the .xz container.

const std = @import("std");

pub const meta = .{
    .doc = "LZMA1, LZMA2 and the .xz / .lzma containers: streaming decoder with a dictionary cap, and a liblzma-compatible encoder",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "XZ Utils liblzma 5.8.1 (0BSD); output checked against it",
    .deps = .{},
};

const decoder = @import("decoder.zig");
const encoder = @import("encoder.zig");

pub const DecodeError = decoder.Error;
pub const DecodeOptions = decoder.Options;
pub const Format = decoder.Format;
pub const Lzma1Props = decoder.Lzma1Props;
pub const decompress = decoder.decompress;
pub const decompressStream = decoder.decompressStream;
pub const DecompressReader = decoder.DecompressReader;
pub const Decoder = decoder.Decoder;

/// The input shapes the differential tests use; public only so
/// `tools/interop.zig` can reach them. Not part of the API.
pub const interop_corpus = @import("shapes.zig");
pub const interop_spec = @import("spec.zig");

// ── encoding ────────────────────────────────────────────────────────────

pub const EncodeFormat = encoder.Format;
pub const EncodeOptions = encoder.Options;
pub const LzmaOptions = encoder.LzmaOptions;
pub const Check = encoder.Check;
pub const MatchFinder = encoder.MatchFinder;
pub const Mode = encoder.Mode;
pub const preset = encoder.preset;
pub const compress = encoder.compress;
pub const compressInto = encoder.compressInto;
pub const compressBound = encoder.compressBound;
pub const Encoder = encoder.Encoder;
pub const StreamWriter = encoder.StreamWriter;

test {
    _ = @import("shapes.zig");
    _ = @import("decoder_test.zig");
    _ = @import("encoder_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("golden_test.zig");
}
