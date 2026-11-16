// SPDX-License-Identifier: MIT

//! arrow — Apache Arrow IPC (stream and file format) for `dataframe.Frame`.
//!
//! `writeStream` / `readStream` turn a whole frame into an Arrow IPC stream and
//! back (waves A2 + A3 of the plan in SPEC.md). Underneath: the FlatBuffers layer
//! (`fb`) Arrow's metadata is written in, the schema tables (`schema`) and the
//! message framing (`ipc`). The file format and body compression follow.

const std = @import("std");

pub const meta = .{
    .doc = "Apache Arrow IPC stream and file format for dataframe frames (in progress: stream format done, file format and compression to come)",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "Apache Arrow columnar format 1.x (arrow-rs arrow-ipc, pyarrow.ipc)",
    .deps = .{"dataframe"},
};

/// The FlatBuffers subset Arrow's metadata uses (bounds-checked reader, back-to-front builder).
pub const fb = @import("fb.zig");
/// Arrow schema metadata (`Schema.fbs`) and the `Message` envelope (`Message.fbs`).
pub const schema = @import("schema.zig");
/// IPC framing (encapsulated messages, end of stream) and the RecordBatch / DictionaryBatch metadata.
pub const ipc = @import("ipc.zig");
/// The frame <-> Arrow type mapping and the stream writer and reader.
pub const stream = @import("stream.zig");

pub const Error = stream.Error;
pub const WriteOptions = stream.WriteOptions;
pub const ReadOptions = stream.ReadOptions;
/// The frame as an Arrow IPC stream (caller frees the bytes).
pub const writeStream = stream.writeStream;
/// An Arrow IPC stream as a frame allocated from an arena.
pub const readStream = stream.readStream;

test {
    _ = fb;
    _ = schema;
    _ = ipc;
    _ = stream;
    _ = @import("stream_test.zig");
}
