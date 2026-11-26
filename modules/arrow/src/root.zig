// SPDX-License-Identifier: MIT

//! arrow — Apache Arrow IPC (stream and file format) for `dataframe.Frame`.
//!
//! `writeStream` / `readStream` turn a whole frame into an Arrow IPC stream and
//! back. Underneath: the FlatBuffers layer
//! (`fb`) Arrow's metadata is written in, the schema tables (`schema`) and the
//! message framing (`ipc`). `writeFile` / `readFile` / `openFile` do the same for the
//! IPC file format, with random access to a record batch, and ZSTD and
//! LZ4_FRAME body compression both ways (`WriteOptions.compression`).

const std = @import("std");

pub const meta = .{
    .doc = "Apache Arrow IPC stream and file format for dataframe frames (stream and file format, ZSTD and LZ4_FRAME body compression)",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "Apache Arrow columnar format 1.x (arrow-rs arrow-ipc, pyarrow.ipc)",
    .deps = .{ "dataframe", "zstd", "lz4" },
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
pub const Compression = stream.Compression;
/// Key/value metadata (`ReadOptions.metadata` out, `WriteOptions.*_metadata` in).
pub const KeyValue = stream.KeyValue;
pub const FieldMetadata = stream.FieldMetadata;
pub const Metadata = stream.Metadata;
/// A column picked by `ReadOptions.columns` (by name or by index).
pub const ColumnRef = stream.ColumnRef;
/// The frame as an Arrow IPC stream (caller frees the bytes).
pub const writeStream = stream.writeStream;
/// An Arrow IPC stream as a frame allocated from an arena.
pub const readStream = stream.readStream;
/// The frame as an Arrow IPC file (caller frees the bytes).
pub const writeFile = stream.writeFile;
/// Every batch of an Arrow IPC file as a frame allocated from an arena.
pub const readFile = stream.readFile;
/// Opens an Arrow IPC file for random access to its record batches.
pub const openFile = stream.openFile;
pub const File = stream.File;

test {
    _ = fb;
    _ = schema;
    _ = ipc;
    _ = stream;
    _ = @import("stream_test.zig");
    _ = @import("hostile_test.zig");
    _ = @import("golden_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("guards_test.zig");
    _ = @import("dict_test.zig");
    _ = @import("sweep_test.zig");
    _ = @import("mutation_test.zig");
}
