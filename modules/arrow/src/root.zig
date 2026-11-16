// SPDX-License-Identifier: MIT

//! arrow — Apache Arrow IPC (stream and file format) for `dataframe.Frame`.
//!
//! Work in progress (wave A1 of the plan in SPEC.md): the FlatBuffers layer
//! (`fb`) Arrow's metadata is written in. The schema mapping, the IPC stream
//! and file formats and body compression follow in later waves.

const std = @import("std");

pub const meta = .{
    .doc = "Apache Arrow IPC stream and file format for dataframe frames (in progress: FlatBuffers metadata layer)",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "Apache Arrow columnar format 1.x (arrow-rs arrow-ipc, pyarrow.ipc)",
    .deps = .{},
};

/// The FlatBuffers subset Arrow's metadata uses (bounds-checked reader, back-to-front builder).
pub const fb = @import("fb.zig");
/// Arrow schema metadata (`Schema.fbs`) and the `Message` envelope (`Message.fbs`).
pub const schema = @import("schema.zig");
/// IPC framing (encapsulated messages, end of stream) and the RecordBatch / DictionaryBatch metadata.
pub const ipc = @import("ipc.zig");

test {
    _ = fb;
    _ = schema;
    _ = ipc;
}
