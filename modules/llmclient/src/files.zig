// SPDX-License-Identifier: MIT

//! The Files API (`/v1/files`, beta `files-api-2025-04-14`): the file
//! metadata object, the list page and the delete acknowledgement, parsed
//! from the wire. The calls are `Client.uploadFile`, `getFile`,
//! `listFiles`, `fileContent` and `deleteFile`; an uploaded file is used in
//! a request as `ImageSource.file` / `DocumentSource.file`.
//!
//! Same conventions as `response.zig`: every string borrows from the
//! arena the caller passes.

const std = @import("std");
const response = @import("response.zig");

pub const ParseError = response.ParseError;

/// The beta header value the Files API needs; `Client` adds it to every
/// call of its own. A request that uses a `file` source has to carry it
/// too (`Client.betas` or `RequestOptions.betas`).
pub const beta = "files-api-2025-04-14";

/// A `file` object.
pub const FileMetadata = struct {
    id: []const u8,
    filename: []const u8,
    mime_type: []const u8,
    size_bytes: u64,
    /// RFC 3339.
    created_at: []const u8,
    /// Whether `Client.fileContent` can fetch it (only files a tool
    /// produced, not the ones you uploaded).
    downloadable: bool,
};

/// One page of `GET /v1/files`; continue with `ListOptions.after_id =
/// last_id` while `has_more`.
pub const FileList = struct {
    data: []const FileMetadata,
    has_more: bool,
    first_id: ?[]const u8,
    last_id: ?[]const u8,
};

/// The answer to `DELETE /v1/files/{id}`.
pub const DeletedFile = struct { id: []const u8 };

fn rootObject(arena: std.mem.Allocator, body: []const u8) ParseError!std.json.ObjectMap {
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    if (root != .object) return error.MalformedResponse;
    return root.object;
}

fn fileFromObject(obj: std.json.ObjectMap) ParseError!FileMetadata {
    if (obj.get("id") == null) return error.MalformedResponse;
    const dl = obj.get("downloadable") orelse .null;
    return .{
        .id = response.strField(obj, "id"),
        .filename = response.strField(obj, "filename"),
        .mime_type = response.strField(obj, "mime_type"),
        .size_bytes = try response.u64Field(obj, "size_bytes"),
        .created_at = response.strField(obj, "created_at"),
        .downloadable = dl == .bool and dl.bool,
    };
}

pub fn parseFile(arena: std.mem.Allocator, body: []const u8) ParseError!FileMetadata {
    return fileFromObject(try rootObject(arena, body));
}

pub fn parseFileList(arena: std.mem.Allocator, body: []const u8) ParseError!FileList {
    const obj = try rootObject(arena, body);
    const items = response.arrField(obj, "data");
    const out = try arena.alloc(FileMetadata, items.len);
    for (items, 0..) |item, i| {
        if (item != .object) return error.MalformedResponse;
        out[i] = try fileFromObject(item.object);
    }
    const more = obj.get("has_more") orelse .null;
    return .{
        .data = out,
        .has_more = more == .bool and more.bool,
        .first_id = response.optStrField(obj, "first_id"),
        .last_id = response.optStrField(obj, "last_id"),
    };
}

pub fn parseDeletedFile(arena: std.mem.Allocator, body: []const u8) ParseError!DeletedFile {
    const obj = try rootObject(arena, body);
    if (obj.get("id") == null) return error.MalformedResponse;
    return .{ .id = response.strField(obj, "id") };
}

// ── tests ───────────────────────────────────────────────────────────────────
//
// The bodies are the shapes of Anthropic's published Files API examples
// (upload / list / delete); not captured from the live API.

const testing = std.testing;

test "parseFile, parseFileList and parseDeletedFile" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try parseFile(a,
        \\{"id":"file_011CNha8iCJcU1wXNR6q4V8w","type":"file","filename":"document.pdf","mime_type":"application/pdf",
        \\"size_bytes":1024000,"created_at":"2025-01-01T00:00:00Z","downloadable":false}
    );
    try testing.expectEqualStrings("file_011CNha8iCJcU1wXNR6q4V8w", f.id);
    try testing.expectEqualStrings("application/pdf", f.mime_type);
    try testing.expectEqual(@as(u64, 1024000), f.size_bytes);
    try testing.expect(!f.downloadable);
    const l = try parseFileList(a,
        \\{"data":[{"id":"file_1","filename":"a.txt","mime_type":"text/plain","size_bytes":3,"created_at":"t","downloadable":true}],
        \\"first_id":"file_1","has_more":false,"last_id":"file_1"}
    );
    try testing.expectEqual(@as(usize, 1), l.data.len);
    try testing.expect(l.data[0].downloadable and !l.has_more);
    try testing.expectEqualStrings("file_1", l.last_id.?);
    try testing.expectEqualStrings("file_1", (try parseDeletedFile(a, "{\"id\":\"file_1\",\"type\":\"file_deleted\"}")).id);
    try testing.expectError(error.MalformedResponse, parseFile(a, "{\"filename\":\"x\"}"));
    try testing.expectError(error.MalformedResponse, parseFile(a, "{\"id\":\"f\",\"size_bytes\":-5}"));
    try testing.expectError(error.MalformedResponse, parseFileList(a, "{\"data\":{}}x"));
    try testing.expectError(error.MalformedResponse, parseDeletedFile(a, "{}"));
}
