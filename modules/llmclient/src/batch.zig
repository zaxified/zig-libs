// SPDX-License-Identifier: MIT

//! The Message Batches API (`/v1/messages/batches`): the batch object, the
//! list page, the delete acknowledgement and one line of a batch's JSONL
//! results, parsed from the wire. The request side is
//! `types.BatchRequest`; the calls are `Client.createBatch`, `getBatch`,
//! `listBatches`, `cancelBatch`, `deleteBatch` and `batchResults`.
//!
//! Same conventions as `response.zig`: every string borrows from the
//! arena the caller passes, nothing here allocates beyond the one
//! `std.json.Value` parse and the slices it builds.

const std = @import("std");
const response = @import("response.zig");

pub const ParseError = response.ParseError;
pub const Message = response.Message;
pub const ErrorDetail = response.ErrorDetail;

/// `processing_status` of a batch.
pub const ProcessingStatus = enum {
    in_progress,
    canceling,
    ended,
    /// A status this client does not know.
    unknown,
};

/// How many of a batch's requests are in each state.
pub const RequestCounts = struct {
    processing: u64 = 0,
    succeeded: u64 = 0,
    errored: u64 = 0,
    canceled: u64 = 0,
    expired: u64 = 0,
};

/// A `message_batch` object. The timestamps are the RFC 3339 strings of
/// the wire; `results_url` is set once the batch has ended.
pub const MessageBatch = struct {
    id: []const u8,
    processing_status: ProcessingStatus,
    request_counts: RequestCounts,
    created_at: []const u8,
    expires_at: []const u8,
    ended_at: ?[]const u8,
    cancel_initiated_at: ?[]const u8,
    results_url: ?[]const u8,
};

/// One page of `GET /v1/messages/batches`; continue with
/// `ListOptions.after_id = last_id` while `has_more`.
pub const BatchList = struct {
    data: []const MessageBatch,
    has_more: bool,
    first_id: ?[]const u8,
    last_id: ?[]const u8,
};

/// The answer to `DELETE /v1/messages/batches/{id}`.
pub const DeletedBatch = struct { id: []const u8 };

/// How one request of a batch ended.
pub const BatchResult = union(enum) {
    succeeded: Message,
    /// The request failed; `type` is the API's error type
    /// (`"invalid_request_error"`, `"overloaded_error"`, ...).
    errored: ErrorDetail,
    canceled,
    expired,
};

/// One line of a batch's results: the request's `custom_id` and its
/// outcome. Results are in no particular order.
pub const BatchResultItem = struct {
    custom_id: []const u8,
    result: BatchResult,
};

fn parseStatus(s: []const u8) ProcessingStatus {
    return std.meta.stringToEnum(ProcessingStatus, s) orelse .unknown;
}

fn rootObject(arena: std.mem.Allocator, body: []const u8) ParseError!std.json.ObjectMap {
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    if (root != .object) return error.MalformedResponse;
    return root.object;
}

fn batchFromObject(obj: std.json.ObjectMap) ParseError!MessageBatch {
    // An object with no `id` is not a batch.
    if (obj.get("id") == null) return error.MalformedResponse;
    var counts: RequestCounts = .{};
    if (response.objField(obj, "request_counts")) |c| counts = .{
        .processing = try response.u64Field(c, "processing"),
        .succeeded = try response.u64Field(c, "succeeded"),
        .errored = try response.u64Field(c, "errored"),
        .canceled = try response.u64Field(c, "canceled"),
        .expired = try response.u64Field(c, "expired"),
    };
    return .{
        .id = response.strField(obj, "id"),
        .processing_status = parseStatus(response.strField(obj, "processing_status")),
        .request_counts = counts,
        .created_at = response.strField(obj, "created_at"),
        .expires_at = response.strField(obj, "expires_at"),
        .ended_at = response.optStrField(obj, "ended_at"),
        .cancel_initiated_at = response.optStrField(obj, "cancel_initiated_at"),
        .results_url = response.optStrField(obj, "results_url"),
    };
}

/// Parses one `message_batch` object (the answer to create, retrieve and
/// cancel).
pub fn parseBatch(arena: std.mem.Allocator, body: []const u8) ParseError!MessageBatch {
    return batchFromObject(try rootObject(arena, body));
}

pub fn parseBatchList(arena: std.mem.Allocator, body: []const u8) ParseError!BatchList {
    const obj = try rootObject(arena, body);
    const items = response.arrField(obj, "data");
    const out = try arena.alloc(MessageBatch, items.len);
    for (items, 0..) |item, i| {
        if (item != .object) return error.MalformedResponse;
        out[i] = try batchFromObject(item.object);
    }
    const more = obj.get("has_more") orelse .null;
    return .{
        .data = out,
        .has_more = more == .bool and more.bool,
        .first_id = response.optStrField(obj, "first_id"),
        .last_id = response.optStrField(obj, "last_id"),
    };
}

pub fn parseDeletedBatch(arena: std.mem.Allocator, body: []const u8) ParseError!DeletedBatch {
    const obj = try rootObject(arena, body);
    if (obj.get("id") == null) return error.MalformedResponse;
    return .{ .id = response.strField(obj, "id") };
}

/// Parses one line of the JSONL results body.
pub fn parseResultLine(arena: std.mem.Allocator, line: []const u8) ParseError!BatchResultItem {
    const obj = try rootObject(arena, line);
    const custom_id = response.optStrField(obj, "custom_id") orelse return error.MalformedResponse;
    const r = response.objField(obj, "result") orelse return error.MalformedResponse;
    const t = response.strField(r, "type");
    const result: BatchResult = if (std.mem.eql(u8, t, "succeeded")) .{
        .succeeded = try response.messageFromObject(arena, response.objField(r, "message") orelse return error.MalformedResponse),
    } else if (std.mem.eql(u8, t, "errored")) blk: {
        // The error is the API's usual envelope, `{"type":"error","error":
        // {"type":..., "message":...}, "request_id":...}`; a bare detail
        // object is read as well.
        const e = response.objField(r, "error") orelse return error.MalformedResponse;
        const inner = response.objField(e, "error") orelse e;
        break :blk .{ .errored = .{ .type = response.strField(inner, "type"), .message = response.strField(inner, "message") } };
    } else if (std.mem.eql(u8, t, "canceled")) .canceled else if (std.mem.eql(u8, t, "expired")) .expired else return error.MalformedResponse;
    return .{ .custom_id = custom_id, .result = result };
}

// ── tests ───────────────────────────────────────────────────────────────────
//
// The bodies are the shapes of Anthropic's published Message Batches
// examples (create / retrieve / results); not captured from the live API.

const testing = std.testing;

test "parseBatch: the in-progress and the ended batch object" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const b = try parseBatch(a,
        \\{"id":"msgbatch_01HkcTjaV5uDC8jWR4ZsDV8d","type":"message_batch","processing_status":"in_progress",
        \\"request_counts":{"processing":2,"succeeded":0,"errored":0,"canceled":0,"expired":0},
        \\"ended_at":null,"created_at":"2024-09-24T18:37:24.100435Z","expires_at":"2024-09-25T18:37:24.100435Z",
        \\"cancel_initiated_at":null,"results_url":null}
    );
    try testing.expectEqualStrings("msgbatch_01HkcTjaV5uDC8jWR4ZsDV8d", b.id);
    try testing.expectEqual(ProcessingStatus.in_progress, b.processing_status);
    try testing.expectEqual(@as(u64, 2), b.request_counts.processing);
    try testing.expectEqual(@as(?[]const u8, null), b.ended_at);
    try testing.expectEqual(@as(?[]const u8, null), b.results_url);
    try testing.expectEqualStrings("2024-09-25T18:37:24.100435Z", b.expires_at);

    const e = try parseBatch(a,
        \\{"id":"msgbatch_x","type":"message_batch","processing_status":"ended",
        \\"request_counts":{"processing":0,"succeeded":1,"errored":1,"canceled":0,"expired":0},
        \\"ended_at":"2024-09-24T19:00:00Z","created_at":"c","expires_at":"x","cancel_initiated_at":"2024-09-24T18:50:00Z",
        \\"results_url":"https://api.anthropic.com/v1/messages/batches/msgbatch_x/results"}
    );
    try testing.expectEqual(ProcessingStatus.ended, e.processing_status);
    try testing.expectEqual(@as(u64, 1), e.request_counts.errored);
    try testing.expectEqualStrings("2024-09-24T18:50:00Z", e.cancel_initiated_at.?);
    try testing.expect(e.results_url != null);
    // An unknown status is `.unknown`, an object with no id is no batch.
    try testing.expectEqual(ProcessingStatus.unknown, (try parseBatch(a, "{\"id\":\"m\",\"processing_status\":\"paused\"}")).processing_status);
    try testing.expectError(error.MalformedResponse, parseBatch(a, "{\"type\":\"message_batch\"}"));
    try testing.expectError(error.MalformedResponse, parseBatch(a, "[]"));
    try testing.expectError(error.MalformedResponse, parseBatch(a, "{\"id\":\"m\",\"request_counts\":{\"errored\":-1}}"));
}

test "parseBatchList and parseDeletedBatch" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try parseBatchList(a,
        \\{"data":[{"id":"msgbatch_1","processing_status":"ended"},{"id":"msgbatch_2","processing_status":"in_progress"}],
        \\"has_more":true,"first_id":"msgbatch_1","last_id":"msgbatch_2"}
    );
    try testing.expectEqual(@as(usize, 2), l.data.len);
    try testing.expect(l.has_more);
    try testing.expectEqualStrings("msgbatch_2", l.last_id.?);
    const empty = try parseBatchList(a, "{\"data\":[],\"has_more\":false,\"first_id\":null,\"last_id\":null}");
    try testing.expectEqual(@as(usize, 0), empty.data.len);
    try testing.expect(!empty.has_more and empty.first_id == null);
    try testing.expectError(error.MalformedResponse, parseBatchList(a, "{\"data\":[3]}"));
    const d = try parseDeletedBatch(a, "{\"id\":\"msgbatch_1\",\"type\":\"message_batch_deleted\"}");
    try testing.expectEqualStrings("msgbatch_1", d.id);
    try testing.expectError(error.MalformedResponse, parseDeletedBatch(a, "{}"));
}

test "parseResultLine: succeeded, errored, canceled and expired" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ok = try parseResultLine(a,
        \\{"custom_id":"my-second-request","result":{"type":"succeeded","message":{"id":"msg_014VwiXbi91y3JMjcpyGBHX5",
        \\"type":"message","role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"Hello again!"}],
        \\"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":11,"output_tokens":36}}}}
    );
    try testing.expectEqualStrings("my-second-request", ok.custom_id);
    try testing.expectEqualStrings("Hello again!", ok.result.succeeded.content[0].text.text);
    try testing.expectEqual(@as(u64, 36), ok.result.succeeded.usage.output_tokens);

    const bad = try parseResultLine(a,
        \\{"custom_id":"r3","result":{"type":"errored","error":{"type":"error","error":{"type":"invalid_request_error",
        \\"message":"max_tokens: 0 < 1"},"request_id":"req_011"}}}
    );
    try testing.expectEqualStrings("invalid_request_error", bad.result.errored.type);
    try testing.expectEqualStrings("max_tokens: 0 < 1", bad.result.errored.message);
    // The bare detail object is read too.
    const bare = try parseResultLine(a, "{\"custom_id\":\"r4\",\"result\":{\"type\":\"errored\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"busy\"}}}");
    try testing.expectEqualStrings("overloaded_error", bare.result.errored.type);
    try testing.expect((try parseResultLine(a, "{\"custom_id\":\"r5\",\"result\":{\"type\":\"canceled\"}}")).result == .canceled);
    try testing.expect((try parseResultLine(a, "{\"custom_id\":\"r6\",\"result\":{\"type\":\"expired\"}}")).result == .expired);
    // No custom_id, no result, an unknown outcome, a succeeded line without a message, not JSON.
    try testing.expectError(error.MalformedResponse, parseResultLine(a, "{\"result\":{\"type\":\"canceled\"}}"));
    try testing.expectError(error.MalformedResponse, parseResultLine(a, "{\"custom_id\":\"r\"}"));
    try testing.expectError(error.MalformedResponse, parseResultLine(a, "{\"custom_id\":\"r\",\"result\":{\"type\":\"paused\"}}"));
    try testing.expectError(error.MalformedResponse, parseResultLine(a, "{\"custom_id\":\"r\",\"result\":{\"type\":\"succeeded\"}}"));
    try testing.expectError(error.MalformedResponse, parseResultLine(a, "not json"));
}

// ── fuzzing: the batch and file parsers over arbitrary bodies ───────────────

const fz = @import("fuzz_test.zig");
const files = @import("files.zig");

const BatchMark = fz.Marker(enum { accepted, refused, genuine });

const batch_corpus = [_][]const u8{
    "{\"custom_id\":\"a\",\"result\":{\"type\":\"succeeded\",\"message\":{\"id\":\"m\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"hi\"}],\"usage\":{\"input_tokens\":1}}}}",
    "{\"custom_id\":\"b\",\"result\":{\"type\":\"errored\",\"error\":{\"type\":\"error\",\"error\":{\"type\":\"x\",\"message\":\"y\"}}}}",
    "{\"id\":\"msgbatch_1\",\"processing_status\":\"ended\",\"request_counts\":{\"succeeded\":1},\"results_url\":\"u\"}",
    "{\"data\":[{\"id\":\"msgbatch_1\"}],\"has_more\":true,\"last_id\":\"msgbatch_1\"}",
    "{\"id\":\"file_1\",\"filename\":\"a\",\"mime_type\":\"text/plain\",\"size_bytes\":3,\"downloadable\":true}",
    "{\"data\":[{\"id\":\"file_1\",\"size_bytes\":1e300}],\"has_more\":false}",
};

fn fuzzBatchSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzBatch(std.testing.Smith, smith, testing.allocator);
}

fn fuzzBatch(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [320]u8 = undefined;
    const len = fz.drawRaw(S, src, &buf, &batch_corpus);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const data = buf[0..len];
    var ok = false;
    if (parseResultLine(a, data)) |_| ok = true else |_| {}
    if (parseBatch(a, data)) |_| ok = true else |_| {}
    if (parseBatchList(a, data)) |_| ok = true else |_| {}
    if (parseDeletedBatch(a, data)) |_| ok = true else |_| {}
    if (files.parseFile(a, data)) |_| ok = true else |_| {}
    if (files.parseFileList(a, data)) |_| ok = true else |_| {}
    if (ok) BatchMark.mark(.accepted) else BatchMark.mark(.refused);

    // A well-formed result line with a drawn custom_id and count comes back whole.
    var id: [24]u8 = undefined;
    const n = src.valueRangeAtMost(u8, 1, id.len);
    for (id[0..n]) |*c| c.* = "abcdefghijklmnopqrstuvwxyz0123456789_-"[src.index(38)];
    const count: u64 = src.value(u64) & std.math.maxInt(i64);
    var jb: [200]u8 = undefined;
    const doc = try std.mem.print(&jb, "{{\"custom_id\":\"{s}\",\"result\":{{\"type\":\"succeeded\",\"message\":{{\"id\":\"m\",\"usage\":{{\"output_tokens\":{d}}}}}}}}}", .{ id[0..n], count });
    const item = parseResultLine(a, doc) catch return error.GenuineLineRefused;
    if (!std.mem.eql(u8, item.custom_id, id[0..n]) or item.result.succeeded.usage.output_tokens != count) return error.GenuineLineChanged;
    BatchMark.mark(.genuine);
}

test "fuzz driver: LLMCLIENT_FUZZ (batch and file parsers)" {
    try fz.fuzz_driver.run(fuzzBatch, .{ .prefix = "LLMCLIENT_FUZZ", .name = "llmclient-batch" });
}
test "fuzz harness: batch and file parsers, 300 seeds, reaches every outcome" {
    try BatchMark.reach(fuzzBatch, "llmclient-batch", 300);
}
test "fuzz batch and file parsers never panic" {
    try testing.fuzz({}, fuzzBatchSmith, .{ .corpus = &batch_corpus });
}
