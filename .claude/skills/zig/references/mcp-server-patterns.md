# MCP Server Patterns in Zig

Real-world patterns from [zig-mcp](https://github.com/nzrsky/zig-mcp) — an MCP server that bridges AI assistants to ZLS via LSP. Pure `std` library, no external dependencies, ~2k LoC. Demonstrates protocol bridging, child process management, thread coordination, and JSON-RPC handling in Zig 0.15.2.

## Table of Contents

- [Architecture: Protocol Bridge](#architecture-protocol-bridge)
- [MCP Transport (Newline-Delimited JSON-RPC)](#mcp-transport-newline-delimited-json-rpc)
- [LSP Transport (Content-Length Framing)](#lsp-transport-content-length-framing)
- [Thread Model & Request Correlation](#thread-model--request-correlation)
- [Arena-Per-Request Memory](#arena-per-request-memory)
- [Child Process Lifecycle](#child-process-lifecycle)
- [Pipe Ownership & Double-Close Prevention](#pipe-ownership--double-close-prevention)
- [Tool Registry Pattern](#tool-registry-pattern)
- [JSON Building with std.json.Stringify](#json-building-with-stdjsonstringify)
- [Lazy Document Sync with Double-Check Locking](#lazy-document-sync-with-double-check-locking)
- [Graceful Degradation](#graceful-degradation)
- [Auto-Reconnect on Crash](#auto-reconnect-on-crash)
- [Custom JSON-RPC Types](#custom-json-rpc-types)
- [File URI Encoding](#file-uri-encoding)
- [Comptime Schema Generation](#comptime-schema-generation)
- [Test Discovery via comptime Import](#test-discovery-via-comptime-import)
- [Common Gotchas](#common-gotchas)

---

## Architecture: Protocol Bridge

```
AI assistant ←(newline JSON-RPC)→ zig-mcp ←(Content-Length JSON-RPC)→ ZLS child process
                                      ↓
                                 zig build/test/check (direct child processes)
```

Three threads in steady state:

| Thread | Role |
|--------|------|
| **Main** | Reads MCP stdin → dispatches → writes MCP stdout |
| **ZLS reader** | Reads ZLS stdout → correlates responses by ID → wakes main |
| **ZLS stderr** | Forwards ZLS stderr to server log |

Key insight: MCP uses newline-delimited messages (no headers), LSP uses `Content-Length: N\r\n\r\n` framing. The bridge translates between the two.

---

## MCP Transport (Newline-Delimited JSON-RPC)

**0.16:** `std.Thread.Mutex` is removed — use `std.Io.Mutex` (needs `io: Io`; see [std.Thread reference](std-thread.md)). `std.Io.File` also has no bare `.read()`/`.writeAll()` anymore — go through the buffered `.reader(io, buf)`/`.writer(io, buf)` wrapper and its `.interface`:

```zig
pub const McpTransport = struct {
    stdin_file: std.Io.File,
    stdout_file: std.Io.File,
    stdout_mutex: std.Io.Mutex = .init,

    pub fn readMessage(self: *McpTransport, io: std.Io, allocator: std.mem.Allocator) !?[]const u8 {
        var line: std.ArrayList(u8) = .empty;
        errdefer line.deinit(allocator);

        var buf: [4096]u8 = undefined;
        var reader = self.stdin_file.reader(io, &buf);
        while (true) {
            const byte = reader.interface.takeByte() catch |err| switch (err) {
                error.EndOfStream => { if (line.items.len == 0) return null; break; },
                else => return err,
            };
            if (byte == '\n') break;
            if (byte == '\r') continue;
            try line.append(allocator, byte);
            if (line.items.len > 1024 * 1024) return error.MessageTooLarge;
        }
        if (line.items.len == 0) return null;
        return try line.toOwnedSlice(allocator);
    }

    /// Thread-safe write with mutex (reader thread may trigger writes).
    pub fn writeMessage(self: *McpTransport, io: std.Io, data: []const u8) !void {
        try self.stdout_mutex.lock(io);
        defer self.stdout_mutex.unlock(io);
        var buf: [4096]u8 = undefined;
        var writer = self.stdout_file.writer(io, &buf);
        try writer.interface.writeAll(data);
        try writer.interface.writeAll("\n");
        try writer.interface.flush();
    }
};
```

- Byte-by-byte read via the buffered `Io.Reader` interface because we need owned memory per message
- `EndOfStream` → graceful `null` (EOF), not a hard error
- `Io.Mutex` on stdout for thread safety
- 1MB limit prevents OOM from malformed input

---

## LSP Transport (Content-Length Framing)

```zig
pub const LspTransport = struct {
    pub const Reader = struct {
        file: std.Io.File,
        io: std.Io,
        buf: [8192]u8 = undefined,
        buf_start: usize = 0,
        buf_end: usize = 0,

        fn readByte(self: *Reader) !?u8 {
            const io = self.io;
            if (self.buf_start >= self.buf_end) {
                const n = self.file.readStreaming(io, &.{&self.buf}) catch |err| switch (err) {
                    error.EndOfStream, error.ReadFailed => return null,
                };
                if (n == 0) return null;
                self.buf_start = 0;
                self.buf_end = n;
            }
            const byte = self.buf[self.buf_start];
            self.buf_start += 1;
            return byte;
        }

        /// Drain internal buffer first, then read directly for large bodies.
        fn readExact(self: *Reader, dest: []u8) !bool {
            const io = self.io;
            var pos: usize = 0;
            while (pos < dest.len) {
                const buffered = self.buf_end - self.buf_start;
                if (buffered > 0) {
                    const to_copy = @min(buffered, dest.len - pos);
                    @memcpy(dest[pos..][0..to_copy], self.buf[self.buf_start..][0..to_copy]);
                    self.buf_start += to_copy;
                    pos += to_copy;
                } else {
                    const n = self.file.readStreaming(io, &.{dest[pos..]}) catch |err| switch (err) {
                        error.EndOfStream, error.ReadFailed => return false,
                    };
                    if (n == 0) return false;
                    pos += n;
                }
            }
            return true;
        }
    };

    /// Write with Content-Length header using fixed stack buffer.
    pub fn writeMessage(file: std.Io.File, io: std.Io, data: []const u8) !void {
        var header_buf: [64]u8 = undefined;
        var header_w: std.Io.Writer = .fixed(&header_buf);
        try header_w.print("Content-Length: {d}\r\n\r\n", .{data.len});
        const header = header_w.buffered();
        try file.writeStreamingAll(io, header);
        try file.writeStreamingAll(io, data);
    }
};
```

- Internal 8KB buffer persists between `readMessage` calls — read-ahead bytes aren't lost
- `readByte` for header parsing (cheap from buffer), `readExact` for body (bypasses buffer for large payloads)
- `writeMessage` uses `std.Io.Writer.fixed` on stack buffer — zero allocations for header formatting

---

## Thread Model & Request Correlation

**0.16:** `std.Thread.Mutex` and `std.Thread.ResetEvent` are removed — use `std.Io.Mutex` and `std.Io.Event` (both need `io: Io`; see [std.Thread reference](std-thread.md)):

```zig
const PendingRequest = struct {
    response: ?[]const u8 = null,
    event: std.Io.Event = .unset,
    allocator: std.mem.Allocator,
};

pub const LspClient = struct {
    next_id: std.atomic.Value(i64) = std.atomic.Value(i64).init(1),
    pending: std.AutoHashMapUnmanaged(i64, *PendingRequest),
    pending_mutex: std.Io.Mutex = .init,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Main thread: send request, block until reader thread delivers response.
    pub fn sendRequest(self: *LspClient, io: std.Io, allocator: std.mem.Allocator, method: []const u8, params: anytype) ![]const u8 {
        const id = self.next_id.fetchAdd(1, .monotonic);
        const pending = try self.allocator.create(PendingRequest);
        pending.* = .{ .allocator = self.allocator };

        { try self.pending_mutex.lock(io); defer self.pending_mutex.unlock(io);
          try self.pending.put(self.allocator, id, pending); }
        errdefer { self.pending_mutex.lock(io) catch {}; defer self.pending_mutex.unlock(io);
                   _ = self.pending.remove(id); self.allocator.destroy(pending); }

        const msg = try json_rpc.writeRequest(allocator, .{ .integer = id }, method, params);
        defer allocator.free(msg);
        try LspTransport.writeMessage(stdin, msg);

        // Block with 30s timeout
        pending.event.waitTimeout(io, .{ .duration = .{ .raw = .fromSeconds(30), .clock = .awake } }) catch {
            // Cleanup and return timeout error
            return error.RequestTimeout;
        };

        const response = pending.response orelse return error.NoResponse;
        defer self.allocator.free(response);
        return try allocator.dupe(u8, response);  // Dupe to caller's allocator
    }

    /// Reader thread: match response ID → wake blocked sender.
    fn readerLoop(self: *LspClient, io: std.Io) void {
        while (self.running.load(.acquire)) {
            const data = reader.readMessage(self.allocator) catch { self.signalAllPending(io); return; };
            if (data == null) { self.signalAllPending(io); return; }
            // Parse, extract "id", lookup pending, set response, event.set(io)
        }
    }
};
```

- Single writer to ZLS stdin (main thread), single reader from ZLS stdout (reader thread)
- Mutex only protects HashMap insert/remove — no lock on I/O
- `Io.Event` blocks main thread until reader delivers response
- `signalAllPending()` wakes all blocked requests when ZLS crashes (prevents deadlock)
- Response duped to caller's allocator (reader uses long-lived allocator)

---

## Arena-Per-Request Memory

```zig
pub fn run(self: *McpServer) !void {
    while (self.state != .shutdown) {
        const data = (try self.transport.readMessage(self.allocator)) orelse break;

        // Fresh arena for each request — all temp allocations freed at once
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();

        self.handleMessage(arena.allocator(), data) catch |err| {
            const error_resp = json_rpc.writeError(arena.allocator(), null,
                json_rpc.ErrorCode.internal_error, "Internal error") catch continue;
            self.transport.writeMessage(error_resp) catch {};
        };
        self.allocator.free(data);  // Raw input freed with parent allocator
    }
}
```

- Arena per request: parse JSON → dispatch → build response → `arena.deinit()` frees everything
- No manual `free()` needed for request-scoped allocations
- Raw input (`data`) allocated by transport with parent allocator, freed explicitly

---

## Child Process Lifecycle

```zig
pub const ZlsProcess = struct {
    io: std.Io,
    zls_path: []const u8,
    child: ?std.process.Child = null,
    restart_count: u32 = 0,
    max_restarts: u32 = 5,

    pub fn spawn(self: *ZlsProcess) !void {
        if (self.child != null) self.kill();
        self.child = try std.process.spawn(self.io, .{
            .argv = &.{self.zls_path},
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .pipe,
        });
    }

    pub fn restart(self: *ZlsProcess) !bool {
        if (self.restart_count >= self.max_restarts) return false;
        self.kill();
        self.restart_count += 1;
        self.spawn() catch return false;
        return true;
    }

    pub fn kill(self: *ZlsProcess) void {
        if (self.child) |*child| {
            // Close stdin first → signals child to exit, then drain the rest
            if (child.stdin) |s| { s.close(self.io); child.stdin = null; }
            if (child.stdout) |s| { s.close(self.io); child.stdout = null; }
            if (child.stderr) |s| { s.close(self.io); child.stderr = null; }
            _ = child.wait(self.io) catch {};
            self.child = null;
        }
    }
};
```

- Close stdin first to signal graceful exit before closing stdout/stderr
- Null-check each pipe individually (may already be detached)
- Bounded restart count prevents infinite restart loops

---

## Pipe Ownership & Double-Close Prevention

```zig
// In main.zig: after LspClient.connect() takes the pipes
zls_proc.detachPipes();

// ZlsProcess.detachPipes:
pub fn detachPipes(self: *ZlsProcess) void {
    if (self.child) |*child| {
        child.stdin = null;   // LspClient now owns these
        child.stdout = null;
        child.stderr = null;
    }
}
```

When one component takes ownership of pipe file descriptors from another, null out the original references. Otherwise both `ZlsProcess.deinit()` and `LspClient.deinit()` would close the same FDs — causing double-close bugs that are extremely hard to debug.

---

## Tool Registry Pattern

```zig
pub const ToolContext = struct {
    lsp_client: *LspClient,
    doc_state: *DocumentState,
    workspace: *const Workspace,
    allocator: std.mem.Allocator,
};

pub const ToolHandler = *const fn (ctx: ToolContext, args: std.json.Value) ToolError![]const u8;

pub const ToolError = error{
    InvalidParams, LspError, NotConnected, RequestTimeout,
    NoResponse, FileNotFound, FileReadError, OutOfMemory,
    CommandFailed, ZlsNotRunning,
};

pub const Registry = struct {
    entries: std.StringHashMapUnmanaged(Entry),
    allocator: std.mem.Allocator,
    const Entry = struct { handler: ToolHandler, definition: mcp_types.Tool };

    pub fn register(self: *Registry, name: []const u8, handler: ToolHandler, definition: mcp_types.Tool) !void {
        try self.entries.put(self.allocator, name, .{ .handler = handler, .definition = definition });
    }
};
```

- Concrete error set (not `anyerror`) — the MCP server maps each error to a human-readable message
- `ToolContext` bundles all dependencies handlers need — avoids global state
- Function pointer + metadata in one entry — `tools/list` returns definitions, `tools/call` invokes handler
- All tools return `[]const u8` (text content) — uniform interface

---

## JSON Building with std.json.Stringify

```zig
fn writeToolResult(self: *McpServer, allocator: std.mem.Allocator, id: RequestId, text: []const u8, is_error: bool) !void {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };

    try jw.beginObject();
    try jw.objectField("jsonrpc"); try jw.write("2.0");
    try jw.objectField("id");     try id.jsonStringify(&jw);
    try jw.objectField("result");
    try jw.beginObject();
    try jw.objectField("content");
    try jw.beginArray();
    try jw.beginObject();
    try jw.objectField("type"); try jw.write("text");
    try jw.objectField("text"); try jw.write(text);
    try jw.endObject();
    try jw.endArray();
    if (is_error) { try jw.objectField("isError"); try jw.write(true); }
    try jw.endObject();
    try jw.endObject();

    const resp = try aw.toOwnedSlice();
    try self.transport.writeMessage(resp);
}
```

Use `std.json.Stringify` + `std.Io.Writer.Allocating` when:
- You need mixed dynamic/static content in one JSON document
- Auto-serialization via `jw.write(struct)` doesn't give enough control
- You need to embed custom serialization (like `RequestId.jsonStringify`)

**Gotcha:** Empty anonymous struct `.{}` serializes as `[]` (empty JSON array), NOT `{}`. For tools with no parameters, explicitly build an empty object:
```zig
.properties = .{ .object = std.json.ObjectMap.init(allocator) }  // → {}
// NOT: .properties = .{}  // → [] which breaks MCP clients
```

---

## Lazy Document Sync with Double-Check Locking

```zig
pub fn ensureOpen(self: *DocumentState, lsp_client: *LspClient, file_path: []const u8, ret_allocator: std.mem.Allocator) ![]const u8 {
    const file_uri = try uri_util.pathToUri(self.allocator, abs_path);

    // Fast path: check under lock
    { self.mutex.lock(); defer self.mutex.unlock();
      if (self.open_docs.get(file_uri)) |_| return try ret_allocator.dupe(u8, file_uri); }

    // Slow path: read file OUTSIDE the lock (no mutex held during I/O)
    const content = std.Io.Dir.cwd().readFileAlloc(self.allocator, abs_path, 10 * 1024 * 1024) catch ...;
    defer self.allocator.free(content);

    // Re-acquire lock, double-check, then register
    self.mutex.lock(); defer self.mutex.unlock();
    if (self.open_docs.get(file_uri)) |_| return try ret_allocator.dupe(u8, file_uri);  // Another thread opened it

    try lsp_client.sendNotification(arena.allocator(), "textDocument/didOpen", ...);
    try self.open_docs.put(self.allocator, stored_uri, .{ .version = 1, .uri = stored_uri });
    return try ret_allocator.dupe(u8, file_uri);
}
```

- Files opened lazily on first tool access — no need to manage document state manually
- Double-check locking: fast mutex check → I/O without lock → re-check under lock
- Prevents duplicate `didOpen` notifications even under concurrent access

---

## Graceful Degradation

```zig
pub fn main() !void {
    const zls_path = findZls(allocator) catch {
        std.debug.print("[zig-mcp] Warning: ZLS not found. LSP tools unavailable.\n", .{});
        return runWithoutZls(allocator, &workspace);  // Command tools still work
    };

    zls_proc.spawn() catch |err| {
        std.debug.print("[zig-mcp] Failed to spawn ZLS: {}\n", .{err});
        return runWithoutZls(allocator, &workspace);
    };
    // ...
}

fn runWithoutZls(allocator: std.mem.Allocator, workspace: *Workspace) !void {
    // Same server setup, same registry — LSP tools return NotConnected errors,
    // but zig_build, zig_test, zig_check, zig_version still work.
}
```

Don't fail hard when an optional dependency is missing. Register all tools regardless — LSP-backed tools return clear error messages, command tools work fine.

---

## Auto-Reconnect on Crash

```zig
fn handleToolsCall(self: *McpServer, ...) !void {
    const result_text = handler(ctx, tool_args) catch |err| {
        if ((err == error.NotConnected or err == error.LspError or err == error.NoResponse)
            and self.tryReconnectZls())
        {
            // Retry once with fresh connection
            const retry_text = handler(ctx, tool_args) catch |retry_err| { ... };
            try self.writeToolResult(allocator, rid, retry_text, false);
            return;
        }
        // ...
    };
}

fn tryReconnectZls(self: *McpServer) bool {
    self.lsp_client.disconnect();       // Close old pipes, join reader threads
    const ok = zls_proc.restart();      // Respawn with bounded retry count
    self.lsp_client.connect(...);       // Attach to new pipes
    self.lsp_client.initialize(...);    // Re-handshake LSP
    self.doc_state.reopenAll(...);      // Re-open tracked documents
    return true;
}
```

- On connection error: disconnect → restart → reconnect → re-initialize → reopen docs → retry
- Single retry — avoids infinite retry loops
- `reopenAll` re-reads file content and sends fresh `didOpen` notifications

---

## Custom JSON-RPC Types

```zig
pub const RequestId = union(enum) {
    integer: i64,
    string: []const u8,
    none,

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !RequestId {
        const token = try source.next();
        return switch (token) {
            .number => |n| .{ .integer = std.fmt.parseInt(i64, n, 10) catch return .{ .string = n } },
            .string, .allocated_string => |s| .{ .string = s },
            .null => .none,
            else => error.UnexpectedToken,
        };
    }

    pub fn jsonStringify(self: RequestId, jw: anytype) !void {
        switch (self) {
            .integer => |i| try jw.write(i),
            .string => |s| try jw.write(s),
            .none => try jw.write(null),
        }
    }
};
```

Implement `jsonParse`/`jsonStringify` for types that have multiple JSON representations. JSON-RPC IDs can be integer, string, or null — a tagged union with custom serialization handles all cases.

---

## File URI Encoding

```zig
pub fn pathToUri(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const prefix = "file://";
    var len: usize = prefix.len;
    for (path) |c| len += if (needsEncoding(c)) @as(usize, 3) else 1;

    const buf = try allocator.alloc(u8, len);
    @memcpy(buf[0..prefix.len], prefix);
    var pos: usize = prefix.len;
    for (path) |c| {
        if (needsEncoding(c)) {
            buf[pos] = '%'; buf[pos+1] = hexDigit(c >> 4); buf[pos+2] = hexDigit(c & 0xf);
            pos += 3;
        } else { buf[pos] = c; pos += 1; }
    }
    return buf;
}

fn needsEncoding(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~', '/', ':' => false,
        else => true,
    };
}
```

- Two-pass: count length → allocate exact → fill. No reallocs.
- Keep `/` and `:` unencoded (valid in file URIs)
- `hexDigit` indexes a comptime string literal — branchless hex encoding

---

## Comptime Schema Generation

```zig
fn makeProps(allocator: std.mem.Allocator, comptime fields: anytype) ToolError!std.json.Value {
    var obj = std.json.ObjectMap.init(allocator);
    inline for (fields) |field| {
        var prop = std.json.ObjectMap.init(allocator);
        prop.put("type", .{ .string = field[1] }) catch return ToolError.OutOfMemory;
        prop.put("description", .{ .string = field[2] }) catch return ToolError.OutOfMemory;
        obj.put(field[0], .{ .object = prop }) catch return ToolError.OutOfMemory;
    }
    return .{ .object = obj };
}

// Usage — declare tool schema inline:
try reg.register("zig_hover", handleHover, .{
    .name = "zig_hover",
    .description = "Get hover info for a symbol",
    .inputSchema = .{
        .properties = try makeProps(reg.allocator, &.{
            .{ "file", "string", "Path to the Zig source file" },
            .{ "line", "integer", "0-based line number" },
            .{ "character", "integer", "0-based character offset" },
        }),
        .required = &.{ "file", "line", "character" },
    },
});
```

`inline for` over comptime tuple of tuples → generates `std.json.ObjectMap` entries at compile time. Schema definitions live right next to handler registration — easy to read, easy to maintain.

---

## Test Discovery via comptime Import

```zig
// main.zig — pull all module tests into the test binary
comptime {
    _ = @import("types/json_rpc.zig");
    _ = @import("types/uri.zig");
    _ = @import("mcp/transport.zig");
    _ = @import("lsp/transport.zig");
    _ = @import("lsp/types.zig");
    _ = @import("mcp/types.zig");
    _ = @import("bridge/registry.zig");
    _ = @import("bridge/tools.zig");
    // ... all modules
}
```

With `zig build test` pointing at `src/main.zig`, this comptime block forces all module tests into the test binary. No need for a separate test runner or test manifest.

---

## Common Gotchas

| Issue | Solution |
|-------|----------|
| Empty `.{}` serializes as `[]` not `{}` | Use `.{ .object = std.json.ObjectMap.init(alloc) }` |
| `std.json.Value = .null` in properties | Breaks MCP client registration — always pass explicit object |
| `u4` can't be left-shifted by 4 | Widen first: `@as(u8, val) << 4` |
| `std.process.Child.Term` fields are lowercase (0.16) | `.exited`, `.signal`, `.stopped`, `.unknown` |
| `SpawnOptions.StdIo` members are lowercase (0.16) | `.pipe`, `.inherit`, `.ignore`, `.close`, `.{ .file = f }` |
| Pipe double-close after ownership transfer | Call `detachPipes()` to null out original references |
| Reader thread blocks on closed pipe | Close pipes before `thread.join()` to unblock |
| `"initialized"` notification needs `{}` | Use raw JSON string — auto-serialized `.{}` sends `[]` |
