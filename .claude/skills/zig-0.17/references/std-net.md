# std.Io.net Reference (0.17.0; migrating from 0.15.x std.net)

Cross-platform networking abstractions: TCP and Unix sockets, address parsing, connecting by host name, stream I/O.

> **CRITICAL: Migration Required (since 0.16, unchanged in 0.17.0)**
>
> **`std.net` is completely removed.** All networking is now under **`std.Io.net`**, which requires an `Io` instance for connect/listen/accept/read/write/close operations.
>
> **Key renames:**
> - `net.Address.parseIp4` → `Io.net.IpAddress.parse` (returns an error union)
> - `net.Stream` → `Io.net.Stream`
> - `net.tcpConnectToHost` → `Io.net.HostName.connect(host, io, port, .{ .mode = .stream })`
> - `net.tcpConnectToAddress` → `IpAddress.connect(&addr, io, .{ .mode = .stream })`
> - `net.connectUnixSocket` → `Io.net.UnixAddress.init(path)` + `.connect(io)`
>
> **Behavioral changes:**
> - `stream.close()` → `stream.close(io)` (requires `Io` by value)
> - `stream.handle` → `stream.socket.handle`
> - Reading and writing go through `stream.reader(io, &buf)` / `stream.writer(io, &buf)` (buffered, like files); flush the writer
> - `std.posix.close` → `stream.close(io)` / `file.close(io)`; `std.c.close` only when already linking libc
> - `net.has_unix_sockets` → `Io.net.has_unix_sockets`


## Migration to std.Io.net

`std.net` is entirely removed. All networking goes through `std.Io.net`, which requires an `Io` runtime instance. This section covers every breaking change with WRONG (0.15.x) vs CORRECT (0.16/0.17) examples.

### Io Runtime Setup

All networking requires an `Io` instance. In an executable take it from `main`; elsewhere construct a concrete `Io` implementation (e.g. `std.Io.Threaded`, the thread-pool-backed one) and get an `Io` value from its `.io()` method:

```zig
// CORRECT: main receives a ready-made Io (plus gpa, arena, environ_map, ...)
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    _ = .{ io, gpa };
}

// Elsewhere (library test harness, C entry point): build one and thread it through
// In an executable use init.io. A bare `.init(gpa, .{})` has no `.environ`: children spawned
// through it get an empty environment (pass `.environ = init.minimal.environ`).
var threaded: std.Io.Threaded = .init(gpa, .{});
defer threaded.deinit();
const io = threaded.io();
```

There is no bare `std.Io.init()`.

### TCP Client Migration

`tcpConnectToHost` is replaced by `HostName.connect` (DNS + try every address); `tcpConnectToAddress` by `IpAddress.connect`.

```zig
// WRONG (0.15.x): tcpConnectToHost — removed
const stream = try net.tcpConnectToHost(allocator, "example.com", 80);
defer stream.close();
```

```zig
// CORRECT: connect by host name (resolves and tries the addresses)
const host: std.Io.net.HostName = try .init("example.com");
const stream = try host.connect(io, 80, .{ .mode = .stream });
defer stream.close(io);

// CORRECT: connect by IP address (no DNS)
const addr = try std.Io.net.IpAddress.parse("192.168.1.1", 8080);
const stream2 = try addr.connect(io, .{ .mode = .stream });
defer stream2.close(io);
```

### TCP Server Migration

`net.Address` becomes `Io.net.IpAddress`. `listen` and `accept` require the `io` instance.

```zig
// WRONG (0.15.x): net.Address + address.listen()
const address = net.Address.initIp4(.{ 0, 0, 0, 0 }, 8080);
var server = try address.listen(.{ .reuse_address = true });
defer server.deinit();
const conn = try server.accept();
defer conn.stream.close();
```

```zig
// CORRECT: Io.net.IpAddress + listen(io) + accept(io) returns the Stream directly
const address = try std.Io.net.IpAddress.parse("0.0.0.0", 8080);
var server = try address.listen(io, .{ .reuse_address = true });
defer server.deinit(io);

const stream = try server.accept(io);
defer stream.close(io);
```

### Address Parsing Migration

`net.Address.parseIp4` is replaced by `Io.net.IpAddress.parse` (text, port); it returns an error union, so use `try`.

```zig
// WRONG (0.15.x): net.Address.parseIp4
const address = try net.Address.parseIp4("192.168.1.1", 8080);
```

```zig
// CORRECT: Io.net.IpAddress.parse (IPv4 or IPv6)
const address = try std.Io.net.IpAddress.parse("192.168.1.1", 8080);
```

### Stream Type Migration

`net.Stream` becomes `Io.net.Stream`. The new stream type has a different field layout.

```zig
// WRONG (0.15.x): net.Stream
fn handleClient(stream: net.Stream) !void {
    const fd = stream.handle;
    defer stream.close();
    // ...
}
```

```zig
// CORRECT: Io.net.Stream — handle is under .socket; Io is passed by value
fn handleClient(stream: std.Io.net.Stream, io: std.Io) !void {
    const fd = stream.socket.handle;
    _ = fd;
    defer stream.close(io);
    // ...
}
```

### close(io) Pattern

All close operations now require an `Io` instance (by value).

```zig
// WRONG (0.15.x): stream.close() — no arguments
stream.close();
```

```zig
// CORRECT: stream.close(io)
stream.close(io);
```

### stream.socket.handle

Accessing the underlying file descriptor changed from `.handle` to `.socket.handle`.

```zig
// WRONG (0.15.x): stream.handle
const fd = stream.handle;
```

```zig
// CORRECT: stream.socket.handle
const fd = stream.socket.handle;
```

### Reading and Writing

`Io.net.Stream` is read and written through a buffered `Reader` / `Writer` that you create with the `Io`, exactly like a file. Always flush the writer.

```zig
// WRONG (0.15.x): reader/writer without Io, reader.interface() as a call
var reader = stream.reader(&read_buf);
var writer = stream.writer(&write_buf);
try writer.interface.writeAll("Hello");
```

```zig
// CORRECT: stream.reader(io, &buf) / stream.writer(io, &buf) + flush
var read_buf: [4096]u8 = undefined;
var write_buf: [1024]u8 = undefined;
var reader = stream.reader(io, &read_buf);
var writer = stream.writer(io, &write_buf);

try writer.interface.writeAll("ping\n");
try writer.interface.flush();

const line = try reader.interface.takeDelimiterExclusive('\n');
```

If a read or write fails with `error.ReadFailed` / `error.WriteFailed`, the underlying error is in `reader.err` / `writer.err`.

### Unix Sockets

`connectUnixSocket` is replaced by `UnixAddress.init(path)` + `.connect(io)`; servers use `.listen(io, .{})`.

```zig
// WRONG (0.15.x): net.connectUnixSocket
const stream = try net.connectUnixSocket("/var/run/app.sock");
```

```zig
// CORRECT: check availability, then connect through Io
if (std.Io.net.has_unix_sockets) {
    const ua = try std.Io.net.UnixAddress.init("/var/run/app.sock");
    const stream = try ua.connect(io);
    defer stream.close(io);
    // stream.reader(io, &buf) / stream.writer(io, &buf) as for TCP
}
```

### std.posix.close

```zig
// WRONG (0.15.x): std.posix.close
std.posix.close(fd);
```

```zig
// CORRECT: close through the owning handle with Io
stream.close(io);   // net stream
file.close(io);     // file

// Fallback only when the program already links libc (`.link_libc = true`):
_ = std.c.close(fd);
```

### has_unix_sockets

```zig
// WRONG (0.15.x): net.has_unix_sockets
if (net.has_unix_sockets) { ... }
```

```zig
// CORRECT: Io.net.has_unix_sockets
if (std.Io.net.has_unix_sockets) { ... }
```

## Stream I/O

### Reading

`stream` is a connected `Io.net.Stream`, `io` the `Io` instance (compiled on 0.17.0). `interface` is a field, not a call, and the underlying error is the `reader.err` field:

```zig
var buf: [4096]u8 = undefined;
var reader = stream.reader(io, &buf);
const r = &reader.interface;

// Read bytes
const data = r.take(100) catch |err| switch (err) {
    error.EndOfStream => &.{},
    error.ReadFailed => return reader.err.?,
};

// Read until delimiter
const line = r.takeDelimiter('\n') catch |err| switch (err) {
    error.StreamTooLong => return error.LineTooLong,
    error.ReadFailed => return reader.err.?,
} orelse return;

// Discard bytes
_ = try r.discard(.limited(100));

// Stream to writer
_ = try r.streamRemaining(&output_writer);
```

### Writing

```zig
var buf: [1024]u8 = undefined;
var writer = stream.writer(io, &buf);
const w = &writer.interface;

// Write bytes
try w.writeAll("Hello, World!");

// Formatted output
try w.print("Count: {d}\n", .{42});

// MUST flush before close
try w.flush();
```

### Read errors

Compiled on 0.17.0:

```zig
var reader = stream.reader(io, &buf);
const r = &reader.interface;

const data = r.take(100) catch |err| switch (err) {
    error.EndOfStream => {
        // Connection closed normally
        return;
    },
    error.ReadFailed => {
        // Get underlying error
        const read_err = reader.err.?;
        switch (read_err) {
            error.ConnectionResetByPeer => return error.Disconnected,
            error.SocketUnconnected => return error.Disconnected,
            else => return read_err,
        }
    },
};
```
