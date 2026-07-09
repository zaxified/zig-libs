# ipcbus

Same-host **unix-socket control plane**: one owner process serves
request/reply over a length-prefixed unix socket, plus a capped in-memory
key→bytes scratch **bus**. Linux, libc-free (raw `std.os.linux` syscalls).

Provenance: original work of the zig-libs authors (MIT). Raw unix transport
(`unixAddr`/`connectUnix`/`listenUnix`/`writeAllFd`/`readExact`), an
accept/dispatch/reply loop, and a scratch KV map. Command handling is a
caller-supplied `dispatch` callback, so this module hosts no application
commands. Framing is delegated to the `framing` module (no re-implemented
length prefix). No third-party code.

- **Status:** extract. **Platform:** linux (raw syscalls, no libc — a
  conscious ceiling). **Role:** server. **Deps:** `framing`.
- **Concurrency:** single_owner — one thread/loop owns the listen socket and
  the `Bus`; the `Bus` is lock-free and must be touched from that thread only.

## Design constraints (v1)

- **Single owner.** One process owns the socket + `Bus`; no internal locking.
- **One connection per request.** Every request is a fresh `connect → write
  one frame → read one frame → close`. No persistent or multiplexed
  connection; `acceptOne` + `handleOne` service exactly one connection at a
  time.
- **No baked-in dispatch.** `Server.handleOne` calls a caller-supplied
  `dispatch(ctx, req_bytes, gpa) !reply_bytes`. All command handling lives in
  the app.
- **Framing delegated.** Every message is a length-prefixed frame from the
  `framing` module. An oversize header is rejected *before* the body is read,
  so a bogus length never blocks waiting for a body that will not arrive.

## API

```zig
const ipcbus = @import("ipcbus");

// ── server (owner process) ──
var srv = try ipcbus.Server.listen("/run/app.sock");
defer srv.deinit();
while (true) {
    const conn = try srv.acceptOne();               // one connection at a time
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    // dispatch is YOUR fn(ctx, req, gpa) !reply — this module bakes in none
    try ipcbus.Server.handleOne(conn, ctx, dispatch, arena.allocator(), .{});
}

// ── client (any process) ──
var reply_buf: [4096]u8 = undefined;
const reply = try ipcbus.Client.request("/run/app.sock", req_bytes, &reply_buf, .{});

// ── in-memory scratch bus (owner thread only) ──
var bus = ipcbus.Bus(64).init(gpa);   // cap = 64 keys, evicts when full
defer bus.deinit();
try bus.set("screens", "[1,2]");
const v = bus.get("screens");         // borrowed until next mutation
var keys: [64][]const u8 = undefined;
const live = bus.list(&keys);
```

`limits` is a `framing.Limits` (`.{}` = 1 MiB default cap). `handleOne`
allocates `limits.max_frame` bytes for the request buffer, so set it to your
protocol's real cap if per-request allocation matters.

The raw transport helpers (`unixAddr`, `connectUnix`, `listenUnix`,
`writeAllFd`, `readExact`) and the `FdReader`/`FdWriter` `std.Io` adapters over
a socket fd are also exported for callers that need to build their own loop.

## Bus semantics

- `set` dupes key + value (owned); overwriting frees the old value in place.
- Inserting a **new** key when at `max_keys` evicts an arbitrary existing entry.
- `version` bumps on every mutation — poll it to detect change.
- `get`/`list` return borrowed slices valid **until the next mutation**.

## Deferred (not in v1)

- **Real push/notify.** This is a poll-a-shared-map model: subscribers poll the
  `Bus` `version` (or re-`get`); there is no server-initiated push.
- **Persistent / multiplexed connections.** One connection per request only.
- **Multi-connection concurrency.** The server handles one connection at a
  time; no thread pool or event loop.
- **Auth / permissions on the socket.** Access is whatever the filesystem
  permissions on the socket path grant; no in-band authentication.
