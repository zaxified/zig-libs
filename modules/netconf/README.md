# netconf

A **NETCONF client** (RFC 6241) over the sibling `ssh` module, in pure Zig — the full
RFC 6242 framing (both dialects), the `<hello>` capability exchange, every standard
protocol operation, and typed `<rpc-reply>` / `<rpc-error>` parsing.

- **RFC 6242 framing, both dialects, as one pure state machine** — the legacy
  end-of-message mechanism (`]]>]]>`, §4.3) used for the hello exchange and for
  `:base:1.0` sessions, and the chunked mechanism (`\n#<len>\n…\n##\n`, §4.2) that becomes
  mandatory when both peers advertise `urn:ietf:params:netconf:base:1.1`. The switch is an
  explicit guarded transition at a message boundary, decided by capability intersection
  and nowhere else.
- **`<hello>` capability exchange** (§8.1) — `<session-id>` rules enforced in both
  directions, standard capabilities resolved (`:candidate`, `:confirmed-commit`,
  `:validate`, `:startup`, `:writable-running`, `:rollback-on-error`, `:url`, `:xpath`,
  `:notification`, `:interleave`), YANG module capabilities kept verbatim, and RFC 6241
  §8.1's "compare only the part before the `?parameters`" rule.
- **Every standard operation** — `get`, `get-config`, `edit-config` (with
  `default-operation` / `test-option` / `error-option` and the `operation=` attribute),
  `copy-config`, `delete-config`, `lock`/`unlock`, `commit` (incl. confirmed commit with
  `confirm-timeout`/`persist`), `discard-changes`, `validate`, `close-session`,
  `kill-session`, plus RFC 5277 `create-subscription` — and a `raw` escape hatch that puts
  caller-supplied operation XML inside the correlated `<rpc>` envelope.
- **Typed replies** — `<ok>`, `<data>`, or one-or-more `<rpc-error>` with every field
  (`error-type`, `error-tag`, `error-severity`, `error-app-tag`, `error-path`,
  `error-message` + `xml:lang`, `error-info` as verbatim XML). An error is a typed Zig
  error **and** retained structured detail; a reply is never silently dropped.
- **Correlation** — `message-id` is allocated monotonically and every reply is checked
  against the outstanding request. A missing or mismatched id is `error.MessageIdMismatch`.
  Interleaved RFC 5277 notifications are queued, not mistaken for a reply.

XML is parsed with the sibling `xml` module (C14N-grade, DOCTYPE rejected by default, so
XXE and billion-laughs are shut off) — this module contains no second XML parser.

Consumers: network-device automation and fleet simulation (the same place `tc`,
`netlink` and `ssh` are used), config push/pull against real routers and switches, and
anywhere you would otherwise shell out to `ncclient`.

## Import

```zig
const netconf = @import("netconf");
```

## Usage

Over SSH (RFC 6242 §2 — subsystem `netconf`):

```zig
// 1. A normal SSH session from the sibling module, up to the subsystem request.
var t = try ssh.transport.connect(&reader, &writer, gpa, verifyHostKey);
try t.requestService("ssh-userauth", &scratch);
try ssh.userauth.authenticatePassword(&t, gpa, user, password);

var session = try ssh.openSession(&t, gpa, .{});
defer session.deinit();
try session.subsystem("netconf");

// 2. NETCONF on top of it.
var adapter: netconf.SshTransport = .init(&session);
var c = try netconf.Client.init(gpa, adapter.transport(), .{});
defer c.deinit();

try c.hello();                       // capability exchange + dialect switch
std.debug.print("session {?d}, {s} framing\n", .{ c.sessionId(), @tagName(c.dialect()) });

// 3. Read the running configuration under a subtree filter.
var r = try c.getConfig(.running, .{ .subtree =
    \\<top xmlns="http://example.com/schema/1.2/config">
    \\  <users/>
    \\</top>
});
defer r.deinit();
const data = try r.expectData();     // error.RpcError keeps the detail in `r.errors`

// 4. Change something on <candidate> and commit it.
var e = try c.editConfig(.{
    .target = .candidate,
    .default_operation = .merge,
    .error_option = .rollback_on_error,
    .payload = .{ .config =
        \\<top xmlns="http://example.com/schema/1.2/config">
        \\  <interface><name>eth0</name><mtu>1500</mtu></interface>
        \\</top>
    },
});
defer e.deinit();
try e.expectOk();

var k = try c.commit(.{ .confirmed = true, .confirm_timeout = 120 });
defer k.deinit();
try k.expectOk();

try c.closeSession();
```

Deleting a node uses the RFC 6241 §7.2 `operation` attribute; the `nc` prefix is bound on
`<config>` for you:

```zig
const body = try std.fmt.allocPrint(gpa,
    "<top xmlns=\"urn:example\"><interface{s}><name>eth0</name></interface></top>",
    .{netconf.Operation.delete.attribute()});
```

The framer alone, with no session and no I/O:

```zig
var f: netconf.Framer = .init(gpa, .end_of_message, .{});
defer f.deinit();
try f.feed(bytes_from_anywhere);          // one byte or one megabyte, same result
while (try f.next()) |msg| { ... }        // valid until the next call
try f.setDialect(.chunked);               // only legal at a message boundary
```

### Read timeouts

`ssh.Session.pumpOnce` blocks, and this module deliberately does **not** wrap it in a
thread or a timer. Exactly one call here blocks — `Client.pumpOnce`, which performs one
`Transport.read` — and everything below it is the pure `Framer`. To bound a wait,
implement `Transport.read` with the deadline you want:

```zig
fn readFn(ctx: *anyopaque, buf: []u8) netconf.TransportError!usize {
    const self: *MyTransport = @ptrCast(@alignCast(ctx));
    // poll()/std.Io on the SSH socket fd first...
    if (!try self.waitReadable(self.deadline_ns)) return 0;  // 0 = nothing this round
    return self.inner.read(buf);
}
```

`read` returning **0 means "no data this round"**, not end of stream (that is
`error.EndOfStream`), so a timed-out read leaves any half-received message intact and the
caller decides whether to wait again or give up. `SshTransport` is the un-timed
reference implementation of the same seam.

## API

### Client

| Call | Meaning |
|---|---|
| `Client.init(gpa, transport, Options)` / `.deinit()` | one session; `Options` carries framing `limits` and the capabilities we advertise |
| `.hello()` | RFC 6241 §8.1 exchange, RFC 6242 §4.1 dialect switch |
| `.sessionId()` / `.serverCapabilities()` / `.dialect()` / `.state` | what the exchange produced |
| `.pumpOnce() !usize` | **the one blocking call** — one `Transport.read`, fed to the framer |
| `.receive() ![]const u8` | next complete message (loops `pumpOnce`) |
| `.send(Rpc) !u64` / `.receiveReply(id) !Reply` | pipelining seam; returns/consumes the `message-id` |
| `.call(Rpc) !Reply` | send + correlated receive |
| `.callOk(Rpc, ?*?Reply) !void` | `call` + `expectOk`, handing the failed reply back |
| `.get` `.getConfig` `.editConfig` `.copyConfig` `.deleteConfig` `.lock` `.unlock` `.commit` `.discardChanges` `.validate` `.killSession` `.createSubscription` `.raw` | one wrapper per RFC 6241 §7/§8 operation |
| `.closeSession()` | §7.8 graceful close |
| `.nextNotification()` / `.awaitNotification()` | RFC 5277 events (queued while waiting for replies) |

### Types

- `Transport` — `{ ctx, vtable{ read, write } }`; `SshTransport.init(&ssh_session)` is the
  ready-made one. `TransportError` = `ReadFailed` / `WriteFailed` / `EndOfStream`.
- `Framer` — `init(gpa, dialect, Limits)`, `feed`, `next`, `setDialect`, `atBoundary`;
  `framing.writeMessage` / `writeChunked` / `frameAlloc` on the encode side. `Limits`
  bounds message size, chunk size and un-terminated pending input.
- `Rpc` — the request union; `Datastore` (`.running`/`.candidate`/`.startup`/`.url`),
  `ConfigSource` (adds `.config`), `Filter` (`.none`/`.subtree`/`.xpath`), `EditConfig`,
  `CopyConfig`, `Commit`, `CreateSubscription`, `Operation`, `DefaultOperation`,
  `TestOption`, `ErrorOption`. XML payloads (filters, `<config>` bodies) are passed
  **verbatim**; scalar values are XML-escaped.
- `Reply` — `.message_id`, `.ok`, `.data` (+ `.data_element` for namespace-correct
  walking), `.body`, `.errors`; `expectOk()`, `expectData()`, `expectMessageId()`,
  `firstError()`. `RpcError` carries `tag`/`tag_text`, `error_type`, `severity`,
  `app_tag`, `path`, `message`, `message_lang`, `info` (verbatim XML) and
  `info_session_id`.
- `Capabilities` — `has()` (RFC 6241 §8.1 `?parameters`-insensitive), `hasExact()`,
  `.list` (verbatim, YANG module capabilities included) and the resolved standard flags.
- `Notification` — `.event_time`, `.event` (verbatim XML).

Errors: `SessionError` unions the transport, framer, hello, reply-parse and
correlation errors, so one `catch` covers a call. The interesting ones are
`error.RpcError` (peer said no — detail retained), `error.MessageIdMismatch`,
`error.NoCommonBaseVersion`, `error.MalformedChunkHeader` / `InvalidChunkSize` /
`ChunkTooLarge` / `EmptyChunkedMessage` / `ExpectedChunkHeader` (hostile framing) and
`error.DelimiterInPayload` (refusing to send a payload that would forge `]]>]]>`).

## Verify

```sh
zig build test-netconf                 # unit/golden/fuzz; the live tests print SKIPPED and pass
zig build test-netconf --release=fast  # same, optimized

# With a real NETCONF server reachable over SSH:
NETCONF_TEST_SERVER=127.0.0.1:8300 \
NETCONF_TEST_USER=admin NETCONF_TEST_PASSWORD=admin \
  zig build test-netconf               # + live hello → get-config → get → rpc-error → close-session,
                                       #   run twice: chunked (:base:1.1) and end-of-message (:base:1.0)
```

Note that OpenSSH alone does **not** provide a `netconf` subsystem — a NETCONF server
(netopeer2, sysrepo, yuma123 `netconfd`, or a Python `netconf`/paramiko server) has to be
running behind it. SPEC.md records exactly which server the live run was verified against,
which goldens come from which RFC section, and the deferred list.

Provenance: clean-room from RFC 6241 / RFC 6242 / RFC 5277. No third-party source was
ported or studied, so there is no `/NOTICE` entry — the RFC citations live in SPEC.md.
