# accesslog

Structured HTTP access-log formatter. One `Entry` per request, emitted to a `std.Io.Writer` in
**JSON Lines**, **logfmt**, or the ubiquitous Apache/NGINX **Combined Log Format** — with
log-injection-safe escaping rigorous enough that a crafted User-Agent or path can never forge a
second log line or break a field. `Entry` is a plain struct, so the formatters work standalone
(no live HTTP request required); `entryFromRequest` is a convenience bridge for the common case
of logging an `http` request/response pair.

- **Model after:** Apache `mod_log_config` (Combined Log Format + its `ap_escape_logitem`
  escaping rule) + Heroku/`kr/logfmt` (logfmt) + the common JSON-Lines access-log convention
  (Caddy/nginx json access log).
- **Platform:** any. **Role:** codec. **Concurrency:** reentrant (pure functions, no shared
  state). **Deps:** `http` (for the `entryFromRequest` bridge) + std only.

Provenance: original work of the zig-libs authors (MIT). No third-party code.

## Quick start — a hand-built `Entry`

```zig
const accesslog = @import("accesslog");

const entry: accesslog.Entry = .{
    .timestamp_ns = 1734000000000000000, // ns since Unix epoch — YOU supply this, no clock read
    .remote_addr = "192.0.2.1:54321",
    .method = "GET",
    .target = "/status?x=1",
    .status = 200,
    .response_bytes = 512,
    .latency_ns = 1_500_000,
    .user_agent = "curl/8.0",
};

var buf: [512]u8 = undefined;
var w: std.Io.Writer = .fixed(&buf);
try accesslog.writeJsonLines(entry, &w);
// {"ts":1734000000000000000,"remote_addr":"192.0.2.1:54321","method":"GET",
//  "target":"/status?x=1","protocol":"HTTP/1.1","status":200,"request_bytes":null,
//  "response_bytes":512,"latency_ns":1500000,"user_agent":"curl/8.0",
//  "referer":null,"request_id":null}
```

Or pick the format at runtime with the `Format` enum:

```zig
try accesslog.write(entry, .logfmt, &w);
// ts=1734000000000000000 remote_addr=192.0.2.1:54321 method=GET target=/status?x=1
// protocol=HTTP/1.1 status=200 response_bytes=512 latency_ns=1500000 user_agent=curl/8.0

try accesslog.write(entry, .combined, &w);
// 192.0.2.1 - - [1734000000000000000] "GET /status?x=1 HTTP/1.1" 200 512 "-" "curl/8.0"
// (note: `%h` is the host alone — Combined-format consumers reject a port here)
```

(Combined's `[%t]` bracket falls back to the raw nanosecond epoch when `Entry.time_formatted`
is null — see "Time contract" below for the spec-shaped alternative.)

## Wiring it to a live request — `entryFromRequest`

```zig
const http = @import("http");
const accesslog = @import("accesslog");

fn handle(req: *http.Server.Request, res: *http.Server.ResponseWriter) !void {
    const t0 = myClock.nowNs(); // caller times it — this module never reads the clock
    defer {
        var addr_buf: [64]u8 = undefined;
        const entry = accesslog.entryFromRequest(req, res, &addr_buf, .{
            .timestamp_ns = t0,
            .latency_ns = myClock.nowNs() - t0,
        });
        accesslog.writeJsonLines(entry, &log_writer) catch {}; // never fail the request over a log line
    }
    // ... handle the request, set res.status, write the body ...
}
```

`entryFromRequest` pulls `method`/`target`/`protocol`/`status`/`User-Agent`/`Referer`/
`remote_addr`/`request_bytes` (declared `Content-Length`) automatically; `timestamp_ns` and
anything else the live types can't supply (latency, a correlation id, a preformatted Combined
time string) comes from `FromRequestOptions`.

## Time contract — no system clock, ever

`Entry.timestamp_ns` is always caller-supplied (ns since the Unix epoch); this module never
calls into the clock. JSON/logfmt use it directly as a number. Combined's real `[%t]` shape
(`10/Oct/2000:13:55:36 -0700`) needs a timezone-aware calendar conversion this module
deliberately doesn't perform — format that string yourself (e.g. with the `datefmt` module) and
pass it as `Entry.time_formatted`; without it, Combined still emits one well-formed bracketed
field, just numeric instead of calendar-shaped.

## Log-injection safety

The primary design goal: a crafted `method`/`target`/`user_agent`/`referer` (or any string field
on a hand-built `Entry`) can never break out of its delimiter, inject a raw newline to forge a
second record, plant a fake `key=value` pair in logfmt, or put a raw control byte on the wire.
Each format has its own escaping rule (JSON string escaping, logfmt quote-when-needed +
backslash escaping, Apache's `ap_escape_logitem`) — see `SPEC.md` for the exact guarantee per
format and the adversarial vectors the test suite exercises (quotes, CR/LF, braces, a fake
`status=200` logfmt pair, control bytes, and a full forged-line attempt against Combined).

## The log is always readable — and what that costs

**Every JSON Lines record this module emits is valid JSON, whatever bytes the request
carried.** That is the mirror of the injection guarantee and it matters just as much: RFC 8259
requires a JSON text to be UTF-8, so a client sending a non-UTF-8 `User-Agent` or request
target used to be able to make its **own** record unparseable — and therefore droppable by the
log pipeline. Log evasion.

To get that, `writeJsonLines` replaces each ill-formed UTF-8 subsequence with **U+FFFD**
(`\u{fffd}`), one per subsequence — Unicode 16.0 §3.9's "U+FFFD Substitution of Maximal
Subparts" recommendation, the same rule the WHATWG Encoding Standard and Rust's
`String::from_utf8_lossy` follow, so a reader who re-decodes the field sees what this module
emitted. Lone surrogates, overlong encodings,
truncated sequences and bare continuation bytes are all covered.

⚠ **The round trip is byte-exact for valid UTF-8 only.** A field carrying arbitrary bytes comes
back with U+FFFD where those bytes were, and the originals are not recoverable from the JSON
output — that is the deliberate trade for a log that never loses a record. logfmt and Combined
are byte-oriented text formats with no encoding requirement of their own, are **not**
sanitized, and keep their byte-exact round trip. `SPEC.md` has the preserved/replaced table,
the exact substitution vectors, and what the choice means one hop downstream.

```zig
entry.user_agent = "curl\xffbad"; // a client's arbitrary bytes
try accesslog.writeJsonLines(entry, &w);
// ..."user_agent":"curl\u{fffd}bad"...   ← parses; the bad byte is marked, not passed on
try accesslog.writeCombined(entry, &w);
// ..."curl\xffbad"                       ← byte-exact; Combined has no encoding requirement
```

## Missing fields

Only `timestamp_ns`/`method`/`target`/`status` are required (`protocol` defaults to
`"HTTP/1.1"`); everything else is optional and renders per format's own convention: JSON emits
an explicit `null`, logfmt omits the key, Combined uses its `-` placeholder (`"-"` for the
quoted Referer/User-Agent fields, matching `mod_log_config`).

## Relationship to `metrics.AccessLog`

`metrics` ships its own small built-in access-log writer, driven off the narrower fields its
`RequestMetrics` middleware can produce for free (method/path/status/duration/bytes — no host,
UA, referer, time, or request-id). This module is the standalone, fuller-fielded formatter
(plus logfmt, plus the injection-escaping this README/SPEC documents) for when those extra
fields matter — the two don't depend on each other.

See `SPEC.md` for the full field table, the exact escaping guarantee per format, and the
`entryFromRequest`/`ResponseWriter.body` byte-count contract.
