# accesslog — spec

Structured HTTP access-log formatter: one `Entry` record per request, emitted to a
`std.Io.Writer` in JSON Lines, logfmt, or Apache/NGINX Combined Log Format. Usage: see
./README.md.

## Fields (`Entry`)

| Field | Type | Meaning |
|---|---|---|
| `timestamp_ns` | `i64` | Nanoseconds since the Unix epoch. **Caller-supplied — see "Time contract" below.** |
| `time_formatted` | `?[]const u8` | Preformatted `[%t]` bracket contents for Combined (e.g. `"22/Jul/2026:10:00:00 +0000"`). Ignored by JSON/logfmt. |
| `remote_addr` | `?[]const u8` | Client address, e.g. `"192.0.2.1:54321"`. |
| `method` | `[]const u8` | Request method token, e.g. `"GET"`. |
| `target` | `[]const u8` | Raw request-target, e.g. `"/path?q=1"`. |
| `protocol` | `[]const u8` | Protocol version string, default `"HTTP/1.1"`. |
| `status` | `u16` | Response status code. |
| `request_bytes` | `?u64` | Request body byte count, when known. |
| `response_bytes` | `?u64` | Response body byte count, when known. |
| `latency_ns` | `?u64` | Request→response latency in nanoseconds. |
| `user_agent` | `?[]const u8` | `User-Agent` header value. |
| `referer` | `?[]const u8` | `Referer` header value. |
| `request_id` | `?[]const u8` | Correlation / request id. |

Only `timestamp_ns`, `method`, `target`, `status` are required; `protocol` defaults to
`"HTTP/1.1"`; everything else is `?` and null when unknown.

## Time contract — no system clock

**This module never reads the clock, anywhere.** `Entry.timestamp_ns` is a caller-supplied
nanosecond Unix timestamp, used verbatim by JSON/logfmt and as the numeric fallback for
Combined's `[%t]` when `time_formatted` is null. Reproducing Apache's actual `[%t]` shape
(`10/Oct/2000:13:55:36 -0700`) requires a timezone-aware calendar conversion, which is a
separate formatting concern this module deliberately does not perform — a caller that wants
the spec-shaped bracket formats the string itself (e.g. with the `datefmt` module, not a
dependency of this one) and passes it as `time_formatted`. Without it, Combined still emits
exactly one well-formed bracketed field (`[<ns-epoch>]`) — not calendar-shaped, but not
malformed either, and it costs nothing extra to support.

## The three formats

### JSON Lines (`writeJsonLines`, `Format.json_lines`)

One JSON object per line, LF-terminated, **fixed key order** (`ts`, `remote_addr`, `method`,
`target`, `protocol`, `status`, `request_bytes`, `response_bytes`, `latency_ns`, `user_agent`,
`referer`, `request_id`), every key always present — an absent optional renders as JSON `null`
rather than being omitted, so the record has a stable schema for log-pipeline consumers.

**Every emitted line is valid JSON, for any input bytes whatsoever** — see "Encoding contract"
below for what that costs.

### logfmt (`writeLogfmt`, `Format.logfmt`)

`key=value` pairs, space-separated, LF-terminated, same key order as JSON Lines. An absent
optional **omits the key** entirely (the logfmt convention — there is no `null`).

### Combined (`writeCombined`, `Format.combined`)

`%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"\n` — the Apache/NGINX Combined Log
Format. `%l` (identity) and `%u` (authenticated user) are always `-`; this module tracks
neither. `%b` is `-` when `response_bytes` is null, the decimal count otherwise (`0` prints
literally, matching real servers — it is not treated as "unknown"). A missing Referer/User-Agent
prints the literal `"-"` (quoted dash), matching `mod_log_config`'s own behavior for a missing
header on what is normally a quoted field.

`%h` is the client **host alone** — never `host:port`. `remote_addr` carries the full peer
address (the JSON and logfmt formats emit it verbatim, port included, because a structured
consumer wants it), so `writeCombined` strips the port for this slot only; an IPv6 address is
logged bare (`::1`, not `[::1]`), as Apache does. This is externally anchored: with the port
present, goaccess 1.10.2 rejects **every** line with `Token '192.0.2.1:54321' doesn't match
specifier '%h'` (valid=0, failed=2); with it stripped, valid=3, failed=0.

## Log-injection escaping guarantees (the primary requirement)

Threat model: `method`, `target`, `user_agent`, `referer` (and, on a hand-built `Entry`, any
string field) may carry attacker-controlled bytes. The goal for every format is that **no
value, however crafted, can**: close its delimiter early and forge a sibling field/key, inject
a raw newline that splits one record into two ("log forging"), or place a raw control byte on
the wire.

- **JSON Lines** — every string field goes through `writeJsonString`: RFC 8259 §7 escaping —
  `"` and `\` backslash-escaped, `\b\t\n\f\r` as their named short escapes, every other byte in
  `0x00-0x1F` as `\u00XX`. `0x7F` (DEL) is not a JSON control character per the spec and passes
  through unescaped — harmless, since it cannot terminate or extend the string. A crafted value
  can never close its string (the closing `"` is always escaped to `\"`), never emit a raw
  newline (always `\n` the two-character escape, never byte `0x0A`), and therefore never forge a
  sibling key or a second line. Verified by round-tripping the emitted line through
  `std.json.parseFromSlice` and asserting the parsed field equals the original payload
  byte-for-byte. The same function additionally enforces the encoding contract below.
- **logfmt** — a value is quoted only when `logfmtNeedsQuote` is true: it is empty or contains a
  space, `"`, `=`, `\`, or any control byte (`0x00-0x1F` or `0x7F`). When quoted, `"`/`\` are
  backslash-escaped, `\n`/`\r`/`\t` get short escapes, any other control byte becomes `\xHH`.
  Because the quoting trigger set is exactly the escape set, an unquoted value is guaranteed to
  contain none of those bytes — benign passthrough is byte-identical, and anything that would
  read as a second `key=value` pair (a bare `=`), break out of a quoted value (a bare `"`), or
  forge a new record (a bare `\n`) is always caught and neutralized.
- **Combined** — `writeClfEscaped` (Apache's own `ap_escape_logitem` rule) is applied to
  **every** field, not just the quoted ones (so even the unquoted `%h`/`%t` slots can't inject a
  raw control byte): `"` and `\` backslash-escaped, every other byte in `0x00-0x1F ∪ {0x7F}`
  (this includes `\n` and `\r`) as `\xHH`. A crafted `%r`/Referer/User-Agent value can never
  close its surrounding quote early or emit a raw newline, so the record stays exactly one line
  no matter what it contains.

All three were verified against a shared adversarial payload — `"`, `\r\n` (line-forge
attempt), `{`/`}` (JSON-structure-confusion attempt), a fake ` status=200` logfmt pair, and
control bytes `0x01`/`0x1F`/`0x7F` — plus a Combined-specific payload that additionally embeds
a full forged Combined line (`"` + `\r\n` + a fake `%h %l %u %t "%r"...` prefix). Every case:
exactly one line out, no raw `\n`/`\r`/other tested control byte on the wire, and (JSON) an
exact round-trip through `std.json`. A benign positive-control value (a normal User-Agent
string, a normal Referer URL) is asserted to pass through unchanged in each format, proving the
escaping isn't over-aggressive.

## Encoding contract — the log must always be readable

Log **evasion** is the mirror image of log injection: a record the pipeline cannot parse is a
record the pipeline drops, so a client able to make its own record unparseable has erased
itself from the log. RFC 8259 requires a JSON text to be UTF-8 and conforming parsers enforce
it, and a request target or `User-Agent` carries whatever bytes the client sent. **JSON Lines
output is therefore unconditionally parseable**: `writeJsonString` replaces ill-formed UTF-8
rather than passing it through.

### What is preserved, what is replaced

| Input | JSON Lines | logfmt / Combined |
|---|---|---|
| ASCII, and any well-formed UTF-8 | **byte-exact**, modulo the JSON escapes above | byte-exact, modulo each format's escapes |
| ill-formed UTF-8 (surrogates, overlongs, truncated sequences, bare continuation bytes, `F5`–`FF`) | **replaced** with U+FFFD, one per ill-formed subsequence | passed through unchanged |
| control bytes `0x00`–`0x1F` | escaped (`\n`, `\u0007`, …) — unchanged by this contract | escaped (`\xHH`) — unchanged |

**This ends the byte-exact round trip for non-UTF-8 input, and that is deliberate.** Before
2026-08-11 the JSON writer passed every byte ≥ `0x20` through verbatim and the module's docs
claimed a malformed byte "only ever affects display, never the string's structural validity" —
that sentence was the opposite of the truth (`std.json` answers `error.SyntaxError` on such a
line, as does CPython's `json`). The owner's decision, 2026-08-11: *the access log must always
be readable; a bad byte must never break it.* The original bytes of an ill-formed field are
**not recoverable** from JSON Lines output; a deployment that needs them must keep the raw
value elsewhere (see "Not shipped" below).

### Substitution policy: one U+FFFD per maximal subpart

Unicode 16.0 §3.9's "U+FFFD Substitution of Maximal Subparts" recommendation, i.e. one
replacement character per *ill-formed subsequence* — the same behaviour as the WHATWG
Encoding Standard and Rust's `String::from_utf8_lossy`, so a reader who re-decodes the field
with any of those sees the string this module emitted. The alternative, one U+FFFD per ill-formed *byte* (what Go's
`encoding/json` does, since its `utf8.DecodeRune` reports size 1 on every error), was not
chosen.

The two policies are observably different exactly on a **truncated but otherwise valid
prefix**, and the tests assert the emitted bytes rather than the rule:

| Input | maximal subpart (this module) | per byte |
|---|---|---|
| `E2 82` (start of `€`) | `U+FFFD` | `U+FFFD U+FFFD` |
| `F0 9F 98` (start of `😀`) | `U+FFFD` | `U+FFFD U+FFFD U+FFFD` |
| `ED A0 80` (U+D800 surrogate) | `U+FFFD U+FFFD U+FFFD` | `U+FFFD U+FFFD U+FFFD` |
| `C0 AF` (overlong `/`) | `U+FFFD U+FFFD` | `U+FFFD U+FFFD` |

The surrogate row is worth reading twice: the two policies **agree** there, because `ED A0` is
not a prefix of any well-formed sequence (Unicode Table 3-7 caps `ED`'s second byte at `9F`),
so `ED` alone is the maximal subpart. A test on that vector alone could not tell the policies
apart; the truncated-prefix rows are what discriminate.

### logfmt and Combined are out of scope, on purpose

Neither format carries an encoding requirement — both are byte-oriented text — so neither is
sanitized and both keep the byte-exact round trip. Measured, not assumed: `goaccess` 1.10.2
reads a Combined log whose `%r` and User-Agent contain `FF` and `ED A0 80` with `valid=3,
failed=0`. What *is* worth knowing is that the exposure re-appears one hop downstream — the
same goaccess run re-emits those bytes into its own JSON report (`-o report.json`), and that
file is then not valid UTF-8 and is rejected by CPython's `json` (`jq` accepts it, substituting
U+FFFD itself while reading, so jq cannot be used as the oracle for this). A deployment that
feeds Combined or logfmt into a JSON-producing analyser inherits the problem at that boundary;
using this module's JSON Lines output avoids it at the source.

### Not shipped: recovering the original bytes

Keeping the raw value recoverable is cheap and was deliberately **not** made the default: an
opt-in flag could emit an extra sibling key (e.g. `"user_agent_raw":"<hex>"`) for each field
whose input was ill-formed, hex being both compact enough and unconditionally UTF-8-safe. It
costs one extra key only on the records that need it, keeps the default lossy-but-parseable per
the decision above, and is a strictly additive schema change (the fixed key order stays; the
raw keys appear after the field they belong to). Not implemented — no consumer asked for it,
and an always-present raw copy of every attacker-controlled field is also an unbounded-size
amplifier on a hot path.

## `entryFromRequest` — the http bridge

`entryFromRequest(req: *const http.Server.Request, res: *const http.Server.ResponseWriter,
addr_buf: []u8, opts: FromRequestOptions) Entry` builds an `Entry` from one served request:
method/target/protocol from `req`, status from `res.status`, `User-Agent`/`Referer` from
`req.header(...)`, `remote_addr` formatted from `req.peerAddress()` into the caller-supplied
`addr_buf` (zero allocation — 64 bytes comfortably covers the longest `std.Io.net.IpAddress`
textual form, `"[xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]:65535"` at 47 bytes).
`request_bytes` defaults to the request's declared `Content-Length` (an `opts.request_bytes`
override wins when given). `response_bytes` uses the same best-effort contract as
`metrics.AccessEntry.bytes`: exact for a buffered or declared-length body, `0` for
HEAD/204/304 (`.discard`), `null` for chunked/until-close/compressed streaming (no running
total is kept). `timestamp_ns`/`time_formatted`/`latency_ns`/`request_id` all come from `opts`
— this module has no other source for them (see the time contract above).

The formatter itself (`write`/`writeJsonLines`/`writeLogfmt`/`writeCombined`) never touches
`http` types — it only consumes the plain `Entry`, so it works identically for a hand-built
record (tests, non-`http.Server`-backed transports, replaying archived data).

## Relationship to `metrics.AccessLog`

The `metrics` module ships a small built-in access-log writer (JSON/Combined) driven off its
own narrower `AccessEntry` (method/path/status/duration/bytes only — no host, UA, referer,
time, or request-id, since that struct is what the `RequestMetrics` middleware can produce for
free on the request-metrics hot path). This module is the standalone, fuller-fielded formatter
for when those extra fields matter, and adds logfmt as a third format plus the rigorous
injection-escaping this SPEC documents. The two are independent — neither imports the other,
and there is no requirement to pick one over the other; `metrics.AccessLog` stays as the
zero-extra-dependency default for a bare metrics deployment, and `accesslog` is what a
production HTTP server (the P2 server this was built for) wires up when it wants full fields.

## Threat model / out of scope

A codec for a machine-generated `Entry` (or a live HTTP request via `entryFromRequest`), not a
general string sanitizer for arbitrary untrusted logging call sites. In scope: neutralizing
log-injection/log-forging via the fields this module itself renders (see above). Out of scope:
downstream log-pipeline parsing bugs (a broken third-party logfmt/JSON parser is not this
module's problem to fix), enforcing a maximum field length (a pathologically long header
still produces a pathologically long — but still single, still well-formed — line; bound
header sizes upstream, e.g. `http.Server.Options`' own 431/414 limits), and PII
redaction/scrubbing (an app that logs a bearer token in a custom field is an app policy issue,
not something this formatter can detect).

## Design & invariants

- Every `write*` function takes `entry: Entry` by value and a `*std.Io.Writer` — no allocation,
  no panics (bounded by the caller's writer; a full fixed buffer returns
  `std.Io.Writer.Error`, never overruns or aborts), reentrant (pure functions, no shared or
  internal state).
- `std`-only + `http` (for `Server.Request`/`Server.ResponseWriter` types in
  `entryFromRequest`) — no other module dependency, no C/libc.

## Verification

`zig build test-accesslog` (Debug + ReleaseFast): byte-exact golden strings for a
representative `Entry` in each of the 3 formats + the `write` enum-dispatch wrapper +
missing-optional-fields rendering per format's convention; the log-injection suite (JSON/
logfmt/Combined, each with a shared adversarial payload plus a Combined-specific forged-line
payload, plus a benign positive control per format); `entryFromRequest` pulling every field off
a socket-free `http.Server.Request`/`ResponseWriter` pair (HTTP/1.1 with a peer address and
headers, HTTP/1.0 with none, and a `request_bytes` override), and one test proving its output
feeds straight into `writeCombined`.

For the encoding contract: a table of ~30 vectors asserting the **exact bytes** emitted for
every ill-formed shape (surrogates, overlongs, truncations, bare continuations, `F5`–`FF`) and
for every boundary of Table 3-7 that must pass through untouched; an exhaustive cross-check of
the well-formedness classifier against `std.unicode` over every 1- and 2-byte string and the
boundary-byte 3-/4-byte extensions; a brute-forced check that each reported ill-formed length
really is the *maximal* subpart, using `std.unicode` rather than a second copy of this module's
table; and the surviving byte-exact round trip stated as its own test. Externally anchored on
CPython's `json` (which enforces UTF-8 at the decode step): 16/16 vectors accepted with
sanitization, 14/16 rejected without it. `jq` is deliberately not used as that oracle — it
substitutes U+FFFD itself while reading and so accepts both.

Three `testing.fuzz` harnesses, one per format, driven from a **written** corpus. The JSON
oracle is one-sided and absolute: for any input bytes the emitted line parses, with no
predicate guarding the assertion; a field that was valid UTF-8 additionally comes back
byte-exact, one that was not comes back valid UTF-8 containing U+FFFD. The corpus is written
rather than generated because a corpus-driven `std.testing.Smith` resolves every *weighted*
draw (`bool`, a small `valueRangeAtMost`) to the range minimum, which would leave every field
empty and every optional absent outside `zig build fuzz`; a dedicated test decodes the corpus
back and asserts that each JSON-visible slot receives ill-formed UTF-8 at least once, so the
harness cannot silently degenerate.

Cost, measured (`ACCESSLOG_BENCH=1 … -Doptimize=ReleaseFast`, `src/bench.zig`, 200 000 records
× 5 alternating rounds, minimum, against a frozen copy of the pre-change writer): a clean ASCII
record **456.7 → 256.2 ns** (−43.9 %, because the sanitizing scan batches pass-through runs
into one `writeAll` where the old escaper wrote byte by byte), a valid-UTF-8 record 436.1 →
329.2 ns (−24.5 %), and a record whose fields are mostly ill-formed 363.4 → 456.9 ns (+25.7 %,
i.e. +93 ns and only for records that actually carry bad bytes). Nothing is allocated and
nothing is copied when the input is clean.
