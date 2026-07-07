# whois

**RFC 3912** WHOIS client: query formatting, IANA/registry **referral
chasing**, and a tiny `key: value` field extractor.

- **Status:** `gap` — no I/O-agnostic RFC 3912 client with referral chasing
  in the Zig ecosystem.
- **Model after:** RFC 3912 whois; the IANA/registry referral chain
  (`whois.iana.org` `refer:` bootstrap → registry → registrar).
- **Provenance:** clean-room from RFC 3912 plus the documented IANA/registry
  referral line conventions (IANA `refer:`, ARIN `ReferralServer:`, Verisign
  `Registrar WHOIS Server:`). No third-party whois implementation consulted
  or copied.
- **Why:** RFC 3912 itself is one page; the real work is knowing *which*
  server to ask. `lookup` starts at the IANA bootstrap and follows referrals
  — depth-capped, cycle-guarded, byte-capped — to the terminal response.
  Replies are deliberately not parsed beyond the referral keys (every
  registry has its own freeform format).
- **Platform:** any (pure logic over a transport seam; only the optional
  `TcpTransport` uses `std.Io.net`). **Role:** client.
  **Concurrency:** reentrant (no shared state).
  **Allocation:** none — fixed buffers throughout.

## API

```zig
const whois = @import("whois");

// Query formatting (RFC 3912 §2: "<query> CRLF")
var qbuf: [whois.max_query_len + 2]u8 = undefined;
const wire = try whois.formatQuery(&qbuf, "example.com"); // "example.com\r\n"
_ = try whois.arinIpQuery(&qbuf, "192.0.2.1");            // "n 192.0.2.1\r\n"
_ = try whois.verisignDomainQuery(&qbuf, "example.com");  // "domain example.com\r\n"

// Referral extraction from a raw reply (never errors on garbage)
const ref = whois.nextServer(reply);            // ?Referral{ .host, .port }
_ = whois.parseServerRef("whois://h.example:43"); // handles whois:// URL form
_ = whois.fieldValue(reply, "Registrar WHOIS Server"); // ?[]const u8, trimmed

// Full lookup with referral chasing over a caller-provided transport seam
var buf: [16 * 1024]u8 = undefined; // per-response byte cap
const result = try whois.lookup(transport, "example.com", .{}, &buf);
// result.response  — final (most authoritative) reply text
// result.chain     — servers consulted in order, root first
// result.truncated — true if the referral depth cap stopped the chase

// Optional real transport (the only network-touching code; tests never dial)
var tcp: whois.TcpTransport = .{ .io = io };
_ = try whois.lookup(tcp.transport(), "example.com", .{}, &buf);
```

`Transport` is one function: "connect to `server:port`, send the formatted
query, read the whole text reply until close" — so everything is offline
testable from canned buffers. Defaults: root `whois.iana.org`, port 43,
max 5 referrals (chain hard cap 8).
