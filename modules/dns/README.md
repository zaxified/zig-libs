# dns

DNS resolver: RFC 1035 message codec + UDP/TCP/DoH transports, forward
(A/AAAA) and reverse (PTR) lookups.

- **Status:** extract + gap — the /etc/hosts + UDP-PTR core is extracted from
  zig-fping's `src/rdns.zig`; the general codec, TCP, EDNS(0) and DoH fill a
  real std gap (`std.Io.net.HostName.lookup` is forward-only and opaque — no
  PTR, no server/transport control, no DoH).
- **Model after:** Go `net` dnsclient + `miekg/dns` (message codec) / c-ares;
  RFC 1035 (wire format), RFC 8484 (DoH).
- **Provenance:** the /etc/hosts + UDP-PTR core is extracted from zig-fping `src/rdns.zig` (fping-derived — see the fping attribution in [NOTICE](../../NOTICE)); the general codec / TCP / EDNS(0) / DoH are clean-room from RFC 1035 / RFC 8484.
- **Deps:** `netaddr` (address parse/format, reverse-name construction,
  RFC 6724 result ordering), `http` (DoH transport), `std.json` (DoH-JSON),
  `std.Io.net` (UDP/TCP).

## Layout

| File | Role |
|------|------|
| `src/message.zig` | Pure wire codec: encode query / decode response — header, question, RR sections, **name-compression pointers** (strictly-backwards rule + jump budget: loops impossible), A/AAAA/PTR/CNAME/NS/MX/TXT/SOA, EDNS(0) OPT. No I/O; golden-byte tested; fuzzed. |
| `src/config.zig` | `/etc/resolv.conf` + `/etc/hosts` parsing, Go-`nameList` search expansion. Pure string logic, fixture-tested. |
| `src/Resolver.zig` | Blocking client: UDP (TC bit → TCP retry), TCP (2-byte length prefix), DoH POST/GET (`application/dns-message`), DoH-JSON (`application/dns-json`). |
| `src/root.zig` | Vocabulary re-exports + netaddr bridges (`reverseName`, `recordIp`). |

## Usage

```zig
const dns = @import("dns");

var resolver = dns.Resolver.init(io, gpa, .{});
defer resolver.deinit();

// getaddrinfo-like: /etc/hosts first, then A + AAAA with the search list,
// RFC 6724-ordered on Linux.
const ips = try resolver.lookupIp("example.com");
defer gpa.free(ips);

// Any record type; caller inspects rcode/answers, message owns its memory.
var msg = try resolver.resolve("example.com", .mx);
defer msg.deinit();
for (msg.answers) |rec| switch (rec.data) {
    .mx => |mx| std.debug.print("{d} {s}\n", .{ mx.preference, mx.exchange }),
    else => {},
};

// Reverse (PTR): hosts file first, then in-addr.arpa / ip6.arpa via netaddr.
const names = try resolver.reverse(netaddr.parseIp("8.8.8.8").?);
defer resolver.freeNames(names);

// DNS-over-HTTPS (RFC 8484) — same API, different transport:
var doh = dns.Resolver.init(io, gpa, .{ .doh_url = "https://dns.google/dns-query" });
defer doh.deinit();
var m2 = try doh.query("example.com", .aaaa);
defer m2.deinit();

// Low-level codec, transport-agnostic:
var buf: [dns.message.max_query_len]u8 = undefined;
const packet = try dns.encodeQuery(&buf, "example.com", .a, .{ .id = 1 });
var decoded = try dns.decode(gpa, response_bytes);
defer decoded.deinit();
```

## Behavior notes

- Decoded names are dotted text **without** the trailing root dot (root = "");
  no `\DDD` escape handling — labels are raw bytes.
- `resolve` returns the last response even on NXDOMAIN/empty — inspect
  `Message.rcode()`; `lookupIp` returns an empty slice when nothing resolves.
- EDNS(0) advertises a 1232-byte UDP payload by default (DNS flag day 2020);
  set `edns_udp_size = null` for plain RFC 1035 queries.
- DoH uses query id 0 (RFC 8484 §4.1 cache friendliness).
- Compression pointers must point strictly backwards (Go dnsmessage rule);
  combined with the 253-char name cap and a 16-jump budget, adversarial
  pointer loops always fail fast with an error — the fuzz test hammers this.
- TCP/DoH connect timeouts fall back to the OS default until std's
  `Io.Threaded` implements `netConnectIp*` with a timeout (same TODO as
  `http.Client`).

## Tests

`zig build test-dns` — offline: golden query bytes, canned responses
(compression, CNAME chain, MX/TXT/SOA/OPT, PTR), adversarial packets
(truncations at every offset, pointer loops, bad rdata lengths, hostile
counts), fuzzed decode, resolv.conf/hosts fixtures, search-list order,
reverse-name goldens (incl. the RFC 3596 example). Live tests (UDP, TCP, DoH
POST/GET, DoH-JSON, PTR of 8.8.8.8) skip gracefully via `error.SkipZigTest`
when the network is unavailable.
