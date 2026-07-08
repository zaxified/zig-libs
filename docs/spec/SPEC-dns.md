# SPEC — `dns`

DNS resolver: forward (A/AAAA) + reverse (PTR) over UDP/TCP **and DoH**.
`extract+gap · any · client · block`. Model after: Go `net` dnsclient + `miekg/dns` (message
codec) / c-ares; RFC 1035 (wire), RFC 8484 (DoH). Seed: `~/workspace/zig-fping/src/rdns.zig`
(working /etc/hosts + RFC 1035 UDP PTR client). Deps: `netaddr`, `http` (DoH), `std.json` (DoH-JSON),
std udp/tcp. `dig`-style CLI can ship as a demo later (not required this task).

## Why

`std.Io.net.HostName.lookup` is forward-only and opaque; there is no reverse (PTR), no explicit
server/transport control, and no DoH in std. `http` (rdap, the REST cluster) and diagnostics want
a real resolver. DoH = privacy/firewall-friendly and validates that `http` works as a dependency.

## Scope (this task)

1. **Message codec (the core — shared by every transport).** Encode a query, decode a response:
   header, question, RR sections; **name compression pointers** (encode may skip; decode MUST
   handle); types A, AAAA, PTR, CNAME, NS, MX, TXT, SOA; IN class; TTL. Robust against malformed
   input (no panics, bounded loops on compression pointers to prevent loops).
2. **Transports:**
   - **UDP** (primary) with **truncation (TC bit) → TCP retry**.
   - **TCP** (2-byte length-prefixed messages).
   - **DoH wire (RFC 8484):** `application/dns-message` — the SAME binary DNS message POSTed
     (or GET w/ base64url `?dns=`) over the `http` module to a DoH endpoint. This is standard DoH.
   - **DoH JSON (optional):** `application/dns-json` (Cloudflare/Google `/resolve?name=&type=`)
     via `http` + `std.json` — the non-standard-but-common variant. Include if cheap; else TODO.
   - **EDNS(0)** OPT record to advertise a larger UDP payload size.
3. **Resolver API + config:** resolve(name, type) → records; reverse(ip) → names (build
   `in-addr.arpa` / `ip6.arpa` from `netaddr`); read `/etc/resolv.conf` for servers + search, and
   `/etc/hosts` first (port from the seed). Caller can pass explicit servers / a DoH URL to
   override system config.

## Public API sketch (small, allocator-explicit; final shape your call)

```zig
pub const Resolver = struct {
    pub fn init(io, gpa, Options) Resolver;   // Options: servers, doh_url, timeout, use_hosts, edns_udp_size
    pub fn deinit(*Resolver) void;
    pub fn resolve(self, name: []const u8, ty: Type) !Answer;   // Answer owns records
    pub fn lookupIp(self, name: []const u8) ![]Ip;              // A + AAAA convenience (netaddr.Ip)
    pub fn reverse(self, ip: Ip) ![][]const u8;                 // PTR
};
pub const Type = enum(u16) { a=1, ns=2, cname=5, soa=6, ptr=12, mx=15, txt=16, aaaa=28, opt=41, _ };
// low-level, transport-agnostic:
pub const Message = struct { pub fn encodeQuery(...); pub fn decode(...); };
```

## Acceptance / verification

- **Offline unit tests (the bulk):** message encode → exact golden bytes for a known query;
  decode of canned responses incl. **compression pointers**, multiple RRs, A + AAAA + PTR + CNAME
  chains; malformed/truncated/pointer-loop inputs return errors (no hang, no panic). resolv.conf /
  hosts parsing on fixtures. Reverse-name construction (`8.8.8.8` → `8.8.8.8.in-addr.arpa`,
  v6 nibble form). `zig build test-dns` green.
- **Live (skip via `error.SkipZigTest` if no network):** resolve `example.com` A over UDP;
  resolve the same over **DoH** (`https://dns.google/dns-query` or `cloudflare-dns.com`) — proving
  the `http` dep works; a PTR lookup of a known IP.
- No panics on any adversarial packet. Register `dns` in build.zig with `deps=&.{"netaddr","http"}`.

## Notes for the implementer

- Use the **zig skill** for Zig 0.16 std APIs. Reuse `netaddr` for all address parse/format and
  the reverse-name construction; reuse `http.Client` for DoH (don't reinvent HTTP).
- Extract the /etc/hosts + UDP PTR logic from the seed `rdns.zig`; build the general message codec
  around it (the seed is PTR-focused — generalize to A/AAAA/etc.).
- Keep the message codec transport-agnostic and separately testable (golden bytes) — it's the part
  that must be bulletproof.
