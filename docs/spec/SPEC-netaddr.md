# SPEC — `netaddr`

IP address parsing/formatting + RFC 6724 destination/source address selection.
`extract · any · util · reent`. Model after: glibc `getaddrinfo` reachability ordering /
Go stdlib `net/addrselect.go`. Seed: `~/workspace/zig-fping/src/netutil.zig`.

## Why

Zig std has address types but **no RFC 6724 destination/source selection** — the "given several
candidate addresses for a dual-stack host, which do I connect to, in what order" logic. `http`,
`dns`, `icmp` all need it. This module also provides ergonomic parse/format helpers.

## Scope (this task)

1. **Parse/format** — IPv4 and IPv6 literals ↔ bytes; parse `host:port` / `[v6]:port`; format
   canonical (RFC 5952 for v6). Reject malformed input (no panics).
2. **Address kind/scope classification** — loopback, link-local, ULA, multicast, global; the
   scope + label + precedence tables RFC 6724 needs.
3. **RFC 6724 destination ordering** — `sortDestinations(candidates, source_for)` ordering the
   candidate list per the rule set (precedence, scope match, longest-matching-prefix, prefer
   higher precedence, etc.). Port the logic from the zig-fping seed (`sortByDestinationPolicy`,
   `policyPrecedence`, `destinationReachable`) and cross-check against Go `addrselect.go`.
4. **Source selection** — best source address for a given destination (the rules that pair with
   destination ordering). zig-fping stubs this; implement the common cases, document the corners.

## Public API sketch (adjust to taste, keep it small + allocator-explicit)

```zig
pub const Ip = union(enum) { v4: [4]u8, v6: [16]u8 };
pub fn parseIp(text: []const u8) ?Ip;
pub fn formatIp(ip: Ip, buf: []u8) []const u8;          // RFC 5952 for v6
pub const HostPort = struct { host: []const u8, port: u16 };
pub fn parseHostPort(text: []const u8) ?HostPort;       // handles [v6]:port
pub const Scope = enum { node_local, link_local, site_local, global };
pub fn scopeOf(ip: Ip) Scope;
pub fn precedenceOf(ip: Ip) u8;                          // RFC 6724 policy table
/// Sort `dsts` in place into RFC 6724 connect-preference order.
pub fn sortDestinations(dsts: []Ip, srcFor: *const fn (Ip) ?Ip) void;
```

## Acceptance / verification (headless)

- Unit tests: parse/format round-trips for a table of v4 + v6 literals incl. canonicalization
  (`2001:db8::1`, `::1`, `::ffff:1.2.3.4`, zero-compression edge cases), and rejection of malformed.
- RFC 6724 ordering test vectors — reuse the ones the zig-fping seed uses; add the canonical
  examples from RFC 6724 §10.
- `scopeOf` / `precedenceOf` unit tests against the RFC 6724 policy table.
- `zig build test-netaddr` green; no allocation in parse/format/classify (allocator only if a
  sort needs scratch — prefer in-place).

## Notes

Platform `any` (pure logic). Keep it dependency-free (std only). This is the foundation `http`
(T2) and `dns` (T3) build on, so land it first and keep the API stable.
