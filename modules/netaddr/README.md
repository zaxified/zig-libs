# netaddr

IP address parse/format + **RFC 6724** destination/source address selection.

- **Status:** `extract` — ported from `zig-fping` `src/netutil.zig`
  (`sortByDestinationPolicy`, `policyPrecedence`, `destinationReachable`),
  extended to the full RFC 6724 destination rule set.
- **Model after:** Go `net/addrselect.go` + glibc `getaddrinfo` (UDP-connect
  route-probe trick). Policy table and rule coverage match Go row-for-row.
- **Provenance:** extracted from zig-fping `src/netutil.zig` (fping-derived — see the fping attribution in [NOTICE](../../NOTICE)); design refs (Go `net/addrselect`, glibc) in NOTICE.
- **Why:** RFC 6724 selection ("several candidate addresses for a dual-stack
  host — which do I connect to, in what order") is a real gap in Zig std;
  foundational for `http`, `dns`, `icmp`.
- **Platform:** any (pure logic; only `systemSource` is Linux-only).
  **Role:** util. **Concurrency:** reentrant (no shared state).
  **Allocation:** none, anywhere.

## API

```zig
const netaddr = @import("netaddr");

// Parse / format (RFC 5952 canonical for v6, no panics on bad input)
const ip = netaddr.parseIp("2001:db8::1").?;      // ?Ip — .{ .v4, .v6 }
var buf: [netaddr.max_ip_text_len]u8 = undefined;
const text = netaddr.formatIp(ip, &buf);           // "2001:db8::1"
const hp = netaddr.parseHostPort("[::1]:8080").?;  // .{ .host = "::1", .port = 8080 }

// RFC 6724 classification
_ = netaddr.scopeOf(ip);        // Scope (RFC 4007-valued enum)
_ = netaddr.precedenceOf(ip);   // policy-table precedence (higher = preferred)
_ = netaddr.labelOf(ip);        // policy-table label
_ = netaddr.commonPrefixLen(a, b);

// Destination ordering (what glibc getaddrinfo does before connect)
netaddr.sortDestinations(addrs, netaddr.systemSource); // Linux route probe
netaddr.sortDestinationsWithSources(addrs, srcs);      // pure, testable core

// Source selection (RFC 6724 §5, common rules)
_ = netaddr.selectSource(host_addrs, dst);
```

## Notes / deviations

- `sortDestinations` implements RFC 6724 §6 rules 1, 2, 5, 6, 8, 9 — the same
  subset as Go. Rules 3/4/7 need OS state (deprecation, home addresses,
  transport nativeness) nobody tracks. Rule 9 (longest matching prefix) is
  IPv6-only, matching Go (see Go issues 13283/18518).
- `selectSource` implements §5 rules 1, 2, 6, 8; rules 3/4/5/7 need
  per-interface OS state and are documented corners (glibc has the same).
- `Scope` is a numeric-backed non-exhaustive enum so unnamed multicast scope
  nibbles order correctly, mirroring Go's `classifyScope`.
- Zone suffixes (`fe80::1%eth0`) are rejected by `parseIp*`; `parseHostPort`
  passes them through in `host` untouched.
