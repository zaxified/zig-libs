# netaddr

IP address parse/format + **RFC 6724** source/destination address selection.

- **Status:** `extract` — seeded in `~/workspace/zig-fping/src/netutil.zig`.
- **Model after:** glibc `getaddrinfo` reachability trick / Go `net/addrselect.go`.
- **Why:** RFC 6724 selection is a real gap in Zig std; foundational for `dns`/`icmp`/`http`.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant (no shared state).

Current file is a stub (`parseIp4`) to establish the module shape.
