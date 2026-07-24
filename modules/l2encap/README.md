# l2encap

Tenant-tagged L2-over-tunnel encapsulation for a multi-tenant L2VPN fabric: wrap
a customer Ethernet frame with a lean versioned header carrying a 24-bit I-SID
(tenant service identifier), a TTL, and BUM / split-horizon control bits, for
transport over an encrypted backbone (WireGuard). Bounds-checked decode of
untrusted tunnel payloads. Composes with `ethfrag` and feeds `wireguard`.

**Status:** gap (placeholder — implementation pending).
