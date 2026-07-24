# l2forward

The E-LAN edge forwarding table for a multi-tenant L2VPN fabric: per-I-SID
customer-MAC learning (MAC → remote PE) with time-injected aging, plus the BUM
ingress-replication set with split-horizon (never replicate back to the source
PE). Given a destination MAC + I-SID + source PE it returns a forward decision:
one remote PE for a known unicast, or the replication set for BUM/unknown. Pure,
deterministic, bounded; pairs with `l2encap`. The caller populates I-SID
membership from the control plane and drives `now`/I/O.

**Status:** gap (placeholder — implementation pending).
