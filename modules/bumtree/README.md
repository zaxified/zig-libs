# bumtree

SPB per-source loop-free BUM (broadcast/unknown-unicast/multicast) distribution
tree + Reverse-Path-Forwarding check, over the `spf-ect` shortest-path engine.
For one I-SID's member set and one source node it computes, per node, the
replication next-hops (children in the source's SPT, pruned to member-leading
branches) and the single RPF ingress (the neighbour toward the source — the only
edge a BUM frame from that source may legally arrive on). The control-plane
loop-free BUM tree that `l2encap`/`l2forward` defer to: split-horizon stops
reflection, RPF + the tree stop transient loops. Pure, deterministic.

**Status:** gap (placeholder — implementation pending).
