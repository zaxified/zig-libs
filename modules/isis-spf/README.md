# isis-spf

Compute the IS-IS shortest-path forwarding table from an `isis-lsdb`: walk each
LSP's IS-reachability TLVs into a topology graph (system-id ↔ node), require
two-way reachability per edge, run the `spf-ect` Dijkstra + ECT tie-breaking
from the local system, and emit a route table (destination system-id → next-hop
system-id + total metric). Pure and deterministic — the bridge that turns the
synchronised link-state database into forwarding decisions. P2P first.

**Status:** gap (placeholder — implementation pending).
