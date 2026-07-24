# isis-sim

A headless multi-node IS-IS/SPB fabric convergence simulator: a `netsim`
Protocol that runs the isis control-plane stack (`isis-lsdb` + `isis-flood`,
with `isis-spf` for routes) on every node over the simulated medium, and asserts
the fabric CONVERGES (every node's LSDB synchronises to the same LSPs) and
RECONVERGES after a netsim-injected link failure. The end-to-end proof that the
five-layer P2P isis stack works together. Adjacencies are the netsim links
(up unless failed); the adjacency FSM handshake is out of scope here.

**Status:** gap (placeholder — implementation pending).
