# spbfib

SPB (802.1aq) forwarding addressing: build the unicast B-MAC FIB from an
`isis-spf` route table (dest node → next-hop) re-keyed by each node's backbone
MAC, and construct the SPBM group multicast destination address from a source's
SPSourceID + an I-SID (the BUM DA whose distribution tree `bumtree` computes).
SPB installs one congruent ECT path per destination (no per-flow ECMP at the
data plane). Pure, deterministic; the unicast counterpart to `bumtree`.

**Status:** gap (placeholder — implementation pending).
