# pbb

IEEE 802.1ah Provider Backbone Bridge (MAC-in-MAC) encapsulation codec: wrap a
customer Ethernet frame in a backbone header (B-DA, B-SA, optional B-Tag/B-VID)
+ the I-TAG carrying the 24-bit I-SID, and decode it back. The real-Ethernet SPB
(802.1aq) data-plane encapsulation — distinct from the sibling `l2encap` (the
lean L2-over-WireGuard variant that drops the backbone MACs). Pure, bounds-
checked decode of untrusted link bytes.

**Status:** gap (placeholder — implementation pending).
