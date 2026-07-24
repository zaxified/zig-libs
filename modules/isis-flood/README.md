# isis-flood

The IS-IS flooding transmit scheduler: drain the `isis-lsdb` per-interface SRM
(send LSP) and SSN (send PSNP ack) flag sets into the ordered list of PDUs to
send, pacing LSP (re)transmissions and emitting periodic CSNPs for database
sync. Pure and time-injected — no threads, no owned timers, no sockets: the
caller supplies `now` + the interfaces with an Up adjacency and does the sends;
this module decides WHAT to send WHEN and updates the LSDB flags. P2P first.

**Status:** gap (placeholder — implementation pending).
