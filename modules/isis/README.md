# isis

IS-IS (ISO/IEC 10589) PDU codec: the common header, the TLV framework, the IIH
(Hello) and LSP PDUs, and the SPB (802.1aq) TLVs, with a raw/unknown-TLV escape
hatch. Pure, bounds-checked encode/decode of untrusted link bytes — the wire
foundation the SPB control plane (adjacency FSM, LSP DB, flooding) builds on.
No state machine here; codec only.

**Status:** gap (placeholder — implementation pending).
