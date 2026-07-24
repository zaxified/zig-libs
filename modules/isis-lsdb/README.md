# isis-lsdb

The IS-IS link-state database: store LSPs by LSP-ID, apply the ISO/IEC 10589
§7.3.15/§7.3.16 newer-LSP comparison (sequence number → zero-lifetime-wins →
checksum), age remaining-lifetime on a time-injected tick and purge at MaxAge,
and maintain the per-interface SRM (flood) / SSN (acknowledge) flag sets a
flooding layer consumes. Pure — no threads, no owned timers, no sockets. Builds
on the `isis` codec; the flooding transmit loop + SPF are later consumers.

**Status:** gap (placeholder — implementation pending).
