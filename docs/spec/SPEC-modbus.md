# SPEC — `modbus`

**Purpose** — A Modbus master for the SCADA / industrial-simulation line-up: a typed, allocation-
free wire codec plus a transport-agnostic client that can drive real devices or simulated fleets.
Covers the nine core public function codes (read/write coils, discrete inputs, holding + input
registers, and the combined read/write) over both **Modbus TCP** (MBAP) and **Modbus RTU** (CRC-16)
framing. Pairs with `mqtt`/`coap` for the industrial/IoT set.

**Model after / Seed** — clean-room from the openly published, royalty-free Modbus specs: Application
Protocol Specification V1.1b3 and Modbus over Serial Line V1.02 (modbus.org). libmodbus (LGPL-2.1+)
is a **behavior reference only** — no source consulted or copied (NOTICE). Greenfield, no seed.

**Design & invariants**
- **Three allocation-free layers, all offline-testable:** `pdu` — transport-independent request
  encode / response parse; big-endian 16-bit registers, coil bits packed LSB-first. Spec quantity
  limits (2000/125 read bits/registers, 1968/123 write, 125/121 for FC 17) are typed errors, not
  truncations. `tcp` framing — MBAP header (transaction id, protocol id 0, length, unit id); `rtu`
  framing — address + PDU + CRC-16 (poly 0xA001 reflected, low byte first on the wire). `Client` —
  a master that talks through a caller-provided `Transport` seam (one blocking send-ADU / receive-
  ADU round-trip), tracking the TCP transaction id; `TcpTransport` is an optional `std.Io.net`
  adapter, the only network-touching code.
- **Concurrency:** single-owner — the `Client` owns the transaction-id counter; not shared across
  threads without external sync.
- **Error policy:** malformed, short, or corrupt replies never panic — every decode path returns a
  typed error (short frame, bad CRC, transaction-id / unit / function mismatch, malformed byte
  counts, address+quantity overflow). Exception responses (`function | 0x80`, codes 1–11) map to a
  typed error set; the code table is non-exhaustive (servers may emit codes outside it).

**Threat model / out of scope** — Modbus is an **unauthenticated, unencrypted** field protocol by
design; there is no on-wire security to defend, and transport security (e.g. a TLS tunnel / Modbus
Security) is entirely the caller's. The codec's job is robustness: hostile/garbage frames from a
misbehaving device or man-in-the-middle resolve to typed errors, never panics or out-of-bounds
reads. **Out of scope:** ASCII framing; broadcast (unit 0, no reply); and the server (slave) side —
though the `pdu` codec is deliberately reusable for a future server.

**Verification** — 32 offline tests. Known-answer tests byte-compare every function code against the
worked wire examples in the application spec §6.1–6.17; CRC-16 is pinned to the canonical
`"123456789" → 0x4B37` check value plus classic example frames; bit packing is checked LSB-first. A
scripted mock transport exercises TCP + RTU round-trips (incl. echoed-reply writes and FC 17), the
exception path, quantity limits, CRC corruption, MBAP/RTU field mismatches, buffer-too-small, and a
garbage-frame no-panic sweep.

**Status** — `gap · any (codec+client pure; TcpTransport uses std.Io.net) · client(master)+codec ·
single-owner` · deps: none (std only).
