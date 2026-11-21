# enip — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-21** — ADDED `pccc` and PCCC over CIP: `Execute PCCC` (class 0x67) on the adapter serving `Config.pccc_files` / `Config.pccc_processor` (typed logical read and masked write with three address fields, diagnostic status), the `pccc` codec and data-table model (`File`, `FileType`, `TypedAddress`, `Requester`, `Message`, `serve`), and `Client.executePccc`; checked live against pycomm3's `SLCDriver`. **Behaviour change:** a request to class 0x67 used to be answered `service_not_supported`; with `pccc_files` empty (the default) it is now `path_destination_unknown` (no such object), otherwise it is served.
- **2026-11-21** — ADDED implicit I/O on the adapter: a `Forward_Open` of transport class 0 or 1 opens an I/O connection over `Config.assemblies` (`Adapter.ioReceive`, `ioPoll`, `ioNextDueUs`, `adapter.IoDatagram`, `adapter.IoReceived`, `Config.io_multicast`, the `io_consumed` / `io_produced` / `io_timeouts` counters), with multicast groups returned in a Sockaddr Info item; `implicit.Config.consume_len` and `Dropped.wrong_size`. **Behaviour change:** a Class 0/1 `Forward_Open` used to be accepted as an explicit connection and is now an I/O connection (refused with an extended status when its path or sizes do not match a served assembly), and an I/O connection is not reachable through `SendUnitData`.
- **2026-11-21** — ADDED `implicit`, the engine of Class 0/1 I/O messaging over an injected microsecond clock: `Connection` (cyclic, change-of-state and application triggers, production inhibit, 32-bit sequence number and 16-bit data count, Run/Idle header, gap and stale detection, the watchdog `RPI x 4 x 2^multiplier`), `encode` (the UDP datagram), `MulticastPool`. New module file, no change to existing names.
- **2026-11-21** — ADDED the Template Object (class 0x6C) and user-defined types on the adapter: `Config.udts` (`adapter.Udt`, `adapter.UdtMember`), `TagBinding.udt`, served as `Get_Attribute_List` (attributes 1, 2, 4, 5) and Read Template, with structure tags listed by the Symbol Object (type word `0x8000 | id`) and a Read Tag that answers `0x02A0` + the handle. Source-compatible (new defaulted fields). **Behaviour change:** a `TagBinding` whose `udt` is set is now enumerated (it was never possible to give one before). Checked live with `pycomm3` 1.2.16 (`tools/udt_serve.zig`, `tools/udt_oracle.py`).
- **2026-11-18** — Adapter serves the **Assembly object** (class `0x04`) from the new `Config.assemblies` (a list of `stdobj.Assembly`: instance id, byte buffer, `writable`, optional `before_get`/`after_set` hooks; empty by default, which withholds the class as before): `Get_Attribute_Single` of the data (3) and size (4) attributes and of the class attributes 1, 2, 3, 6, 7, `Set_Attribute_Single` of the data on a writable instance with the exact size. Refusals as OpENer: unknown instance `0x05`, unknown attribute `0x14`, non-writable or size attribute `0x0E`, short `0x13`, long `0x15`, hook refusal `0x09`; `Get_Attributes_All` is `service_not_supported`. Anchored against a stock pycomm3 `CIPDriver` (`goldens.assembly_table`, replayed byte-exact; the live test takes `ENIP_TEST_ASM=1`). Behaviour change: only for a caller that sets `Config.assemblies`; `Set_Attribute_Single` on class `0x04` is `service_not_supported` as before when the list is empty. Backlog item closed.
- **2026-11-18** — Adapter serves the **Ethernet Link object** (class `0xF6`, instance 1): `Get_Attributes_All` and `Get_Attribute_Single` for the required attributes 1 to 3 (interface speed, interface flags, physical address) from the new `Config.ethernet_link` (`null` withholds it); the optional counters and everything else answer `attribute_not_supported`. Behaviour change: class `0xF6` used to answer `path_destination_unknown` for everything and now answers as above by default. Delta mutation: 15 mutants, 14 killed, 1 equivalent.
- **2026-11-18** — Adapter serves the **TCP/IP Interface object** (class `0xF5`, instance 1): `Get_Attributes_All` and `Get_Attribute_Single` for attributes 1 to 6 (status, configuration capability and control, physical link path, interface configuration, host name) from the new `Config.tcpip` (`stdobj` module; `null` withholds it), and `Set_Attribute_Single` for attributes 3, 5 and 6 behind `Config.allow_tcpip_set` (otherwise `attribute_not_settable`). Behaviour change: class `0xF5` used to answer `path_destination_unknown` for everything and now answers as above by default; `Set_Attribute_Single` on it used to be `service_not_supported`. Delta mutation: 111 mutants, 105 killed, 6 equivalent.
- **2026-11-17** — Fix: `Client.sendConnectedCip` no longer consumes a sequence count for a request that cannot be framed (a request of 245-446 octets passed the margin guard, advanced `conn.sequence`, then failed `BufferTooSmall`); the count is committed after both encodes succeed (CIP Vol 2: sequence count per transmitted data packet). Behaviour change: the connection's `sequence` is unchanged after a `BufferTooSmall` from this call.
- **2026-11-17** — Whole-module mutation audit (1391 mutants, 1349 killed, 42 argued equivalent/unobservable; card `mutation 2026-11-17 (1349/1391, 42 eq)`); about 90 boundary tests added next to the code (data-length ceilings, path limits, exact buffers, every CIP type's width and byte order, session and connection matching, reply budgets, TCP framing). NO CONSUMER-VISIBLE CHANGE besides the fix above.

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** `zig fmt` (0.17) rewrote `@intFromEnum`/`@enumFromInt` to `@backingInt`/`@fromBackingInt` in sources and tests; same values, same behaviour.
- **2026-10-18** — Ported to Zig 0.17.0. comptime `strRepeat` helper: larger `@setEvalBranchQuota` (0.17 counts more branches per iteration).
- **2026-10-10** — tests: deterministic fuzz driver `ENIP_FUZZ` over the existing harnesses (now generic over their choice source; the driver draws a corpus entry with 0-3 octets damaged, maybe truncated) with an in-suite reach test per harness. Fourteen harnesses (encap decode/framer/items, epath, tagpath, types, cpf decode/envelope, cip messages/multiple/attrList, connmgr, adapter, clientReply). Verdict: 200,000 runs each, ReleaseSafe, clean.
- **2026-10-06** — **BEHAVIOURAL, not breaking:** `TcpTransport.setReadTimeout`
  now bounds the **whole** encapsulation message a `read` returns, not just the
  wait for its first octet — the open MED finding of today's review (SPEC.md,
  `**Review 2026-10-06**`, item 6). A peer that sent one octet, part of a
  header, or a header and part of its body and then went quiet used to hold
  the reading thread (the adapter's included) without limit; that read now
  fails with `error.ReadFailed` once the timeout passes. The deadline is taken
  from the monotonic clock when the read starts, and a message that arrives in
  pieces inside it is still read whole. Unchanged: no octet before the
  deadline is still `0` ("nothing this round"), no timeout still blocks, and
  `TransportError` has no new variant.

- **2026-10-06** — **BEHAVIOURAL, not breaking:** Review: security re-review of
  what landed after the 2026-08-11 review — six findings, five fixed, one
  reported open (details in SPEC.md, `**Review 2026-10-06**`). Behaviour that
  changes: `Adapter`'s `Multiple_Service_Packet` validates its whole offset
  table before running any embedded request (a bad later offset used to be
  refused only after an earlier write had been applied), and budgets its reply
  up front, answering an embedded request that does not fit as
  `reply_data_too_large` instead of failing `handle` with
  `error.BufferTooSmall` — no reply — after earlier writes in the batch had
  landed; an `Unconnected_Send`'s inner reply is built into the caller's space;
  `Write Tag`, `Forward_Open`, `Forward_Close` and `Reset` check their reply
  fits before changing state. `connmgr.UnconnectedSend.decode` refuses a
  non-zero pad octet after an odd embedded message with the new
  `DecodeError.BadPad` (a consumer switching exhaustively over that set needs
  one more arm). The adapter's element offset (`member id × size + byte
  offset`, all peer-supplied) is computed checked, so it no longer traps on a
  32-bit `usize`, and `TcpTransport.setReadTimeout` clamps a value past
  `poll(2)`'s `i32` instead of trapping. Open, not fixed: `TcpTransport`'s read
  timeout covers only a message's first octet. Each fix has a test that failed
  before it (the 32-bit one under `-Dtarget=x86-linux-musl`).




- **2026-08-22** — `TransportError` and `client.Error` gained a `Canceled` variant, and
  `TcpTransport` now recovers it at the socket boundary. A `std.Io` cancellation
  (`Future.cancel`) was being erased twice on its way to a caller: `Io.Reader.Error` has
  no `Canceled` variant — the concrete `std.Io.net.Stream.Reader` keeps the real cause in
  its out-of-band `err` field — and `readFn`/`writeFn` then folded every failure into
  `ReadFailed`/`WriteFailed`, so an orderly shutdown was indistinguishable from a dead
  peer. `readFn`/`writeFn` consult that `err` field before mapping, and `client` widens
  transport errors through one exhaustive `fromTransport` switch instead of four
  hand-written ones, so a future variant cannot silently arrive as something else.
  Separately, `waitReadable` (the `poll(2)` behind `setReadTimeout`) is **not** a `std.Io`
  cancellation point: `std.posix.poll` restarts itself on `EINTR`, so the cancel's signal
  was swallowed and a canceled read came back as `0` — "nothing available this round" —
  leaving a caller polling a connection it had already abandoned. It now asks
  `Io.checkCancel` once the wait ends. `UdpDiscovery` needed no change: it is not a
  `Transport`, and `Socket.receive`/`receiveTimeout` already carry `Io.Cancelable`.
  Two tests cover it (blocking read, and the `poll` path); both were confirmed to fail
  with the recovery removed.
- **2026-08-18** — Portability fix (`check-portable`): the "huge index" overflow test
  built `wrapping_index` from a hardcoded `1 << 63`, which doesn't fit `usize` on a
  32-bit target. The literal's job was "half of `usize`'s range, rounded up, so `* 2`
  wraps" — a target-relative property, not a 64-bit-specific one — so replaced it with
  `(std.math.maxInt(usize) / 2) + 1`, which equals the original `1 << 63` exactly on
  64-bit and generalizes correctly to any width. Compile-only, identical behaviour on
  every target that already built. Verified: `zig build portable-enip` and
  `zig build test-enip --summary all` (164/167, 3 pre-existing skips) both green.
- **2026-08-14** — Provenance corrected: README stated that no third-party source
  had been consulted as a design reference, while `src/connmgr.zig:250` cites
  `epan/dissectors/packet-cip.c` and the internal `hf_cip_cm_fwo_*` field
  identifiers — names visible only in Wireshark's source, not in anything
  `rawshark` prints. The module was genuinely oracle-only when it was written;
  `5f9685e` later derived the `ConnectionParameters` reserved-bit masks from
  Wireshark's field map (the ODVA spec being paywalled) and said so in its own
  message, but the Provenance paragraph was never updated. Now recorded, with
  the upstream licence (GPL-2.0). Documentation only; no code change, and
  nothing owed — a design reference carries no condition even from GPL source.

- **2026-08-11** — Security audit: seven findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on `OpENer` /
  `EIPScanner` (design reference, not a test anchor).
- **2026-07-23** — New module: EtherNet/IP + CIP — encapsulation layer
  (register/unregister session, SendRRData/SendUnitData), CIP messaging (Get/Set
  Attribute, Multiple Service Packet), connection manager, and a tag/symbolic path.
