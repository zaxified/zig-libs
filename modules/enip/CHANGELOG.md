# enip — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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

- **2026-09-10** — **NO CONSUMER-VISIBLE CHANGE.** `connmgr`'s fuzz corpus: the
  three entries meant to exercise the accept path of `UnconnectedSend`,
  `ForwardOpen` and `ForwardClose` were typed by hand and, per the harness's own
  note, only ever hit the reject path. Worse, re-measured today: two of them
  (the `Unconnected_Send` bodies) no longer decode AT ALL — `UnconnectedSend.decode`
  grew `TrailingData`/`BadReserved` checks after these seeds were written (the F3
  regression fix), and the note claiming "2 accepted" was never re-run against
  that change. All three are now built through the module's own encoders instead
  of by hand (`UnconnectedSend.encode`/`ForwardOpen.encode`/`ForwardClose.encode`),
  plus a companion test that pins the round trip. Measured: 11/11 non-empty
  seeds, both `UnconnectedSend` seeds now accepted (were 0), the encoder-built
  `ForwardOpen` accepted at its own width (was 0), the encoder-built
  `ForwardClose` accepted (was 0) — verified with a mutant on `ForwardOpen.encode`
  (flipped one output byte): 5/170 tests failed, including both new tests, at the
  exact byte the mutant touched; reverted, back to 167/170 (3 skip). `large`
  `ForwardOpen` and both reply decoders (`ForwardOpenReply`/`ForwardCloseReply`)
  still have no seed shaped for them — a corpus gap the updated harness comment
  now records rather than hides.

- **2026-09-07** — **NO CONSUMER-VISIBLE CHANGE:** the local `fuzzSeed` copies in
  this module's fuzz files are now `testkit.fuzz.seed` / `seedHex`. The helper
  existed **33 times across 12 modules in three shapes**, each carrying its own
  note about the same trap (the returned array has to be container-level or the
  slice dangles with the right length and garbage behind it), and the count was
  growing by roughly eight per module burned down. Proved byte-identical to the
  copies it replaces before the copies were deleted — a temporary test compared
  the old formula against the new one over this module's own seed literals, and
  was itself checked non-vacuous by breaking it. Test-only; nothing a consumer
  imports changed.

- **2026-09-06** — **NO CONSUMER-VISIBLE CHANGE:** all 14 fuzz harnesses in
  this module were replaying a single fixed input. Thirteen drew their frame as
  `smith.bytes(&buf)` followed by a ranged `smith.valueRangeAtMost(...)`, and a
  `Smith` ranged draw returns the range MINIMUM unless the eight octets it reads
  as a little-endian u64 already lie inside the range — `bytes` had just eaten
  the seed, so the length was its minimum every time. They now draw with
  `smith.slice(&buf)`, the knobs that used to precede the frame (`fuzzAdapter`'s
  session-open flag, `fuzzTypes`' type code, `fuzzAttrList`' value width) follow
  it and are drawn with `value(u64)`, and each harness carries a corpus of real
  wire frames or tag paths. Measured over those corpora, non-empty inputs /
  inputs a decoder accepts: encapsulation 0 -> 13/11, the framer 0 -> 5 fed and
  6 messages out, identity and service items 0 -> 7/6, CPF lists 0 -> 10/4, CPF
  envelopes 0 -> 5/3, CIP messages 0 -> 12/10, Multiple Service 0 -> 8/5,
  attribute lists 1 -> 8 distinct (list, width) pairs, EPATHs 0 -> 13/10, tag
  paths 0 -> 16/9, tag payloads 1 -> 14 distinct (payload, type code) pairs and
  0 -> 14 accepted, Connection Manager 0 -> 9/2.
- **2026-09-06** — **NO CONSUMER-VISIBLE CHANGE:** two of those harnesses were
  worse than the count suggests, and both are now measured in their own
  comments. `fuzzAdapter`'s `smith.boolWeighted(1, 1)` — "half the runs start
  with a session already open, so the paths past the session check are
  reachable" — was `false` on every run, so no run ever had a session open;
  it is now 6 of 12, with 9 replies where there were none. `fuzzClientReply`'s
  ranged length had a minimum of 24 rather than 0, so the client was fed a bare
  encapsulation header with an empty body on every seed; the six seeds now
  arrive at 28..82 octets and the CPF body reaches the reply decoder.

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
