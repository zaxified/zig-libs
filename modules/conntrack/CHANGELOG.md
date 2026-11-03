# conntrack — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-03** — Grade 2. Performance line in the card's format; `check-uapi` now also checks `src/ext.zig` (143 constants matched, 0 mismatches).

- **2026-11-03** — **BUG FIX:** `dumpWith`/`dump` exceeding `max_flows` or the 1 Mi record ceiling returned `TooManyMessages` in the middle of the kernel's dump, so the next request on that socket answered EBUSY. They now discard the rest without allocating, read to the DONE and then return the error; the socket stays usable. Precedence: an interruption beats it (restart, or `InconsistentDump` for `.zero_counters`, still one request); of a bad record and this limit the first in wire order wins. Only the 65536-datagram budget still stops undrained: after `TooManyMessages` close the socket unless you know it was a record limit (Socket doc). SPEC survey date corrected to 2026-11-03.

- **2026-11-03** — Review fix round. **BUG FIX:** `statsExpect` returned an empty slice on every kernel (it filtered on the request's type `0x0203`; the kernel replies `0x0103`, measured live); a stats or expectation dump now treats a record of another type as `MalformedReply` instead of skipping it into an empty answer. `.zero_counters` is never retried, refused with `InvalidRequest` when a filter is given, and its counters are lost on any error (documented). New `FlowQuery.max_flows` (returned-flow bound, default unchanged), `Expect.fn_truncated` (long function names are cut to 15 characters instead of failing the dump), `nextExpectEvents`/`ExpectEventIterator`. **CONSUMER-VISIBLE:** the new `Flow` fields (master tuple, helper, labels, seq-adjust, synproxy, SCTP, DCCP) decode leniently: a wrong-width or oversized value leaves the field `null` and the flow still decodes, exactly as those attributes were skipped before; no existing attribute got stricter. `Flow` is 488 bytes (256 before): `dump()`'s worst case at its 1 Mi cap is 488 MiB. Golden tests now run on big-endian targets (the captures are byte-swapped at comptime into the target's framing; mips32: 92 pass, 6 skip). Tests: ScriptedTransport tests for the client filter, filtered EINVAL, `max_flows`, every zero-counters path, stats/expectation records and `awaitOver`; the dump-engine fuzz harness drives every request kind; per-decoder reach labels. Fuzz `CONNTRACK_FUZZ=200000` ReleaseSafe clean. Bench: new `dec_rich` row; `dec_flow` 0.086x, `dec_dgram` 0.086x, `dec_rich` 0.083x.
- **2026-11-03** — Card to parity, `zig build bench-conntrack`: pure decode of 64 generated flows against Go ti-mo/conntrack v0.6.0 (MIT, pinned in `tools/go_bench`): `dec_flow` 0.097x, `dec_dgram` 0.097x by wall time (counts agree). SPEC: scope parity, verdict per survey gap, ReleaseSmall probe on mips32 soft-float big-endian and arm cortex-a7 is byte-identical before and after (30256 and 11464 bytes: axp pays nothing for the new API). No code change.

- **2026-11-03** — Grade-2 survey, API additions only (nothing removed; `Flow` grew from 256 to 488 bytes, so `dump()`'s worst case at its 1 Mi-flow cap is now 488 MiB). `Flow` decodes `tuple_master`, `helper`, `labels`, `seq_adj_orig`/`_reply`, `synproxy`, `sctp`, `dccp`. New `src/ext.zig`, re-exported: `Socket.dumpWith`/`dumpEachWith(FlowQuery)` with `DumpKind` (`.table`, `.zero_counters`, `.dying`, `.unconfirmed`) and `DumpFilter` (mark/mask, status/mask, zone; sent to the kernel and re-applied to every decoded flow, so a kernel that ignores the attribute still answers correctly); `statsCpu`, `statsGlobal`, `statsExpect`; `dumpExpect` + `Expect`; `setRecvBuffer`/`recvBufferSize`. The dump engines are now one generic engine over the record type (behaviour of `dump`/`dumpEach` unchanged). Tests: a live netns test of the new calls, wire tests on every new attribute, sweep tests on every new pub input, fuzz corpus seeds that reach the new decoders. Tests that embed little-endian golden frames now skip on big-endian targets instead of failing (`qemu-mips`: 49 pass, 42 skip, 0 fail).

- **2026-10-31** — **API change:** `RecvError` gains netlink's `ForeignDatagramLimit` (passed through from `recvDatagramStrict`).
- **2026-10-31** — **BEHAVIOURAL, not breaking:** no-panic sweep + blind review (§ GX). `dump()` stops with `TooManyMessages` after `max_dump_flows` (1 Mi) produced flows (was: only the datagram budget, ~12× decode amplification); `NLM_F_DUMP_INTR` drains the interrupted dump to its DONE before the re-send (the kernel answered the immediate re-send with EBUSY), `dumpEach` returns `InconsistentDump` only after the drain; a dump that fails on one bad record drains to DONE before returning `MalformedReply`, so the next request on the same socket works (after `TooManyMessages` close the socket); `EventIterator.next` returns a framing error once and then ends (was: the same error forever, a `catch continue` loop spun).

- **2026-10-09** — tests: deterministic fuzz driver `CONNTRACK_FUZZ` over the existing harnesses (`decodeFlow` on arbitrary and on damaged corpus entries, the dump engine).

- **2026-10-04** — **Tests:** mutation run (34 schemata mutants, all killed after 5 new tests:
  `nfgenmsg` byte order, PROTOINFO/TCP-flags/family decoding guards, ICMPv6 attribute numbers and
  the PROTOINFO gate in the builders, and `awaitFlowOver`/`dumpOver` message filtering through the
  scripted transport). No code change.

- **2026-09-10** — **A1 audit, two findings.** (A1) `dumpOver`/`dumpEachOver` carried the old
  unbounded multi-part reply loop forward when they were factored out of `Socket.dump` — unlike
  the sibling `awaitFlow` (C-06, F6), which got a message budget in the same pass. `DumpError`
  already declared `error.TooManyMessages` (inherited from `netlink.DumpError`), advertising a
  bound neither engine could ever produce; a kernel that never sends `NLMSG_DONE` spun both loops
  forever. New `max_dump_messages` (65536, same ceiling as `max_await_messages`, reset per dump
  attempt) makes it real. (A5) `decodeFlow` cross-checked a tuple's own src/dst family (F5) but
  never `orig` against `reply`, nor either against the message's own `nfgen_family` — both now
  rejected with the existing `error.AddressFamilyMismatch`. Not breaking: both errors already
  existed in their respective error sets.
- **2026-09-07** — Both fuzz targets ran one fixed input. `wire.fuzzDecode` opened with
  `smith.bytes(&raw)` and a ranged length, which returns the range minimum when fewer than eight
  input octets remain, so the length was 0 on every seed and all four of its readings — flow
  payload, `nfgenmsg`, tuple nest, and message stream — were handed an empty slice. Its buffer
  was 512 octets, so `dump_reply_three_flows` could not have passed through it either: a seed
  longer than the buffer reads back as the EMPTY one. `root.fuzzDumpEngine` was worse. It opened
  with `smith.value(u8)`, so outside `--fuzz` every draw was its minimum, in order: errno 0, a
  ONE-datagram script, and selector 0 — a single reply with no `NLMSG_DONE` behind it, which runs
  the scripted transport off the end and errors out before the retry budget, the errdefer or the
  ownership of the collected flows is touched. Its own doc comment says the W2-07 double free
  "needed four consecutive `NLM_F_DUMP_INTR`"; the engine never saw two datagrams, let alone
  four. Both now draw bytes first (`smith.slice`, with `testkit.fuzz.Cursor` reading the dump
  scenario out of the seed) and carry corpora: eleven readable dump scripts including the
  four-INTR sequence and an error arriving after flows were collected, and twelve ctnetlink
  buffers built from the module's captured goldens. Guards pin flows collected, INTR retries
  entered, tuple nests walked and addresses read — an `nfgenmsg` with no attributes decodes into
  an all-default `Flow`, so acceptance says nothing about whether the attribute walk ran.

- **2026-08-18** — **BEHAVIOURAL, not breaking**: `dump`/`dumpEach`/`flush` now return a new
  `error.SubsystemUnavailable` instead of `error.InvalidRequest` when the kernel's `EINVAL`
  means "`nf_conntrack_netlink` is not registered" (e.g. stock OpenWRT 25.12.4) rather than
  "malformed request" — the two were indistinguishable before, and reporting the wrong one for
  a mutating op like `flush` is an operational hazard. `get`/`delete`/`insert`/`update` are
  unchanged (deliberately: they carry a caller-supplied `Tuple`/`NewSpec`, so `EINVAL` there
  stays genuinely ambiguous with a malformed request). Additive to `DumpError`/`RequestError`/
  `WriteError`, so no existing `catch`/`switch` with an `else` arm needs a change; a caller with
  an *exhaustive* switch over the old error set on `dump`/`flush` specifically needs a new arm.
  See SPEC.md "EINVAL vs subsystem absent".
- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against a
  live capture from `libnetfilter_conntrack` / conntrack-tools — used in-repo as a
  black-box capture oracle.
- **2026-07-22** — New module: Linux ctnetlink (`NETLINK_NETFILTER` /
  `NFNL_SUBSYS_CTNETLINK`) client — typed conntrack flow dump/get/delete plus event
  subscription, over `netlink`'s write engine.
