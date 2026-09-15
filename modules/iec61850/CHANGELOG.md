# iec61850 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-17** — **NO CONSUMER-VISIBLE CHANGE:** tests only. The write→read→write regression
  test bound the fixed port 15684; its peer now binds port 0 and publishes the port it got. The F-B
  test ("one octet does not park the read") slept a fixed 1200 ms and then canceled. On a loaded
  machine a correct read could still be on its way back, a false red. The test now waits for the
  read to return on its own, with a 20 s watchdog.

- **2026-09-13** — **BEHAVIOURAL:** A1 finding `iec62351` N1 (cross-module, one commit with
  `iec62351`). `goose.Frame.decode` took `Length - 8` octets as the PDU, so a frame secured under
  IEC 62351-6 decoded with the security extension glued onto the PDU, and `Pdu.decode` — which did
  not require exact consumption — returned its stNum/sqNum with no sign that authentication
  existed. The PDU now ends at its own BER length; `Frame.decode` refuses trailing octets inside
  `Length` with `error.SecurityExtensionPresent`, the new `Frame.decodeSecured` returns them as
  `Frame.extension`, and `Pdu.decode` refuses octets after the element (`error.TrailingOctets`).

- **2026-09-10** — ⛔⛔ **`Server.associated` was a bare `bool` shared by every
  multiplexed peer, so a peer that had sent no `CR`, no CONNECT SPDU and no
  AARQ reached `handleMms` the instant its first frame arrived, as long as
  ANY other peer on the same `Server` had completed a handshake (A1
  iec61850, "recorded and NOT fixed"; `.concurrency = .single_owner`'s own
  documented multiplexing path — see the `peer` field's doc comment — is
  exactly what made this reachable). Replaced with `associated_peers`, a
  bounded (`max_associations = 8`) table of the peer ids that actually
  completed their own handshake; `handleConnect` now returns the new
  `error.TooManyAssociations` once it is full instead of quietly sharing a
  slot. Reproduced straight-line: one real peer associates, a second,
  never-before-seen peer id sends a well-formed MMS Identify request as its
  *first* frame — before the fix `handle` decoded and answered it (a full
  served MMS response, vendor `zig-libs`); after the fix it is
  `error.Unsupported`, unconditionally. `zig build test-iec61850`: 2 failing
  (the targeted regression plus one collateral) → 0 failing, 426/437 passing
  (P1: 0 consumers in `zig-libs`).
  Also (F-E, same audit): `handleSpdu`'s `give_tokens_or_data` arm checked a
  PDV's presentation context was *defined and accepted*, never that it was
  *the MMS one* — the ACSE context (id 1) is defined and accepted on every
  association too. `client.zig`'s matching read path already carried this
  guard (`if (pdv.context_id != self.mms_context) return error.UndefinedContext;`);
  the server path did not. Reproduced: an MMS Identify request wrapped under
  the accepted ACSE context id was served before the fix (a decoded, valid
  reply) and is `error.UndefinedContext` after.

- **2026-09-07** — ⭐ **`goose.fuzzStructuredGoose` had a corpus, and it chose
  0-or-1 for every decision it made.** The seed generator emitted one
  little-endian `u64` per draw carrying only a single bit. That was built on the
  right insight — `Smith` discards a scalar word outside the draw's declared
  range and returns the range minimum — with the wrong step size, and the
  arithmetic consequences were total: `gocb_len` (range 1…40) and `go_id_len`
  (1…26) were **constantly 1**, because 0 is out of range and 1 is the only
  other value a bit carries; `n_vals` was 0 or 1 of a possible 8; the MMS type
  switch was 0 or 1 of 0…6, so **five of the seven alternatives were
  unreachable**, including the `octetString` case with its own nested
  `smith.bytes`; and every `stNum`, `sqNum`, `confRev` and `timeAllowedToLive`
  was 0 or 1. The harness's own comment says it lets the fuzzer choose "the
  names, the replay counters, the timestamp, the flags, the VLAN tag, how many
  data-set entries and of which MMS types".
  It now draws one `smith.slice` and reads every choice off a
  `testkit.fuzz.Cursor`, so a choice octet is an octet. Measured over the same
  six patterns: **all seven MMS alternatives reached** (was two), `n_vals` up to
  **8** (was 1), `gocb_ref` up to **27** octets and `go_id` up to **23** (both
  were 1), a VLAN tag on 4 scripts and Ethernet padding on 6. The corpus keeps
  one four-octet script on purpose, shorter than the name pool, which reproduces
  the collapse exactly and is pinned beside the coverage.
  With this, `check-fuzz-reach` reports **no collapsed target in `iec61850`**:
  27 at the start of the burn-down, 0 now.

- **2026-09-07** — **`reporting`: the last two R1 harnesses, restructured rather
  than exempted.** `fuzzRcbWrite` opened with the buffered/unbuffered choice and
  `fuzzReassemble` with the data-set member count. A ranged first draw returns
  the range MINIMUM outside `--fuzz`, and once one draw comes up short `Smith`
  **discards the rest of the input**, so every later choice collapsed too.
  `fuzzReassemble` was the worse of the two: one member of one octet against a
  zero PDU budget, and every round's drop decision 0 — meaning every segment
  dropped, so the reassembler under test was **never handed a segment at all**.
  That is pinned in the guard rather than asserted: the empty script reproduces
  the old draws exactly and scores **1 segment emitted, 0 pushed**. The eight
  seeded scripts score **11 emitted, 6 pushed, 4 reports completed**.
  `fuzzRcbWrite` now reads the block kind off the seed's first octet and the
  attribute index off its length: 14 of 14 seeds non-empty, **12 decoded, 2 ok,
  5 denied, 5 invalid** — where the collapse produced an empty slice and no
  write at all.

- **2026-09-07** — **`logging`, `scl`, `server` and `settinggroups`: six more
  harnesses fed, and one of them could never have taken this module's own
  reference document.** All six had the `smith.bytes` + ranged-length collapse
  and now draw with one `smith.slice`.
  ⭐ `scl.fuzzScl`'s buffer was 1024 octets and `scl.sample` — the only complete
  SCL document this module has — is **4065**. `Smith.slice` reads a seed longer
  than the buffer back as the EMPTY one, silently, so the reference document
  could not have passed through the harness at all. The buffer is now 8192 and
  the guard asserts every seed reads back non-empty, which is what makes that
  visible instead of silent. `server.fuzzServer` has the same hazard from the
  other side: its corpus is the captured frame table, and the 6675-octet
  `GetNameList` reply is filtered out at comptime rather than left to look like
  a seed.
  ⚠ `settinggroups.fuzzSgcb` chose its attribute with a **second** scalar draw,
  which is exhausted by the time it runs and returns the range minimum, so every
  seed would have gone to `NumOfSG` — read-only, so `denied`, twelve times. The
  attribute index now comes from the seed's own length.
  Measured, all zero before: `fuzzJournal` 8 of 8 seeds non-empty, **1 request,
  4 responses, 1 entry walked, 6 status names**; `fuzzDeletion` 7 of 7, **1
  InitializeJournal, 4 DeleteJournal, 1 response**; `fuzzScl` 8 of 8, **4 parsed
  and 2 resolved**; `fuzzFragment` 6 of 7 non-empty (one empty id on purpose),
  **7 rendered documents parsed**; `fuzzServer` 29 of 29, **3 frames handled
  without a typed error, 2 answered**; `fuzzSgcb` 12 of 12, **8 decoded, 1 ok,
  1 denied, 6 invalid**.

- **2026-09-07** — ⭐ **BUGFIX: a direct operate left the finished client's
  identity on the point.** `Point.operate`'s non-enhanced success path set
  `state` and `select_deadline_ms` by hand and left `owner` and `ctl_num`
  holding the command it had just executed, so a `direct-with-normal-security`
  object came to rest `unselected` while still naming an owner — the state
  `reset()` exists to avoid. It now calls `reset()`. `fuzzPoint` **asserts
  exactly this invariant** and had never caught it: its first draw was a ranged
  one, which returns the range minimum outside `--fuzz`, so `ctl_model` was
  always `status_only` and every command was refused before it reached the
  path. The assertion fired on the first seeded run. Pinned as a value test.
- **2026-09-07** — **`control`: three more harnesses fed.** `fuzzControl` and
  `fuzzClassify` had the `smith.bytes` + ranged-length collapse and now draw
  with one `smith.slice`, over corpora lifted out of `controlgoldens.zig` — the
  captured `Oper`, `LastApplError` and `CommandTermination+` structures a real
  IED exchanged with a real client, peeled out of the frames layer by layer.
  `fuzzPoint` was the R1 shape and was **restructured rather than exempted**: it
  now reads one `smith.slice` and drives the state machine from a byte script
  (`ctlModel, sboTimeout, execTimeout`, then `advance, ctlNum, op, client` per
  round), which makes a seed reviewable and every branch reachable. Measured,
  all zero before: `fuzzControl` 15 of 15 seeds non-empty, **4 commands and 1
  LastApplError** decoded; `fuzzClassify` 7 of 7, **4 reports, 4 classified**;
  `fuzzPoint` 9 of 9 scripts, **66 accepted and 102 rejected outcomes** over 288
  rounds. The collapse is pinned in the same guard: an empty script reproduces
  the old draws exactly (every read returns the range minimum), and it scores
  **0 accepted, 32 rejected** — one input, `status_only`, `not_supported` 32
  times, which is everything the target ever executed.

- **2026-09-07** — **`mms`, `mmsdata`, `report`, `goose` and `sv`: five more
  decoders that were only ever handed the empty slice.** Same collapse:
  `smith.bytes(&buf)` followed by a ranged length draw, which returns the range
  MINIMUM when fewer than eight octets remain. Each now draws with one
  `smith.slice` and carries a corpus. `sv`, `goose` and `report` build the
  positive half at run time — from `captured_frame_hex`, `captured_frame_sq3_hex`
  and the two `captured_report` PDUs — because those exist in this module only as
  captures or as encoder output, and the harness and its guard build the corpus
  from the same place. Measured, all zero before: `mms.fuzzDecode` 24 of 24
  non-empty, **19 decoded (8 requests, 5 responses)**; `report.fuzzReport` 8 of 8,
  **2 reports and 1 RCB**; `goose.fuzzDecode` 9 of 9, **1 PDU and 2 frames**;
  `sv.fuzzDecode` 10 of 10, **1 ASDU, 1 savPdu, 1 frame**. The arm counts are
  pinned separately because each harness branches on them: a corpus of confirmed
  requests only would leave both response arms as dead as the collapse left them.

- **2026-09-07** — **`ber`, `mmsdata` and `acsi`: four more harnesses that threw
  their input away, and a round-trip assertion that was false.** `ber.fuzzDecode`,
  `ber.fuzzIterate`, `mmsdata.fuzzData` and `acsi.fuzzParse` all opened
  `smith.bytes(&buf)` and then drew the length with a ranged draw, which returns
  the range MINIMUM when fewer than eight octets remain — the length was **0 for
  every seed**. `ber.fuzzTagLength` was the other shape: its first draw was
  `smith.value(u32)`, so all but 1 in 2^32 input words collapsed the tag number
  to 0, and it never decoded octets a peer could send at all — it only ran
  encode-then-decode on its own output. It now draws the octets first and runs
  the codecs in wire order (identifier, then length), feeding the encode
  direction from those same octets so one seed drives the whole body.
  Each now carries a corpus taken from this file's own value tests. Measured:
  `ber.fuzzDecode` 19 of 19 seeds non-empty and **9 decoded**; `ber.fuzzIterate`
  9 of 9 and **10 members yielded**; `ber.fuzzTagLength` 14 of 15 non-empty (one
  empty seed on purpose) and **10 tags / 6 lengths** decoded; `mmsdata.fuzzData`
  22 of 22 and **15 decoded, 14 validated**; `acsi.fuzzParse` 22 of 22 and
  **4 ACSI / 4 MMS** references parsed. Before the fix every one of those
  numbers was 0, because every seed read back as the empty slice.
- **2026-09-07** — ⭐ **`ber.fuzzDecode` asserted something untrue about BER.**
  Seeding it exposed it: the harness required a definite-length element to
  re-encode to exactly the octets it arrived in, but `decodeLength` accepts the
  **non-minimal** long form — X.690 mandates minimal length octets in DER
  (§10.1), not in BER — so `04 81 03 'a' 'b' 'c'` decodes here and re-encodes as
  the four-octet `04 03 'a' 'b' 'c'`. The assertion had never executed, because
  the length draw above it was always 0. It is now guarded on the incoming
  encoding being minimal, and `a non-minimal long-form length decodes, and does
  not re-encode to its own octets` pins the behaviour as a value test.

- **2026-09-07** — **Six fuzz harnesses now receive their input; they did not
  before.** `tpkt.fuzzDecode`, `tpkt.fuzzFramer`, `cotp.fuzzDecode`,
  `session.fuzzDecode`, `presentation.fuzzDecode` and `acse.fuzzDecode` all
  opened `smith.bytes(&buf)` and then drew the length with a ranged draw. `bytes`
  takes `@min(buf.len, in.len)` octets, so the ranged draw found fewer than the
  eight it needs and returned the range MINIMUM — the length was **0 for every
  seed**, and the decoder was called with an empty slice while the input sat
  unread in the buffer. Measured on `tpkt.fuzzDecode`: 0 of 9 seeds non-empty
  before, 9 of 9 after. `tpkt.fuzzFramer` was worse and invisible: there the
  length never touched the buffer at all, it was the bound of the loop that
  feeds the framer, so `while (off < len)` never ran and a harness named "framer
  never panics or hangs" fed the framer **nothing**. `check-fuzz-reach`'s R2 rule
  did not see that shape until it was widened the same day.
  Each of the six now draws with one `smith.slice` and carries a corpus built
  from this module's own value tests — the captured CR/CC TPDUs, one frame per
  typed refusal each decoder names, and for `presentation`, whose accepted CPs
  exist only as encoder output, three frames built at run time by `encodeCp` /
  `encodeCpa` / `encodeUserData`.
  ⭐ The four corpus guards are the part worth keeping: they assert that every
  seed reads back non-empty (a seed longer than the harness's buffer silently
  reads back EMPTY) and pin how many the decoder accepts. The `presentation`
  guard earned itself immediately — its literal-only corpus scored **0 of 7
  accepted**, exercising the refusal path and nothing else.

- **2026-09-03** — Drift re-audit (window `d163578..HEAD`, +1140/-73 over 14 files). Four findings,
  all fixed and mutation-checked.

  - **CRITICAL, cross-association request injection.** The 2026-08-31 F6 fix added inbound COTP
    reassembly as **per-`Server`** state, and a `Server` is what the module's own live loop
    multiplexes several associations onto, setting `Server.peer` per frame. So a peer could send a
    complete, valid MMS request in a `DT` with `eot` **clear**, leaving it parked in the shared
    buffer, and the next peer to send any terminal `DT` — a legal empty one is enough — caused that
    parked request to be decoded and served with `peer` set to *its* association id. `peer` is the
    only thing arbitrating a select, a setting-group edit and an RCB reservation, so this
    substituted the ownership check outright. Reproduced: peer A's direct operate is refused
    (`AccessFailed`, `stVal=false`), A parks the same operate, B sends an empty `DT` — the breaker
    closes, `operates` goes 1→2, and the positive Operate response is returned to **B**. Identical
    in Debug and ReleaseFast. Fixed by making the buffer single-tenant (`reasm_peer`), and by
    dropping it on `CR`, `DR`, `ABORT`/`FINISH` and `releaseAssociationOf`.

  - **HIGH, one octet parks the read forever with a timeout configured.** `setReadTimeout`
    documents "Bounds how long a read blocks", but the poll guarded only the *entry* to the read:
    once one octet was available, `readSliceAll` blocked in the kernel waiting for the other three
    header octets, with no deadline. Measured 20x past a configured 100 ms bound. The module's own
    multi-peer server loop reads its links serially, so one octet from one unauthenticated
    connection — no association, no authentication — stopped every other association, emitted no
    reports and drained no notifications. `readAllBounded` (the shape proved in the sibling
    `iec104`) now bounds the whole frame; `readVec` rather than `readSliceShort`, because the
    latter is short only at end of stream and reintroduces the block.

  - **MEDIUM, a failed reassembly wedged the connection permanently.** `Reassembler.push` zeroes
    its own `len` on overflow, but the write-back to `Server.reasm_len` sat after the `try`, so the
    abandoned fragment's octets stayed and were prepended to every later request — for the server
    and, in the identical shape, for the client. Nothing reset it on `CR`, `DR`, `ABORT` or
    `FINISH` either.

  - **MEDIUM (test gap), the oversized-TPKT guard had no test.** `if (total > buf.len)` stops
    `readSliceAll(buf[header_len..total])` running to a wire-chosen `total` of up to 65535 past the
    caller's buffer — a trap in Debug, an out-of-bounds write from network data in ReleaseFast. It
    could be deleted with 398/409 green. It was the only one of eight mutations that survived.

  Doc: SPEC's "The multi-association `Server`" entry enumerated the shared state as the context
  table and PDU size and is now accurate about reassembly and `associated`; the `.single_owner`
  concurrency line contradicts the multiplexing pattern the module documents and ships, which is
  recorded rather than resolved because resolving it means deciding whether `Server` gets an
  association table.


- **2026-08-22** — `TcpTransport` now surfaces `error.Canceled` (a new
  `TransportError` variant) instead of `error.ReadFailed`/`error.WriteFailed`
  when a blocked read or write is interrupted by `std.Io`'s `Future.cancel`.
  Covers both the direct blocking read and the `read_timeout_ms` poll path,
  which is not itself a `std.Io` cancellation point and needed an explicit
  `checkCancel` after the wait to see the request at all. Separately,
  `Client.awaitNotification`'s retry loop used to catch every `poll` failure
  — including `Canceled` — and just try again, so a canceled wait came back
  indistinguishable from "no termination arrived yet" (`error.NoResponse`
  after burning through every round). It now propagates `Canceled`
  immediately and leaves every other transient failure retrying as before.
  The `Link`/`LinkError` seam (GOOSE/SV, layer-2) is untouched — this module
  takes no raw socket of its own for it, so there is nothing here that owns
  an fd to recover a cancellation from.
- **2026-08-18** — Portability fix (`check-portable`): `ber.encodeLength`'s multi-byte
  branch shifted its `usize` length by a hardcoded `shift: u6`. On a 32-bit target
  `Log2Int(usize)` is `u5`, so `v >> shift` failed to compile (`u6` doesn't coerce down
  to `u5`). Retyped `shift` as `std.math.Log2Int(usize)` — the value shifted
  (`encodeLength`'s `v: usize`) is genuinely platform-width, so the shift-amount type
  should track it rather than hardcode either width. Compile-only, identical semantics
  on every target that already builds (the actual shift amounts here top out at 24 bits
  for a 4-byte 32-bit `usize`, well inside `u5`); no behavioural test added. Verified:
  `zig build portable-iec61850` still reports unrelated wasi-surface failures (thread
  spawn in single-threaded mode, `os.linux.VDSO`, libc `poll`/`nanosleep`,
  `process.Environ.GlobalBlock.view`) — out of scope for this fix — but the `u5`/`u6`
  diagnostic this fix targeted is gone; `zig build test-iec61850` still 395/406 (11
  pre-existing skips).
- **2026-08-06** — Security audit: six findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified against a live capture from
  `libiec61850` (C, MZ Automation).
- **2026-07-23** — New module: IEC 61850 substation automation — MMS (ISO 9506) client
  over ISO-on-TCP with the ACSI object model, plus GOOSE publish/subscribe encoding and
  SV sampled values.
