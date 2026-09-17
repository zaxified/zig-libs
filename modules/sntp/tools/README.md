# `sntp` verification instruments

Seven instruments, run by hand. None is wired into `zig build`: three need a
**listening socket** (a local hostile stub on loopback), and the mutation runner
costs a full build plus 38 tests per row. `zig build test-sntp` must require
none of it (`CONVENTIONS.md` §9).

⚠ Nothing here touches a public NTP server. That is a property worth keeping,
not an accident: the audit proved it with `strace`, and a verification tool that
quietly reaches the internet cannot be run in CI, offline, or on a plane.

Figures below were measured on 2026-09-17 against the tree as it stands.

## The hostile peer: how `query` is tested without a network

| tool | question it answers |
|---|---|
| `stub.py` | An SNTP server written from RFC 4330 §4 alone, with 17 hostile scenarios. Also `decode-golden`: an independent decoder for the module's frozen golden reply. |
| `client.zig` | Drives the module's real `query` — socket, receive loop, deadline — against that stub, reporting elapsed time. |
| `run_scenarios.sh` | Wires the two together, one scenario per run. |

```bash
zig build-exe -O ReleaseSafe --dep sntp -Mmain=client.zig -Msntp=../src/root.zig \
    --cache-dir <scratch>/zc-client -femit-bin=<scratch>/client
CLIENT=<scratch>/client modules/sntp/tools/run_scenarios.sh
```

**Measured: 17 scenarios, and four that the audit recorded as ACCEPTED are now
REJECTED.** That is the fixes being visible rather than asserted:

| scenario | at audit time | today | closed by |
|---|---|---|---|
| `li3` (Leap Indicator 3) | ACCEPTED, stratum=1 | `UnsynchronizedLeap` | F7 |
| `zero_t2` (all-zero T2) | ACCEPTED, offset ≈ −63 years | `ReceiveTimestampUnset` | F3 |
| `mac68` (48 B + NTP MAC) | ACCEPTED, MAC silently dropped | `InvalidLength` | F2 |
| `long1024` (48 B + 976 B) | ACCEPTED | `InvalidLength` | F2 |

The timing properties hold too, and they need a socket to observe at all:
`wrongport` ends in `Timeout` after **3001 ms** (the deadline bounds the whole
run, not one receive step), `silent` after **1500 ms**, and
`flood_then_correct` succeeds in **14 ms** despite 2000 decoy datagrams from
foreign ports arriving first.

⚠ **One hostile case still succeeds, and the probe keeps it visible:**
`far_future` is ACCEPTED with an offset of **3476.7 days**. Nothing bounds the
offset handed back to a caller. SPEC acknowledges the gap; no test pins it,
because there is no guard to pin.

### The golden reply has an independent decoder

`stub.py decode-golden` recomputes offset and delay from the same 48 captured
bytes using a decoder written from the RFC, not from the module. Measured today:
`offset_ns 8011074`, `delay_ns 40052890` — exactly what the golden test asserts.

⚠ Its independence is **medium, not high**, and that belongs in writing: it is a
second implementation from the same spec by the same author, not a third-party
stack (`ntplib`, `chronyc`, `ntpdate`, `sntp` are not installed here). What is
genuinely foreign is the **input** — 48 bytes a Google server actually sent.

## Would the suite notice if a guard were removed?

    modules/sntp/tools/mutate.py              # the whole table
    modules/sntp/tools/mutate.py --only M9    # rows whose id contains "M9"
    modules/sntp/tools/mutate.py --controls   # only the controls

15 mutations and 2 controls, each copying the live `modules/sntp/src/root.zig`
into a per-process scratch tree.

Measured: **17 rows, 16 RED, 1 GREEN, 0 BROKEN, 0 anchor problems**, every
verdict pinned and re-run for self-consistency (17/17). The single GREEN is the
negative control, which must be green.
**There are no survivors** — every guard in this module is held by a test.

### The two controls point opposite ways

`NC-no-edit` mutates nothing and must come back **GREEN**; if the unmutated
suite does not pass, nothing below it measures the module. `PC-control` swaps
`seconds`/`fraction` in `Timestamp.fromBytes` and must come back **RED**; if a
corrupted codec survives, the runner is measuring nothing. The audit's runner
had only the second kind, and **no exit code at all** — it printed every row and
returned 0 whatever the table said.

### Two anchors rotted *because the finding was fixed*

This is the interesting part, and it is not the usual "the file grew" rot:

- `M1` named `try verifyOriginate(reply, t1);` **inside `query`**.
- `M9` named `if (!incoming.from.eql(&dest)) continue;`, also inside `query`.

Audit finding F1 was precisely that those two guards sat where no test could
reach them. The fix **moved** them into `processReply`/`validateReply`, which a
unit test now drives directly — so the old anchors match zero times. `M1` also
changed its argument: the echo is checked against `origin_nonce`, the CSPRNG
wire nonce F4 introduced, not against the clock reading `t1`.

Three rows are new and the audit could not have had them: `M13` (F2's
truncation check), `M14` (F3's receive-zero check) and `M15` (F7's leap check)
had no guard to remove back then. All three come back RED.

### `BROKEN` is not `RED`, and all three re-derivations hit it

Neutralising a guard can leave a **parameter** unused, which in Zig is a compile
error — and a mutant that does not build ran nothing, so scoring it RED would
claim the suite noticed something it never saw. `M1`, `M9` and `M13` all failed
this way first (`origin_nonce`, `from`/`server`, `truncated`). The cure is to
spend the value: `_ = origin_nonce;` — the parameter-shaped form of the fix this
campaign proved on `s7comm`'s `D2`.

### And the command line rots separately from the anchors

The audit's runner drove a bare `zig test <file>`. Measured today it fails at
`root.zig:1209` with `no module named 'testkit'`; with `--dep testkit` the same
suite is **37 passed, 1 skipped, rc=0**. A dry run cannot see this — 11 of the
audit's 13 anchors still matched their site exactly once.

## Hostile input, cost, and the nonce

| tool | question it answers |
|---|---|
| `sweep.zig` | Exhaustive over both header bytes, then every length 0..80: does anything panic, and exactly which packets are accepted? |
| `probe_codec.zig` | Origin correlation, offset bounds, arithmetic extremes, era rollover, and the entropy of the wire nonce. |
| `bench.zig` | Per-reply codec cost, and the allocation count on the whole `query` path. |

**`sweep` — the accept count is a moving target, and that is the point.** The
audit measured **420** accepted = 4 LI × 7 VN × 15 stratum. Measured today:
**315** = 3 × 7 × 15, with **`UnsynchronizedLeap` = 105** (= 1 × 7 × 15) newly
appearing in the rejection breakdown. The arithmetic matches exactly, and it is
F7 shipping. An unchanged 420 would have meant a regression. The random half:
**3 240 000 packets** over lengths 0..80, 196 accepted (all at length 48), no
panic, in ReleaseSafe so the bounds and overflow checks are live.

⚠ Two things had to change before `sweep` would even build against the live
module, and neither was visible without building it: its `switch (e)` was
exhaustive over the **old** error set (F3 and F7 added two), and it left
`receive` zero — which since F3 would have failed every packet on that one
guard and reported 0 accepted, a number that looks like a finding and is
actually a stale instrument.

**`probe_codec` section E was re-pointed, not copied.** The audit measured the
entropy of `nowTimestamp()`, because back then the clock reading *was* the wire
nonce — 21–24 bits against a doc comment claiming 64. F4 split them. Measuring
the clock today would answer a question the module no longer asks, and the audit
record explicitly leaves the replacement unmeasured. Measured now:

- **E1, the CSPRNG nonce `query` actually sends:** 200 000 draws, **199 996
  distinct**, 4 collisions against a birthday expectation of 4, bottom-3-bit
  histogram flat within ±1 %. A full 32 bits.
- **E2, the clock it replaced (contrast only):** 200 000 distinct but **strictly
  monotonic**, minimum step ≈ 25.8 ns. An off-path attacker bracketing a 100 ms
  window searches **~2^21.9** values, not 2^32.

**`bench`** — `SPEC.md` and `README.md` state no performance numbers for this
module, so there is nothing to re-derive; there is also nothing to notice a
regression, which is what this is for. ReleaseSafe, 2 000 000 iterations:
`decodeResponse` **5.02 ns/op**, decode+verify+offset+delay **6.16 ns/op**,
`encodeRequest` **29.08 ns/op**. And the audit's allocation anchor, re-derived
against a live stub: **allocs during `query` = 0, live delta = 0 B, peak live =
0 B**.

## What was deliberately not brought over

`.zig-cache/audit-sntp` was 259 MB.

- `sntp.zig` — the audit's copy of the module: **964 lines against the live
  1305, 427 differing lines**, because the whole F1/F2 refactor landed after it.
  Every audit probe imported it; all of them now import the live module.
- `sntp_trunc.zig` + `client_trunc.zig` — **spent**. This instrumented pair is
  what proved F2 (the kernel sets `trunc` and the module never read it). F2 is
  fixed, and `validateReply: rejects a truncated datagram…` pins it.
- `fuzzprobe.zig` — **spent**. It measured that the default gate reached exactly
  one input of length 0 (F5). Fixed in `8e468f69` (`smith.slice`), and the
  corpus test pins what each seed reaches.
- `clockres.zig` — **spent**. It measured clock granularity to size F4's
  entropy argument. The nonce is no longer clock-derived, so the question is
  gone; `probe_codec`'s E2 keeps the contrast measurement.
- `build.zig` — audit scratch for driving `fuzzprobe` under `--fuzz`.
