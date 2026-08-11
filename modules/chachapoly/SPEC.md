# chachapoly — design & threat model (SPEC)

Auditor/design reference. Consumer usage lives in `README.md`; metadata lives in
`src/root.zig`'s `pub const meta`; this file does not restate either.

## What this module is

A performance-specialized ChaCha20 stream cipher + ChaCha20-Poly1305 AEAD,
per **RFC 8439**. It duplicates capability that `std.crypto` already ships
(`std.crypto.stream.chacha`, `std.crypto.aead.chacha_poly`) — a deliberate
exception to the prefer-std rule, justified by throughput.

## Why it exists (the dedup justification)

`std`'s ChaCha is already vectorised, but *within* a single block: the diagonal
layout spreads one 64-byte block across four `@Vector(4·degree, u32)` rows and
rotates the columns with `@shuffle`. Crucially it selects `degree` at comptime
from `builtin.cpu.has(.x86, .avx2)` / `avx512f`. On the default `baseline`
x86-64 target (the target `zig build` uses unless `-Dcpu` is passed) neither is
present, so `std` runs at `degree = 1` — a single 128-bit lane, one block at a
time. That is the ~3.9×-slower-than-OpenSSL path the task measured (std ~478 MB/s
vs OpenSSL AVX2 ~1852 MB/s at 8 KiB). We cannot patch `std`, so we ship our own.

The data-plane case is real: WireGuard authenticates every packet, and
TLS/Noise bulk transfer is AEAD-bound. A 1.3–1.6× win on the AEAD hot path is
worth a specialized duplicate.

## Design — the block-parallel (transpose) layout

Instead of `std`'s within-block diagonal SIMD, this module uses the **transpose**
layout: process `N` consecutive counter blocks at once, holding each of the 16
ChaCha state words in its own `@Vector(N, u32)` whose lane `j` is that word for
block `counter +% j`. Then:

- A quarter-round (`add / xor / rotl` on words `a,b,c,d`) becomes the identical
  op on four vectors — **N-way data-parallel, and with no in-block `@shuffle`**,
  because the parallelism is *across* blocks, not across the 4 columns of one
  block. The column and diagonal rounds are just different `(a,b,c,d)` index
  quadruples over the same 16 vectors.
- After 20 rounds we add the original state (`x[i] +%= s[i]`, the counter add
  landing per-lane via the initial `splat(counter) +% iota`), then **transpose**
  the 16 word-major vectors back to `N` block-major 64-byte little-endian
  outputs.

`N = wide = 8`. A `@Vector(8, u32)` lowers to one 256-bit AVX2 register when the
target enables AVX2 (`-Dcpu=native` or any `x86_64_v3`+ target), and to a pair of
128-bit SSE2 registers on `baseline` — correct either way, faster when AVX2 is
on.

**The `<8`-block tail.** There is no `N = 1` instantiation of the engine any
more: a tail longer than one block generates one *whole* `N = 8` group and
discards the unused suffix (a wide group costs about what a single scalar block
costs), and a tail of one block or less is handed to
`std.crypto.stream.chacha` — see `delegate_max_bytes` below. So the module has
exactly one *width* of its own keystream code, plus std's for short runs.

**Counter semantics.** IETF ChaCha20 has a 32-bit block counter. `ChaCha20.xor`
and `.stream` *assert* that the request stays inside `64·(2^32 − counter)`
bytes, matching `std`'s own assert — a wrap would restart and reuse the
keystream (two-time pad). Inside the loop the counter still advances with `+%`;
the discarded lanes of a tail group may run past 2^32−1, but those bytes are
never emitted. The differential tests stay inside the non-wrapping domain (wrap
past 2^32 blocks is out of `std`'s and the RFC's defined range and is not
diffed).

## Short inputs are std's code — the two delegation thresholds

Both engines here are block- or lane-*parallel*, so their cost is flat in the
length: a group costs the same whether it emits 65 bytes or 512. Below a
break-even size that loses to `std`, which vectorises *within* a block and has a
cheap single-block shape. Rather than ship a documented regression on
short-packet traffic, the module hands those lengths back to `std`:

| constant | in | condition | what runs |
|---|---|---|---|
| `delegate_max_bytes` = 64 | `ChaCha20.xor` / `.stream` | whole call, or the post-group tail, is ≤ 64 B | `std.crypto.stream.chacha.ChaCha20IETF` |
| `aead_delegate_max` = 128 | `ChaCha20Poly1305.encrypt` / `.decrypt` | `m.len + ad.len ≤ 128` | `std.crypto.aead.chacha_poly.ChaCha20Poly1305` |
| `wide_min_groups` = 3 | `poly1305.Generic(L).update` | fewer than 3 whole lane groups (< 192 B at L = 4) | `std.crypto.onetimeauth.Poly1305` |

**Consumer-visible consequence, stated plainly:** for an AEAD call whose message
plus AD is 128 bytes or less — a WireGuard keepalive, a tunnelled TCP ACK, a
Noise handshake payload — this module *is* `std.crypto.aead.chacha_poly`, and
none of the speedups quoted below apply. That is deliberate: parity there is
exact by construction rather than by tuning. The wins start at 144 B and reach
2.5–3× by 1420 B / 8 KiB.

Every one of these branches is on a **length** — public, on the wire before a
byte is authenticated. None may ever be made to depend on key or plaintext.

The AEAD-threshold branch is the one place delegation is not a straight
hand-off: `std`'s `decrypt` leaves `m` *undefined* on rejection, while this
module promises `m` is zeroed, so the delegated failure path re-adds the
`secureZero` by hand (`root.zig:538`).

`delegate_max_bytes` and `aead_delegate_max` are guarded by a test-build path
witness (`chacha_path` / `aead_path`) that asserts which engine each length was
routed to; a mis-routing is otherwise byte-invisible. `wide_min_groups` has
**no** such witness — see the audit note in `~/CML/20260808-zig-libs-audit/`.

## Poly1305 — lane-parallel above a threshold, std's scalar core below it

Lives in `src/poly1305.zig`; that file's doc comment is the primary reference
and is not restated here. The construction around it is unchanged and is exactly
what RFC 8439 §2.8 requires (one-time key = ChaCha20 keystream block at counter
0; MAC over `ad ‖ pad16 ‖ ciphertext ‖ pad16 ‖ le64(ad.len) ‖ le64(ct.len)`;
ciphertext at counter 1).

The shape, in one paragraph: Poly1305 is `H = Σ mᵢ·r^(n−i+1)` in GF(2^130−5), so
`L` blocks can be absorbed per multiply by running one Horner recurrence per lane
with the shared multiplier `r^L` and folding the lanes at the end against
`(r^L, …, r^1)`. That needs a limb layout SIMD can multiply — five 26-bit limbs,
because the widest integer multiply x86 vectors have is `PMULUDQ`'s 32×32→64.
`lanes` is picked at comptime (AVX-512F → 8, AVX2 → 4, otherwise 1).

**It is a hybrid, and that is the load-bearing design decision.** The power table
`r^1..r^L` costs `L−1` field multiplies up front, and the 26-bit layout is
*worse* than std's 2×64 when run one block at a time. A pure-vector version
measured **0.47× std at 64 bytes** — a real regression on the short-packet
traffic (WireGuard keepalives, handshakes) this module exists to serve. So
`Generic(L)` embeds `std.crypto.onetimeauth.Poly1305`, delegates the key, the
leftover buffer, the tail, the final reduction and the tag to it, and intercepts
only runs of ≥ `wide_min_groups` whole lane groups. Below the threshold the
executed code is std's.

The seam reads and writes three of std's public fields — `h` (the
partially-reduced accumulator), `r` (the clamped key half) and `leftover`. That
coupling is deliberate and is pinned by the every-length differential below: if
any of those meanings drifted, the sweep would fail rather than silently forge.

Measured on an i7-7920HQ (AVX2), ReleaseFast: MAC 1.0× at 32 B, 0.98× at 128 B,
1.06× at 256 B, 1.5× at 512 B, 2.0× at 1420 B, 2.5× at 8 KiB; full AEAD 2.8× at
8 KiB and 2.6× for a 1420-byte packet.

`ChaCha20.xor` is **fused**: whole `wide`-block groups are transposed straight
out of the `@Vector` state into 64-byte vectors, XORed against unaligned loads of
the input and stored, with no `[64 * wide]u8` staging buffer. The staged shape it
replaced was worse than an extra copy — its `out[j] = in[j] ^ ks[j]` loop was not
vectorised at all, because `out` may alias `in`, so it emitted one
`movzbl`/`xor`/`mov` per byte and held `xor` to 1102 MB/s against `stream`'s
2219. Fused it reaches 2383 MB/s, and the AEAD 845 → 1406 MB/s at 8 KiB.

Only the sub-group tail still stages, and it generates one *whole* `wide` group
and discards the unused blocks: a wide group costs roughly what a single `N = 1`
block costs, so this wins for any tail longer than one block. The discarded lanes
may carry block counters past 2^32-1 through the `+% iota`; those bytes are never
emitted, so the anti-wrap guarantee is unaffected. This is most of the 1420-byte
gain (542 → 1127 MB/s), which is the size that matters for the per-packet case.

`xor` requires `out` and `in` to be either the same slice (in-place) or disjoint;
partially overlapping slices are not supported, matching std's block-buffered
`xor`. In-place is covered by tests at every length 0..1024.

## Constant-time

ChaCha and Poly1305 are inherently constant-time: only add / xor / rotate /
(Poly1305) multiply / mask, no secret-indexed memory access and no data-dependent
branches. The lane-parallel MAC adds only arithmetic of that same shape; every
branch it introduces is on message length or buffer occupancy, both public, and
the lane count is a comptime constant rather than a runtime dispatch. The
`@Vector` ops preserve this (SIMD lanes are data-oblivious). The
byte-serialization transpose indexes vectors by **comptime** lane/word indices
only. Tag verification uses `std.crypto.timing_safe.eql`, and a failed `decrypt`
`secureZero`s both the computed tag and the plaintext buffer before returning
`error.AuthenticationFailed` — a caller must not read `m` on error.

**This holds in `ReleaseFast`, which is what ships — and only there.** The
lane-parallel MAC uses *checked* `*` / `+` rather than `*%` / `+%` on purpose,
so that a deferred-carry bounds mistake panics instead of silently forging a
tag; in `Debug` / `ReleaseSafe` the compiler turns each of those into an
overflow branch on a secret-derived value.

**The measurement, in full, so the claim is exactly as wide as the evidence.**
Since 2026-08-11 it is a **committed program**, not numbers a reader has to take
on faith: [`src/ctgrind_harness.zig`](src/ctgrind_harness.zig), driven by
[`../../scripts/ctgrind.sh`](../../scripts/ctgrind.sh). It marks the 32-byte
Poly1305 key `MAKE_MEM_UNDEFINED`, forces a volatile reload so the optimizer
cannot keep a defined register copy, and drives it through `Poly1305.create` at
16/64/192/1024/8192 B plus a chunked `update`/`pad`/`update`/`final` stream.
Run it:

```sh
scripts/ctgrind.sh chachapoly
```

Zig 0.16.0, valgrind 3.26.0, x86_64 (i7-7920HQ), `lanes = 4`, 2026-08-11.
`in-file` = memcheck error CONTEXTS whose stack names `poly1305.zig`, not error
counts:

| build | `-fvalgrind` | key tainted | contexts | of those, inside `poly1305.zig` | exit |
|---|---|---|---|---|---|
| `ReleaseFast` | yes | yes | **4** | **0** | 99 |
| `ReleaseSafe` | yes | yes | **214** | **210** | 99 |
| `Debug`       | yes | yes | **285** | **281** | 99 |
| `ReleaseFast` | yes | **no** — negative control | 0 | 0 | 0 |
| `ReleaseSafe` | yes | **no** — negative control | 0 | 0 | 0 |
| `Debug`       | yes | **no** — negative control | 0 | 0 | 0 |
| `ReleaseFast` | **no** | yes — trap | 0 | 0 | 0 |
| `ReleaseSafe` | **no** | yes — trap | 0 | 0 | 0 |
| `Debug`       | **no** | yes — trap | 0 | 0 | 0 |

(An earlier hand-run of the same experiment recorded 3 / 280 / 294 across the
first three rows. Same shape, same conclusion; the small differences are the
committed harness's slightly different message set, and these are the numbers
that can now be re-taken.)

Three things make the `ReleaseFast` zero mean something. First, the trap rows:
**without `-fvalgrind` every run reads 0 regardless**, because
`std.valgrind.doClientRequest` returns early unless `builtin.valgrind_support`,
which the release modes disable — a clean run built without the switch is a
silent no-op, not a result. Second, the negative-control rows: untainted, every
mode reports 0, so the counts above are taint-caused and not ambient noise.
Third, the `ReleaseFast` count is **non-zero** — its 4 contexts are branches on
the *tag*, raised inside the harness's own hex formatter, which is the proof
that taint travelled key → tag through the entire MAC and that the MAC left no
branch behind on the way.

**Teeth, measured 2026-08-11.** The `ReleaseSafe`/`Debug` rows are already a
positive control no optimizer can delete — 210 and 281 contexts *inside*
`poly1305.zig` prove the taint reaches the MAC's arithmetic. For the
`ReleaseFast` row specifically, injecting a secret-dependent early return
(`var z: u8 = 0; for (key) |b| z |= b; if (z == 0) { @memset(out, 0); return; }`
at the top of `create` — the exact defect class) moves it from **4 total / 0
in-file** to **5 / 1, exit 99**. This matters because the obvious cheap defect
does *not* survive: an `if (key[0] > 128)` compiles to a branchless select at
ReleaseFast and proves nothing. Reverted; `cmp` against a pre-mutation copy
confirmed byte-identical.

The `ReleaseSafe` innermost frames are precisely the checked operators: the five
schoolbook rows of `mulRed`, the carry chain, `buildPowers`' power table and the
lane fold. `std`'s own scalar `Poly1305` shows the same class of artifact in its
`mulWide`.

**Decision (recorded, not deferred): the checked operators stay.** A
deferred-carry bounds mistake that panics is strictly better than one that
silently forges a tag, and the branches in question are never *taken* on correct
input — what `ReleaseSafe` loses is the machine-checkable absence of the branch,
not a demonstrated leak. So the contract is narrowed rather than the code:
**ship this module at `ReleaseFast` if constant time matters**, and do not read
the structural argument above as covering `ReleaseSafe`.

Beyond that measurement this is a *structural* CT argument (no secret-dependent
control flow exists in the source), not a machine-checked-disassembly audit like
`montint`/`k256`.

## Verification

- **RFC 8439 KATs**, byte-exact, Debug + ReleaseFast: §2.3.2 (ChaCha20 block /
  keystream at counter 1), §2.4.2 (the "sunscreen" encryption), §2.5.2 (Poly1305
  tag), §2.8.2 (AEAD encrypt: ciphertext + tag).
- **RFC 8439 §A.3 Poly1305 vectors** — all eleven, at every lane width
  L ∈ {1,2,4,8}. These are the ones written to break a wrong implementation:
  r = 0, s = 0, r = 2^130−6, the two "imperfect carry propagation" pairs, and a
  127-byte message that lands mid-lane at every width.
- **Poly1305 differential vs `std` for EVERY length 0..2048**, at every lane
  width, plus a random-key stress, an all-0xff key/message worst case for the
  deferred-carry bound, and every `update` split point (the streaming path the
  AEAD actually drives). The partial-final-block and lane-boundary-straddle
  cases are where parallel Poly1305 implementations break, so they are swept
  exhaustively rather than sampled.
- **Differential vs the `std` oracle** across block-boundary edge lengths
  `{0,1,15,16,17,31,63,64,65,127,128,129,255,256,257,511,512,513,1000,4096}`:
  our `ChaCha20.stream`/`.xor` equal `std`'s byte-for-byte at several counters;
  our AEAD ciphertext **and** tag equal `std`'s, `decrypt(encrypt)` is identity,
  our AEAD opens `std`'s ciphertext and `std` opens ours (cross-decrypt), and
  both tag-tamper and ciphertext-tamper are rejected. `std` is the authority — a
  divergence in any edge length fails the build.
- A `>8`-block (20-block) case exercises two wide passes + a 4-block tail and the
  per-lane counter increment across the boundary, byte-exact vs `std`.

The `std` differential is what makes the SIMD safe: correctness of the transpose
layout + tail handling + counter carry is pinned to `std`'s scalar/diagonal
implementation at every awkward length, so a wrong keystream cannot ship.

### Threshold guards — the one property bytes cannot check

This module has **three** tuning constants, and all three are invisible to every
byte-comparing test in it, because both engines produce identical bytes: the
faster path exists to be faster, not different. So each has a test-build-only
*witness* recording which engine a call took, and a table test asserting the
routing:

| constant | value | witness | first size on the fast path |
|---|---|---|---|
| `delegate_max_bytes` (ChaCha20) | **64** | `root.chacha_path` | 65 B |
| `aead_delegate_max` (whole AEAD, `m.len + ad.len`) | **128** | `root.aead_path` | 129 B |
| `wide_min_groups` (Poly1305 lanes) | **3** | `poly1305.mac_path` | 96/192/384 B at L = 2/4/8 |

The witnesses are `void` outside a test build (`builtin.is_test` is comptime),
so none of this reaches shipped code and the `.reentrant` claim is unaffected.

**The numbers are asserted as literals, not as expressions over themselves.** A
case table written `.{ .m = aead_delegate_max, .want = .std_delegated }` moves
with the constant and stays green for any value of it — verified: mutating
`aead_delegate_max` 128 → 130 and `delegate_max_bytes` 64 → 80 both exited 0
against the symbolic tables alone. The literal tables that now follow them turn
both red, as does `wide_min_groups` 3 → 4096 (the mutation that switches the
lane-parallel MAC off entirely: measured cost, MAC 4048 → 1698 MB/s at 8 KiB,
2.47× → 1.06× vs std) and 3 → 2. The symbolic tables are kept because they pin a
different property — every comparison replayed against every implementation of
it, which is how two real routing holes in `decrypt` and `stream` were found.

## Non-goals / backlog

- **AVX-512 (L = 8) is correctness-tested but perf-unmeasured** — no AVX-512
  hardware here. The selection is comptime, so a host that has it takes the
  8-lane path untested for *speed*; it is not untested for *correctness*.
- **2-lane SSE2 / NEON Poly1305** — deliberately not taken: two 26-bit lanes do
  not beat one 64×64→128 scalar multiply, so those targets stay on std.
- **XChaCha20 / XChaCha20-Poly1305** (24-byte extended nonce, HChaCha20) — not
  needed by current consumers; add if a consumer wants it.
- Machine-checked CT disassembly audit (as done for the asm field modules). The
  valgrind/memcheck tainted-key measurement in the constant-time section above
  is not a substitute for one.
- ~~A test-build path witness for `wide_min_groups`~~ — **DONE 2026-08-11.**
  `poly1305.mac_path` is now the third witness alongside `chacha_path` /
  `aead_path`, and the boundaries it asserts are written as literal byte counts
  (96 / 192 / 384 at L = 2 / 4 / 8) rather than as `wide_min_bytes ± 1`, so the
  test cannot re-assert a retuned constant. See "Threshold guards" below.

Consumers already wired to this module (`@import("chachapoly")`, all using
`ChaCha20Poly1305`): `noise`, `wireguard`, `dtls`, `quic-crypto`, `hpke`,
`signal`, `aeadframe`, `timelock_envelope`. `bolt8` still uses `std`'s. Any
change to the delegation thresholds or the MAC is therefore live on those
paths, not staged behind a rewiring step.
