# Formal litmus certification (herd7)

This directory holds the **formal** layer of the lockfree module's weak-memory
certification: `herd7` litmus tests that model-check the three load-bearing
synchronization shapes against the AArch64 and RISC-V (RVWMO) axiomatic memory
models. It sits atop the static disassembly certification in `../SPEC.md` §7 —
that section proves the compiler *emits* the right barriers; these tests prove
those barriers *forbid the bug* under the formal models (and that removing them
lets it back in).

## Toolchain

- `herd7` 7.58 (herdtools7). `run.sh` uses env `HERD7` (binary; default `herd7`
  from PATH). When `HERD7` is unset and `opam` exists, it first loads
  `eval "$(opam env)"`.
- Env `HERD_LIBDIR`: when set, passed as `-set-libdir` (for a herd7 binary that
  ships no model files; point it at herdtools7 tag 7.58 `herd/libdir`).
- Models: the herd7-shipped `aarch64.cat` and `riscv.cat` (found by name from
  herd7's libdir — passed as `-model aarch64.cat` / `-model riscv.cat`).

Run everything: `bash run.sh` (prints each test's `Observation` line and checks
it against the expected verdict; exit 0 iff all match).

## The two shapes, and the matched-pair method

For each shape and each arch there is a **matched pair**:

- **safe** (`*-sc`, `*-rel-acq`) — the ordering the module's code actually uses,
  written with the exact instruction lowerings from SPEC §7. herd7 must report
  the unsafe (bug) condition as **Never**.
- **positive control** (`*-relaxed`) — the *same* test with the ordering
  deliberately weakened to plain/monotonic accesses. herd7 must report the bug
  condition as **Sometimes/Allowed**.

The positive control is the point of the exercise: a "safe" test that is Never
only because the condition was mis-encoded is worthless. The control flipping to
Sometimes proves two things at once — (a) the litmus encoding really exercises
the reordering (it is not vacuously safe), and (b) the barrier the code uses is
load-bearing: strip it and the model permits the use-after-free / stale-read.
In every `exists` clause the condition is written as the **bug** outcome.

### Shape 1 — EBR pin/scan Dekker interlock (store-buffering, SB)

`enterCritical` publishes the reader's local epoch (a STORE) and then loads a
shared queue pointer; symmetrically `tryAdvance` stores its advance/unlink and
then scans reader epochs (a LOAD). The dangerous outcome is the classic SB
store-buffering result where **both** sides' store→load reorders: the reclaimer's
scan misses the pin *and* the reader still holds a pre-unlink pointer, so the
reclaimer frees memory a reader is using (UAF). The code makes both sides
seq_cst; the control demotes them to plain.

- `ebr-interlock-aarch64-sc.litmus` — STLR/LDAR (RCsc pair, no DMB). **Never.**
- `ebr-interlock-aarch64-relaxed.litmus` — STR/LDR. **Sometimes.**
- `ebr-interlock-riscv-sc.litmus` — `fence rw,w;sd` store and
  `fence rw,rw;ld;fence r,rw` load (leading full fence = the store→load barrier).
  **Never.**
- `ebr-interlock-riscv-relaxed.litmus` — plain `sd`/`ld`, no fences. **Sometimes.**

### Shape 2 — Michael-Scott queue publish/consume (message-passing, MP)

`enqueue` writes `node.value` (plain) then publishes the `next` link with a
release-ordered store (the code's link CAS is seq_cst, which is ≥ release);
`dequeue` reads `next` (acquire) then reads `node.value` (plain). The forbidden
MP outcome is "consumer observes the published pointer but reads a stale/
uninitialized payload". The safe variant uses release/acquire; the control makes
both plain.

- `msqueue-aarch64-rel-acq.litmus` — STLR publish / LDAR consume. **Never.**
- `msqueue-aarch64-relaxed.litmus` — STR / LDR. **Sometimes.**
- `msqueue-riscv-rel-acq.litmus` — `fence rw,w;sd` publish /
  `ld;fence r,rw` consume. **Never.**
- `msqueue-riscv-relaxed.litmus` — plain `sd`/`ld`. **Sometimes.**

### Shape 3 — Chase-Lev deque pop/steal Dekker interlock (SB with an RMW)

`deque.zig` replaces the paper's seq_cst fences by seq_cst accesses. Owner `pop`
does a seq_cst STORE of the lowered `bottom` and then a seq_cst LOAD of `top`; a
thief whose claiming CAS on `top` has just succeeded (seq_cst RMW 0->1) then
loads `bottom` (its next steal). Bug outcome: owner reads the OLD `top` AND the
thief reads the OLD `bottom` (both miss each other, same item taken twice).

- `deque-popsteal-aarch64-sc.litmus` — STLR / LDAR / CASAL (accepted by herd7
  7.58). **Never.**
- `deque-popsteal-aarch64-relaxed.litmus` — STR / LDR / plain CAS. **Sometimes.**
- `deque-popsteal-riscv-sc.litmus` — store/load lowerings as in Shape 1,
  `amoswap.w.aqrl` as the RMW (CAS stand-in; the claim always succeeds here).
  **Never.**
- `deque-popsteal-riscv-relaxed.litmus` — plain `sd`/`lw`/`ld`, `amoswap.w`
  without aq/rl. **Sometimes.**

## Mapping to the source

| Litmus var | Source atomic |
|---|---|
| SB `pin` | `Participant.local_epoch` (pin store in `enterCritical`, scan load in `tryAdvance`) |
| SB `ptr` | queue `head`/`tail`/`Node.next` (unlink CAS vs. reader's pointer load) |
| deque `bottom` | `Deque.bottom` (owner store in `pop`, thief load in `steal`) |
| deque `top` | `Deque.top` (owner load in `pop`, thief claiming CAS in `steal`) |
| MP `data` | `Node.value` (plain, written once before publish) |
| MP `flag` | `Node.next` (release-published link / acquire-consumed) |

## Scope (honest)

These tests certify the three **extracted** sync shapes — the pin/scan
interlock, the MS-queue publish/consume and the deque pop/steal interlock —
under the axiomatic AArch64/RVWMO models. They are **not** a whole-program
proof: the full grace-period safety theorem (SPEC §4a / `ebr.zig` `tryAdvance`)
reduces the module's reclamation safety to the first two plus the seq_cst total
order, `deque.zig`'s file comment reduces the deque to the third (and the second
for `push`), and those reductions are reviewed arguments, not machine-checked
ones here. Dynamic stress on real
ARM/RISC-V hardware remains the one thing beyond this layer; with the static
codegen cert (§7) and this formal cert (§7.1) both green, it is now
belt-and-suspenders rather than the sole evidence.
