// SPDX-License-Identifier: MIT
//! Program builders — the FABLE-tier core of this module.
//!
//! Each function here returns a verifier-ready instruction sequence for one
//! fixed, named eBPF program. All instruction ENCODING is free: `std.os.
//! linux.BPF.Insn` already ships every opcode builder needed (`mov`, `alu`,
//! `jmp`, `ld_map_fd1`/`2`, `ldx`/`stx`, `call`, `xadd`, `exit`, …) — see
//! `../README.md`'s std-inventory section. What is NOT free, and what makes
//! this file genuinely hard rather than mechanical, is choosing the exact
//! SEQUENCE and SHAPE of those instructions so the in-kernel verifier's
//! abstract interpreter (register-type lattice, scalar-range tracking,
//! stack-slot liveness, helper-argument type checking, reference-state
//! tracking for acquire/release helpers) accepts the program. Getting the
//! encoding right is necessary but nowhere near sufficient; getting the
//! verifier-facing PROOF SHAPE right is the actual task. See each function's
//! doc comment for the specific constraints it must satisfy, and
//! `../SPEC.md` for the golden-vector methodology used to validate a
//! finished encoder offline (no kernel required for the byte-exact check;
//! a kernel IS required to confirm the verifier actually accepts it).
//!
//! The three builders below are implemented (the former `TODO(fable/core)`
//! `@panic` stubs); their instruction sequences are golden-vector tested and,
//! under CAP_BPF/root, load-verified against the live kernel. Signatures are
//! final — the fixed call shape was not redesigned.

const std = @import("std");
const linux = std.os.linux;
const BPF = linux.BPF;

/// `std.os.linux.BPF.Insn` — the packed-struct wire encoding, re-exported so
/// callers of this module don't need a second import for it.
pub const Insn = BPF.Insn;

/// A built program ready for `load.zig`'s `prog_load` wrapper: the
/// instruction stream plus the `BPF_PROG_TYPE_*` it must be loaded as (the
/// verifier's context-access whitelist and allowed-helper set both key off
/// this, so it travels with the instructions rather than being a separate
/// caller-supplied argument that could get out of sync).
pub const Program = struct {
    prog_type: BPF.ProgType,
    insns: []const Insn,
};

/// Returned by `xdpFilter`/`ringbufEmit` when a caller-supplied size would
/// overflow the builder's fixed file-scope instruction buffer, or overflow
/// the `i16`/`i32` byte-offset arithmetic used while emitting into it. These
/// are cheap, mechanical input-validation failures — not verifier rejections
/// (the verifier is never reached; the malformed program is never built).
pub const BuildError = error{
    /// `key_size` (and/or `key_offset`) is large enough that emitting the
    /// per-byte key-copy loop would overflow `xdp_buf`.
    KeyTooLarge,
    /// `key_offset + key_size` would overflow the `i16` packet byte-offset
    /// field used by the key-copy loads (`ldx`/`stx` `.off`).
    KeyOffsetTooLarge,
    /// `record_size` is large enough that emitting the zero-fill loop would
    /// overflow `ringbuf_buf`, or would overflow the `i16`/`i32` size
    /// arithmetic used to build the program.
    RecordTooLarge,
};

// ── kprobe-counter ──────────────────────────────────────────────────────────

/// Build the `kprobe-counter` program: on every kprobe hit, atomically
/// increment slot 0 of `counter_map_fd` (a `BPF_MAP_TYPE_ARRAY` or
/// `BPF_MAP_TYPE_PERCPU_ARRAY`, key size 4, value size 8) and return.
///
/// `BPF_PROG_TYPE_KPROBE`, context = `bpf_user_pt_regs_t*` (an opaque
/// register snapshot; this program never touches it — the whole point of a
/// pure counter is it doesn't need to decode ctx at all, which is why this
/// is the SIMPLEST of the three builders here, closer to Opus-tier
/// boilerplate than the other two — see the module README's difficulty
/// verdict).
///
/// Verifier constraints this must satisfy:
///  1. The map fd is loaded via the two-instruction `BPF_LD_IMM64` pseudo
///     relocation (`Insn.ld_map_fd1`/`Insn.ld_map_fd2`) — a PLAIN `ld_dw1`/
///     `ld_dw2` with the raw fd value does NOT work; the verifier only
///     resolves `src_reg == BPF_PSEUDO_MAP_FD` loads into a real
///     `CONST_PTR_TO_MAP` type, and `bpf_map_lookup_elem`'s first argument
///     (`ARG_CONST_MAP_PTR`) rejects anything else.
///  2. `bpf_map_lookup_elem`'s second argument (`ARG_PTR_TO_MAP_KEY`)
///     requires a pointer into the BPF stack (`r10`-relative) whose
///     pointed-to bytes are ALREADY INITIALIZED for exactly the map's
///     `key_size` (here 4) — so a `stx`/`st` writing the key (a constant
///     `0`, the counter's only slot) must be emitted BEFORE the `call`, and
///     the pointer passed in `r2` must be `r10 + off` with `off` matching
///     that store exactly. An uninitialized or wrongly-sized stack read here
///     is the single most common map-lookup verifier rejection
///     ("invalid indirect read from stack").
///  3. `bpf_map_lookup_elem` returns `PTR_TO_MAP_VALUE_OR_NULL` in `r0`. The
///     verifier requires an explicit `r0 == 0` branch (`Insn.jeq(.r0, 0,
///     off)`) on EVERY path before `r0` is dereferenced — skip it and the
///     verifier rejects with "R0 invalid mem access, value_or_null". The
///     null branch must jump to the program's `exit()`.
///  4. Once past the null check, `r0` has type `PTR_TO_MAP_VALUE` with a
///     verifier-tracked size of exactly the map's `value_size` (8) — any
///     store/load through it must fit within those 8 bytes.
///  5. The increment itself should be `Insn.xadd(r0, r1)` (atomic
///     fetch-add), NOT a plain load-add-store — a kprobe fires concurrently
///     on every CPU that hits the probed function, so a non-atomic
///     read-modify-write loses updates under real load even though the
///     verifier has no opinion on atomicity (this is a CORRECTNESS
///     requirement the verifier does not enforce, not a rejection risk —
///     document it precisely so it isn't "fixed" away by a well-meaning
///     later edit). Using a `PERCPU_ARRAY` map instead sidesteps the need
///     for `xadd` entirely (each CPU gets its own slot); either design is
///     valid, but the choice changes this function's instruction sequence
///     and must be picked deliberately, not left ambiguous.
///  6. `r0` must hold a return value and the LAST instruction on every path
///     must be `Insn.exit()` — the verifier rejects a program with no
///     provably-reached `BPF_EXIT`, and separately rejects reading an
///     uninitialized `r0` at exit (kprobe program return value is
///     conventionally `0`).
pub fn kprobeCounter(counter_map_fd: linux.fd_t) []const Insn {
    // Storage contract (all three builders): the returned slice points into a
    // file-scope buffer, not heap — the fixed signature carries no allocator
    // and no caller buffer, and the `counter_map_fd` value must be baked into
    // the `ld_map_fd` immediate, so the instruction stream cannot be a plain
    // `const`. This matches the module's declared `.concurrency =
    // .single_owner`: a builder is called once at setup and its result loaded
    // immediately. A second call to the SAME builder overwrites the previous
    // slice — build-then-load, do not stash the slice across another build.
    const R = Insn.Reg;
    var b: Buf = .{ .buf = &kprobe_buf };

    // (1) 4-byte key = 0 on the stack. `st .word` writes a known scalar 0 into
    //     [r10-4, r10), initializing exactly key_size(=4) bytes so the
    //     ARG_PTR_TO_MAP_KEY pointer below reads only initialized stack
    //     ("invalid indirect read from stack" otherwise).
    b.emit(Insn.st(.word, R.r10, -4, 0));
    // (2) r2 = &key  (r10-relative), the ARG_PTR_TO_MAP_KEY argument.
    b.emit(Insn.mov(R.r2, R.r10));
    b.emit(Insn.add(R.r2, -4));
    // (3) r1 = map  via the two-slot BPF_PSEUDO_MAP_FD relocation — the ONLY
    //     load the verifier resolves to CONST_PTR_TO_MAP (ARG_CONST_MAP_PTR).
    b.emit(Insn.ld_map_fd1(R.r1, counter_map_fd));
    b.emit(Insn.ld_map_fd2(counter_map_fd));
    // (4) r0 = bpf_map_lookup_elem(map, &key) -> PTR_TO_MAP_VALUE_OR_NULL.
    b.emit(Insn.call(.map_lookup_elem));
    // (5) Mandatory null-check before any deref. On the null path r0 is already
    //     0 — the kprobe return convention — so jump straight to exit().
    //     off = exit_index(10) - (pc(6)+1) = 3.
    b.emit(Insn.jeq(R.r0, 0, 3));
    // (6) Atomic increment: *(u64*)(r0) += 1. `xadd` (BPF_ATOMIC add, no fetch)
    //     is a CORRECTNESS requirement the verifier does NOT enforce — a kprobe
    //     fires concurrently on every CPU, so a plain ldx/add/stx would lose
    //     updates under load. Do not "simplify" this to a non-atomic RMW. (A
    //     PERCPU_ARRAY map would make each CPU's slot private and let a plain
    //     store suffice; this builder stays map-type-agnostic and uses the
    //     atomic, which is correct for a shared ARRAY map too.)
    b.emit(Insn.mov(R.r1, 1));
    b.emit(Insn.xadd(R.r0, R.r1));
    // (7) return 0 (success path) + the single shared exit.
    b.emit(Insn.mov(R.r0, 0));
    b.emit(Insn.exit());
    return b.slice();
}

// ── xdp-filter ──────────────────────────────────────────────────────────────

/// Configuration for `xdpFilter` — a fixed contract; the FABLE pass fills
/// `xdpFilter`'s body against exactly this shape, it does not redesign it.
pub const XdpFilterOptions = struct {
    /// `BPF_MAP_TYPE_HASH` or `_ARRAY` fd used as the block/allow list. A
    /// present key means "drop".
    block_map_fd: linux.fd_t,
    /// Byte offset from the start of the packet (Ethernet frame) of the
    /// field used as the lookup key (e.g. 26 for an IPv4 source address in
    /// a plain, non-VLAN-tagged frame).
    key_offset: u16,
    /// Width in bytes of the lookup key at `key_offset` (must match the
    /// block map's `key_size`; 4 for an IPv4 address).
    key_size: u16,
};

/// Build the `xdp-filter` program: look up a fixed-offset packet field in
/// `opts.block_map_fd`; `XDP_DROP` on a hit, `XDP_PASS` otherwise.
///
/// `BPF_PROG_TYPE_XDP`, context = `struct xdp_md { u32 data; u32 data_end;
/// u32 data_meta; u32 ingress_ifindex; u32 rx_queue_index; u32
/// egress_ifindex; }` — THIS IS THE HARD ONE. Every field is a 32-bit
/// OFFSET-into-the-struct load (`data` at ctx+0, `data_end` at ctx+4,
/// `data_meta` at ctx+8, `ingress_ifindex` at ctx+12, `rx_queue_index` at
/// ctx+16, `egress_ifindex` at ctx+20 — get one of these wrong and
/// `BPF_PROG_LOAD` fails immediately with "invalid bpf_context access",
/// before the harder constraints below are even reached).
///
/// Verifier constraints this must satisfy:
///  1. Loading `ctx->data` (offset 0) is special-cased by the verifier: the
///     destination register of THAT SPECIFIC load is retyped from a plain
///     scalar to `PTR_TO_PACKET`; loading `ctx->data_end` (offset 4)
///     likewise yields `PTR_TO_PACKET_END`. Loading the same struct fields
///     through any other route (e.g. after a stack spill/reload) does NOT
///     preserve this typing — the packet pointer must flow directly from
///     the ctx load to its uses.
///  2. THE bounds-check dominance pattern: any read of packet bytes beyond
///     what's already range-proven requires, on EVERY path that reaches the
///     read, a preceding unsigned comparison of the form `ptr + width <=
///     data_end` using `Insn.jlt`/`Insn.jle`/`Insn.jge` etc. against the
///     SAME `data_end` register, where `ptr` is derived by a plain
///     immediate `ADD` from the SAME register that was compared. Reorder
///     the check after the access, compare against a copied/aliased
///     register, or recompute the pointer in a way the verifier's
///     scalar-range tracking can't follow through, and the load is
///     rejected as "invalid access to packet" even when it is provably
///     safe at runtime — this dominance requirement (not the comparison
///     itself) is the single most-cited "why won't my XDP program load"
///     verifier subtlety.
///  3. The lookup key (the `opts.key_size` bytes at `opts.key_offset` into
///     the now-PTR_TO_PACKET-typed data register) must itself be
///     bounds-checked per point 2 BEFORE being copied to the stack slot fed
///     to `bpf_map_lookup_elem` (which needs an initialized, `r10`-relative
///     stack pointer exactly as in `kprobeCounter` — same
///     `ARG_PTR_TO_MAP_KEY` constraint, same `PTR_TO_MAP_VALUE_OR_NULL`
///     null-check-before-dereference constraint on the returned `r0`).
///  4. Return-value convention: `r0` must be one of `XDP_ABORTED(0)`,
///     `XDP_DROP(1)`, `XDP_PASS(2)`, `XDP_TX(3)`, `XDP_REDIRECT(4)`. Unlike
///     most of the constraints above, the verifier does **not** range-check
///     this value for `BPF_PROG_TYPE_XDP` — an out-of-range `r0` loads fine
///     and silently misbehaves at the network layer instead of failing
///     verification. Document this explicitly: it LOOKS like a verifier
///     constraint but is actually an unenforced ABI convention, and testing
///     it needs a behavioral check, not a load-time one.
pub fn xdpFilter(opts: XdpFilterOptions) BuildError![]const Insn {
    // ── input validation (BEFORE any @intCast/arithmetic below can panic) ──
    // Fixed instruction count around the key-copy loop: 5 before it (2 ctx
    // loads + mov/add + the reserved jgt slot) + 6 after (mov/add/ld_map_fd
    // x2/call/reserved jeq slot) + 2 (DROP path) + 2 (PASS path) = 15; the
    // loop itself emits 2 instructions per key byte. Reject any `key_size`
    // that would overflow `xdp_buf` instead of silently writing past it.
    const xdp_fixed_insns = 15;
    const needed = xdp_fixed_insns + @as(usize, opts.key_size) * 2;
    if (needed > xdp_buf.len) return error.KeyTooLarge;
    // `off` (below) and every `off + k` for `k in [0, key_size)` must fit in
    // the `i16` `.off` field of the emitted `ldx`/`stx` instructions; a
    // conservative single bound covers both without needing two checks.
    if (@as(u32, opts.key_offset) + @as(u32, opts.key_size) > std.math.maxInt(i16)) {
        return error.KeyOffsetTooLarge;
    }

    const R = Insn.Reg;
    const XDP_DROP: i32 = 1;
    const XDP_PASS: i32 = 2;
    const off: i16 = @intCast(opts.key_offset);
    const n: i16 = @intCast(opts.key_size);
    // The packet-region end we must prove in-bounds: data + key_offset +
    // key_size. Kept in an i32 to bake into the ADD immediate below.
    const region_end: i32 = @as(i32, opts.key_offset) + @as(i32, opts.key_size);

    var b: Buf = .{ .buf = &xdp_buf };

    // (1) Load data_end FIRST (from ctx=r1), THEN data — the second load
    //     overwrites r1 (ctx), so data_end must already be saved. The verifier
    //     special-cases these exact ctx offsets: a `.word` load of ctx+4 retypes
    //     its dst to PTR_TO_PACKET_END, ctx+0 to PTR_TO_PACKET. The packet
    //     pointer must flow DIRECTLY from this load to its uses — a stack
    //     spill/reload would lose the PTR_TO_PACKET typing.
    b.emit(Insn.ldx(.word, R.r2, R.r1, 4)); // r2 = data_end
    b.emit(Insn.ldx(.word, R.r1, R.r1, 0)); // r1 = data  (ctx clobbered)
    // (2) Bounds-check DOMINANCE: derive the region end by a plain immediate ADD
    //     from the SAME register that will be compared, then compare against the
    //     SAME data_end register, BEFORE any packet byte is read. If
    //     data + key_offset + key_size > data_end, the key is not fully present:
    //     fall through to XDP_PASS. This single check dominates every packet
    //     read below, which is exactly what the verifier's scalar-range tracker
    //     requires ("invalid access to packet" otherwise).
    b.emit(Insn.mov(R.r3, R.r1)); // r3 = data
    b.emit(Insn.add(R.r3, region_end)); // r3 = data + key_offset + key_size
    // jgt r3, data_end -> PASS. Target (the XDP_PASS mov) is the 2nd-from-last
    // instruction; patched after the layout is known.
    const jgt_idx = b.reserve();
    // (3) Copy the now-proven-in-bounds key bytes to [r10-n, r10). Byte-wise
    //     loads keep this correct for any key_size and sidestep packet-access
    //     alignment rules. Each read is dominated by the check in (2).
    var k: i16 = 0;
    while (k < n) : (k += 1) {
        b.emit(Insn.ldx(.byte, R.r4, R.r1, off + k)); // r4 = data[off+k]
        b.emit(Insn.stx(.byte, R.r10, -n + k, R.r4)); // key[k] = r4
    }
    // (4) Map lookup — same discipline as kprobeCounter: r2 = &key (initialized
    //     r10-relative stack), r1 = map via pseudo-fd, then null-check the
    //     PTR_TO_MAP_VALUE_OR_NULL before treating a hit as "block".
    b.emit(Insn.mov(R.r2, R.r10));
    b.emit(Insn.add(R.r2, -n));
    b.emit(Insn.ld_map_fd1(R.r1, opts.block_map_fd));
    b.emit(Insn.ld_map_fd2(opts.block_map_fd));
    b.emit(Insn.call(.map_lookup_elem));
    // r0 == 0 (key absent) -> PASS; else fall through to DROP.
    const jeq_idx = b.reserve();
    // (5) Blocked path: XDP_DROP. NOTE: the verifier does NOT range-check the
    //     XDP return value — an out-of-range r0 loads fine and only misbehaves
    //     at the network layer. XDP_DROP/PASS here is an unenforced ABI
    //     convention, not a verifier constraint (test behaviorally, not at load).
    b.emit(Insn.mov(R.r0, XDP_DROP));
    b.emit(Insn.exit());
    // (6) PASS path (also the bounds-fail and key-absent target).
    const pass_idx = b.len();
    b.emit(Insn.mov(R.r0, XDP_PASS));
    b.emit(Insn.exit());

    // Patch the two forward jumps now that PASS's index is known.
    b.patchJumpTo(jgt_idx, Insn.jgt(R.r3, R.r2, 0), pass_idx);
    b.patchJumpTo(jeq_idx, Insn.jeq(R.r0, 0, 0), pass_idx);
    return b.slice();
}

// ── ringbuf-emit ─────────────────────────────────────────────────────────────

/// Configuration for `ringbufEmit` — a fixed contract; see `xdpFilter`'s doc
/// comment for why this is a struct rather than positional args.
pub const RingbufEmitOptions = struct {
    /// `BPF_MAP_TYPE_RINGBUF` fd (key_size = value_size = 0, max_entries =
    /// ring size in bytes, must be a power of 2).
    ringbuf_map_fd: linux.fd_t,
    /// Size in bytes of the fixed-size record this program emits per
    /// invocation (e.g. `@sizeOf(Event)`). MUST end up as a compile-time
    /// constant baked into the generated `bpf_ringbuf_reserve()` call — see
    /// constraint 2 below; this is a build-time parameter of the generated
    /// program, not something the resulting bytecode reads at runtime.
    record_size: u32,
};

/// Build the `ringbuf-emit` program: reserve `opts.record_size` bytes in
/// `opts.ringbuf_map_fd`, fill them from the program's context data, submit.
///
/// Program type left to the caller's attach point (kprobe/tracepoint/XDP all
/// have `bpf_ringbuf_reserve`/`_submit`/`_discard` in their allowed-helper
/// set); this builder only owns the ringbuf-reservation sequence, not
/// whatever context-specific bytes get copied into the reserved record.
///
/// Verifier constraints this must satisfy (the reference-tracking rules
/// below are the newest and least forgiving part of the verifier's model —
/// arguably the subtlest of the three programs in this file):
///  1. `bpf_ringbuf_reserve(map, size, flags)` returns
///     `PTR_TO_ALLOC_MEM_OR_NULL` in `r0` — a pointer type the verifier's
///     REFERENCE-STATE tracker treats specially: the instant `r0` is
///     non-null, that pointer counts as an OPEN, unreleased reference
///     attached to this verifier path's state, independent of the
///     null-check-before-dereference rule every other pointer type here
///     already needs.
///  2. `size` binds to `bpf_ringbuf_reserve`'s `ARG_CONST_ALLOC_SIZE_OR_ZERO`
///     argument type: the verifier requires this operand to be a
///     PROVABLY-CONSTANT immediate (a plain `Insn.mov(reg, opts.record_size)`
///     with an `i32` immediate, not a value computed at runtime or read from
///     memory) — this is what lets `bpf_ringbuf_reserve` skip the extra
///     `memcpy` that `bpf_ringbuf_output` pays for, but it means the record
///     size is frozen into the PROGRAM at build time, exactly matching why
///     `opts.record_size` is a `build`-time argument to this Zig function
///     rather than something the generated bytecode reads from a register.
///  3. Every write into the reserved region must stay within `[r0, r0 +
///     opts.record_size)` — `PTR_TO_ALLOC_MEM`'s verifier-tracked range is
///     exactly `record_size` bytes, checked the same way `PTR_TO_MAP_VALUE`
///     bounds are in `kprobeCounter`.
///  4. THE hard part: on EVERY path from a successful (non-null) reserve to
///     the program's `exit()` — including any early-return/error path taken
///     AFTER the reserve — the program must call either
///     `bpf_ringbuf_submit(r0, flags)` (publish) or `bpf_ringbuf_discard(r0,
///     flags)` (drop) exactly once. Reaching `BPF_EXIT` on ANY path with the
///     reference still open is rejected as "Unreleased reference id=…" —
///     this is a whole-CFG liveness property, not a local instruction-shape
///     one, so it constrains how any branching within this program's body
///     may be structured (e.g. a bounds-check failure discovered after
///     reserving must discard before jumping to exit, it cannot just jump
///     past the submit/discard).
///  5. Documented escape hatch, NOT used by this builder but worth recording
///     for whoever implements it: `bpf_ringbuf_output(map, data, size,
///     flags)` performs the reserve+copy+submit as one call, trading an
///     extra `memcpy` for sidestepping reference-state tracking entirely —
///     its `data`/`size` argument pair instead binds to `ARG_PTR_TO_MEM` +
///     `ARG_CONST_SIZE`, which is the SAME initialized-stack-region
///     constraint `bpf_trace_printk`-style helpers use, not the
///     reference-tracking constraint above. Choosing reserve/submit vs.
///     output is a deliberate, signature-changing decision, not an
///     implementation detail — this function commits to reserve/submit
///     (see the doc comment above) precisely because it's the harder,
///     more representative case for a Fable-tier pass to demonstrate.
pub fn ringbufEmit(opts: RingbufEmitOptions) BuildError![]const Insn {
    // ── input validation (BEFORE any @intCast/arithmetic below can panic) ──
    // Fixed instruction count around the zero-fill loop: 6 before it
    // (ld_map_fd x2/mov x2/call/reserved jeq slot) + 3 after (mov x2/call
    // submit) + 2 (shared exit tail) = 11; the loop itself emits one
    // `double_word` store per full 8-byte chunk plus up to 7 trailing `byte`
    // stores. Reject any `record_size` that would overflow `ringbuf_buf`
    // instead of silently writing past it. This bound also keeps
    // `record_size` well within `i16`/`i32` range, so the `@intCast`s below
    // (`size`, `rec_end`) cannot panic either.
    const ringbuf_fixed_insns = 11;
    const zero_fill_insns = @as(usize, opts.record_size) / 8 + @as(usize, opts.record_size) % 8;
    if (ringbuf_fixed_insns + zero_fill_insns > ringbuf_buf.len) return error.RecordTooLarge;

    const R = Insn.Reg;
    const size: i32 = @intCast(opts.record_size);

    var b: Buf = .{ .buf = &ringbuf_buf };

    // (1) r1 = ringbuf map (pseudo-fd); r2 = size as a PROVABLY-CONSTANT
    //     immediate — ARG_CONST_ALLOC_SIZE_OR_ZERO rejects a runtime-computed or
    //     memory-loaded size, which is why record_size is a build-time argument
    //     baked straight into this `mov`. r3 = flags(0).
    b.emit(Insn.ld_map_fd1(R.r1, opts.ringbuf_map_fd));
    b.emit(Insn.ld_map_fd2(opts.ringbuf_map_fd));
    b.emit(Insn.mov(R.r2, size));
    b.emit(Insn.mov(R.r3, 0));
    // (2) r0 = bpf_ringbuf_reserve(map, size, 0) -> PTR_TO_ALLOC_MEM_OR_NULL.
    //     The instant r0 is non-null it is an OPEN reference the verifier tracks
    //     until released on EVERY path to exit().
    b.emit(Insn.call(.ringbuf_reserve));
    // (3) Null-check. On the NULL path NO reference was acquired, so it may go
    //     straight to exit() without a submit/discard. Target = exit index.
    const jeq_idx = b.reserve();
    // (4) Zero-fill the reserved record so no uninitialized kernel memory is
    //     published to userspace. Every write stays within [r0, r0+record_size)
    //     — PTR_TO_ALLOC_MEM is bounds-tracked exactly like PTR_TO_MAP_VALUE.
    //     `st` (store-immediate) needs no scratch register. 8-byte chunks, then
    //     a byte tail for any non-multiple-of-8 record.
    var written: i16 = 0;
    const rec_end: i16 = @intCast(opts.record_size);
    while (rec_end - written >= 8) : (written += 8) {
        b.emit(Insn.st(.double_word, R.r0, written, 0));
    }
    while (written < rec_end) : (written += 1) {
        b.emit(Insn.st(.byte, R.r0, written, 0));
    }
    // (5) Release the reference on the success path: bpf_ringbuf_submit(r0, 0).
    //     Passing the reserved pointer to submit/discard is what the verifier
    //     counts as the release — reaching exit() with it still open is
    //     "Unreleased reference id=…". (discard(r0,0) is the drop-instead-of-
    //     publish variant; a post-reserve error path would jump to a discard
    //     rather than skipping past this submit — this minimal program has no
    //     such branch, so submit on the sole success path suffices.)
    b.emit(Insn.mov(R.r1, R.r0));
    b.emit(Insn.mov(R.r2, 0));
    b.emit(Insn.call(.ringbuf_submit));
    // (6) return 0 + the single shared exit (also the null-path target).
    const exit_idx = b.len();
    b.emit(Insn.mov(R.r0, 0));
    b.emit(Insn.exit());

    b.patchJumpTo(jeq_idx, Insn.jeq(R.r0, 0, 0), exit_idx);
    return b.slice();
}

// ── shared instruction-buffer helper ─────────────────────────────────────────
//
// See the storage contract on `kprobeCounter`: builders return a slice into a
// file-scope buffer (fixed signature = no allocator/caller buffer, runtime fd
// must be baked into the stream). One buffer per builder so distinct program
// types don't clobber each other; `.single_owner` covers the same-builder-twice
// case. Buffers are generously sized for the fixed, small programs here.

var kprobe_buf: [16]Insn = undefined;
var xdp_buf: [64]Insn = undefined;
var ringbuf_buf: [128]Insn = undefined;

/// Tiny append-and-patch cursor over a fixed backing buffer. Offsets in emitted
/// jumps are computed as `target_index - (jump_index + 1)`, in instruction
/// SLOTS (an `ld_map_fd` pair occupies two slots), matching the verifier's pc
/// model.
const Buf = struct {
    buf: []Insn,
    n: usize = 0,

    fn emit(self: *Buf, insn: Insn) void {
        // Defense in depth: callers (`xdpFilter`/`ringbufEmit`) validate
        // caller-supplied sizes against buffer capacity BEFORE emitting, so
        // this should never fire. If it does, that's an internal invariant
        // violation (a builder's own instruction-count arithmetic is wrong),
        // not attacker input — fail loudly (also in ReleaseFast) rather than
        // silently corrupting the adjacent file-scope buffer.
        if (self.n >= self.buf.len) @panic("ebpf.Buf.emit: instruction buffer capacity exceeded");
        self.buf[self.n] = insn;
        self.n += 1;
    }

    /// Reserve one slot for a forward jump whose target isn't known yet; returns
    /// its index for a later `patchJumpTo`.
    fn reserve(self: *Buf) usize {
        if (self.n >= self.buf.len) @panic("ebpf.Buf.reserve: instruction buffer capacity exceeded");
        const idx = self.n;
        self.buf[self.n] = Insn.ja(0); // placeholder, overwritten by patch
        self.n += 1;
        return idx;
    }

    fn len(self: *const Buf) usize {
        return self.n;
    }

    /// Overwrite a reserved slot with `template` retargeted to `target` index,
    /// computing the pc-relative offset. `template`'s own `.off` is ignored.
    fn patchJumpTo(self: *Buf, jump_idx: usize, template: Insn, target: usize) void {
        var insn = template;
        insn.off = @intCast(@as(isize, @intCast(target)) - @as(isize, @intCast(jump_idx)) - 1);
        self.buf[jump_idx] = insn;
    }

    fn slice(self: *const Buf) []const Insn {
        return self.buf[0..self.n];
    }
};

// ── tests ────────────────────────────────────────────────────────────────────
//
// Two layers, matching SPEC.md's two validation questions:
//   * Offline golden-vector + structural tests (always run, no privilege): each
//     builder's output is asserted byte-exact against a hand-derived,
//     clang-cross-checked sequence, plus targeted checks of the verifier-
//     critical structure (xdp bounds-check dominance, ringbuf release-on-all-
//     paths). These prove the encoder is DETERMINISTIC and matches a known-good
//     shape without needing a kernel.
//   * A privileged real-load test (gated on CAP_BPF/root, SKIPS otherwise) that
//     hands all three programs to the live in-kernel verifier via load.zig —
//     the only thing that proves the current kernel actually ACCEPTS them.
// See `../SPEC.md` "Golden vectors" for the clang -target bpf + llvm-objdump /
// bpftool prog dump xlated methodology used to obtain the reference shapes.

const testing = std.testing;
const builtin = @import("builtin");

// Golden vectors — PROVENANCE: hand-derived from the BPF ISA + verifier rules,
// then CROSS-CHECKED against `clang -21 -target bpf -O2` disassembly of the
// equivalent C (the SPEC.md methodology). Documented, intentional divergences
// from clang's output (both verifier-accepted, semantically identical):
//   * stores use ST-immediate (`st`, opcodes 0x62/0x7a/0x72) where clang loads a
//     zero into a register first and uses STX (0x63/0x7b) — this builder needs
//     no scratch register for a constant store.
//   * kprobe increment uses plain `xadd` (BPF_ATOMIC add, no fetch; imm=0,
//     opcode 0xdb) vs clang's fetch-add for `__sync_fetch_and_add` (imm=1) — the
//     return value is unused, so the cheaper no-fetch atomic is correct.
//   * the xdp key copy is byte-wise loads/stores vs clang's shift-or reassembly
//     of a u32 — byte-wise is alignment-safe for any key_size.
// A byte-exact match to clang is therefore NOT expected or asserted; the golden
// is the verifier-critical STRUCTURE this builder commits to. The owner-gate's
// privileged real-load test (below) is what confirms current-kernel acceptance.
//
// Encodings spelled out as raw packed-struct fields (independent of the builder
// helpers) so a regression in `Insn.*`/the builders is caught, not masked.

const golden_kprobe_counter = [_]Insn{
    .{ .code = 0x62, .dst = 10, .src = 0, .off = -4, .imm = 0 }, // st  W   *(u32*)(r10-4) = 0
    .{ .code = 0xbf, .dst = 2, .src = 10, .off = 0, .imm = 0 }, // mov     r2 = r10
    .{ .code = 0x07, .dst = 2, .src = 0, .off = 0, .imm = -4 }, // add     r2 += -4
    .{ .code = 0x18, .dst = 1, .src = 1, .off = 0, .imm = 4 }, // ld_map_fd1 r1 = map(fd=4)
    .{ .code = 0x00, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // ld_map_fd2 (hi32)
    .{ .code = 0x85, .dst = 0, .src = 0, .off = 0, .imm = 1 }, // call    map_lookup_elem
    .{ .code = 0x15, .dst = 0, .src = 0, .off = 3, .imm = 0 }, // jeq     r0==0 -> exit
    .{ .code = 0xb7, .dst = 1, .src = 0, .off = 0, .imm = 1 }, // mov     r1 = 1
    .{ .code = 0xdb, .dst = 0, .src = 1, .off = 0, .imm = 0 }, // xadd    *(u64*)(r0) += r1
    .{ .code = 0xb7, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // mov     r0 = 0
    .{ .code = 0x95, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // exit
};

test "golden: kprobeCounter matches the hand-derived, clang-cross-checked sequence" {
    const insns = kprobeCounter(4);
    try testing.expectEqualSlices(Insn, &golden_kprobe_counter, insns);
}

const golden_xdp_filter = [_]Insn{
    .{ .code = 0x61, .dst = 2, .src = 1, .off = 4, .imm = 0 }, // ldx W  r2 = data_end
    .{ .code = 0x61, .dst = 1, .src = 1, .off = 0, .imm = 0 }, // ldx W  r1 = data
    .{ .code = 0xbf, .dst = 3, .src = 1, .off = 0, .imm = 0 }, // mov    r3 = data
    .{ .code = 0x07, .dst = 3, .src = 0, .off = 0, .imm = 30 }, // add   r3 += 26+4
    .{ .code = 0x2d, .dst = 3, .src = 2, .off = 16, .imm = 0 }, // jgt   r3 > data_end -> PASS
    .{ .code = 0x71, .dst = 4, .src = 1, .off = 26, .imm = 0 }, // ldx B r4 = data[26]
    .{ .code = 0x73, .dst = 10, .src = 4, .off = -4, .imm = 0 }, // stx B key[0]
    .{ .code = 0x71, .dst = 4, .src = 1, .off = 27, .imm = 0 }, // ldx B r4 = data[27]
    .{ .code = 0x73, .dst = 10, .src = 4, .off = -3, .imm = 0 }, // stx B key[1]
    .{ .code = 0x71, .dst = 4, .src = 1, .off = 28, .imm = 0 }, // ldx B r4 = data[28]
    .{ .code = 0x73, .dst = 10, .src = 4, .off = -2, .imm = 0 }, // stx B key[2]
    .{ .code = 0x71, .dst = 4, .src = 1, .off = 29, .imm = 0 }, // ldx B r4 = data[29]
    .{ .code = 0x73, .dst = 10, .src = 4, .off = -1, .imm = 0 }, // stx B key[3]
    .{ .code = 0xbf, .dst = 2, .src = 10, .off = 0, .imm = 0 }, // mov   r2 = r10
    .{ .code = 0x07, .dst = 2, .src = 0, .off = 0, .imm = -4 }, // add   r2 += -4
    .{ .code = 0x18, .dst = 1, .src = 1, .off = 0, .imm = 3 }, // ld_map_fd1 r1 = map(fd=3)
    .{ .code = 0x00, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // ld_map_fd2 (hi32)
    .{ .code = 0x85, .dst = 0, .src = 0, .off = 0, .imm = 1 }, // call  map_lookup_elem
    .{ .code = 0x15, .dst = 0, .src = 0, .off = 2, .imm = 0 }, // jeq   r0==0 -> PASS
    .{ .code = 0xb7, .dst = 0, .src = 0, .off = 0, .imm = 1 }, // mov   r0 = XDP_DROP
    .{ .code = 0x95, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // exit
    .{ .code = 0xb7, .dst = 0, .src = 0, .off = 0, .imm = 2 }, // mov   r0 = XDP_PASS
    .{ .code = 0x95, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // exit
};

test "golden: xdpFilter matches the hand-derived, clang-cross-checked sequence" {
    const insns = try xdpFilter(.{ .block_map_fd = 3, .key_offset = 26, .key_size = 4 });
    try testing.expectEqualSlices(Insn, &golden_xdp_filter, insns);
}

const golden_ringbuf_emit = [_]Insn{
    .{ .code = 0x18, .dst = 1, .src = 1, .off = 0, .imm = 5 }, // ld_map_fd1 r1 = map(fd=5)
    .{ .code = 0x00, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // ld_map_fd2 (hi32)
    .{ .code = 0xb7, .dst = 2, .src = 0, .off = 0, .imm = 16 }, // mov  r2 = 16 (const size)
    .{ .code = 0xb7, .dst = 3, .src = 0, .off = 0, .imm = 0 }, // mov   r3 = 0 (flags)
    .{ .code = 0x85, .dst = 0, .src = 0, .off = 0, .imm = 131 }, // call ringbuf_reserve
    .{ .code = 0x15, .dst = 0, .src = 0, .off = 5, .imm = 0 }, // jeq   r0==0 -> tail (mov r0,0; exit)
    .{ .code = 0x7a, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // st DW *(u64*)(r0+0) = 0
    .{ .code = 0x7a, .dst = 0, .src = 0, .off = 8, .imm = 0 }, // st DW *(u64*)(r0+8) = 0
    .{ .code = 0xbf, .dst = 1, .src = 0, .off = 0, .imm = 0 }, // mov   r1 = r0
    .{ .code = 0xb7, .dst = 2, .src = 0, .off = 0, .imm = 0 }, // mov   r2 = 0 (flags)
    .{ .code = 0x85, .dst = 0, .src = 0, .off = 0, .imm = 132 }, // call ringbuf_submit
    .{ .code = 0xb7, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // mov   r0 = 0
    .{ .code = 0x95, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // exit
};

test "golden: ringbufEmit matches the hand-derived, clang-cross-checked sequence" {
    const insns = try ringbufEmit(.{ .ringbuf_map_fd = 5, .record_size = 16 });
    try testing.expectEqualSlices(Insn, &golden_ringbuf_emit, insns);
}

test "xdpFilter: bounds-check dominates every packet read + forward jumps land on XDP_PASS" {
    const insns = try xdpFilter(.{ .block_map_fd = 7, .key_offset = 26, .key_size = 4 });
    // Locate the jgt bounds check and every packet-byte load (ldx from r1).
    var jgt_i: ?usize = null;
    for (insns, 0..) |ins, i| {
        if (ins.code == 0x2d) jgt_i = i; // JMP|JGT|X
    }
    try testing.expect(jgt_i != null);
    // Every ldx-from-packet (src=1, a byte load, code 0x71) must come AFTER the
    // dominating bounds check — this is the property the verifier enforces.
    for (insns, 0..) |ins, i| {
        if (ins.code == 0x71 and ins.src == 1) try testing.expect(i > jgt_i.?);
    }
    // Both forward jumps (jgt at bounds-fail, jeq at map-miss) target the same
    // XDP_PASS instruction (mov r0,2 followed by exit).
    for (insns, 0..) |ins, i| {
        if (ins.code == 0x2d or (ins.code == 0x15 and ins.dst == 0)) {
            const target = i + 1 + @as(usize, @intCast(ins.off));
            try testing.expectEqual(@as(i32, 2), insns[target].imm); // XDP_PASS
            try testing.expectEqual(@as(u8, 0x95), insns[target + 1].code); // exit
        }
    }
}

test "ringbufEmit: reserve reference released on the success path; null path holds none" {
    const insns = try ringbufEmit(.{ .ringbuf_map_fd = 9, .record_size = 24 });
    // Exactly one reserve and one submit/discard on the success path.
    var reserves: usize = 0;
    var releases: usize = 0;
    for (insns) |ins| {
        if (ins.code == 0x85 and ins.imm == 131) reserves += 1; // ringbuf_reserve
        if (ins.code == 0x85 and (ins.imm == 132 or ins.imm == 133)) releases += 1; // submit/discard
    }
    try testing.expectEqual(@as(usize, 1), reserves);
    try testing.expectEqual(@as(usize, 1), releases);
    // The null-check jumps forward PAST the submit straight to exit — proving
    // the null path (which holds no reference) never double-releases.
    var jeq_i: usize = 0;
    var submit_i: usize = 0;
    for (insns, 0..) |ins, i| {
        if (ins.code == 0x15 and ins.dst == 0) jeq_i = i;
        if (ins.code == 0x85 and ins.imm == 132) submit_i = i;
    }
    const jeq_target = jeq_i + 1 + @as(usize, @intCast(insns[jeq_i].off));
    try testing.expect(submit_i < jeq_target); // null path skips the submit
    // Null path lands on the shared tail (mov r0,0) which falls into exit() —
    // r0 is forced to 0 and no reference is released a second time.
    try testing.expectEqual(@as(u8, 0xb7), insns[jeq_target].code); // mov r0, imm
    try testing.expectEqual(@as(u4, 0), insns[jeq_target].dst);
    try testing.expectEqual(@as(i32, 0), insns[jeq_target].imm);
    try testing.expectEqual(@as(u8, 0x95), insns[jeq_target + 1].code); // exit
}

test "ringbufEmit: record_size not a multiple of 8 uses a byte tail, all writes in-bounds" {
    const insns = try ringbufEmit(.{ .ringbuf_map_fd = 3, .record_size = 12 });
    var max_off: i16 = -1;
    var dw_stores: usize = 0;
    var b_stores: usize = 0;
    for (insns) |ins| {
        if (ins.code == 0x7a) { // st DW into r0
            dw_stores += 1;
            if (ins.off + 8 > max_off) max_off = ins.off + 8;
        }
        if (ins.code == 0x72) { // st B into r0
            b_stores += 1;
            if (ins.off + 1 > max_off) max_off = ins.off + 1;
        }
    }
    try testing.expectEqual(@as(usize, 1), dw_stores); // one 8-byte chunk
    try testing.expectEqual(@as(usize, 4), b_stores); // + 4-byte tail
    try testing.expectEqual(@as(i16, 12), max_off); // writes cover exactly [0,12)
}

test "ringbufEmit: over-capacity record_size is rejected, not an OOB write" {
    // Reproduces the audit's finding: record_size = 1024 used to run the
    // zero-fill loop straight past `ringbuf_buf`'s 128-slot capacity
    // (`index out of bounds: index 128, len 128` in Debug/ReleaseSafe; a
    // silent OOB write into adjacent globals under ReleaseFast). Must now
    // fail closed with a typed error instead.
    try testing.expectError(error.RecordTooLarge, ringbufEmit(.{ .ringbuf_map_fd = 5, .record_size = 1024 }));
    // A comfortably in-range size still works (regression guard on the
    // capacity check itself being too strict).
    _ = try ringbufEmit(.{ .ringbuf_map_fd = 5, .record_size = 64 });
}

test "ringbufEmit: record_size large enough to overflow the i32/i16 @intCasts is rejected" {
    // Separately from the buffer-capacity path: a record_size this large
    // used to panic at `@intCast(opts.record_size)` (the `size`/`rec_end`
    // locals) before the zero-fill loop was even reached.
    try testing.expectError(error.RecordTooLarge, ringbufEmit(.{ .ringbuf_map_fd = 5, .record_size = std.math.maxInt(u32) }));
}

test "xdpFilter: over-capacity key_size is rejected, not an OOB write" {
    // A key_size large enough that the 2-instructions-per-byte copy loop
    // would overflow `xdp_buf`'s 64-slot capacity must fail closed.
    try testing.expectError(
        error.KeyTooLarge,
        xdpFilter(.{ .block_map_fd = 3, .key_offset = 26, .key_size = 64 }),
    );
    // A comfortably in-range key_size still works.
    _ = try xdpFilter(.{ .block_map_fd = 3, .key_offset = 26, .key_size = 4 });
}

test "xdpFilter: key_offset large enough to overflow the i16 @intCast is rejected" {
    // key_offset > maxInt(i16) used to panic at `@intCast(opts.key_offset)`
    // (the `off` local) regardless of key_size.
    try testing.expectError(
        error.KeyOffsetTooLarge,
        xdpFilter(.{ .block_map_fd = 3, .key_offset = 65000, .key_size = 4 }),
    );
}

/// Privileged, capability-gated real-load test: build each program and hand it
/// to the in-kernel verifier via `load.zig`. Skips (does NOT fail) without
/// CAP_BPF/root, so CI/sandbox runs degrade gracefully — an unprivileged pass
/// asserts the golden/structure only, NOT that the verifier accepted anything.
fn hasBpfCapability() bool {
    return linux.geteuid() == 0;
}

test "load: all three FABLE programs pass the in-kernel verifier (needs CAP_BPF/root)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) return error.SkipZigTest;

    const load = @import("load.zig").load;

    // kprobe-counter over a PERCPU_ARRAY (key 4, value 8, 1 slot).
    {
        const map_fd = BPF.map_create(.percpu_array, 4, 8, 1) catch |e| switch (e) {
            error.PermissionDenied => return error.SkipZigTest,
            else => return e,
        };
        defer _ = linux.close(map_fd);
        const prog: Program = .{ .prog_type = .kprobe, .insns = kprobeCounter(map_fd) };
        const fd = try load(prog, "MIT");
        _ = linux.close(fd);
    }
    // xdp-filter over a HASH block map (key 4, value 1).
    {
        const map_fd = BPF.map_create(.hash, 4, 1, 64) catch |e| switch (e) {
            error.PermissionDenied => return error.SkipZigTest,
            else => return e,
        };
        defer _ = linux.close(map_fd);
        const prog: Program = .{
            .prog_type = .xdp,
            .insns = try xdpFilter(.{ .block_map_fd = map_fd, .key_offset = 26, .key_size = 4 }),
        };
        const fd = try load(prog, "MIT");
        _ = linux.close(fd);
    }
    // ringbuf-emit over a RINGBUF map (key/value 0, size a power of two).
    {
        const map_fd = BPF.map_create(.ringbuf, 0, 0, 4096) catch |e| switch (e) {
            error.PermissionDenied => return error.SkipZigTest,
            else => return e,
        };
        defer _ = linux.close(map_fd);
        const prog: Program = .{
            .prog_type = .kprobe,
            .insns = try ringbufEmit(.{ .ringbuf_map_fd = map_fd, .record_size = 16 }),
        };
        const fd = try load(prog, "MIT");
        _ = linux.close(fd);
    }
}

test "Program/Options structs have the shape the load/attach layers expect" {
    // A structural smoke test that does not touch any panicking builder:
    // confirms the fixed contract (Program.{prog_type,insns},
    // XdpFilterOptions/RingbufEmitOptions field names) compiles and is
    // usable by load.zig/attach.zig without needing the builders to run.
    const p: Program = .{ .prog_type = .kprobe, .insns = &.{Insn.exit()} };
    try testing.expectEqual(BPF.ProgType.kprobe, p.prog_type);
    try testing.expectEqual(@as(usize, 1), p.insns.len);

    const xo: XdpFilterOptions = .{ .block_map_fd = 3, .key_offset = 26, .key_size = 4 };
    try testing.expectEqual(@as(u16, 26), xo.key_offset);

    const ro: RingbufEmitOptions = .{ .ringbuf_map_fd = 3, .record_size = 16 };
    try testing.expectEqual(@as(u32, 16), ro.record_size);
}
