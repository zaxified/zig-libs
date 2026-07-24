// SPDX-License-Identifier: MIT
//! Classifier program builder — composes `ebpf`'s already-verifier-proven
//! primitives (bounds-check dominance for direct packet access, the
//! `ld_map_fd`/`ARG_PTR_TO_MAP_KEY`/null-check-before-deref map-lookup
//! discipline) into a NEW fixed program: parse Ethernet+IPv4, extract a
//! source or destination /32 lookup key, resolve it against a
//! `BPF_MAP_TYPE_LPM_TRIE` ruleset map, and stash the resulting class
//! handle into a scratch map before returning `XDP_PASS`.
//!
//! **No Fable-tier core here — see `../README.md`'s "Tier verdict" section
//! for the full argument.** Short version: every verifier-hard PATTERN this
//! program needs (`ctx->data`/`ctx->data_end` retyping, bounds-check
//! dominance over a packet region, the map-lookup pseudo-fd/initialized-
//! key/null-check-before-deref discipline) is already implemented,
//! golden-tested, and CAP_BPF-load-verified in the sibling `ebpf` module's
//! `programs.zig` (`xdpFilter`/`kprobeCounter`) — this function does not
//! invent a new pattern, it SEQUENCES the same ones at different packet
//! offsets, with more fields read under one bounds check, and with an
//! LPM-shaped key instead of an exact-match one. The bounds-check-then-parse
//! portion below was additionally cross-checked against `clang -O2 -target
//! bpf`'s own codegen for an equivalent C fragment (see the golden test's
//! provenance comment) — not just reasoned about by analogy.

const std = @import("std");
const ebpf = @import("ebpf");
const Insn = ebpf.Insn;
const linux = std.os.linux;

/// Which packet field the LPM lookup key is drawn from.
pub const KeyField = enum {
    src,
    dst,

    /// Byte offset from the start of the packet (Ethernet frame) — IPv4's
    /// fixed (no-options) header places `saddr` at header-offset 12 and
    /// `daddr` at 16, plus the 14-byte Ethernet header ahead of it.
    fn offset(self: KeyField) i16 {
        return switch (self) {
            .src => 26,
            .dst => 30,
        };
    }
};

/// Fixed contract for `buildClassifierProgram` — a struct, not positional
/// args, matching this repo's convention for multi-field program options
/// (see `ebpf.XdpFilterOptions`'s doc comment for the rationale).
pub const ClassifierOptions = struct {
    /// `BPF_MAP_TYPE_LPM_TRIE` fd (see `maps.createLpmTrieMap`). Key =
    /// `rules.LpmKey` (8 bytes: native-endian `u32` prefixlen + 4-byte IPv4
    /// address — see `rules.LpmKey.toBytes`), value = a `u32` class handle.
    lpm_map_fd: linux.fd_t,
    /// A single-slot `BPF_MAP_TYPE_PERCPU_ARRAY` (key = `u32` 0, see
    /// `maps.createScratchMap`) this program writes the resolved class
    /// handle into on every packet. PERCPU, not a plain ARRAY, so packets
    /// classified concurrently on different RX queues/CPUs never race on
    /// the same shared slot — the same tradeoff `ebpf.kprobeCounter`'s doc
    /// comment discusses for its counter map (see there for the general
    /// pattern this mirrors).
    scratch_map_fd: linux.fd_t,
    /// Which IPv4 address field the lookup key is drawn from.
    key_field: KeyField = .src,
    /// Class handle written for a packet that fails any parse/bounds check
    /// (too short, non-IPv4 EtherType, IPv4 options present — see
    /// `../README.md` "Scope") OR finds no LPM match. Callers conventionally
    /// reserve 0 for "unclassified / best-effort".
    default_class: u32 = 0,
};

const XDP_PASS: i32 = 2;

/// IPv4's EtherType (0x0800) as it appears after a PLAIN (non-byte-swapping)
/// load of the two wire bytes, on THIS host's endianness — see
/// `buildClassifierProgram`'s doc comment point 1 for why this is not
/// simply `0x0800`. Comptime-evaluable (`builtin.cpu.arch.endian()` is
/// known at compile time), so this is a single fixed instruction immediate,
/// not a per-call computation.
const ethertype_ipv4_native: u16 = std.mem.bigToNative(u16, 0x0800);

/// Build the `xdp-classifier` program described in `../README.md`.
///
/// `BPF_PROG_TYPE_XDP` — same context shape `ebpf.xdpFilter` documents in
/// full (`ctx->data`/`ctx->data_end` special-cased loads, bounds-check
/// dominance; see `ebpf`'s `programs.zig`). This function's own contract,
/// precisely:
///
///  1. **EtherType byte order.** `ldx half_word` is a PLAIN memory load — it
///     does NOT convert network (big-endian) byte order to anything. IPv4's
///     EtherType wire bytes are `[0x08, 0x00]`; loading them as a native u16
///     on a little-endian host yields `0x0008`, not `0x0800`.
///     `std.mem.bigToNative(u16, 0x0800)` is exactly the "big-endian wire
///     bytes, read natively" conversion, so `ethertype_ipv4_native` is the
///     correct comparison constant on any host endianness — confirmed
///     against `clang -O2 -target bpf`'s own codegen for the equivalent C
///     comparison (`if (eth_proto != 0x0008)` on this little-endian build
///     host; see the golden test's provenance comment below).
///  2. **One bounds check dominates every packet read.** `[data, data+34)`
///     covers the 14-byte Ethernet header AND the 20-byte fixed (no
///     options) IPv4 header in a SINGLE dominance check, exactly the
///     "derive region-end by a plain ADD from the compared register, check
///     BEFORE any read" pattern `ebpf.xdpFilter`'s doc comment names as the
///     single most load-bearing XDP verifier subtlety — reused verbatim
///     here, just for a wider region covering more downstream fields
///     (EtherType at +12, IHL at +14, src/dst IPv4 at +26/+30) instead of
///     `xdpFilter`'s one fixed field. `clang -O2 -target bpf` compiles the
///     equivalent C bounds check to the identical instruction shape (mov +
///     add-immediate-34 + jgt against the SAME two registers) — see the
///     golden test below.
///  3. **IPv4 options are out of scope for v1** (see `../README.md`
///     "Scope"): this program checks the IHL nibble equals 5 (a plain
///     20-byte header, the overwhelming majority of real traffic) and falls
///     to `opts.default_class` otherwise, rather than computing a
///     variable-length header offset. IPv6 is likewise out of scope — both
///     are documented, ADDITIVE extensions (a new bounds-check-and-parse
///     block following this same pattern), not a redesign of what's here.
///  4. **LPM key construction** copies `opts.key_field`'s 4 address bytes
///     byte-wise into the stack (identical technique to `ebpf.xdpFilter`'s
///     key copy — alignment-safe, dominated by the same bounds check) and
///     prepends a native-endian `u32` prefixlen of 32 (an exact-`/32`
///     lookup key — the `BPF_MAP_TYPE_LPM_TRIE` map itself performs the
///     longest-prefix search against however-specific the ruleset's stored
///     entries are; this program never needs to know the matched entry's
///     actual prefix length, only that ONE key format is used both here and
///     when rules are loaded into the map — see `rules.LpmKey`, which is
///     the single source of truth both sides commit to).
///  5. **Two map lookups, same null-check-before-deref discipline as
///     `ebpf.kprobeCounter`/`ebpf.xdpFilter`**: the LPM lookup (a miss falls
///     to `opts.default_class`, indistinguishable from a parse/bounds
///     failure — see design note below) and the scratch-map write-back (its
///     one slot always exists for a correctly created 1-entry
///     `PERCPU_ARRAY`, but the null check is kept anyway — defensive,
///     matches this repo's established discipline of never assuming a map
///     lookup can't fail).
///  6. **Class register survives across BOTH helper calls.** The matched
///     (or default) class value is held in `r6` — a CALLEE-SAVED register
///     per the BPF helper calling convention (helpers clobber `r0`-`r5`,
///     never `r6`-`r9`/`r10`); it is set once (from the LPM lookup's result,
///     or the default-class immediate) and must still be intact after the
///     SECOND `bpf_map_lookup_elem` call (the scratch-map lookup) for the
///     final `stx` to write the right value. Using a caller-saved register
///     here would be a genuine, easy-to-miss correctness bug the verifier
///     does NOT flag (an overwritten `r6` is still a valid scalar from the
///     verifier's point of view — this is a helper-ABI correctness
///     requirement, not a verifier-rejection risk, the same category
///     `ebpf.kprobeCounter`'s atomic-increment note documents).
///  7. **Always returns `XDP_PASS`.** This program classifies, it does not
///     filter — `opts.default_class` or a matched class is written to
///     `opts.scratch_map_fd` either way and the packet continues up the
///     stack (to `tc`/a queueing discipline that reads the classification,
///     in a LibreQoS-style deployment). A DROP-on-no-match variant would be
///     a one-instruction change (the DEFAULT block's `mov r0, ...`) but is
///     deliberately not what this fixed contract commits to.
///
/// Design note on the shared DEFAULT class: a too-short packet, a non-IPv4
/// EtherType, an IPv4-with-options packet, and an LPM miss are all
/// deliberately indistinguishable at the output (all four write
/// `opts.default_class`) — a caller needing to tell them apart needs a
/// different, richer output shape (e.g. distinct class values per failure
/// reason, or a ring-buffer trace via `ebpf.ringbufEmit`); collapsing them
/// to one "not specifically classified" bucket is the right default for a
/// shaper (per `../README.md`'s LibreQoS framing, an unclassified packet
/// gets best-effort treatment, full stop, regardless of WHY it wasn't
/// classified).
pub fn buildClassifierProgram(opts: ClassifierOptions) []const Insn {
    const R = Insn.Reg;
    const key_off = opts.key_field.offset();

    var b: Buf = .{ .buf = &prog_buf };

    // (1) ctx->data_end then ctx->data — data_end MUST be read first, the
    //     second load clobbers r1 (ctx). The verifier retypes these exact
    //     ctx offsets to PTR_TO_PACKET_END / PTR_TO_PACKET (see
    //     ebpf.xdpFilter's doc comment point 1).
    b.emit(Insn.ldx(.word, R.r2, R.r1, 4)); // r2 = data_end
    b.emit(Insn.ldx(.word, R.r1, R.r1, 0)); // r1 = data

    // (2) Single dominating bounds check: [data, data+34) covers Ethernet
    //     (14) + fixed IPv4 (20). Every packet read below is at an offset
    //     < 34 and therefore proven safe by this ONE check (see doc comment
    //     point 2).
    b.emit(Insn.mov(R.r3, R.r1));
    b.emit(Insn.add(R.r3, 34));
    const bounds_jmp = b.reserve(); // jgt r3, r2 -> DEFAULT

    // (3) EtherType must be IPv4 (see doc comment point 1 for the constant).
    b.emit(Insn.ldx(.half_word, R.r4, R.r1, 12));
    const ethertype_jmp = b.reserve(); // jne r4, ethertype_ipv4_native -> DEFAULT

    // (4) IHL must be 5 (no options) — see doc comment point 3.
    b.emit(Insn.ldx(.byte, R.r4, R.r1, 14));
    b.emit(Insn.alu_and(R.r4, 0x0f));
    const ihl_jmp = b.reserve(); // jne r4, 5 -> DEFAULT

    // (5) Copy the 4 key-field address bytes into [r10-4, r10) — byte-wise,
    //     same alignment-safe technique as ebpf.xdpFilter's key copy, each
    //     read dominated by the single check above.
    var k: i16 = 0;
    while (k < 4) : (k += 1) {
        b.emit(Insn.ldx(.byte, R.r5, R.r1, key_off + k));
        b.emit(Insn.stx(.byte, R.r10, -4 + k, R.r5));
    }
    // Prefixlen = 32 (exact key width — see doc comment point 4). Native-
    // endian word store, matching rules.LpmKey.toBytes's encoding exactly;
    // both paths must agree, see rules.zig's module doc.
    b.emit(Insn.st(.word, R.r10, -8, 32));

    // (6) LPM lookup: r2 = &key (r10-8, 8 bytes: prefixlen+addr), r1 = map
    //     via pseudo-fd. Same discipline as ebpf.kprobeCounter/xdpFilter.
    b.emit(Insn.mov(R.r2, R.r10));
    b.emit(Insn.add(R.r2, -8));
    b.emit(Insn.ld_map_fd1(R.r1, opts.lpm_map_fd));
    b.emit(Insn.ld_map_fd2(opts.lpm_map_fd));
    b.emit(Insn.call(.map_lookup_elem));
    const lpm_miss_jmp = b.reserve(); // jeq r0, 0 -> DEFAULT

    // (7) Matched: r6 (callee-saved, see doc comment point 6) = *(u32*)(r0).
    //     r0 has verifier-tracked size == the map's value_size (4), so this
    //     load needs no further bounds check (same reasoning as
    //     ebpf.kprobeCounter's post-null-check deref).
    b.emit(Insn.ldx(.word, R.r6, R.r0, 0));
    const skip_default_jmp = b.reserve(); // ja -> TAIL

    // DEFAULT: any parse/bounds failure or LPM miss lands here.
    const default_idx = b.len();
    // opts.default_class is a u32; MOV64's immediate form sign-extends a
    // 32-bit imm, so @intCast would spuriously panic for any value >=
    // 0x8000_0000 (out of i32's range) even though that value is perfectly
    // valid as a class handle. @bitCast reinterprets the same 32 bits
    // instead — correct here because only the low 32 bits are ever read
    // back out (the final `stx .word` below stores exactly those bits; the
    // sign-extended upper 32 bits of r6 are never observed).
    b.emit(Insn.mov(R.r6, @as(i32, @bitCast(opts.default_class))));

    // TAIL: write r6 (matched-or-default class) to the scratch map.
    const tail_idx = b.len();
    b.emit(Insn.st(.word, R.r10, -4, 0)); // scratch key = 0 (stack region reused — the LPM lookup above is done reading it)
    b.emit(Insn.mov(R.r2, R.r10));
    b.emit(Insn.add(R.r2, -4));
    b.emit(Insn.ld_map_fd1(R.r1, opts.scratch_map_fd));
    b.emit(Insn.ld_map_fd2(opts.scratch_map_fd));
    b.emit(Insn.call(.map_lookup_elem));
    const scratch_miss_jmp = b.reserve(); // jeq r0, 0 -> SKIP_WRITE
    b.emit(Insn.stx(.word, R.r0, 0, R.r6));

    const skip_write_idx = b.len();
    b.emit(Insn.mov(R.r0, XDP_PASS));
    b.emit(Insn.exit());

    b.patchJumpTo(bounds_jmp, Insn.jgt(R.r3, R.r2, 0), default_idx);
    b.patchJumpTo(ethertype_jmp, Insn.jne(R.r4, @as(i32, ethertype_ipv4_native), 0), default_idx);
    b.patchJumpTo(ihl_jmp, Insn.jne(R.r4, @as(i32, 5), 0), default_idx);
    b.patchJumpTo(lpm_miss_jmp, Insn.jeq(R.r0, 0, 0), default_idx);
    b.patchJumpTo(skip_default_jmp, Insn.ja(0), tail_idx);
    b.patchJumpTo(scratch_miss_jmp, Insn.jeq(R.r0, 0, 0), skip_write_idx);

    return b.slice();
}

// Storage contract, matching ebpf.programs.zig's builders exactly: the
// returned slice points into a file-scope buffer, not heap (no allocator in
// the fixed signature, and runtime fd values must be baked into the `ld_
// map_fd` immediates). Build-then-load; a second call overwrites the first
// call's slice (see ebpf.kprobeCounter's doc comment for the full rationale
// — this module's `.concurrency = .single_owner` mirrors ebpf's).
var prog_buf: [64]Insn = undefined;

/// Tiny append-and-patch cursor over a fixed backing buffer — the same
/// shape as ebpf.programs.zig's private `Buf` helper (not exported by
/// `ebpf`, so this is a from-scratch, independently-written equivalent, not
/// a copy). Offsets in emitted jumps are computed as `target_index -
/// (jump_index + 1)`, in instruction SLOTS (an `ld_map_fd` pair occupies two
/// slots), matching the verifier's pc model.
const Buf = struct {
    buf: []Insn,
    n: usize = 0,

    fn emit(self: *Buf, insn: Insn) void {
        self.buf[self.n] = insn;
        self.n += 1;
    }

    fn reserve(self: *Buf) usize {
        const idx = self.n;
        self.buf[self.n] = Insn.ja(0); // placeholder, overwritten by patch
        self.n += 1;
        return idx;
    }

    fn len(self: *const Buf) usize {
        return self.n;
    }

    fn patchJumpTo(self: *Buf, jump_idx: usize, template: Insn, target: usize) void {
        var insn = template;
        insn.off = @intCast(@as(isize, @intCast(target)) - @as(isize, @intCast(jump_idx)) - 1);
        self.buf[jump_idx] = insn;
    }

    fn slice(self: *const Buf) []const Insn {
        return self.buf[0..self.n];
    }
};

// ── CPUMAP steering: redirect a matched flow to a chosen CPU ────────────────
//
// The classifier above stashes a class handle and returns XDP_PASS; this
// second builder is the piece that actually STEERS a flow, the last shaper
// primitive in the LibreQoS pipeline
// (`XDP bpf_redirect_map(&cpumap, cpu) -> BPF_MAP_TYPE_CPUMAP -> per-CPU tc
// MQ/HTB tree`). It reuses this file's exact house patterns — the same
// `ctx`-decode + single dominating bounds check + EtherType/IHL parse + LPM
// lookup as `buildClassifierProgram` — and appends a `bpf_redirect_map` tail
// instead of a scratch write.

const XDP_PASS_action: i32 = 2; // == XDP_PASS; used as the redirect fallback

/// Fixed contract for `buildCpumapSteerProgram`, same struct-not-positional
/// convention as `ClassifierOptions`.
pub const CpumapSteerOptions = struct {
    /// `BPF_MAP_TYPE_LPM_TRIE` fd — the SAME ruleset map `buildClassifierProgram`
    /// uses (see `ClassifierOptions.lpm_map_fd` / `maps.createLpmTrieMap`). The
    /// matched `u32` value is the class handle whose reduction picks the CPU
    /// (see the CPU-selection note below).
    lpm_map_fd: linux.fd_t,
    /// `BPF_MAP_TYPE_CPUMAP` fd (see `maps.createCpuMap`) this program redirects
    /// into. Its `max_entries` should be `cpu_count`, and every slot
    /// `0..cpu_count` should be populated (`maps.populateCpu`) — an unpopulated
    /// slot is a runtime redirect miss that falls back to `redirect_flags`
    /// (see below), not a verifier problem.
    cpumap_fd: linux.fd_t,
    /// Number of CPUs the ruleset's class handles are reduced onto. The target
    /// CPU is `class % cpu_count` (see the CPU-selection note). Must be
    /// non-zero — a 0 divisor is both a build error here and a verifier
    /// rejection (BPF_MOD by zero); `buildCpumapSteerProgram` returns
    /// `SteerBuildError.InvalidCpuCount` for it.
    cpu_count: u32,
    /// Which IPv4 address field the LPM key is drawn from — same meaning and
    /// same 26/30 offsets as `ClassifierOptions.key_field`. `.src` keys on the
    /// subscriber's source address (the LibreQoS default for upstream/egress
    /// classification).
    key_field: KeyField = .src,
    /// The `flags` argument to `bpf_redirect_map(map, key, flags)`. Kept 0 by
    /// default — the most portable value, accepted by every kernel. On kernels
    /// with the redirect-fallback-action feature (>= 5.15), a caller may set
    /// this to `XDP_PASS` (2) so a redirect into an unpopulated CPUMAP slot
    /// returns XDP_PASS instead of XDP_ABORTED; this program never depends on
    /// that (it reduces the key with `% cpu_count` so the index is always in
    /// range, and a fully populated map has no miss), it is exposed only so a
    /// defensive caller can opt in.
    redirect_flags: u32 = 0,
};

pub const SteerBuildError = error{
    /// `cpu_count == 0` — see `CpumapSteerOptions.cpu_count`.
    InvalidCpuCount,
};

/// Build the redirect-to-CPUMAP steering program.
///
/// `BPF_PROG_TYPE_XDP`. For each packet it parses Ethernet+IPv4 (the IDENTICAL
/// `ctx`-decode + single dominating `[data, data+34)` bounds check + EtherType
/// + IHL-must-be-5 sequence as `buildClassifierProgram` — see that function's
/// doc comment points 1-4, reused verbatim here), does the SAME LPM lookup on
/// `opts.key_field`'s /32 key, and then:
///
///  - **CPU-selection policy: class-reduced, not per-flow-hashed.** The matched
///    class handle `c` selects CPU `c % opts.cpu_count`. This mirrors real
///    LibreQoS, whose XDP program takes the CPU straight from a per-subscriber
///    prefix lookup (NOT a per-flow RSS hash): every packet of a subscriber's
///    prefix resolves to the same class, hence the same CPU, hence the same
///    per-CPU MQ/HTB tree a downstream `tc`/`tcplan` stage shapes. A per-flow
///    5-tuple hash would keep each *flow* on one CPU but SPLIT one subscriber
///    across CPUs, breaking the per-subscriber shaping invariant — so it is
///    deliberately not used. A deployment wanting an explicit class->CPU table
///    stores CPU-valued handles (`c < cpu_count`, so `c % cpu_count == c`).
///  - **Redirect + fallback.** `r2 = class`, `r2 %= cpu_count` (always in
///    range), then `bpf_redirect_map(&cpumap, r2, opts.redirect_flags)`; the
///    program returns the helper's result (`XDP_REDIRECT` on success). Every
///    OTHER path — too-short packet, non-IPv4 EtherType, IPv4 options, or an
///    LPM miss — returns `XDP_PASS`, the safe fallback (the packet continues up
///    the normal stack, exactly the classifier's "unclassified = best-effort"
///    default).
///
/// Returns `SteerBuildError.InvalidCpuCount` if `opts.cpu_count == 0`. Same
/// file-scope-buffer storage contract as `buildClassifierProgram`, but a
/// SEPARATE buffer (`steer_prog_buf`) so a caller may build and hold both a
/// classifier and a steer program at once.
pub fn buildCpumapSteerProgram(opts: CpumapSteerOptions) SteerBuildError![]const Insn {
    if (opts.cpu_count == 0) return SteerBuildError.InvalidCpuCount;

    const R = Insn.Reg;
    const key_off = opts.key_field.offset();

    var b: Buf = .{ .buf = &steer_prog_buf };

    // (1) ctx->data_end then ctx->data (data_end first — the second load
    //     clobbers r1). Same retype as buildClassifierProgram point 1.
    b.emit(Insn.ldx(.word, R.r2, R.r1, 4)); // r2 = data_end
    b.emit(Insn.ldx(.word, R.r1, R.r1, 0)); // r1 = data

    // (2) Single dominating bounds check: [data, data+34) covers Ethernet(14)
    //     + fixed IPv4(20). Reused verbatim from buildClassifierProgram
    //     point 2.
    b.emit(Insn.mov(R.r3, R.r1));
    b.emit(Insn.add(R.r3, 34));
    const bounds_jmp = b.reserve(); // jgt r3, r2 -> PASS

    // (3) EtherType must be IPv4 (point 1's native-endian constant).
    b.emit(Insn.ldx(.half_word, R.r4, R.r1, 12));
    const ethertype_jmp = b.reserve(); // jne r4, ipv4 -> PASS

    // (4) IHL must be 5 (no options) — point 3.
    b.emit(Insn.ldx(.byte, R.r4, R.r1, 14));
    b.emit(Insn.alu_and(R.r4, 0x0f));
    const ihl_jmp = b.reserve(); // jne r4, 5 -> PASS

    // (5) Copy the 4 key-field address bytes into [r10-4, r10) and prepend a
    //     native-endian prefixlen of 32 — identical to buildClassifierProgram
    //     point 4 (same rules.LpmKey byte layout both sides commit to).
    var k: i16 = 0;
    while (k < 4) : (k += 1) {
        b.emit(Insn.ldx(.byte, R.r5, R.r1, key_off + k));
        b.emit(Insn.stx(.byte, R.r10, -4 + k, R.r5));
    }
    b.emit(Insn.st(.word, R.r10, -8, 32));

    // (6) LPM lookup: r2 = &key, r1 = map via pseudo-fd (point 5 discipline).
    b.emit(Insn.mov(R.r2, R.r10));
    b.emit(Insn.add(R.r2, -8));
    b.emit(Insn.ld_map_fd1(R.r1, opts.lpm_map_fd));
    b.emit(Insn.ld_map_fd2(opts.lpm_map_fd));
    b.emit(Insn.call(.map_lookup_elem));
    const lpm_miss_jmp = b.reserve(); // jeq r0, 0 -> PASS

    // (7) Hit: class = *(u32*)(r0), loaded straight into r2 (the redirect KEY
    //     register), then reduced to a valid CPU index by `% cpu_count`. r0 is
    //     PTR_TO_MAP_VALUE here (null-checked above), size == value_size (4),
    //     so the word load needs no further bounds check — same reasoning as
    //     buildClassifierProgram point 7.
    b.emit(Insn.ldx(.word, R.r2, R.r0, 0));
    b.emit(Insn.alu(64, .mod, R.r2, @as(i32, @bitCast(opts.cpu_count))));

    // (8) redirect_map(&cpumap, cpu, flags): r1 = cpumap via pseudo-fd (this
    //     clobbers r1, harmless — r2 holds the key, preserved across the
    //     ld_map_fd pair and the flags mov), r3 = flags. The program returns
    //     the helper's result (XDP_REDIRECT on success). helper id 51.
    b.emit(Insn.ld_map_fd1(R.r1, opts.cpumap_fd));
    b.emit(Insn.ld_map_fd2(opts.cpumap_fd));
    b.emit(Insn.mov(R.r3, @as(i32, @bitCast(opts.redirect_flags))));
    b.emit(Insn.call(.redirect_map));
    b.emit(Insn.exit());

    // PASS: every parse/bounds failure or LPM miss lands here — safe fallback.
    const pass_idx = b.len();
    b.emit(Insn.mov(R.r0, XDP_PASS_action));
    b.emit(Insn.exit());

    b.patchJumpTo(bounds_jmp, Insn.jgt(R.r3, R.r2, 0), pass_idx);
    b.patchJumpTo(ethertype_jmp, Insn.jne(R.r4, @as(i32, ethertype_ipv4_native), 0), pass_idx);
    b.patchJumpTo(ihl_jmp, Insn.jne(R.r4, @as(i32, 5), 0), pass_idx);
    b.patchJumpTo(lpm_miss_jmp, Insn.jeq(R.r0, 0, 0), pass_idx);

    return b.slice();
}

// Separate file-scope buffer from `prog_buf` (see that buffer's storage
// contract) so a caller may build a classifier AND a steer program and hold
// both returned slices at once; a second buildCpumapSteerProgram call still
// overwrites the previous steer slice, same single_owner discipline.
var steer_prog_buf: [64]Insn = undefined;

// ── tests ────────────────────────────────────────────────────────────────────
//
// Same two layers as ebpf.programs.zig: an offline golden-vector +
// structural test (always runs, no privilege) and a CAP_BPF/root-gated
// real-load test (skips otherwise) against the live in-kernel verifier.

const testing = std.testing;
const builtin = @import("builtin");

// Golden vector — PROVENANCE: hand-derived from the BPF ISA (opcode/field
// values cross-referenced against std.os.linux.BPF's own constants), with
// the bounds-check/EtherType/IHL-check/byte-copy portion (instructions 0-17
// below) ADDITIONALLY cross-checked against real `clang -O2 -target bpf`
// disassembly of the equivalent C:
//
//   struct xdp_md { u32 data; u32 data_end; ... };
//   u8 *data = (u8*)(long)ctx->data, *data_end = (u8*)(long)ctx->data_end;
//   if (data + 34 > data_end) return DEFAULT;
//   u16 eth_proto = *(u16*)(data + 12);
//   u8 version_ihl = *(data + 14);
//   if (eth_proto != 0x0008) return DEFAULT;      // htons(0x0800) on LE
//   if ((version_ihl & 0x0f) != 5) return DEFAULT;
//   key[0..4] = data[26..30];                     // src field
//
// which clang compiles (verified in this repo's own dev environment via
// `clang -target bpf -O2 -c`, `llvm-objdump -d`) to the identical
// instruction SHAPE this builder emits: `w2=*(u32*)(r1+4)`,
// `w1=*(u32*)(r1+0)`, `r3=r1; r3+=0x22; if r3>r2 goto ...`,
// `w2=*(u16*)(r1+0xc)`, `if w2!=0x8 goto ...`, `w2=*(u8*)(r1+0xe); w2&=0xf;
// if w2!=0x5 goto ...`, then four `*(u8*)(r1+off)` reads at 0x1a-0x1d
// (26-29, exactly the src-field offsets this builder uses).
//
// The remaining instructions (18-37: LPM key/prefixlen construction, both
// map lookups, the class-register handoff, the scratch write, the XDP
// return) reuse — instruction-for-instruction, not just "the same idea" —
// the pseudo-map-fd/initialized-key/null-check-before-deref pattern already
// golden-tested AND CAP_BPF-load-verified in ebpf.programs.zig's
// kprobeCounter/xdpFilter (see this file's module doc); that pattern is not
// re-derived here, it is REUSED, so no fresh clang cross-check was needed
// for it. Documented, intentional divergences from clang's own choices
// (both verifier-accepted, semantically identical, matching ebpf's own
// "divergence" disclosure style): this builder uses full 64-bit ALU/JMP ops
// throughout (opcodes ending `f`/`5`/`7`) where clang's `-O2` narrows
// several of them to 32-bit sub-register forms (`w`-register mnemonics,
// e.g. `0x56`/`0x54` instead of `0x55`/`0x57`) — both are correct given
// every value compared here originates from a zero-extending byte/half-word
// load, this builder simply stays consistent with the 64-bit style
// ebpf.programs.zig's existing goldens already use throughout.

const golden_lpm_fd: linux.fd_t = 10;
const golden_scratch_fd: linux.fd_t = 11;

const golden_classifier = [_]Insn{
    .{ .code = 0x61, .dst = 2, .src = 1, .off = 4, .imm = 0 }, // ldx W  r2 = data_end
    .{ .code = 0x61, .dst = 1, .src = 1, .off = 0, .imm = 0 }, // ldx W  r1 = data
    .{ .code = 0xbf, .dst = 3, .src = 1, .off = 0, .imm = 0 }, // mov    r3 = r1
    .{ .code = 0x07, .dst = 3, .src = 0, .off = 0, .imm = 34 }, // add   r3 += 34 (14 eth + 20 ipv4)
    .{ .code = 0x2d, .dst = 3, .src = 2, .off = 22, .imm = 0 }, // jgt   r3 > data_end -> DEFAULT(27)
    .{ .code = 0x69, .dst = 4, .src = 1, .off = 12, .imm = 0 }, // ldx H r4 = ethertype
    .{ .code = 0x55, .dst = 4, .src = 0, .off = 20, .imm = 8 }, // jne   r4 != 0x0008 -> DEFAULT(27)
    .{ .code = 0x71, .dst = 4, .src = 1, .off = 14, .imm = 0 }, // ldx B r4 = version_ihl
    .{ .code = 0x57, .dst = 4, .src = 0, .off = 0, .imm = 15 }, // and   r4 &= 0x0f
    .{ .code = 0x55, .dst = 4, .src = 0, .off = 17, .imm = 5 }, // jne   r4 != 5 -> DEFAULT(27)
    .{ .code = 0x71, .dst = 5, .src = 1, .off = 26, .imm = 0 }, // ldx B r5 = data[26]
    .{ .code = 0x73, .dst = 10, .src = 5, .off = -4, .imm = 0 }, // stx B key[0]
    .{ .code = 0x71, .dst = 5, .src = 1, .off = 27, .imm = 0 }, // ldx B r5 = data[27]
    .{ .code = 0x73, .dst = 10, .src = 5, .off = -3, .imm = 0 }, // stx B key[1]
    .{ .code = 0x71, .dst = 5, .src = 1, .off = 28, .imm = 0 }, // ldx B r5 = data[28]
    .{ .code = 0x73, .dst = 10, .src = 5, .off = -2, .imm = 0 }, // stx B key[2]
    .{ .code = 0x71, .dst = 5, .src = 1, .off = 29, .imm = 0 }, // ldx B r5 = data[29]
    .{ .code = 0x73, .dst = 10, .src = 5, .off = -1, .imm = 0 }, // stx B key[3]
    .{ .code = 0x62, .dst = 10, .src = 0, .off = -8, .imm = 32 }, // st  W  prefixlen = 32
    .{ .code = 0xbf, .dst = 2, .src = 10, .off = 0, .imm = 0 }, // mov   r2 = r10
    .{ .code = 0x07, .dst = 2, .src = 0, .off = 0, .imm = -8 }, // add   r2 += -8
    .{ .code = 0x18, .dst = 1, .src = 1, .off = 0, .imm = golden_lpm_fd }, // ld_map_fd1 r1 = lpm(fd=10)
    .{ .code = 0x00, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // ld_map_fd2 (hi32)
    .{ .code = 0x85, .dst = 0, .src = 0, .off = 0, .imm = 1 }, // call  map_lookup_elem
    .{ .code = 0x15, .dst = 0, .src = 0, .off = 2, .imm = 0 }, // jeq   r0==0 -> DEFAULT(27)
    .{ .code = 0x61, .dst = 6, .src = 0, .off = 0, .imm = 0 }, // ldx W r6 = *(u32*)(r0)  (matched class)
    .{ .code = 0x05, .dst = 0, .src = 0, .off = 1, .imm = 0 }, // ja    -> TAIL(28)
    .{ .code = 0xb7, .dst = 6, .src = 0, .off = 0, .imm = 0 }, // DEFAULT(27): mov r6 = default_class(0)
    .{ .code = 0x62, .dst = 10, .src = 0, .off = -4, .imm = 0 }, // TAIL(28): st W scratch_key = 0
    .{ .code = 0xbf, .dst = 2, .src = 10, .off = 0, .imm = 0 }, // mov   r2 = r10
    .{ .code = 0x07, .dst = 2, .src = 0, .off = 0, .imm = -4 }, // add   r2 += -4
    .{ .code = 0x18, .dst = 1, .src = 1, .off = 0, .imm = golden_scratch_fd }, // ld_map_fd1 r1 = scratch(fd=11)
    .{ .code = 0x00, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // ld_map_fd2 (hi32)
    .{ .code = 0x85, .dst = 0, .src = 0, .off = 0, .imm = 1 }, // call  map_lookup_elem
    .{ .code = 0x15, .dst = 0, .src = 0, .off = 1, .imm = 0 }, // jeq   r0==0 -> SKIP_WRITE(36)
    .{ .code = 0x63, .dst = 0, .src = 6, .off = 0, .imm = 0 }, // stx W *scratch_value = r6
    .{ .code = 0xb7, .dst = 0, .src = 0, .off = 0, .imm = 2 }, // SKIP_WRITE(36): mov r0 = XDP_PASS
    .{ .code = 0x95, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // exit
};

test "golden: buildClassifierProgram matches the hand-derived, clang-cross-checked sequence" {
    const insns = buildClassifierProgram(.{
        .lpm_map_fd = golden_lpm_fd,
        .scratch_map_fd = golden_scratch_fd,
        .key_field = .src,
        .default_class = 0,
    });
    try testing.expectEqualSlices(Insn, &golden_classifier, insns);
}

test "buildClassifierProgram: key_field = .dst reads offsets 30-33 instead of 26-29" {
    const insns = buildClassifierProgram(.{
        .lpm_map_fd = 3,
        .scratch_map_fd = 4,
        .key_field = .dst,
    });
    var byte_reads_from_packet: usize = 0;
    for (insns) |ins| {
        // ldx byte, src=r1 (packet), dst=r5 — specifically the key-copy
        // loop's reads (the IHL check at (4) also does a byte load from r1,
        // but into r4 at a fixed offset 14, not r5 — excluded here so this
        // test targets only the key-field-dependent reads).
        if (ins.code == 0x71 and ins.src == 1 and ins.dst == 5) {
            try testing.expect(ins.off >= 30 and ins.off <= 33);
            byte_reads_from_packet += 1;
        }
    }
    try testing.expectEqual(@as(usize, 4), byte_reads_from_packet);
}

test "buildClassifierProgram: default_class >= 0x8000_0000 round-trips via bitCast, no panic" {
    const insns = buildClassifierProgram(.{
        .lpm_map_fd = 3,
        .scratch_map_fd = 4,
        .default_class = 0xFFFF_FFFF,
    });
    // The DEFAULT block's `mov r6, imm` must carry the exact bit pattern
    // back out (-1 as an i32 == the low 32 bits of 0xFFFF_FFFF).
    var found = false;
    for (insns) |ins| {
        if (ins.code == 0xb7 and ins.dst == 6) {
            try testing.expectEqual(@as(i32, -1), ins.imm);
            found = true;
        }
    }
    try testing.expect(found);
}

test "structural: every packet-derived read is dominated by the single bounds check" {
    const insns = buildClassifierProgram(.{ .lpm_map_fd = 5, .scratch_map_fd = 6 });
    var bounds_check_i: ?usize = null;
    for (insns, 0..) |ins, i| {
        if (ins.code == 0x2d) bounds_check_i = i; // JMP|JGT|X
    }
    try testing.expect(bounds_check_i != null);
    for (insns, 0..) |ins, i| {
        // Any load whose source is r1 (the packet-data register) after ctx
        // decoding: half-word (0x69), byte (0x71), or word (0x61, only the
        // two ctx loads use word+src==r1 with i==0/1, both BEFORE the
        // check, which is correct — the ctx loads themselves are what the
        // bounds check is validated against, not packet reads that need
        // the check).
        if ((ins.code == 0x69 or ins.code == 0x71) and ins.src == 1) {
            try testing.expect(i > bounds_check_i.?);
        }
    }
}

test "structural: both map lookups null-check r0 before any dereference" {
    const insns = buildClassifierProgram(.{ .lpm_map_fd = 5, .scratch_map_fd = 6 });
    var calls: usize = 0;
    var null_checks: usize = 0;
    for (insns, 0..) |ins, i| {
        if (ins.code == 0x85 and ins.imm == 1) { // call map_lookup_elem
            calls += 1;
            // The very next instruction must be the null-check jeq.
            try testing.expect(i + 1 < insns.len);
            try testing.expectEqual(@as(u8, 0x15), insns[i + 1].code);
            try testing.expectEqual(@as(u4, 0), insns[i + 1].dst);
            null_checks += 1;
        }
    }
    try testing.expectEqual(@as(usize, 2), calls);
    try testing.expectEqual(@as(usize, 2), null_checks);
}

test "structural: exactly one exit, it is the last instruction, and r0 is a valid XDP action" {
    const insns = buildClassifierProgram(.{ .lpm_map_fd = 5, .scratch_map_fd = 6 });
    var exits: usize = 0;
    for (insns) |ins| {
        if (ins.code == 0x95) exits += 1;
    }
    try testing.expectEqual(@as(usize, 1), exits);
    try testing.expectEqual(@as(u8, 0x95), insns[insns.len - 1].code);
    // Immediately preceding instruction sets r0 to a valid XDP_* value
    // (0..4 — see ebpf.xdpFilter's doc comment point 4 on this being an
    // unenforced ABI convention, not a verifier check, hence tested
    // behaviorally here rather than relied on structurally).
    const set_r0 = insns[insns.len - 2];
    try testing.expectEqual(@as(u8, 0xb7), set_r0.code);
    try testing.expectEqual(@as(u4, 0), set_r0.dst);
    try testing.expect(set_r0.imm >= 0 and set_r0.imm <= 4);
}

test "structural: all stack (r10-relative) stores stay within [-8, 0) — the LPM key region" {
    const insns = buildClassifierProgram(.{ .lpm_map_fd = 5, .scratch_map_fd = 6 });
    for (insns) |ins| {
        const is_store_to_stack = (ins.code == 0x62 or ins.code == 0x63 or ins.code == 0x73) and ins.dst == 10;
        if (is_store_to_stack) {
            try testing.expect(ins.off >= -8 and ins.off < 0);
        }
    }
}

test "structural: r6 is never used as a helper-call argument (would be clobbered) or written by a call" {
    // r0-r5 are caller-saved across a BPF helper call; only r6 (chosen for
    // the class value, see doc comment point 6) must never appear as a
    // call's implicit argument register purpose. This is a coarse but
    // useful regression guard: no instruction in this program ever treats
    // r6 as anything other than a plain scalar mov-target/source.
    const insns = buildClassifierProgram(.{ .lpm_map_fd = 5, .scratch_map_fd = 6 });
    // Confirm r6 only ever appears as: the dst of the two class
    // assignments (ldx from LPM value / mov default_class), or the src of
    // the final stx. Any OTHER appearance would indicate a register
    // allocation bug.
    var r6_roles: usize = 0;
    for (insns) |ins| {
        if (ins.dst == 6 or ins.src == 6) {
            const is_class_ldx = ins.code == 0x61 and ins.dst == 6;
            const is_class_mov = ins.code == 0xb7 and ins.dst == 6;
            const is_class_stx_src = ins.code == 0x63 and ins.src == 6;
            try testing.expect(is_class_ldx or is_class_mov or is_class_stx_src);
            r6_roles += 1;
        }
    }
    try testing.expectEqual(@as(usize, 3), r6_roles);
}

/// Privileged, capability-gated real-load test: build the program with
/// freshly created maps and hand it to the in-kernel verifier via
/// `ebpf.load`. Skips (does NOT fail) without CAP_BPF/root, matching
/// `ebpf`'s own gated tests — an unprivileged pass asserts the golden/
/// structure only, NOT that the verifier accepted anything.
fn hasBpfCapability() bool {
    return linux.geteuid() == 0;
}

test "load: buildClassifierProgram passes the in-kernel verifier (needs CAP_BPF/root)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) return error.SkipZigTest;

    const maps = @import("maps.zig");

    const lpm_fd = maps.createLpmTrieMap(64) catch |e| switch (e) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    };
    defer _ = linux.close(lpm_fd);

    const scratch_fd = maps.createScratchMap() catch |e| switch (e) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    };
    defer _ = linux.close(scratch_fd);

    const insns = buildClassifierProgram(.{ .lpm_map_fd = lpm_fd, .scratch_map_fd = scratch_fd });
    const prog: ebpf.Program = .{ .prog_type = .xdp, .insns = insns };
    const fd = try ebpf.load(prog, "MIT");
    _ = linux.close(fd);
}

// ── CPUMAP steering tests ───────────────────────────────────────────────────

const redirect_map_helper_id: i32 = @intFromEnum(std.os.linux.BPF.Helper.redirect_map);

// Golden vector for buildCpumapSteerProgram. Instructions 0-24 are the SAME
// ctx-decode / bounds-check / EtherType+IHL / key-copy / LPM-lookup sequence
// as `golden_classifier` above (already clang-cross-checked + CAP_BPF-load-
// verified there) — reused, not re-derived. The genuinely new tail (25-33) is
// hand-derived from the BPF ISA: load the matched class into the redirect KEY
// register (r2), reduce it `% cpu_count` (BPF_ALU64|MOD|K == 0x97), then the
// pseudo-fd/flags/redirect_map(helper 51) call and a return of its result;
// every non-hit path jumps to the shared XDP_PASS tail (32-33).
const golden_steer_lpm_fd: linux.fd_t = 10;
const golden_steer_cpumap_fd: linux.fd_t = 12;

const golden_steer = [_]Insn{
    .{ .code = 0x61, .dst = 2, .src = 1, .off = 4, .imm = 0 }, // 0  ldx W r2 = data_end
    .{ .code = 0x61, .dst = 1, .src = 1, .off = 0, .imm = 0 }, // 1  ldx W r1 = data
    .{ .code = 0xbf, .dst = 3, .src = 1, .off = 0, .imm = 0 }, // 2  mov r3 = r1
    .{ .code = 0x07, .dst = 3, .src = 0, .off = 0, .imm = 34 }, // 3  add r3 += 34
    .{ .code = 0x2d, .dst = 3, .src = 2, .off = 27, .imm = 0 }, // 4  jgt r3 > data_end -> PASS(32)
    .{ .code = 0x69, .dst = 4, .src = 1, .off = 12, .imm = 0 }, // 5  ldx H r4 = ethertype
    .{ .code = 0x55, .dst = 4, .src = 0, .off = 25, .imm = 8 }, // 6  jne r4 != 0x0008 -> PASS(32)
    .{ .code = 0x71, .dst = 4, .src = 1, .off = 14, .imm = 0 }, // 7  ldx B r4 = version_ihl
    .{ .code = 0x57, .dst = 4, .src = 0, .off = 0, .imm = 15 }, // 8  and r4 &= 0x0f
    .{ .code = 0x55, .dst = 4, .src = 0, .off = 22, .imm = 5 }, // 9  jne r4 != 5 -> PASS(32)
    .{ .code = 0x71, .dst = 5, .src = 1, .off = 26, .imm = 0 }, // 10 ldx B r5 = data[26]
    .{ .code = 0x73, .dst = 10, .src = 5, .off = -4, .imm = 0 }, // 11 stx B key[0]
    .{ .code = 0x71, .dst = 5, .src = 1, .off = 27, .imm = 0 }, // 12 ldx B r5 = data[27]
    .{ .code = 0x73, .dst = 10, .src = 5, .off = -3, .imm = 0 }, // 13 stx B key[1]
    .{ .code = 0x71, .dst = 5, .src = 1, .off = 28, .imm = 0 }, // 14 ldx B r5 = data[28]
    .{ .code = 0x73, .dst = 10, .src = 5, .off = -2, .imm = 0 }, // 15 stx B key[2]
    .{ .code = 0x71, .dst = 5, .src = 1, .off = 29, .imm = 0 }, // 16 ldx B r5 = data[29]
    .{ .code = 0x73, .dst = 10, .src = 5, .off = -1, .imm = 0 }, // 17 stx B key[3]
    .{ .code = 0x62, .dst = 10, .src = 0, .off = -8, .imm = 32 }, // 18 st W prefixlen = 32
    .{ .code = 0xbf, .dst = 2, .src = 10, .off = 0, .imm = 0 }, // 19 mov r2 = r10
    .{ .code = 0x07, .dst = 2, .src = 0, .off = 0, .imm = -8 }, // 20 add r2 += -8
    .{ .code = 0x18, .dst = 1, .src = 1, .off = 0, .imm = golden_steer_lpm_fd }, // 21 ld_map_fd1 r1 = lpm(10)
    .{ .code = 0x00, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // 22 ld_map_fd2 (hi32)
    .{ .code = 0x85, .dst = 0, .src = 0, .off = 0, .imm = 1 }, // 23 call map_lookup_elem
    .{ .code = 0x15, .dst = 0, .src = 0, .off = 7, .imm = 0 }, // 24 jeq r0==0 -> PASS(32)
    .{ .code = 0x61, .dst = 2, .src = 0, .off = 0, .imm = 0 }, // 25 ldx W r2 = *(u32*)(r0)  (class -> redirect key)
    .{ .code = 0x97, .dst = 2, .src = 0, .off = 0, .imm = 4 }, // 26 mod r2 %= cpu_count(4)
    .{ .code = 0x18, .dst = 1, .src = 1, .off = 0, .imm = golden_steer_cpumap_fd }, // 27 ld_map_fd1 r1 = cpumap(12)
    .{ .code = 0x00, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // 28 ld_map_fd2 (hi32)
    .{ .code = 0xb7, .dst = 3, .src = 0, .off = 0, .imm = 0 }, // 29 mov r3 = redirect_flags(0)
    .{ .code = 0x85, .dst = 0, .src = 0, .off = 0, .imm = 51 }, // 30 call redirect_map (helper 51)
    .{ .code = 0x95, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // 31 exit (returns r0 = redirect result)
    .{ .code = 0xb7, .dst = 0, .src = 0, .off = 0, .imm = 2 }, // 32 PASS: mov r0 = XDP_PASS
    .{ .code = 0x95, .dst = 0, .src = 0, .off = 0, .imm = 0 }, // 33 exit
};

test "golden: buildCpumapSteerProgram matches the hand-derived sequence" {
    const insns = try buildCpumapSteerProgram(.{
        .lpm_map_fd = golden_steer_lpm_fd,
        .cpumap_fd = golden_steer_cpumap_fd,
        .cpu_count = 4,
        .key_field = .src,
        .redirect_flags = 0,
    });
    try testing.expectEqual(redirect_map_helper_id, @as(i32, 51)); // brief-claimed id, confirmed
    try testing.expectEqualSlices(Insn, &golden_steer, insns);
}

/// Structural well-formedness predicate for a steer program, shared by the
/// positive assertion below and the positive-CONTROL test: the program must
/// end in `exit`, contain exactly one `redirect_map` call, reference the
/// cpumap via a pseudo-`ld_map_fd` immediately before that call, and reduce
/// the redirect KEY (r2) with a `% cpu_count` (BPF_MOD) op. A mutation of any
/// of these (see the positive-control test) makes it return false.
fn steerLooksWellFormed(insns: []const Insn) bool {
    if (insns.len == 0 or insns[insns.len - 1].code != 0x95) return false;

    var redirect_i: ?usize = null;
    var redirect_calls: usize = 0;
    for (insns, 0..) |ins, i| {
        if (ins.code == 0x85 and ins.imm == redirect_map_helper_id) {
            redirect_i = i;
            redirect_calls += 1;
        }
    }
    if (redirect_calls != 1) return false;
    const ri = redirect_i.?;

    // The redirect KEY must be reduced mod cpu_count into r2 somewhere before
    // the call (BPF_ALU64|MOD|K == 0x97, dst r2).
    var has_mod_key = false;
    for (insns[0..ri]) |ins| {
        if (ins.code == 0x97 and ins.dst == 2) has_mod_key = true;
    }
    if (!has_mod_key) return false;

    // The cpumap must be loaded via a two-slot pseudo ld_map_fd (0x18 into r1
    // with src == PSEUDO_MAP_FD(1), followed by the 0x00 continuation) that
    // precedes the redirect call. Require such a pair between the mod and the
    // call.
    if (ri < 2) return false;
    const hi = insns[ri - 1];
    const lo = insns[ri - 2];
    if (!(lo.code == 0x18 and lo.dst == 1 and lo.src == 1)) {
        // ...unless a flags mov sits between the ld_map_fd pair and the call.
        if (ri < 3) return false;
        const hi2 = insns[ri - 2];
        const lo2 = insns[ri - 3];
        if (!(lo2.code == 0x18 and lo2.dst == 1 and lo2.src == 1 and hi2.code == 0x00)) return false;
    } else if (hi.code != 0x00) {
        return false;
    }
    return true;
}

test "structural: steer program is well-formed (redirect_map + cpumap pseudo-fd + mod key)" {
    const insns = try buildCpumapSteerProgram(.{ .lpm_map_fd = 7, .cpumap_fd = 9, .cpu_count = 8 });
    try testing.expect(steerLooksWellFormed(insns));

    // The redirect call references the cpumap fd (9), not the lpm fd (7): find
    // the ld_map_fd pair feeding the redirect call.
    var found_cpumap_ref = false;
    for (insns, 0..) |ins, i| {
        if (ins.code == 0x85 and ins.imm == redirect_map_helper_id) {
            // Walk back to the nearest 0x18 (ld_map_fd1) — that is the map arg.
            var j = i;
            while (j > 0) : (j -= 1) {
                if (insns[j - 1].code == 0x18) {
                    try testing.expectEqual(@as(i32, 9), insns[j - 1].imm);
                    found_cpumap_ref = true;
                    break;
                }
            }
        }
    }
    try testing.expect(found_cpumap_ref);
}

test "structural: every non-hit path falls back to a single trailing XDP_PASS" {
    const insns = try buildCpumapSteerProgram(.{ .lpm_map_fd = 7, .cpumap_fd = 9, .cpu_count = 8 });

    // Exactly two exits: the redirect-tail exit and the PASS-tail exit.
    var exits: usize = 0;
    for (insns) |ins| {
        if (ins.code == 0x95) exits += 1;
    }
    try testing.expectEqual(@as(usize, 2), exits);

    // Last instruction is exit; the one before it sets r0 = XDP_PASS(2).
    try testing.expectEqual(@as(u8, 0x95), insns[insns.len - 1].code);
    const pass = insns[insns.len - 2];
    try testing.expectEqual(@as(u8, 0xb7), pass.code);
    try testing.expectEqual(@as(u4, 0), pass.dst);
    try testing.expectEqual(@as(i32, 2), pass.imm);
    const pass_idx = insns.len - 2;

    // Every forward branch (jgt bounds, the two jne parse checks, the jeq LPM
    // miss) targets that shared PASS instruction.
    var branches: usize = 0;
    for (insns, 0..) |ins, i| {
        const is_branch = ins.code == 0x2d or ins.code == 0x55 or (ins.code == 0x15 and ins.dst == 0);
        if (is_branch) {
            const target = i + 1 + @as(usize, @intCast(ins.off));
            try testing.expectEqual(pass_idx, target);
            branches += 1;
        }
    }
    try testing.expectEqual(@as(usize, 4), branches); // jgt + 2x jne + jeq
}

test "buildCpumapSteerProgram: key_field = .dst reads offsets 30-33" {
    const insns = try buildCpumapSteerProgram(.{ .lpm_map_fd = 3, .cpumap_fd = 4, .cpu_count = 2, .key_field = .dst });
    var byte_reads_from_packet: usize = 0;
    for (insns) |ins| {
        if (ins.code == 0x71 and ins.src == 1 and ins.dst == 5) {
            try testing.expect(ins.off >= 30 and ins.off <= 33);
            byte_reads_from_packet += 1;
        }
    }
    try testing.expectEqual(@as(usize, 4), byte_reads_from_packet);
}

test "buildCpumapSteerProgram: cpu_count = 0 is a build error, not a div-by-zero program" {
    try testing.expectError(SteerBuildError.InvalidCpuCount, buildCpumapSteerProgram(.{
        .lpm_map_fd = 3,
        .cpumap_fd = 4,
        .cpu_count = 0,
    }));
}

test "positive control: a steer stream with the wrong redirect helper id is rejected" {
    // Prove the structural check actually bites: take a real, well-formed steer
    // program, corrupt ONLY the redirect helper id (51 -> map_lookup_elem 1),
    // and confirm steerLooksWellFormed flips from true to false. This is the
    // permanent guard that the well-formedness predicate is not vacuous.
    const good = try buildCpumapSteerProgram(.{ .lpm_map_fd = 7, .cpumap_fd = 9, .cpu_count = 8 });
    try testing.expect(steerLooksWellFormed(good));

    var broken: [64]Insn = undefined;
    @memcpy(broken[0..good.len], good);
    for (broken[0..good.len]) |*ins| {
        if (ins.code == 0x85 and ins.imm == redirect_map_helper_id) ins.imm = 1; // wrong helper
    }
    try testing.expect(!steerLooksWellFormed(broken[0..good.len]));
}

test "load: buildCpumapSteerProgram passes the in-kernel verifier (needs CAP_BPF/root)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) return error.SkipZigTest;

    const maps = @import("maps.zig");

    const lpm_fd = maps.createLpmTrieMap(64) catch |e| switch (e) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    };
    defer _ = linux.close(lpm_fd);

    const cpumap_fd = maps.createCpuMap(4) catch |e| switch (e) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    };
    defer _ = linux.close(cpumap_fd);

    const insns = try buildCpumapSteerProgram(.{ .lpm_map_fd = lpm_fd, .cpumap_fd = cpumap_fd, .cpu_count = 4 });
    const prog: ebpf.Program = .{ .prog_type = .xdp, .insns = insns };
    // Loaded under "GPL": bpf_redirect_map is not a GPL-only helper on current
    // kernels, but claiming GPL removes any gpl-only-helper ambiguity for the
    // verifier acceptance check this test exists to make (the license string is
    // a claim about the generated program, independent of this module's MIT
    // license). Skips cleanly without CAP_BPF, like every gated test here.
    const fd = ebpf.load(prog, "GPL") catch |e| switch (e) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    };
    _ = linux.close(fd);
}
