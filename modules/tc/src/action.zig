// SPDX-License-Identifier: MIT
//! tc **actions** — the `TCA_ACT_*` action list a filter runs on a match, and
//! the standalone shared action table (`RTM_NEWACTION`/`DELACTION`/
//! `GETACTION`).
//!
//! An action list is one nested attribute (`TCA_U32_ACT`, `TCA_FLOWER_ACT`,
//! or `TCA_ACT_TAB` for the standalone family — all three are the same shape).
//! Its children are **1-indexed ordinal nests**: the first action is attribute
//! type `1`, the second `2`, and so on up to `TCA_ACT_MAX_PRIO` (32). Using a
//! 0-based index is the classic mistake here — the kernel's
//! `tcf_action_init` loop treats attribute type `0` as out of range and the
//! whole list is silently rejected or renumbered. `appendActionList` is the
//! only place this module numbers them, and the two-action goldens pin `1`
//! and `2`.
//!
//! Each ordinal nest carries:
//!
//! ```text
//! TCA_ACT_KIND      "gact" / "mirred" / "police" / …   (NUL-terminated)
//! TCA_ACT_OPTIONS   nested, kind-specific              (with NLA_F_NESTED)
//! TCA_ACT_COOKIE    opaque ≤ 16 bytes, optional
//! ```
//!
//! or, for the `tc actions del|get` reference form, `TCA_ACT_KIND` +
//! `TCA_ACT_INDEX`. Note the asymmetry with `TCA_OPTIONS` on a qdisc:
//! `TCA_ACT_OPTIONS` is sent **with** `NLA_F_NESTED`, the ordinal and the
//! outer list nest without it. The kernel accepts either; the goldens pin
//! this form.
//!
//! Every kind's options begin with the same `struct tc_gen` prologue —
//! `index`, `capab`, `action`, `refcnt`, `bindcnt` — where `action` is the
//! `TC_ACT_*` verdict the action returns to the classifier. `TC_ACT_PIPE` is
//! what chains one action into the next: an action that returns `PIPE` lets
//! the list continue, while `SHOT`/`STOLEN`/`OK` end it. `police` is the one
//! exception to the prologue: `struct tc_police` interleaves its own fields
//! between `action` and `refcnt` (see `Police`).
//!
//! Rates and bursts reuse `ratespec.zig` — the same psched arithmetic htb and
//! tbf use. A `police` burst is the transmit time of `burst` bytes at the
//! full rate, and — unlike htb and tbf — its rate tables also come from the
//! full 64-bit rate; only the ratespec's 32-bit `rate` field is clamped to
//! `~0U`, with the true rate carried in `TCA_POLICE_RATE64`.

const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const netlink = @import("netlink");
const codec = netlink.codec;

const ratespec = @import("ratespec.zig");
const Psched = ratespec.Psched;
const RateSpec = ratespec.RateSpec;
const LinkLayer = ratespec.LinkLayer;

// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

const handle_mod = @import("handle.zig");
const Handle = handle_mod.Handle;

const qdisc = @import("qdisc.zig");

/// `IFNAMSIZ`-ish cap on a kind string, shared with qdisc/class/filter kinds.
pub const kind_max = qdisc.kind_max;

// ── attribute-type constants (kernel UAPI, linux/pkt_cls.h) ─────────────────

/// Per-action attributes inside one ordinal nest (`TCA_ACT_*`).
pub const TCA_ACT = struct {
    pub const UNSPEC: u16 = 0;
    pub const KIND: u16 = 1;
    pub const OPTIONS: u16 = 2;
    pub const INDEX: u16 = 3;
    pub const STATS: u16 = 4;
    pub const PAD: u16 = 5;
    pub const COOKIE: u16 = 6;
    pub const FLAGS: u16 = 7;
    pub const HW_STATS: u16 = 8;
    pub const USED_HW_STATS: u16 = 9;
    pub const IN_HW_COUNT: u16 = 10;
};

/// Attributes on a **standalone** action message's `tcamsg` header
/// (`TCA_ROOT_*`; `TCA_ROOT_TAB` is also spelled `TCA_ACT_TAB`).
pub const TCA_ROOT = struct {
    pub const UNSPEC: u16 = 0;
    pub const TAB: u16 = 1;
    pub const FLAGS: u16 = 2;
    pub const COUNT: u16 = 3;
    pub const TIME_DELTA: u16 = 4;
    pub const EXT_WARN_MSG: u16 = 5;
};

/// `TCA_ACT_TAB` — the action list attribute of a standalone action message.
pub const TCA_ACT_TAB: u16 = TCA_ROOT.TAB;

/// `TCA_ROOT_FLAGS` bits (an `nla_bitfield32`).
pub const TCA_ACT_FLAG = struct {
    /// `TCA_ACT_FLAG_LARGE_DUMP_ON` — what `tc actions ls` always sets.
    pub const LARGE_DUMP_ON: u32 = 1 << 0;
    pub const TERSE_DUMP: u32 = 1 << 1;
};

/// gact attributes (`TCA_GACT_*`).
pub const TCA_GACT = struct {
    pub const UNSPEC: u16 = 0;
    pub const TM: u16 = 1;
    pub const PARMS: u16 = 2;
    pub const PROB: u16 = 3;
    pub const PAD: u16 = 4;
};

/// mirred attributes (`TCA_MIRRED_*`).
pub const TCA_MIRRED = struct {
    pub const UNSPEC: u16 = 0;
    pub const TM: u16 = 1;
    pub const PARMS: u16 = 2;
    pub const PAD: u16 = 3;
    pub const BLOCKID: u16 = 4;
};

/// police attributes (`TCA_POLICE_*`).
pub const TCA_POLICE = struct {
    pub const UNSPEC: u16 = 0;
    pub const TBF: u16 = 1;
    pub const RATE: u16 = 2;
    pub const PEAKRATE: u16 = 3;
    pub const AVRATE: u16 = 4;
    pub const RESULT: u16 = 5;
    pub const TM: u16 = 6;
    pub const PAD: u16 = 7;
    pub const RATE64: u16 = 8;
    pub const PEAKRATE64: u16 = 9;
    pub const PKTRATE64: u16 = 10;
    pub const PKTBURST64: u16 = 11;
};

/// skbedit attributes (`TCA_SKBEDIT_*`).
pub const TCA_SKBEDIT = struct {
    pub const UNSPEC: u16 = 0;
    pub const TM: u16 = 1;
    pub const PARMS: u16 = 2;
    pub const PRIORITY: u16 = 3;
    pub const QUEUE_MAPPING: u16 = 4;
    pub const MARK: u16 = 5;
    pub const PAD: u16 = 6;
    pub const PTYPE: u16 = 7;
    pub const MASK: u16 = 8;
    pub const FLAGS: u16 = 9;
    pub const QUEUE_MAPPING_MAX: u16 = 10;
};

/// vlan attributes (`TCA_VLAN_*`).
pub const TCA_VLAN = struct {
    pub const UNSPEC: u16 = 0;
    pub const TM: u16 = 1;
    pub const PARMS: u16 = 2;
    pub const PUSH_VLAN_ID: u16 = 3;
    pub const PUSH_VLAN_PROTOCOL: u16 = 4;
    pub const PAD: u16 = 5;
    pub const PUSH_VLAN_PRIORITY: u16 = 6;
    pub const PUSH_ETH_DST: u16 = 7;
    pub const PUSH_ETH_SRC: u16 = 8;
};

/// Generic statistics attribute types (linux/gen_stats.h `TCA_STATS_*`),
/// nested inside `TCA_ACT_STATS`.
pub const TCA_STATS = struct {
    pub const UNSPEC: u16 = 0;
    pub const BASIC: u16 = 1;
    pub const RATE_EST: u16 = 2;
    pub const QUEUE: u16 = 3;
    pub const APP: u16 = 4;
    pub const RATE_EST64: u16 = 5;
    pub const PAD: u16 = 6;
    pub const BASIC_HW: u16 = 7;
    pub const PKT64: u16 = 8;
};

pub const kind_gact = "gact";
pub const kind_mirred = "mirred";
pub const kind_police = "police";
pub const kind_skbedit = "skbedit";
pub const kind_vlan = "vlan";
pub const kind_connmark = "connmark";
pub const kind_csum = "csum";
pub const kind_sample = "sample";
pub const kind_tunnel_key = "tunnel_key";
pub const kind_mpls = "mpls";
pub const kind_nat = "nat";
pub const kind_pedit = "pedit";
pub const kind_ct = "ct";

/// `TCA_ACT_MAX_PRIO` — the kernel's cap on actions in one list.
pub const max_actions = 32;
/// `TC_COOKIE_MAX_SIZE`.
pub const max_cookie_len = 16;
/// How many actions of a list this module decodes into a `Filter`. The
/// kernel's cap is `max_actions`, but a decoded `Action` is a value type
/// embedded in every dumped filter, so the per-filter decode is capped;
/// `ActionList.total` still reports the true count. The standalone
/// `Socket.actions()` dump is **not** capped — it uses `ActionIterator`.
pub const max_actions_decoded = 4;

/// `sizeof(struct tc_gen)` — index, capab, action, refcnt, bindcnt.
pub const tc_gen_len = 20;
/// `sizeof(struct tc_gact)` — nothing but the prologue.
pub const tc_gact_len = tc_gen_len;
/// `sizeof(struct tc_gact_p)` — ptype, pval, paction.
pub const tc_gact_p_len = 8;
/// `sizeof(struct tc_mirred)` — prologue + eaction + ifindex.
pub const tc_mirred_len = tc_gen_len + 8;
/// `sizeof(struct tc_vlan)` — prologue + v_action.
pub const tc_vlan_len = tc_gen_len + 4;
/// `sizeof(struct tc_skbedit)` — nothing but the prologue.
pub const tc_skbedit_len = tc_gen_len;
/// `SKBEDIT_F_INHERITDSFIELD` — a bit of the 64-bit `TCA_SKBEDIT_FLAGS`.
pub const SKBEDIT_F_INHERITDSFIELD: u64 = 0x20;
/// `sizeof(struct tc_police)` — see `Police` for the field order (it is *not*
/// a `tc_gen` prologue plus extras).
pub const tc_police_len = 56;
/// `sizeof(struct tcf_t)` — install, lastuse, expires, firstuse.
pub const tcf_t_len = 32;
/// `sizeof(struct tcamsg)` — family + two pad fields.
pub const tcamsg_len = 4;

// ── verdicts ────────────────────────────────────────────────────────────────

/// `TC_ACT_JUMP` and `TC_ACT_GOTO_CHAIN`: the opcode bits of the composite
/// verdicts, and `TC_ACT_EXT_VAL_MASK`, the bits that carry their operand.
pub const tc_act_jump: u32 = 0x10000000;
pub const tc_act_goto_chain: u32 = 0x20000000;
pub const tc_act_ext_val_mask: u32 = 0x0fffffff;

/// `TC_ACT_*` — what an action returns to the classifier that ran it.
///
/// * `.ok` / `.shot` — accept / drop the packet, ending the list.
/// * `.pipe` — **continue into the next action of the list**. This is the
///   only verdict that chains, and it is the default for the actions that are
///   normally used mid-list (`skbedit`, `vlan`, a mirroring `mirred`).
/// * `.stolen` — the packet was consumed elsewhere (a redirecting `mirred`).
/// * `.reclassify` — restart classification from the top.
/// * `.trap` — hand the packet to userspace (hardware-offload trap).
/// * `.unspec` (-1) — `tc`'s `continue`: fall through to the next *filter*.
///
/// Non-exhaustive: a newer kernel may dump a verdict this module predates.
pub const Verdict = enum(i32) {
    unspec = -1,
    ok = 0,
    reclassify = 1,
    shot = 2,
    pipe = 3,
    stolen = 4,
    queued = 5,
    repeat = 6,
    redirect = 7,
    trap = 8,
    _,

    pub fn raw(v: Verdict) i32 {
        return @backingInt(v);
    }

    /// `TC_ACT_GOTO_CHAIN | chain` — `tc … action goto chain N`: continue
    /// classification in chain `chain` (a 28-bit index; higher bits are
    /// dropped).
    pub fn gotoChain(chain: u32) Verdict {
        return fromRaw(@bitCast(tc_act_goto_chain | (chain & tc_act_ext_val_mask)));
    }

    /// `TC_ACT_JUMP | count` — `tc … action jump N`: skip `count` actions.
    pub fn jump(count: u32) Verdict {
        return fromRaw(@bitCast(tc_act_jump | (count & tc_act_ext_val_mask)));
    }

    /// The chain a `gotoChain` verdict names, or null for any other verdict.
    pub fn chainIndex(v: Verdict) ?u32 {
        const r: u32 = @bitCast(v.raw());
        if (r & ~tc_act_ext_val_mask != tc_act_goto_chain) return null;
        return r & tc_act_ext_val_mask;
    }

    /// The count of a `jump` verdict, or null for any other verdict.
    pub fn jumpCount(v: Verdict) ?u32 {
        const r: u32 = @bitCast(v.raw());
        if (r & ~tc_act_ext_val_mask != tc_act_jump) return null;
        return r & tc_act_ext_val_mask;
    }

    pub fn fromRaw(v: i32) Verdict {
        return @fromBackingInt(@intCast(v));
    }
};

/// `struct tc_gen` — the prologue every action kind's options struct starts
/// with (police being the documented exception).
///
/// `refcnt`/`bindcnt`/`capab` are kernel bookkeeping: a request always sends
/// zero and only a dump fills them in.
pub const Gen = struct {
    /// The shared action table index. 0 asks the kernel to allocate one.
    index: u32 = 0,
    capab: u32 = 0,
    action: Verdict = .ok,
    refcnt: i32 = 0,
    bindcnt: i32 = 0,

    pub fn encode(g: Gen) [tc_gen_len]u8 {
        var out: [tc_gen_len]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], g.index, native_endian);
        std.mem.writeInt(u32, out[4..8], g.capab, native_endian);
        std.mem.writeInt(i32, out[8..12], g.action.raw(), native_endian);
        std.mem.writeInt(i32, out[12..16], g.refcnt, native_endian);
        std.mem.writeInt(i32, out[16..20], g.bindcnt, native_endian);
        return out;
    }

    pub fn decode(b: *const [tc_gen_len]u8) Gen {
        return .{
            .index = std.mem.readInt(u32, b[0..4], native_endian),
            .capab = std.mem.readInt(u32, b[4..8], native_endian),
            .action = Verdict.fromRaw(std.mem.readInt(i32, b[8..12], native_endian)),
            .refcnt = std.mem.readInt(i32, b[12..16], native_endian),
            .bindcnt = std.mem.readInt(i32, b[16..20], native_endian),
        };
    }
};

// ── errors ──────────────────────────────────────────────────────────────────

pub const EncodeError = std.mem.Allocator.Error || error{
    /// More than `TCA_ACT_MAX_PRIO` actions in one list.
    TooManyActions,
    /// A `TCA_ACT_COOKIE` longer than `TC_COOKIE_MAX_SIZE`.
    CookieTooLong,
    /// `police` without a rate (`rate`, `pkt_rate` or `avrate`).
    MissingRate,
    /// `police` with both a byte `rate` and a packet `pkt_rate` — `tc` and
    /// the kernel allow one.
    RateConflict,
    /// `police` without a burst — the kernel has no sensible default.
    MissingBurst,
    /// `police` with a `peakrate` but no `mtu` (`tc` rejects this too).
    MissingMtu,
    /// A pre-encoded `raw` payload longer than one netlink attribute.
    OptionsTooLong,
    /// `cell_log`/`pcell_log` outside `[0, ratespec.max_cell_log]` — see
    /// `ratespec.checkCellLog`.
    InvalidCellLog,
};

// ── gact ────────────────────────────────────────────────────────────────────

/// `tc_gact_p.ptype` — how the probabilistic variant picks its packets.
///
/// Non-exhaustive, like `Verdict`: the value is read off the wire, and a
/// newer kernel (or a hostile peer) may send one this module predates.
/// `@enumFromInt` on an exhaustive enum panicked there (found by the
/// Fuzz driver, seed 202).
pub const ProbType = enum(u16) {
    /// `PGACT_NONE`.
    none = 0,
    /// `PGACT_NETRAND` — a fresh pseudo-random draw per packet.
    netrand = 1,
    /// `PGACT_DETERM` — every `pval`-th packet.
    determ = 2,
    _,
};

/// `struct tc_gact_p` — the `random RANDTYPE ACTION VAL` modifier.
pub const GactProb = struct {
    ptype: ProbType = .determ,
    /// The randomness parameter: a 1-in-`pval` chance (`netrand`) or every
    /// `pval`-th packet (`determ`).
    pval: u16,
    /// The verdict taken when the draw fires; the plain `action` applies
    /// otherwise.
    paction: Verdict = .ok,

    pub fn encode(p: GactProb) [tc_gact_p_len]u8 {
        var out: [tc_gact_p_len]u8 = undefined;
        std.mem.writeInt(u16, out[0..2], @backingInt(p.ptype), native_endian);
        std.mem.writeInt(u16, out[2..4], p.pval, native_endian);
        std.mem.writeInt(i32, out[4..8], p.paction.raw(), native_endian);
        return out;
    }

    pub fn decode(b: *const [tc_gact_p_len]u8) GactProb {
        return .{
            .ptype = @fromBackingInt(@intCast(std.mem.readInt(u16, b[0..2], native_endian))),
            .pval = std.mem.readInt(u16, b[2..4], native_endian),
            .paction = Verdict.fromRaw(std.mem.readInt(i32, b[4..8], native_endian)),
        };
    }
};

/// **gact** — the generic action: a bare verdict (`tc … action drop|pass|
/// continue|reclassify|pipe|trap`), optionally applied probabilistically.
pub const Gact = struct {
    /// The verdict. `tc`'s bare `action drop` is `.shot`, `action pass` is
    /// `.ok`, `action continue` is `.unspec`.
    action: Verdict = .shot,
    /// Shared action table index; 0 lets the kernel allocate one.
    index: u32 = 0,
    /// `random determ|netrand ACTION VAL` — the `tc_gact_p` variant.
    random: ?GactProb = null,
    /// `TCA_ACT_COOKIE`, ≤ 16 opaque bytes echoed back on dump.
    cookie: []const u8 = &.{},
    extra: Extra = .{},
};

/// Wire readback of a gact action's options.
pub const GactWire = struct {
    random: ?GactProb = null,
};

// ── mirred ──────────────────────────────────────────────────────────────────

/// `tc_mirred.eaction` — which direction and which of copy/steal.
pub const MirredAction = enum(i32) {
    /// `TCA_EGRESS_REDIR` — steal the packet onto the target's egress.
    egress_redir = 1,
    /// `TCA_EGRESS_MIRROR` — copy it onto the target's egress.
    egress_mirror = 2,
    /// `TCA_INGRESS_REDIR` — steal it onto the target's ingress.
    ingress_redir = 3,
    /// `TCA_INGRESS_MIRROR` — copy it onto the target's ingress.
    ingress_mirror = 4,
    _,

    /// The verdict `tc` pairs with each mode: a redirect **steals** the
    /// packet (the list ends), a mirror **pipes** (the list continues).
    pub fn defaultVerdict(e: MirredAction) Verdict {
        return switch (e) {
            .egress_redir, .ingress_redir => .stolen,
            else => .pipe,
        };
    }
};

/// **mirred** — redirect or mirror a packet to another interface.
pub const Mirred = struct {
    eaction: MirredAction,
    /// The target interface index (`dev NAME`).
    ifindex: u32,
    index: u32 = 0,
    /// Override the verdict; null uses `eaction.defaultVerdict()`, which is
    /// what `tc` sends.
    action: ?Verdict = null,
    cookie: []const u8 = &.{},
    extra: Extra = .{},
};

/// Wire readback of a mirred action's options.
pub const MirredWire = struct {
    eaction: MirredAction = @fromBackingInt(@intCast(0)),
    ifindex: u32 = 0,
};

// ── police ──────────────────────────────────────────────────────────────────

/// **police** — a token-bucket rate limiter with a verdict per outcome.
///
/// `struct tc_police` is *not* a `tc_gen` prologue plus extras: its field
/// order is `index, action, limit, burst, mtu, rate, peakrate, refcnt,
/// bindcnt, capab`, with `action` sitting where `capab` would be in `tc_gen`.
/// `Gen`-shaped access to a decoded police action is still available on
/// `Action.gen`, reassembled from those fields.
///
/// Rates are **bytes per second** and `burst`/`mtu` are **bytes**, converted
/// to psched ticks with the same `ratespec` arithmetic htb and tbf use.
pub const Police = struct {
    /// Committed rate in bytes/s. Required unless `pkt_rate` or `avrate` is
    /// given.
    rate: u64 = 0,
    /// Bucket depth in bytes (`burst`/`buffer`). Required with `rate` — the
    /// kernel has no default.
    burst: u64 = 0,
    /// Optional peak rate in bytes/s; needs `mtu`.
    peakrate: u64 = 0,
    /// Peak-bucket MTU in bytes. Sent verbatim in `tc_police.mtu` (unlike
    /// tbf, police does **not** convert it to ticks) and used to derive the
    /// rate tables' cell shift.
    mtu: u32 = 0,
    /// `tc_police.limit`; 0 in every `tc` command line this module mirrors.
    limit: u32 = 0,
    index: u32 = 0,
    /// The verdict for traffic **over** the rate — `tc`'s
    /// `conform-exceed EXCEEDACT`. `tc`'s default is `.reclassify`.
    exceed: Verdict = .reclassify,
    /// The verdict for traffic **within** the rate — the `/NOTEXCEEDACT` half
    /// of `conform-exceed`, sent as `TCA_POLICE_RESULT`. null omits it.
    notexceed: ?Verdict = null,
    /// Minimum packet unit for the rate tables.
    mpu: u16 = 0,
    /// Per-packet link overhead in bytes.
    overhead: u16 = 0,
    linklayer: LinkLayer = .ethernet,
    /// Force the rate/peak table cell shift; null derives it from `mtu`.
    cell_log: ?u8 = null,
    pcell_log: ?u8 = null,
    /// `pkts_rate N` — a packet-per-second policer (`TCA_POLICE_PKTRATE64`)
    /// instead of a byte rate; give `rate = 0` and a `pkt_burst`.
    pkt_rate: u64 = 0,
    /// `pkts_burst N` — the bucket depth in packets, sent as ticks
    /// (`TCA_POLICE_PKTBURST64`).
    pkt_burst: u64 = 0,
    /// `avrate N` — the average-rate limit in bytes per second
    /// (`TCA_POLICE_AVRATE`), which `tc` sends alone (the kernel needs a
    /// rate estimator for it). With it, `rate` and `burst` may stay 0.
    avrate: u32 = 0,
    cookie: []const u8 = &.{},
    extra: Extra = .{},
};

/// Wire readback of a police action's options.
pub const PoliceWire = struct {
    index: u32 = 0,
    /// The exceed verdict (`tc_police.action`).
    exceed: Verdict = .ok,
    limit: u32 = 0,
    /// Bucket depth in **psched ticks** (divide back with
    /// `Psched.calcXmitSize` for bytes).
    burst: u32 = 0,
    /// MTU in bytes, as sent.
    mtu: u32 = 0,
    rate: RateSpec = .{},
    peakrate: RateSpec = .{},
    refcnt: i32 = 0,
    bindcnt: i32 = 0,
    capab: u32 = 0,
    /// `TCA_POLICE_RATE64` when present, else the 32-bit ratespec rate — so
    /// always the effective rate in bytes/s.
    rate64: u64 = 0,
    peakrate64: u64 = 0,
    /// `TCA_POLICE_RESULT` — the notexceed verdict, when the kernel sent one.
    notexceed: ?Verdict = null,
    /// `TCA_POLICE_AVRATE`.
    avrate: ?u32 = null,
    /// `TCA_POLICE_PKTRATE64`, packets per second.
    pkt_rate: ?u64 = null,
    /// `TCA_POLICE_PKTBURST64`, in psched ticks.
    pkt_burst: ?u64 = null,
};

// ── skbedit ─────────────────────────────────────────────────────────────────

/// `PACKET_*` (linux/if_packet.h) — the values `skbedit ptype` accepts.
pub const PACKET = struct {
    pub const HOST: u16 = 0;
    pub const BROADCAST: u16 = 1;
    pub const MULTICAST: u16 = 2;
    pub const OTHERHOST: u16 = 3;
};

/// **skbedit** — rewrite scheduling metadata on the packet.
pub const Skbedit = struct {
    /// `priority X:Y` — the skb priority, a `Handle`-shaped class id.
    priority: ?Handle = null,
    /// `mark N` — the firewall mark.
    mark: ?u32 = null,
    /// `mark N/MASK` — the mask half (`TCA_SKBEDIT_MASK`): only the bits in
    /// the mask are replaced. Sent right after the mark.
    mask: ?u32 = null,
    /// `inheritdsfield` — take the skb priority from the packet's DS field
    /// (`SKBEDIT_F_INHERITDSFIELD` in `TCA_SKBEDIT_FLAGS`).
    inherit_dsfield: bool = false,
    /// `queue_mapping N` — the TX queue.
    queue_mapping: ?u16 = null,
    /// `ptype host|broadcast|multicast|otherhost` (`PACKET.*`).
    ptype: ?u16 = null,
    index: u32 = 0,
    /// skbedit is a mid-list action, so the verdict defaults to `.pipe`.
    action: Verdict = .pipe,
    cookie: []const u8 = &.{},
    extra: Extra = .{},
};

/// Wire readback of an skbedit action's options.
pub const SkbeditWire = struct {
    priority: ?Handle = null,
    mark: ?u32 = null,
    inherit_dsfield: bool = false,
    queue_mapping: ?u16 = null,
    ptype: ?u16 = null,
    mask: ?u32 = null,
};

// ── vlan ────────────────────────────────────────────────────────────────────

/// `tc_vlan.v_action` — `TCA_VLAN_ACT_*`.
pub const VlanAction = enum(i32) {
    pop = 1,
    push = 2,
    modify = 3,
    pop_eth = 4,
    push_eth = 5,
    _,
};

/// **vlan** — push, pop or modify an 802.1Q/802.1ad tag.
pub const Vlan = struct {
    v_action: VlanAction,
    /// `id N` — the VLAN id (push/modify).
    id: ?u16 = null,
    /// `protocol 802.1Q|802.1ad` as a host-order ethertype (0x8100/0x88A8);
    /// encoded big-endian. Omitted when null — which is exactly what `tc`
    /// does, and the kernel then defaults a push to 802.1Q.
    proto: ?u16 = null,
    /// `priority N` — the 3-bit PCP.
    prio: ?u8 = null,
    /// `push_eth dst_mac M` / `src_mac M` — the Ethernet header a
    /// `.push_eth` action puts on a packet that has none.
    eth_dst: ?[6]u8 = null,
    eth_src: ?[6]u8 = null,
    index: u32 = 0,
    /// vlan is a mid-list action, so the verdict defaults to `.pipe`.
    action: Verdict = .pipe,
    cookie: []const u8 = &.{},
    extra: Extra = .{},
};

/// Wire readback of a vlan action's options.
pub const VlanWire = struct {
    v_action: VlanAction = @fromBackingInt(@intCast(0)),
    id: ?u16 = null,
    proto: ?u16 = null,
    prio: ?u8 = null,
    eth_dst: ?[6]u8 = null,
    eth_src: ?[6]u8 = null,
};

// ── per-action attributes shared by every kind ──────────────────────────────

/// `struct nla_bitfield32` — a value and the selector naming which bits of it
/// the kernel should look at.
pub const Bitfield32 = struct {
    value: u32,
    selector: u32,

    fn encode(b: Bitfield32) [8]u8 {
        var out: [8]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], b.value, native_endian);
        std.mem.writeInt(u32, out[4..8], b.selector, native_endian);
        return out;
    }

    fn decode(data: []const u8) ?Bitfield32 {
        if (data.len < 8) return null;
        return .{
            .value = std.mem.readInt(u32, data[0..4], native_endian),
            .selector = std.mem.readInt(u32, data[4..8], native_endian),
        };
    }
};

/// `TCA_ACT_FLAGS_*` — bits of `Extra.flags`.
pub const TCA_ACT_FLAGS_BIT = struct {
    pub const NO_PERCPU_STATS: u32 = 1 << 0;
    pub const SKIP_HW: u32 = 1 << 1;
    pub const SKIP_SW: u32 = 1 << 2;
};

/// `TCA_ACT_HW_STATS_*` — bits of `Extra.hw_stats`.
pub const TCA_ACT_HW_STATS_BIT = struct {
    pub const IMMEDIATE: u32 = 1 << 0;
    pub const DELAYED: u32 = 1 << 1;
    pub const ANY: u32 = IMMEDIATE | DELAYED;
};

/// The action-level attributes every kind accepts next to its options, in
/// the order `tc` sends them (after the cookie): `TCA_ACT_HW_STATS`, then
/// `TCA_ACT_FLAGS`. `tc … skip_hw` sends `flags = {2, 2}`; `hw_stats
/// immediate` sends `{1, 1}`; `hw_stats disabled` sends `{0, 0}`.
pub const Extra = struct {
    flags: ?Bitfield32 = null,
    hw_stats: ?Bitfield32 = null,
};

// ── connmark ────────────────────────────────────────────────────────────────

/// `TCA_CONNMARK_*`.
pub const TCA_CONNMARK = struct {
    pub const UNSPEC: u16 = 0;
    pub const PARMS: u16 = 1;
    pub const TM: u16 = 2;
    pub const PAD: u16 = 3;
};

/// `sizeof(struct tc_connmark)` — prologue + `zone` + 2 bytes of padding.
pub const tc_connmark_len = tc_gen_len + 4;

/// **connmark** — restore the packet mark from the conntrack entry.
pub const Connmark = struct {
    /// `zone N` — the conntrack zone to look the entry up in.
    zone: u16 = 0,
    index: u32 = 0,
    /// `tc` sends `TC_ACT_PIPE` for a connmark that names a zone.
    action: Verdict = .pipe,
    cookie: []const u8 = &.{},
    extra: Extra = .{},
};

pub const ConnmarkWire = struct {
    zone: u16 = 0,
};

// ── csum ────────────────────────────────────────────────────────────────────

/// `TCA_CSUM_*`.
pub const TCA_CSUM = struct {
    pub const UNSPEC: u16 = 0;
    pub const PARMS: u16 = 1;
    pub const TM: u16 = 2;
    pub const PAD: u16 = 3;
};

/// `TCA_CSUM_UPDATE_FLAG_*` — which checksums `csum` recomputes.
pub const CSUM_FLAG = struct {
    pub const IPV4HDR: u32 = 1;
    pub const ICMP: u32 = 2;
    pub const IGMP: u32 = 4;
    pub const TCP: u32 = 8;
    pub const UDP: u32 = 16;
    pub const UDPLITE: u32 = 32;
    pub const SCTP: u32 = 64;
};

/// `sizeof(struct tc_csum)` — prologue + `update_flags`.
pub const tc_csum_len = tc_gen_len + 4;

/// **csum** — recompute checksums after a rewrite (`tc … action csum ip4h
/// udp`).
pub const Csum = struct {
    /// `CSUM_FLAG.*` bits.
    update_flags: u32,
    index: u32 = 0,
    action: Verdict = .ok,
    cookie: []const u8 = &.{},
    extra: Extra = .{},
};

pub const CsumWire = struct {
    update_flags: u32 = 0,
};

// ── sample ──────────────────────────────────────────────────────────────────

/// `TCA_SAMPLE_*`.
pub const TCA_SAMPLE = struct {
    pub const UNSPEC: u16 = 0;
    pub const TM: u16 = 1;
    pub const PARMS: u16 = 2;
    pub const RATE: u16 = 3;
    pub const TRUNC_SIZE: u16 = 4;
    pub const PSAMPLE_GROUP: u16 = 5;
    pub const PAD: u16 = 6;
};

/// **sample** — copy 1 in `rate` packets to a psample group.
pub const Sample = struct {
    /// `rate N` — one packet in N.
    rate: u32,
    /// `group N` — the psample group.
    group: u32,
    /// `trunc N` — truncate the sampled copy to N bytes.
    trunc_size: ?u32 = null,
    index: u32 = 0,
    /// sample is a mid-list action: `tc` sends `TC_ACT_PIPE`.
    action: Verdict = .pipe,
    cookie: []const u8 = &.{},
    extra: Extra = .{},
};

pub const SampleWire = struct {
    rate: ?u32 = null,
    trunc_size: ?u32 = null,
    group: ?u32 = null,
};

// ── tunnel_key ──────────────────────────────────────────────────────────────

/// `TCA_TUNNEL_KEY_*`.
pub const TCA_TUNNEL_KEY = struct {
    pub const UNSPEC: u16 = 0;
    pub const TM: u16 = 1;
    pub const PARMS: u16 = 2;
    pub const ENC_IPV4_SRC: u16 = 3;
    pub const ENC_IPV4_DST: u16 = 4;
    pub const ENC_IPV6_SRC: u16 = 5;
    pub const ENC_IPV6_DST: u16 = 6;
    pub const ENC_KEY_ID: u16 = 7;
    pub const PAD: u16 = 8;
    pub const ENC_DST_PORT: u16 = 9;
    pub const NO_CSUM: u16 = 10;
    pub const ENC_OPTS: u16 = 11;
    pub const ENC_TOS: u16 = 12;
    pub const ENC_TTL: u16 = 13;
    pub const NO_FRAG: u16 = 14;
};

/// `sizeof(struct tc_tunnel_key)` — prologue + `t_action`.
pub const tc_tunnel_key_len = tc_gen_len + 4;

/// `tc_tunnel_key.t_action`.
pub const TunnelKeyAction = enum(i32) {
    /// `TCA_TUNNEL_KEY_ACT_SET` — attach tunnel metadata to the packet.
    set = 1,
    /// `TCA_TUNNEL_KEY_ACT_RELEASE` — drop it (`tc … tunnel_key unset`).
    release = 2,
    _,
};

/// **tunnel_key** — set or release the encapsulation metadata of a packet
/// (the transmit side of a metadata-mode vxlan/geneve/gre device).
pub const TunnelKey = struct {
    t_action: TunnelKeyAction = .set,
    /// `src_ip` / `dst_ip` (IPv4), network byte order as written.
    src_ip4: ?[4]u8 = null,
    dst_ip4: ?[4]u8 = null,
    src_ip6: ?[16]u8 = null,
    dst_ip6: ?[16]u8 = null,
    /// `id N` — the tunnel key / VNI, sent big-endian.
    key_id: ?u32 = null,
    /// `dst_port N`, sent big-endian.
    dst_port: ?u16 = null,
    tos: ?u8 = null,
    ttl: ?u8 = null,
    /// `nocsum` / `csum`. `tc` always sends `TCA_TUNNEL_KEY_NO_CSUM`: 0 when
    /// the outer checksum is wanted, 1 for `nocsum`.
    no_csum: bool = false,
    /// `nofrag` — `TCA_TUNNEL_KEY_NO_FRAG` (a flag attribute).
    no_frag: bool = false,
    /// A pre-encoded `TCA_TUNNEL_KEY_ENC_OPTS` payload (the geneve / vxlan /
    /// erspan option nest, which `tc` builds from `geneve_opts`,
    /// `vxlan_opts` and `erspan_opts`). Not decoded on readback.
    enc_opts: []const u8 = &.{},
    index: u32 = 0,
    /// tunnel_key is a mid-list action: `tc` sends `TC_ACT_PIPE`.
    action: Verdict = .pipe,
    cookie: []const u8 = &.{},
    extra: Extra = .{},
};

pub const TunnelKeyWire = struct {
    t_action: TunnelKeyAction = @fromBackingInt(@intCast(0)),
    src_ip4: ?[4]u8 = null,
    dst_ip4: ?[4]u8 = null,
    src_ip6: ?[16]u8 = null,
    dst_ip6: ?[16]u8 = null,
    key_id: ?u32 = null,
    dst_port: ?u16 = null,
    tos: ?u8 = null,
    ttl: ?u8 = null,
    no_csum: ?bool = null,
    no_frag: bool = false,
};

// ── mpls ────────────────────────────────────────────────────────────────────

/// `TCA_MPLS_*`.
pub const TCA_MPLS = struct {
    pub const UNSPEC: u16 = 0;
    pub const TM: u16 = 1;
    pub const PARMS: u16 = 2;
    pub const PAD: u16 = 3;
    pub const PROTO: u16 = 4;
    pub const LABEL: u16 = 5;
    pub const TC: u16 = 6;
    pub const TTL: u16 = 7;
    pub const BOS: u16 = 8;
};

/// `sizeof(struct tc_mpls)` — prologue + `m_action`.
pub const tc_mpls_len = tc_gen_len + 4;

/// `tc_mpls.m_action` — `TCA_MPLS_ACT_*`.
pub const MplsAction = enum(i32) {
    pop = 1,
    push = 2,
    modify = 3,
    dec_ttl = 4,
    mac_push = 5,
    _,
};

/// **mpls** — push, pop or modify an MPLS label stack entry.
pub const Mpls = struct {
    m_action: MplsAction,
    /// `protocol` — the ethertype of the payload (pop) or of the stack (push),
    /// host order, sent big-endian.
    proto: ?u16 = null,
    label: ?u32 = null,
    tc: ?u8 = null,
    ttl: ?u8 = null,
    bos: ?u8 = null,
    index: u32 = 0,
    /// mpls is a mid-list action: `tc` sends `TC_ACT_PIPE`.
    action: Verdict = .pipe,
    cookie: []const u8 = &.{},
    extra: Extra = .{},
};

pub const MplsWire = struct {
    m_action: MplsAction = @fromBackingInt(@intCast(0)),
    proto: ?u16 = null,
    label: ?u32 = null,
    tc: ?u8 = null,
    ttl: ?u8 = null,
    bos: ?u8 = null,
};

// ── nat ─────────────────────────────────────────────────────────────────────

/// `TCA_NAT_*`.
pub const TCA_NAT = struct {
    pub const UNSPEC: u16 = 0;
    pub const PARMS: u16 = 1;
    pub const TM: u16 = 2;
    pub const PAD: u16 = 3;
};

/// `sizeof(struct tc_nat)` — prologue + `old_addr`, `new_addr`, `mask`,
/// `flags`.
pub const tc_nat_len = tc_gen_len + 16;

/// `TCA_NAT_FLAG_EGRESS`.
pub const TCA_NAT_FLAG_EGRESS: u32 = 1;

/// **nat** — stateless IPv4 NAT of one address or prefix (`tc … action nat
/// ingress|egress OLD[/PLEN] NEW`).
pub const Nat = struct {
    /// The address (prefix) to rewrite, network byte order as written.
    old_addr: [4]u8,
    new_addr: [4]u8,
    /// The prefix mask as an address (`/24` is `255.255.255.0`); `tc` sends
    /// the all-ones mask for a bare address.
    mask: [4]u8 = .{ 255, 255, 255, 255 },
    /// `egress` rewrites the source address, `ingress` (false) the
    /// destination.
    egress: bool = false,
    index: u32 = 0,
    action: Verdict = .ok,
    cookie: []const u8 = &.{},
    extra: Extra = .{},
};

pub const NatWire = struct {
    old_addr: [4]u8 = @splat(0),
    new_addr: [4]u8 = @splat(0),
    mask: [4]u8 = @splat(0),
    egress: bool = false,
};

// ── pedit ───────────────────────────────────────────────────────────────────

/// `TCA_PEDIT_*`.
pub const TCA_PEDIT = struct {
    pub const UNSPEC: u16 = 0;
    pub const TM: u16 = 1;
    pub const PARMS: u16 = 2;
    pub const PAD: u16 = 3;
    pub const PARMS_EX: u16 = 4;
    pub const KEYS_EX: u16 = 5;
    pub const KEY_EX: u16 = 6;
};

/// `TCA_PEDIT_KEY_EX_*`.
pub const TCA_PEDIT_KEY_EX = struct {
    pub const HTYPE: u16 = 1;
    pub const CMD: u16 = 2;
};

/// `sizeof(struct tc_pedit_sel)` before its keys — prologue, `nkeys`,
/// `flags`, two bytes of padding.
pub const tc_pedit_sel_len = tc_gen_len + 4;
/// `sizeof(struct tc_pedit_key)`.
pub const tc_pedit_key_len = 24;
/// The most keys one pedit action may carry (`nkeys` is a `u8`).
pub const max_pedit_keys = 255;
/// How many keys a decoded pedit action keeps (the rest are counted in
/// `PeditWire.nkeys`).
pub const max_pedit_keys_decoded = 8;

/// `enum pedit_header_type` — which header an extended key's offset is
/// relative to.
pub const PeditHdr = enum(u16) {
    network = 0,
    eth = 1,
    ip4 = 2,
    ip6 = 3,
    tcp = 4,
    udp = 5,
    _,
};

/// `enum pedit_cmd`.
pub const PeditCmd = enum(u16) {
    set = 0,
    add = 1,
    _,
};

/// One `struct tc_pedit_key` plus its extended-key attributes: the kernel
/// computes `word = (word & mask) ^ val` (or an add for `.add`) on the
/// 32-bit word at `off` bytes into the header.
///
/// `mask` and `val` are the numbers as read **big-endian off the packet**
/// (first byte most significant): `ip dst set 10.1.2.3` is `val =
/// 0x0a010203, mask = 0` at `off = 16`. A set bit in `mask` KEEPS that bit.
pub const PeditKey = struct {
    htype: PeditHdr = .network,
    cmd: PeditCmd = .set,
    mask: u32,
    val: u32,
    off: u32,
    at: u32 = 0,
    offmask: u32 = 0,
    shift: u32 = 0,
};

pub const PeditMungeError = error{
    /// The output slice is too small for the words the range covers.
    TooManyKeys,
    /// `retain` has a different length than `data`.
    BadRetain,
};

/// Split a byte-range edit into the 32-bit-word keys the kernel wants —
/// what `tc … pedit munge ip6 dst set 2001:db8::1` does. `data` is written at
/// byte offset `off` of the header `htype` names (`cmd` is `.set` or `.add`);
/// `retain` (same length as `data`, default all ones) is the `retain MASK`
/// modifier: only those bits of `data` are changed. Returns the filled prefix
/// of `out`.
pub fn peditMunge(
    out: []PeditKey,
    htype: PeditHdr,
    cmd: PeditCmd,
    off: u32,
    data: []const u8,
    retain: ?[]const u8,
) PeditMungeError![]PeditKey {
    if (retain) |r| if (r.len != data.len) return error.BadRetain;
    if (data.len == 0) return out[0..0];
    const first = off & ~@as(u32, 3);
    const last = (off + @as(u32, @intCast(data.len)) - 1) & ~@as(u32, 3);
    const words = (last - first) / 4 + 1;
    if (words > out.len) return error.TooManyKeys;
    var i: usize = 0;
    while (i < words) : (i += 1) {
        var keep: [4]u8 = @splat(0xff);
        var val: [4]u8 = @splat(0);
        const word_off = first + @as(u32, @intCast(i)) * 4;
        for (0..4) |b| {
            const pos = word_off + @as(u32, @intCast(b));
            if (pos < off or pos >= off + data.len) continue;
            const idx = pos - off;
            const r: u8 = if (retain) |rr| rr[idx] else 0xff;
            keep[b] = ~r;
            val[b] = data[idx] & r;
        }
        out[i] = .{
            .htype = htype,
            .cmd = cmd,
            .mask = std.mem.readInt(u32, &keep, .big),
            .val = std.mem.readInt(u32, &val, .big),
            .off = word_off,
        };
    }
    return out[0..words];
}

/// **pedit** — edit packet header words in place.
pub const Pedit = struct {
    keys: []const PeditKey,
    /// `true` (the default, `tc … pedit ex …`) sends `TCA_PEDIT_PARMS_EX`
    /// plus a `TCA_PEDIT_KEYS_EX` list naming each key's header type and
    /// command; `false` is the legacy `TCA_PEDIT_PARMS` (set only, `htype`
    /// and `cmd` ignored, offsets relative to the network header).
    extended: bool = true,
    index: u32 = 0,
    /// `tc`'s default for pedit is `TC_ACT_OK`.
    action: Verdict = .ok,
    cookie: []const u8 = &.{},
    extra: Extra = .{},
};

pub const PeditWire = struct {
    /// The key count the kernel reported (may exceed `keys.len`).
    nkeys: u8 = 0,
    flags: u8 = 0,
    /// The first `max_pedit_keys_decoded` keys; `htype`/`cmd` come from
    /// `TCA_PEDIT_KEYS_EX` (network / set when it is absent).
    keys: [max_pedit_keys_decoded]PeditKey = @splat(.{ .mask = 0, .val = 0, .off = 0 }),
    /// How many entries of `keys` are filled.
    len: u8 = 0,
    extended: bool = false,
};

// ── ct ──────────────────────────────────────────────────────────────────────

/// `TCA_CT_*`.
pub const TCA_CT = struct {
    pub const UNSPEC: u16 = 0;
    pub const PARMS: u16 = 1;
    pub const TM: u16 = 2;
    pub const ACTION: u16 = 3;
    pub const ZONE: u16 = 4;
    pub const MARK: u16 = 5;
    pub const MARK_MASK: u16 = 6;
    pub const LABELS: u16 = 7;
    pub const LABELS_MASK: u16 = 8;
    pub const NAT_IPV4_MIN: u16 = 9;
    pub const NAT_IPV4_MAX: u16 = 10;
    pub const NAT_IPV6_MIN: u16 = 11;
    pub const NAT_IPV6_MAX: u16 = 12;
    pub const NAT_PORT_MIN: u16 = 13;
    pub const NAT_PORT_MAX: u16 = 14;
    pub const PAD: u16 = 15;
    pub const HELPER_NAME: u16 = 16;
    pub const HELPER_FAMILY: u16 = 17;
    pub const HELPER_PROTO: u16 = 18;
};

/// `TCA_CT_ACT_*` — bits of `Ct.ct_action`.
pub const CT_ACT = struct {
    pub const COMMIT: u16 = 1 << 0;
    pub const FORCE: u16 = 1 << 1;
    pub const CLEAR: u16 = 1 << 2;
    pub const NAT: u16 = 1 << 3;
    pub const NAT_SRC: u16 = 1 << 4;
    pub const NAT_DST: u16 = 1 << 5;
};

/// `sizeof(struct tc_ct)` — nothing but the prologue.
pub const tc_ct_len = tc_gen_len;

/// Longest `HELPER_NAME` kept on readback (`NF_CT_HELPER_NAME_LEN`).
pub const ct_helper_name_max = 16;

/// The `helper FAMILY-PROTO-NAME` modifier.
pub const CtHelper = struct {
    /// `AF_INET` (2) or `AF_INET6` (10).
    family: u8,
    /// `IPPROTO_TCP` (6) or `IPPROTO_UDP` (17).
    proto: u8,
    name: []const u8,
};

/// **ct** — connection tracking: `tc … action ct commit zone 5 mark 7/0xff`,
/// `ct nat`, `ct clear`.
pub const Ct = struct {
    /// `CT_ACT.*` bits. `tc ct commit` is `COMMIT`, `ct clear` is `CLEAR`,
    /// `ct nat` is `NAT`; `commit nat src` adds `NAT | NAT_SRC`.
    ct_action: u16 = 0,
    zone: ?u16 = null,
    mark: ?u32 = null,
    mark_mask: ?u32 = null,
    /// `label LABEL/MASK`, both 128 bits as sent (no byte swapping).
    labels: ?[16]u8 = null,
    labels_mask: ?[16]u8 = null,
    /// `nat src|dst addr MIN-MAX` for IPv4; for a single address both equal.
    nat_ipv4_min: ?[4]u8 = null,
    nat_ipv4_max: ?[4]u8 = null,
    nat_ipv6_min: ?[16]u8 = null,
    nat_ipv6_max: ?[16]u8 = null,
    /// `port MIN-MAX`, sent big-endian.
    nat_port_min: ?u16 = null,
    nat_port_max: ?u16 = null,
    helper: ?CtHelper = null,
    index: u32 = 0,
    /// ct is a mid-list action: `tc` sends `TC_ACT_PIPE`.
    action: Verdict = .pipe,
    cookie: []const u8 = &.{},
    extra: Extra = .{},
};

pub const CtWire = struct {
    ct_action: u16 = 0,
    zone: ?u16 = null,
    mark: ?u32 = null,
    mark_mask: ?u32 = null,
    labels: ?[16]u8 = null,
    labels_mask: ?[16]u8 = null,
    nat_ipv4_min: ?[4]u8 = null,
    nat_ipv4_max: ?[4]u8 = null,
    nat_ipv6_min: ?[16]u8 = null,
    nat_ipv6_max: ?[16]u8 = null,
    nat_port_min: ?u16 = null,
    nat_port_max: ?u16 = null,
    helper_family: ?u8 = null,
    helper_proto: ?u8 = null,
    helper_name_buf: [ct_helper_name_max]u8 = @splat(0),
    helper_name_len: u8 = 0,

    pub fn helperName(w: *const CtWire) []const u8 {
        return w.helper_name_buf[0..w.helper_name_len];
    }
};

/// The kind-specific readback of the kinds `Action` carries in `Action.ext`.
pub const ExtWire = union(enum) {
    connmark: ConnmarkWire,
    csum: CsumWire,
    sample: SampleWire,
    tunnel_key: TunnelKeyWire,
    mpls: MplsWire,
    nat: NatWire,
    pedit: PeditWire,
    ct: CtWire,
};

// ── raw escape hatch ────────────────────────────────────────────────────────

/// Any action kind this module does not model: a kind string plus a
/// pre-encoded `TCA_ACT_OPTIONS` payload (a sequence of rtattrs, e.g. a
/// `TCA_CONNMARK_PARMS` you built yourself). An empty payload still emits the
/// options nest, which is what every kind's parser expects.
pub const Raw = struct {
    kind: []const u8,
    options: []const u8 = &.{},
    index: u32 = 0,
    cookie: []const u8 = &.{},
    extra: Extra = .{},
};

// ── the action spec ─────────────────────────────────────────────────────────

/// One action to install. A list of these becomes the nested `TCA_*_ACT`
/// attribute of a filter, or the `TCA_ACT_TAB` of a standalone
/// `RTM_NEWACTION`.
pub const ActionSpec = union(enum) {
    gact: Gact,
    mirred: Mirred,
    police: Police,
    skbedit: Skbedit,
    vlan: Vlan,
    connmark: Connmark,
    csum: Csum,
    sample: Sample,
    tunnel_key: TunnelKey,
    mpls: Mpls,
    nat: Nat,
    pedit: Pedit,
    ct: Ct,
    raw: Raw,

    pub fn kind(self: ActionSpec) []const u8 {
        return switch (self) {
            .gact => kind_gact,
            .mirred => kind_mirred,
            .police => kind_police,
            .skbedit => kind_skbedit,
            .vlan => kind_vlan,
            .connmark => kind_connmark,
            .csum => kind_csum,
            .sample => kind_sample,
            .tunnel_key => kind_tunnel_key,
            .mpls => kind_mpls,
            .nat => kind_nat,
            .pedit => kind_pedit,
            .ct => kind_ct,
            .raw => |r| r.kind,
        };
    }

    /// The opaque `TCA_ACT_COOKIE`, or an empty slice.
    pub fn cookie(self: ActionSpec) []const u8 {
        return switch (self) {
            inline else => |a| a.cookie,
        };
    }

    /// The action-level `TCA_ACT_HW_STATS` / `TCA_ACT_FLAGS` attributes.
    pub fn extra(self: ActionSpec) Extra {
        return switch (self) {
            inline else => |a| a.extra,
        };
    }

    /// The shared-table index the spec asks for (0 = kernel-allocated).
    pub fn index(self: ActionSpec) u32 {
        return switch (self) {
            inline else => |a| a.index,
        };
    }

    /// Append the kind-specific body of `TCA_ACT_OPTIONS` (the caller opens
    /// and closes the nest).
    pub fn appendOptions(
        self: ActionSpec,
        gpa: std.mem.Allocator,
        list: *std.ArrayList(u8),
        ps: Psched,
    ) EncodeError!void {
        switch (self) {
            .gact => |g| try appendGactOptions(g, gpa, list),
            .mirred => |m| try appendMirredOptions(m, gpa, list),
            .police => |p| try appendPoliceOptions(p, gpa, list, ps),
            .skbedit => |s| try appendSkbeditOptions(s, gpa, list),
            .vlan => |v| try appendVlanOptions(v, gpa, list),
            .connmark => |c| try appendConnmarkOptions(c, gpa, list),
            .csum => |c| try appendCsumOptions(c, gpa, list),
            .sample => |x| try appendSampleOptions(x, gpa, list),
            .tunnel_key => |t| try appendTunnelKeyOptions(t, gpa, list),
            .mpls => |m| try appendMplsOptions(m, gpa, list),
            .nat => |n| try appendNatOptions(n, gpa, list),
            .pedit => |x| try appendPeditOptions(x, gpa, list),
            .ct => |c| try appendCtOptions(c, gpa, list),
            .raw => |r| {
                if (r.options.len > std.math.maxInt(u16)) return error.OptionsTooLong;
                try list.appendSlice(gpa, r.options);
                try list.appendNTimes(gpa, 0, codec.alignUp(r.options.len) - r.options.len);
            },
        }
    }
};

// ── encoding ────────────────────────────────────────────────────────────────

fn appendAttr(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    data: []const u8,
) std.mem.Allocator.Error!void {
    codec.appendAttr(gpa, list, attr_type, data) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // every caller passes a bounded buffer
        error.OutOfMemory => return error.OutOfMemory,
    };
}

const appendAttrU64 = codec.appendAttrU64;

fn appendAttrBe16(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u16,
) std.mem.Allocator.Error!void {
    var raw: [2]u8 = undefined;
    std.mem.writeInt(u16, &raw, value, .big);
    try appendAttr(gpa, list, attr_type, &raw);
}

/// `TCA_ACT_KIND`. The kind is caller-supplied (`ActionSpec.raw`,
/// `ActionRef.kind`) and nothing bounds it, so a kind past the attribute's
/// 16-bit length is `OptionsTooLong` — as `message.zig`'s `appendKind` (F8).
/// It used to be `unreachable` here: a reachable panic (UB in ReleaseFast).
fn appendKind(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    k: []const u8,
) EncodeError!void {
    codec.appendAttrString(gpa, list, TCA_ACT.KIND, k) catch |err| switch (err) {
        error.AttrTooLong => return error.OptionsTooLong,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

fn appendGactOptions(
    g: Gact,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
) EncodeError!void {
    const gen: Gen = .{ .index = g.index, .action = g.action };
    try appendAttr(gpa, list, TCA_GACT.PARMS, &gen.encode());
    if (g.random) |p| try appendAttr(gpa, list, TCA_GACT.PROB, &p.encode());
}

fn appendMirredOptions(
    m: Mirred,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
) EncodeError!void {
    const gen: Gen = .{
        .index = m.index,
        .action = m.action orelse m.eaction.defaultVerdict(),
    };
    var buf: [tc_mirred_len]u8 = undefined;
    buf[0..tc_gen_len].* = gen.encode();
    std.mem.writeInt(i32, buf[20..24], @backingInt(m.eaction), native_endian);
    std.mem.writeInt(u32, buf[24..28], m.ifindex, native_endian);
    try appendAttr(gpa, list, TCA_MIRRED.PARMS, &buf);
}

/// Clamp a 64-bit rate into a `tc_ratespec.rate` the way `tc` does: anything
/// needing more than 32 bits is pinned to `~0U` and carried in the companion
/// `*_RATE64` attribute.
fn clampRate(rate: u64) u32 {
    return if (rate >= (1 << 32)) std.math.maxInt(u32) else @intCast(rate);
}

fn appendPoliceOptions(
    p: Police,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ps: Psched,
) EncodeError!void {
    if (p.rate != 0 and p.pkt_rate != 0) return error.RateConflict;
    if (p.rate == 0 and p.pkt_rate == 0 and p.avrate == 0) return error.MissingRate;
    if (p.rate == 0 and p.peakrate != 0) return error.MissingRate;
    if (p.rate != 0 and p.burst == 0) return error.MissingBurst;
    if (p.pkt_rate != 0 and p.pkt_burst == 0) return error.MissingBurst;
    if (p.peakrate != 0 and p.mtu == 0) return error.MissingMtu;
    try ratespec.checkCellLog(p.cell_log);
    try ratespec.checkCellLog(p.pcell_log);

    var rate_spec: RateSpec = .{
        .rate = clampRate(p.rate),
        .mpu = p.mpu,
        .overhead = p.overhead,
    };
    var peak_spec: RateSpec = .{
        .rate = clampRate(p.peakrate),
        .mpu = p.mpu,
        .overhead = p.overhead,
    };

    var rtab: [ratespec.rate_table_entries]u32 = undefined;
    var ptab: [ratespec.rate_table_entries]u32 = undefined;
    // **Unlike htb and tbf**, police computes its tables from the *full*
    // 64-bit rate, where those two bake the ~0U clamp into their tables.
    // The `rate 40gbit` goldens pin the difference —
    // their last table entry is 7, not the 8 the clamped rate would give.
    if (p.rate != 0) ratespec.calcRateTable(ps, &rate_spec, &rtab, p.cell_log, p.mtu, p.linklayer, p.rate);
    const burst_ticks = if (p.rate != 0) ps.calcXmitTime(p.rate, p.burst) else 0;
    if (p.peakrate != 0) {
        // F10: unlike htb/tbf, police feeds calcRateTable the *unclamped*
        // rate via rate_override (see the note above), so the reuse
        // condition compares those raw values, not rate_spec/peak_spec.
        if (p.peakrate == p.rate and p.pcell_log == p.cell_log) {
            ptab = rtab;
            peak_spec.cell_align = rate_spec.cell_align;
            peak_spec.cell_log = rate_spec.cell_log;
            peak_spec.linklayer = rate_spec.linklayer;
        } else {
            ratespec.calcRateTable(ps, &peak_spec, &ptab, p.pcell_log, p.mtu, p.linklayer, p.peakrate);
        }
    }

    var tbf: [tc_police_len]u8 = @splat(0);
    std.mem.writeInt(u32, tbf[0..4], p.index, native_endian);
    std.mem.writeInt(i32, tbf[4..8], p.exceed.raw(), native_endian);
    std.mem.writeInt(u32, tbf[8..12], p.limit, native_endian);
    std.mem.writeInt(u32, tbf[12..16], burst_ticks, native_endian);
    std.mem.writeInt(u32, tbf[16..20], p.mtu, native_endian);
    if (p.rate != 0) tbf[20..32].* = rate_spec.encode();
    if (p.peakrate != 0) tbf[32..44].* = peak_spec.encode();
    // refcnt/bindcnt/capab stay 0 — the kernel owns them.
    try appendAttr(gpa, list, TCA_POLICE.TBF, &tbf);

    if (p.rate != 0) {
        try appendAttr(gpa, list, TCA_POLICE.RATE, &ratespec.encodeRateTable(&rtab));
        if (p.rate >= (1 << 32)) try appendAttrU64(gpa, list, TCA_POLICE.RATE64, p.rate);
    }
    if (p.peakrate != 0) {
        try appendAttr(gpa, list, TCA_POLICE.PEAKRATE, &ratespec.encodeRateTable(&ptab));
        if (p.peakrate >= (1 << 32))
            try appendAttrU64(gpa, list, TCA_POLICE.PEAKRATE64, p.peakrate);
    }
    if (p.avrate != 0) try codec.appendAttrU32(gpa, list, TCA_POLICE.AVRATE, p.avrate);
    if (p.notexceed) |r|
        try codec.appendAttrU32(gpa, list, TCA_POLICE.RESULT, @bitCast(r.raw()));
    if (p.pkt_rate != 0) {
        try appendAttrU64(gpa, list, TCA_POLICE.PKTRATE64, p.pkt_rate);
        try appendAttrU64(gpa, list, TCA_POLICE.PKTBURST64, ps.calcXmitTime(p.pkt_rate, p.pkt_burst));
    }
}

fn appendSkbeditOptions(
    s: Skbedit,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
) EncodeError!void {
    const gen: Gen = .{ .index = s.index, .action = s.action };
    try appendAttr(gpa, list, TCA_SKBEDIT.PARMS, &gen.encode());
    // Attribute order does not matter to the kernel; this one is fixed so the
    // requests stay byte-identical to the goldens.
    if (s.queue_mapping) |q| try codec.appendAttrU16(gpa, list, TCA_SKBEDIT.QUEUE_MAPPING, q);
    if (s.priority) |h| try codec.appendAttrU32(gpa, list, TCA_SKBEDIT.PRIORITY, h.raw);
    if (s.mark) |m| try codec.appendAttrU32(gpa, list, TCA_SKBEDIT.MARK, m);
    if (s.mask) |m| try codec.appendAttrU32(gpa, list, TCA_SKBEDIT.MASK, m);
    if (s.ptype) |t| try codec.appendAttrU16(gpa, list, TCA_SKBEDIT.PTYPE, t);
    if (s.inherit_dsfield) try appendAttrU64(gpa, list, TCA_SKBEDIT.FLAGS, SKBEDIT_F_INHERITDSFIELD);
}

fn appendVlanOptions(
    v: Vlan,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
) EncodeError!void {
    const gen: Gen = .{ .index = v.index, .action = v.action };
    var buf: [tc_vlan_len]u8 = undefined;
    buf[0..tc_gen_len].* = gen.encode();
    std.mem.writeInt(i32, buf[20..24], @backingInt(v.v_action), native_endian);
    try appendAttr(gpa, list, TCA_VLAN.PARMS, &buf);
    if (v.id) |id| try codec.appendAttrU16(gpa, list, TCA_VLAN.PUSH_VLAN_ID, id);
    if (v.proto) |pr| try appendAttrBe16(gpa, list, TCA_VLAN.PUSH_VLAN_PROTOCOL, pr);
    if (v.prio) |pc| try codec.appendAttrU8(gpa, list, TCA_VLAN.PUSH_VLAN_PRIORITY, pc);
    if (v.eth_dst) |m| try appendAttr(gpa, list, TCA_VLAN.PUSH_ETH_DST, &m);
    if (v.eth_src) |m| try appendAttr(gpa, list, TCA_VLAN.PUSH_ETH_SRC, &m);
}

/// `TCA_*_PARMS`: the `tc_gen` prologue plus a kind's fixed tail.
fn appendGenParms(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    index: u32,
    verdict: Verdict,
    tail: []const u8,
) std.mem.Allocator.Error!void {
    var buf: [tc_gen_len + 16]u8 = undefined;
    std.debug.assert(tail.len <= 16);
    const gen: Gen = .{ .index = index, .action = verdict };
    buf[0..tc_gen_len].* = gen.encode();
    @memcpy(buf[tc_gen_len..][0..tail.len], tail);
    try appendAttr(gpa, list, attr_type, buf[0 .. tc_gen_len + tail.len]);
}

fn appendAttrBe32(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u32,
) std.mem.Allocator.Error!void {
    var raw: [4]u8 = undefined;
    std.mem.writeInt(u32, &raw, value, .big);
    try appendAttr(gpa, list, attr_type, &raw);
}

fn appendConnmarkOptions(c: Connmark, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) EncodeError!void {
    var tail: [4]u8 = @splat(0);
    std.mem.writeInt(u16, tail[0..2], c.zone, native_endian);
    try appendGenParms(gpa, list, TCA_CONNMARK.PARMS, c.index, c.action, &tail);
}

fn appendCsumOptions(c: Csum, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) EncodeError!void {
    var tail: [4]u8 = undefined;
    std.mem.writeInt(u32, &tail, c.update_flags, native_endian);
    try appendGenParms(gpa, list, TCA_CSUM.PARMS, c.index, c.action, &tail);
}

fn appendSampleOptions(s: Sample, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) EncodeError!void {
    try appendGenParms(gpa, list, TCA_SAMPLE.PARMS, s.index, s.action, &.{});
    try codec.appendAttrU32(gpa, list, TCA_SAMPLE.RATE, s.rate);
    try codec.appendAttrU32(gpa, list, TCA_SAMPLE.PSAMPLE_GROUP, s.group);
    if (s.trunc_size) |t| try codec.appendAttrU32(gpa, list, TCA_SAMPLE.TRUNC_SIZE, t);
}

fn appendTunnelKeyOptions(t: TunnelKey, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) EncodeError!void {
    if (t.enc_opts.len > std.math.maxInt(u16) - 4) return error.OptionsTooLong;
    // Attribute order follows `tc`'s command-line parse; the PARMS block
    // comes last (the goldens pin it).
    if (t.src_ip4) |a| try appendAttr(gpa, list, TCA_TUNNEL_KEY.ENC_IPV4_SRC, &a);
    if (t.dst_ip4) |a| try appendAttr(gpa, list, TCA_TUNNEL_KEY.ENC_IPV4_DST, &a);
    if (t.src_ip6) |a| try appendAttr(gpa, list, TCA_TUNNEL_KEY.ENC_IPV6_SRC, &a);
    if (t.dst_ip6) |a| try appendAttr(gpa, list, TCA_TUNNEL_KEY.ENC_IPV6_DST, &a);
    if (t.key_id) |k| try appendAttrBe32(gpa, list, TCA_TUNNEL_KEY.ENC_KEY_ID, k);
    if (t.dst_port) |p| try appendAttrBe16(gpa, list, TCA_TUNNEL_KEY.ENC_DST_PORT, p);
    if (t.tos) |v| try codec.appendAttrU8(gpa, list, TCA_TUNNEL_KEY.ENC_TOS, v);
    if (t.ttl) |v| try codec.appendAttrU8(gpa, list, TCA_TUNNEL_KEY.ENC_TTL, v);
    if (t.enc_opts.len != 0) try appendAttr(gpa, list, TCA_TUNNEL_KEY.ENC_OPTS, t.enc_opts);
    try codec.appendAttrU8(gpa, list, TCA_TUNNEL_KEY.NO_CSUM, @intFromBool(t.no_csum));
    if (t.no_frag) try appendAttr(gpa, list, TCA_TUNNEL_KEY.NO_FRAG, &.{});
    var tail: [4]u8 = undefined;
    std.mem.writeInt(i32, &tail, @backingInt(t.t_action), native_endian);
    try appendGenParms(gpa, list, TCA_TUNNEL_KEY.PARMS, t.index, t.action, &tail);
}

fn appendMplsOptions(m: Mpls, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) EncodeError!void {
    var tail: [4]u8 = undefined;
    std.mem.writeInt(i32, &tail, @backingInt(m.m_action), native_endian);
    try appendGenParms(gpa, list, TCA_MPLS.PARMS, m.index, m.action, &tail);
    if (m.label) |l| try codec.appendAttrU32(gpa, list, TCA_MPLS.LABEL, l);
    if (m.proto) |p| try appendAttrBe16(gpa, list, TCA_MPLS.PROTO, p);
    if (m.tc) |v| try codec.appendAttrU8(gpa, list, TCA_MPLS.TC, v);
    if (m.ttl) |v| try codec.appendAttrU8(gpa, list, TCA_MPLS.TTL, v);
    if (m.bos) |v| try codec.appendAttrU8(gpa, list, TCA_MPLS.BOS, v);
}

fn appendNatOptions(n: Nat, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) EncodeError!void {
    var tail: [16]u8 = undefined;
    tail[0..4].* = n.old_addr;
    tail[4..8].* = n.new_addr;
    tail[8..12].* = n.mask;
    std.mem.writeInt(u32, tail[12..16], if (n.egress) TCA_NAT_FLAG_EGRESS else 0, native_endian);
    try appendGenParms(gpa, list, TCA_NAT.PARMS, n.index, n.action, &tail);
}

fn appendPeditOptions(p: Pedit, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) EncodeError!void {
    if (p.keys.len > max_pedit_keys) return error.OptionsTooLong;
    const sel = try gpa.alloc(u8, tc_pedit_sel_len + p.keys.len * tc_pedit_key_len);
    defer gpa.free(sel);
    @memset(sel, 0);
    const gen: Gen = .{ .index = p.index, .action = p.action };
    sel[0..tc_gen_len].* = gen.encode();
    sel[tc_gen_len] = @intCast(p.keys.len);
    for (p.keys, 0..) |k, i| {
        const b = sel[tc_pedit_sel_len + i * tc_pedit_key_len ..][0..tc_pedit_key_len];
        // struct tc_pedit_key: mask, val, off, at, offmask, shift. mask and
        // val are the packet-order words (big-endian bytes in memory).
        std.mem.writeInt(u32, b[0..4], k.mask, .big);
        std.mem.writeInt(u32, b[4..8], k.val, .big);
        std.mem.writeInt(u32, b[8..12], k.off, native_endian);
        std.mem.writeInt(u32, b[12..16], k.at, native_endian);
        std.mem.writeInt(u32, b[16..20], k.offmask, native_endian);
        std.mem.writeInt(u32, b[20..24], k.shift, native_endian);
    }
    try appendAttr(gpa, list, if (p.extended) TCA_PEDIT.PARMS_EX else TCA_PEDIT.PARMS, sel);
    if (!p.extended) return;
    const keys = try codec.nestBegin(gpa, list, TCA_PEDIT.KEYS_EX | codec.NLA_F_NESTED);
    for (p.keys) |k| {
        const ex = try codec.nestBegin(gpa, list, TCA_PEDIT.KEY_EX | codec.NLA_F_NESTED);
        try codec.appendAttrU16(gpa, list, TCA_PEDIT_KEY_EX.HTYPE, @backingInt(k.htype));
        try codec.appendAttrU16(gpa, list, TCA_PEDIT_KEY_EX.CMD, @backingInt(k.cmd));
        codec.nestEnd(list, ex) catch return error.OptionsTooLong;
    }
    codec.nestEnd(list, keys) catch return error.OptionsTooLong;
}

fn appendCtOptions(c: Ct, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) EncodeError!void {
    if (c.zone) |z| try codec.appendAttrU16(gpa, list, TCA_CT.ZONE, z);
    if (c.mark) |m| try codec.appendAttrU32(gpa, list, TCA_CT.MARK, m);
    if (c.mark_mask) |m| try codec.appendAttrU32(gpa, list, TCA_CT.MARK_MASK, m);
    if (c.labels) |l| try appendAttr(gpa, list, TCA_CT.LABELS, &l);
    if (c.labels_mask) |l| try appendAttr(gpa, list, TCA_CT.LABELS_MASK, &l);
    if (c.nat_ipv4_min) |a| try appendAttr(gpa, list, TCA_CT.NAT_IPV4_MIN, &a);
    if (c.nat_ipv4_max) |a| try appendAttr(gpa, list, TCA_CT.NAT_IPV4_MAX, &a);
    if (c.nat_ipv6_min) |a| try appendAttr(gpa, list, TCA_CT.NAT_IPV6_MIN, &a);
    if (c.nat_ipv6_max) |a| try appendAttr(gpa, list, TCA_CT.NAT_IPV6_MAX, &a);
    if (c.nat_port_min) |p| try appendAttrBe16(gpa, list, TCA_CT.NAT_PORT_MIN, p);
    if (c.nat_port_max) |p| try appendAttrBe16(gpa, list, TCA_CT.NAT_PORT_MAX, p);
    if (c.helper) |h| {
        try codec.appendAttrU8(gpa, list, TCA_CT.HELPER_FAMILY, h.family);
        try codec.appendAttrU8(gpa, list, TCA_CT.HELPER_PROTO, h.proto);
        codec.appendAttrString(gpa, list, TCA_CT.HELPER_NAME, h.name) catch |err| switch (err) {
            error.AttrTooLong => return error.OptionsTooLong,
            error.OutOfMemory => return error.OutOfMemory,
        };
    }
    // `tc` always sends the action word, 0 for a plain `ct zone N`.
    try codec.appendAttrU16(gpa, list, TCA_CT.ACTION, c.ct_action);
    try appendGenParms(gpa, list, TCA_CT.PARMS, c.index, c.action, &.{});
}

/// Append a complete action list as one nested attribute — `TCA_U32_ACT`,
/// `TCA_FLOWER_ACT` or `TCA_ACT_TAB`, all identical in shape.
///
/// Entries are numbered **from 1**. An empty list appends nothing at all
/// (`tc` omits the attribute rather than sending an empty nest).
pub fn appendActionList(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    actions: []const ActionSpec,
    ps: Psched,
) EncodeError!void {
    if (actions.len == 0) return;
    if (actions.len > max_actions) return error.TooManyActions;
    for (actions) |a| {
        if (a.cookie().len > max_cookie_len) return error.CookieTooLong;
    }
    const outer = try codec.nestBegin(gpa, list, attr_type);
    for (actions, 0..) |a, i| {
        // 1-based ordinal: attribute type 0 is TCA_ACT_UNSPEC and the kernel
        // will not accept an action there.
        const ordinal: u16 = @intCast(i + 1);
        const entry = try codec.nestBegin(gpa, list, ordinal);
        try appendKind(gpa, list, a.kind());
        // TCA_ACT_OPTIONS carries NLA_F_NESTED (the qdisc-level TCA_OPTIONS
        // does not); see the module doc comment.
        const opts = try codec.nestBegin(gpa, list, TCA_ACT.OPTIONS | codec.NLA_F_NESTED);
        try a.appendOptions(gpa, list, ps);
        codec.nestEnd(list, opts) catch return error.OptionsTooLong;
        const ck = a.cookie();
        if (ck.len != 0) try appendAttr(gpa, list, TCA_ACT.COOKIE, ck);
        const ex = a.extra();
        if (ex.hw_stats) |b| try appendAttr(gpa, list, TCA_ACT.HW_STATS, &b.encode());
        if (ex.flags) |b| try appendAttr(gpa, list, TCA_ACT.FLAGS, &b.encode());
        codec.nestEnd(list, entry) catch return error.OptionsTooLong;
    }
    codec.nestEnd(list, outer) catch return error.OptionsTooLong;
}

/// A reference to an already-installed action in the shared table — what
/// `tc actions del|get action KIND index N` sends, and (with a null `index`)
/// what `tc actions ls action KIND` sends.
pub const ActionRef = struct {
    kind: []const u8,
    index: ?u32 = null,
};

/// Append a list of action *references* (`TCA_ACT_KIND` + optional
/// `TCA_ACT_INDEX`, no options) as one nested attribute. Same 1-based
/// ordinal numbering as `appendActionList`.
pub fn appendActionRefs(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    refs: []const ActionRef,
) EncodeError!void {
    if (refs.len > max_actions) return error.TooManyActions;
    const outer = try codec.nestBegin(gpa, list, attr_type);
    for (refs, 0..) |r, i| {
        const ordinal: u16 = @intCast(i + 1);
        const entry = try codec.nestBegin(gpa, list, ordinal);
        try appendKind(gpa, list, r.kind);
        if (r.index) |idx| try codec.appendAttrU32(gpa, list, TCA_ACT.INDEX, idx);
        codec.nestEnd(list, entry) catch return error.OptionsTooLong;
    }
    codec.nestEnd(list, outer) catch return error.OptionsTooLong;
}

/// Append `TCA_ROOT_FLAGS`, an `nla_bitfield32` (value, selector) pair.
pub fn appendRootFlags(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    value: u32,
    selector: u32,
) std.mem.Allocator.Error!void {
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u32, raw[0..4], value, native_endian);
    std.mem.writeInt(u32, raw[4..8], selector, native_endian);
    try appendAttr(gpa, list, TCA_ROOT.FLAGS, &raw);
}

// ── decoding ────────────────────────────────────────────────────────────────

/// `TCA_ACT_STATS` — the counters a dumped action carries.
pub const Stats = struct {
    /// `TCA_STATS_BASIC` (or `TCA_STATS_PKT64` for the packet count).
    bytes: u64 = 0,
    packets: u64 = 0,
    /// `TCA_STATS_QUEUE`.
    drops: u32 = 0,
    overlimits: u32 = 0,
};

/// `struct tcf_t` — the per-action timestamps, in kernel jiffies-derived
/// units. Present in each kind's `*_TM` attribute.
pub const Tm = struct {
    install: u64 = 0,
    lastuse: u64 = 0,
    expires: u64 = 0,
    firstuse: u64 = 0,
};

/// One action, as read back from a dumped filter or the shared action table.
/// A fixed-size value type: no allocation, safe to copy out of the receive
/// buffer.
pub const Action = struct {
    /// The 1-based ordinal this action had in its list.
    order: u16 = 0,
    kind_buf: [kind_max]u8 = @splat(0),
    kind_len: u8 = 0,
    /// The shared `tc_gen` prologue. For `police` it is reassembled from the
    /// equivalent `tc_police` fields.
    gen: Gen = .{},
    /// `TCA_ACT_INDEX` at the action level, when the sender used the
    /// reference form (`tc actions del|get`).
    index_attr: ?u32 = null,
    cookie_buf: [max_cookie_len]u8 = @splat(0),
    cookie_len: u8 = 0,
    gact: ?GactWire = null,
    mirred: ?MirredWire = null,
    police: ?PoliceWire = null,
    skbedit: ?SkbeditWire = null,
    vlan: ?VlanWire = null,
    /// The readback of the kinds added after the first five (`connmark`,
    /// `csum`, `sample`, `tunnel_key`, `mpls`, `nat`, `pedit`, `ct`).
    ext: ?ExtWire = null,
    /// `TCA_ACT_FLAGS`.
    flags: ?Bitfield32 = null,
    /// `TCA_ACT_HW_STATS`.
    hw_stats: ?Bitfield32 = null,
    /// `TCA_ACT_USED_HW_STATS` — which hardware stats the kernel used.
    used_hw_stats: ?Bitfield32 = null,
    /// `TCA_ACT_IN_HW_COUNT` — how many devices the action is offloaded to.
    in_hw_count: ?u32 = null,
    stats: ?Stats = null,
    tm: ?Tm = null,

    pub fn kind(a: *const Action) []const u8 {
        return a.kind_buf[0..a.kind_len];
    }

    pub fn cookie(a: *const Action) []const u8 {
        return a.cookie_buf[0..a.cookie_len];
    }
};

fn copyKind(buf: *[kind_max]u8, len: *u8, s: []const u8) codec.Error!void {
    if (s.len > kind_max) return error.BadLength;
    @memcpy(buf[0..s.len], s);
    len.* = @intCast(s.len);
}

fn parseTm(data: []const u8) ?Tm {
    if (data.len < tcf_t_len) return null;
    return .{
        .install = std.mem.readInt(u64, data[0..8], native_endian),
        .lastuse = std.mem.readInt(u64, data[8..16], native_endian),
        .expires = std.mem.readInt(u64, data[16..24], native_endian),
        .firstuse = std.mem.readInt(u64, data[24..32], native_endian),
    };
}

fn parseStats(data: []const u8) codec.Error!Stats {
    var s: Stats = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        // struct gnet_stats_basic { __u64 bytes; __u32 packets; } — the
        // kernel pads it out to 16 bytes, so only the prefix is read.
        TCA_STATS.BASIC, TCA_STATS.BASIC_HW => if (a.data.len >= 12) {
            s.bytes = std.mem.readInt(u64, a.data[0..8], native_endian);
            if (s.packets == 0) s.packets = std.mem.readInt(u32, a.data[8..12], native_endian);
        },
        // struct gnet_stats_queue { qlen, backlog, drops, requeues, overlimits }
        TCA_STATS.QUEUE => if (a.data.len >= 20) {
            s.drops = std.mem.readInt(u32, a.data[8..12], native_endian);
            s.overlimits = std.mem.readInt(u32, a.data[16..20], native_endian);
        },
        // 64-bit packet counter, authoritative when present.
        TCA_STATS.PKT64 => if (a.data.len >= 8) {
            s.packets = std.mem.readInt(u64, a.data[0..8], native_endian);
        },
        else => {},
    };
    return s;
}

fn parseGactOptions(a: *Action, data: []const u8) codec.Error!void {
    var w: GactWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |attr| switch (attr.type) {
        TCA_GACT.PARMS => {
            if (attr.data.len < tc_gact_len) return error.BadLength;
            a.gen = Gen.decode(attr.data[0..tc_gen_len]);
        },
        TCA_GACT.PROB => if (attr.data.len >= tc_gact_p_len) {
            w.random = GactProb.decode(attr.data[0..tc_gact_p_len]);
        },
        TCA_GACT.TM => a.tm = parseTm(attr.data),
        else => {},
    };
    a.gact = w;
}

fn parseMirredOptions(a: *Action, data: []const u8) codec.Error!void {
    var w: MirredWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |attr| switch (attr.type) {
        TCA_MIRRED.PARMS => {
            if (attr.data.len < tc_mirred_len) return error.BadLength;
            a.gen = Gen.decode(attr.data[0..tc_gen_len]);
            w.eaction = @fromBackingInt(@intCast(std.mem.readInt(i32, attr.data[20..24], native_endian)));
            w.ifindex = std.mem.readInt(u32, attr.data[24..28], native_endian);
        },
        TCA_MIRRED.TM => a.tm = parseTm(attr.data),
        else => {},
    };
    a.mirred = w;
}

fn parsePoliceOptions(a: *Action, data: []const u8) codec.Error!void {
    var w: PoliceWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |attr| switch (attr.type) {
        TCA_POLICE.TBF => {
            if (attr.data.len < tc_police_len) return error.BadLength;
            w.index = std.mem.readInt(u32, attr.data[0..4], native_endian);
            w.exceed = Verdict.fromRaw(std.mem.readInt(i32, attr.data[4..8], native_endian));
            w.limit = std.mem.readInt(u32, attr.data[8..12], native_endian);
            w.burst = std.mem.readInt(u32, attr.data[12..16], native_endian);
            w.mtu = std.mem.readInt(u32, attr.data[16..20], native_endian);
            w.rate = RateSpec.decode(attr.data[20..32]);
            w.peakrate = RateSpec.decode(attr.data[32..44]);
            w.refcnt = std.mem.readInt(i32, attr.data[44..48], native_endian);
            w.bindcnt = std.mem.readInt(i32, attr.data[48..52], native_endian);
            w.capab = std.mem.readInt(u32, attr.data[52..56], native_endian);
        },
        TCA_POLICE.RATE64 => if (attr.data.len >= 8) {
            w.rate64 = std.mem.readInt(u64, attr.data[0..8], native_endian);
        },
        TCA_POLICE.PEAKRATE64 => if (attr.data.len >= 8) {
            w.peakrate64 = std.mem.readInt(u64, attr.data[0..8], native_endian);
        },
        TCA_POLICE.AVRATE => if (attr.data.len >= 4) {
            w.avrate = std.mem.readInt(u32, attr.data[0..4], native_endian);
        },
        TCA_POLICE.PKTRATE64 => if (attr.data.len >= 8) {
            w.pkt_rate = std.mem.readInt(u64, attr.data[0..8], native_endian);
        },
        TCA_POLICE.PKTBURST64 => if (attr.data.len >= 8) {
            w.pkt_burst = std.mem.readInt(u64, attr.data[0..8], native_endian);
        },
        TCA_POLICE.RESULT => if (attr.data.len >= 4) {
            w.notexceed = Verdict.fromRaw(std.mem.readInt(i32, attr.data[0..4], native_endian));
        },
        TCA_POLICE.TM => a.tm = parseTm(attr.data),
        else => {},
    };
    if (w.rate64 == 0) w.rate64 = w.rate.rate;
    if (w.peakrate64 == 0) w.peakrate64 = w.peakrate.rate;
    // police has no tc_gen; present the equivalent fields uniformly.
    a.gen = .{
        .index = w.index,
        .capab = w.capab,
        .action = w.exceed,
        .refcnt = w.refcnt,
        .bindcnt = w.bindcnt,
    };
    a.police = w;
}

fn parseSkbeditOptions(a: *Action, data: []const u8) codec.Error!void {
    var w: SkbeditWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |attr| switch (attr.type) {
        TCA_SKBEDIT.PARMS => {
            if (attr.data.len < tc_skbedit_len) return error.BadLength;
            a.gen = Gen.decode(attr.data[0..tc_gen_len]);
        },
        TCA_SKBEDIT.PRIORITY => if (attr.data.len >= 4) {
            w.priority = Handle.fromRaw(std.mem.readInt(u32, attr.data[0..4], native_endian));
        },
        TCA_SKBEDIT.QUEUE_MAPPING => if (attr.data.len >= 2) {
            w.queue_mapping = std.mem.readInt(u16, attr.data[0..2], native_endian);
        },
        TCA_SKBEDIT.MARK => if (attr.data.len >= 4) {
            w.mark = std.mem.readInt(u32, attr.data[0..4], native_endian);
        },
        TCA_SKBEDIT.PTYPE => if (attr.data.len >= 2) {
            w.ptype = std.mem.readInt(u16, attr.data[0..2], native_endian);
        },
        TCA_SKBEDIT.MASK => if (attr.data.len >= 4) {
            w.mask = std.mem.readInt(u32, attr.data[0..4], native_endian);
        },
        TCA_SKBEDIT.FLAGS => if (attr.data.len >= 8) {
            w.inherit_dsfield = std.mem.readInt(u64, attr.data[0..8], native_endian) & SKBEDIT_F_INHERITDSFIELD != 0;
        },
        TCA_SKBEDIT.TM => a.tm = parseTm(attr.data),
        else => {},
    };
    a.skbedit = w;
}

fn parseVlanOptions(a: *Action, data: []const u8) codec.Error!void {
    var w: VlanWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |attr| switch (attr.type) {
        TCA_VLAN.PARMS => {
            if (attr.data.len < tc_vlan_len) return error.BadLength;
            a.gen = Gen.decode(attr.data[0..tc_gen_len]);
            w.v_action = @fromBackingInt(@intCast(std.mem.readInt(i32, attr.data[20..24], native_endian)));
        },
        TCA_VLAN.PUSH_VLAN_ID => if (attr.data.len >= 2) {
            w.id = std.mem.readInt(u16, attr.data[0..2], native_endian);
        },
        TCA_VLAN.PUSH_VLAN_PROTOCOL => if (attr.data.len >= 2) {
            w.proto = std.mem.readInt(u16, attr.data[0..2], .big);
        },
        TCA_VLAN.PUSH_VLAN_PRIORITY => if (attr.data.len >= 1) {
            w.prio = attr.data[0];
        },
        TCA_VLAN.PUSH_ETH_DST => w.eth_dst = copyArray(6, attr.data),
        TCA_VLAN.PUSH_ETH_SRC => w.eth_src = copyArray(6, attr.data),
        TCA_VLAN.TM => a.tm = parseTm(attr.data),
        else => {},
    };
    a.vlan = w;
}

fn readGen(a: *Action, data: []const u8, min_len: usize) codec.Error!void {
    if (data.len < min_len) return error.BadLength;
    a.gen = Gen.decode(data[0..tc_gen_len]);
}

fn copyArray(comptime n: usize, data: []const u8) ?[n]u8 {
    if (data.len < n) return null;
    return data[0..n].*;
}

fn parseConnmarkOptions(a: *Action, data: []const u8) codec.Error!void {
    var w: ConnmarkWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |attr| switch (attr.type) {
        TCA_CONNMARK.PARMS => {
            try readGen(a, attr.data, tc_connmark_len);
            w.zone = std.mem.readInt(u16, attr.data[20..22], native_endian);
        },
        TCA_CONNMARK.TM => a.tm = parseTm(attr.data),
        else => {},
    };
    a.ext = .{ .connmark = w };
}

fn parseCsumOptions(a: *Action, data: []const u8) codec.Error!void {
    var w: CsumWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |attr| switch (attr.type) {
        TCA_CSUM.PARMS => {
            try readGen(a, attr.data, tc_csum_len);
            w.update_flags = std.mem.readInt(u32, attr.data[20..24], native_endian);
        },
        TCA_CSUM.TM => a.tm = parseTm(attr.data),
        else => {},
    };
    a.ext = .{ .csum = w };
}

fn parseSampleOptions(a: *Action, data: []const u8) codec.Error!void {
    var w: SampleWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |attr| switch (attr.type) {
        TCA_SAMPLE.PARMS => try readGen(a, attr.data, tc_gen_len),
        TCA_SAMPLE.RATE => if (attr.data.len >= 4) {
            w.rate = std.mem.readInt(u32, attr.data[0..4], native_endian);
        },
        TCA_SAMPLE.TRUNC_SIZE => if (attr.data.len >= 4) {
            w.trunc_size = std.mem.readInt(u32, attr.data[0..4], native_endian);
        },
        TCA_SAMPLE.PSAMPLE_GROUP => if (attr.data.len >= 4) {
            w.group = std.mem.readInt(u32, attr.data[0..4], native_endian);
        },
        TCA_SAMPLE.TM => a.tm = parseTm(attr.data),
        else => {},
    };
    a.ext = .{ .sample = w };
}

fn parseTunnelKeyOptions(a: *Action, data: []const u8) codec.Error!void {
    var w: TunnelKeyWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |attr| switch (attr.type) {
        TCA_TUNNEL_KEY.PARMS => {
            try readGen(a, attr.data, tc_tunnel_key_len);
            w.t_action = @fromBackingInt(@intCast(std.mem.readInt(i32, attr.data[20..24], native_endian)));
        },
        TCA_TUNNEL_KEY.ENC_IPV4_SRC => w.src_ip4 = copyArray(4, attr.data),
        TCA_TUNNEL_KEY.ENC_IPV4_DST => w.dst_ip4 = copyArray(4, attr.data),
        TCA_TUNNEL_KEY.ENC_IPV6_SRC => w.src_ip6 = copyArray(16, attr.data),
        TCA_TUNNEL_KEY.ENC_IPV6_DST => w.dst_ip6 = copyArray(16, attr.data),
        TCA_TUNNEL_KEY.ENC_KEY_ID => if (attr.data.len >= 4) {
            w.key_id = std.mem.readInt(u32, attr.data[0..4], .big);
        },
        TCA_TUNNEL_KEY.ENC_DST_PORT => if (attr.data.len >= 2) {
            w.dst_port = std.mem.readInt(u16, attr.data[0..2], .big);
        },
        TCA_TUNNEL_KEY.ENC_TOS => if (attr.data.len >= 1) {
            w.tos = attr.data[0];
        },
        TCA_TUNNEL_KEY.ENC_TTL => if (attr.data.len >= 1) {
            w.ttl = attr.data[0];
        },
        TCA_TUNNEL_KEY.NO_CSUM => if (attr.data.len >= 1) {
            w.no_csum = attr.data[0] != 0;
        },
        TCA_TUNNEL_KEY.NO_FRAG => w.no_frag = true,
        TCA_TUNNEL_KEY.TM => a.tm = parseTm(attr.data),
        else => {},
    };
    a.ext = .{ .tunnel_key = w };
}

fn parseMplsOptions(a: *Action, data: []const u8) codec.Error!void {
    var w: MplsWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |attr| switch (attr.type) {
        TCA_MPLS.PARMS => {
            try readGen(a, attr.data, tc_mpls_len);
            w.m_action = @fromBackingInt(@intCast(std.mem.readInt(i32, attr.data[20..24], native_endian)));
        },
        TCA_MPLS.PROTO => if (attr.data.len >= 2) {
            w.proto = std.mem.readInt(u16, attr.data[0..2], .big);
        },
        TCA_MPLS.LABEL => if (attr.data.len >= 4) {
            w.label = std.mem.readInt(u32, attr.data[0..4], native_endian);
        },
        TCA_MPLS.TC => if (attr.data.len >= 1) {
            w.tc = attr.data[0];
        },
        TCA_MPLS.TTL => if (attr.data.len >= 1) {
            w.ttl = attr.data[0];
        },
        TCA_MPLS.BOS => if (attr.data.len >= 1) {
            w.bos = attr.data[0];
        },
        TCA_MPLS.TM => a.tm = parseTm(attr.data),
        else => {},
    };
    a.ext = .{ .mpls = w };
}

fn parseNatOptions(a: *Action, data: []const u8) codec.Error!void {
    var w: NatWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |attr| switch (attr.type) {
        TCA_NAT.PARMS => {
            try readGen(a, attr.data, tc_nat_len);
            w.old_addr = attr.data[20..24].*;
            w.new_addr = attr.data[24..28].*;
            w.mask = attr.data[28..32].*;
            w.egress = std.mem.readInt(u32, attr.data[32..36], native_endian) & TCA_NAT_FLAG_EGRESS != 0;
        },
        TCA_NAT.TM => a.tm = parseTm(attr.data),
        else => {},
    };
    a.ext = .{ .nat = w };
}

fn parsePeditOptions(a: *Action, data: []const u8) codec.Error!void {
    var w: PeditWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |attr| switch (attr.type) {
        TCA_PEDIT.PARMS, TCA_PEDIT.PARMS_EX => {
            try readGen(a, attr.data, tc_pedit_sel_len);
            w.extended = attr.type == TCA_PEDIT.PARMS_EX;
            w.nkeys = attr.data[tc_gen_len];
            w.flags = attr.data[tc_gen_len + 1];
            if (attr.data.len < tc_pedit_sel_len + @as(usize, w.nkeys) * tc_pedit_key_len)
                return error.BadLength;
            const n = @min(@as(usize, w.nkeys), max_pedit_keys_decoded);
            for (0..n) |i| {
                const b = attr.data[tc_pedit_sel_len + i * tc_pedit_key_len ..][0..tc_pedit_key_len];
                w.keys[i] = .{
                    .mask = std.mem.readInt(u32, b[0..4], .big),
                    .val = std.mem.readInt(u32, b[4..8], .big),
                    .off = std.mem.readInt(u32, b[8..12], native_endian),
                    .at = std.mem.readInt(u32, b[12..16], native_endian),
                    .offmask = std.mem.readInt(u32, b[16..20], native_endian),
                    .shift = std.mem.readInt(u32, b[20..24], native_endian),
                };
            }
            w.len = @intCast(n);
        },
        TCA_PEDIT.KEYS_EX => {
            // One KEY_EX nest per key, in key order.
            var ki: usize = 0;
            var kit: codec.AttrIterator = .{ .buf = attr.data };
            while (try kit.next()) |ex| {
                if (ex.type != TCA_PEDIT.KEY_EX) continue;
                if (ki < max_pedit_keys_decoded) {
                    var eit: codec.AttrIterator = .{ .buf = ex.data };
                    while (try eit.next()) |e| switch (e.type) {
                        TCA_PEDIT_KEY_EX.HTYPE => if (e.data.len >= 2) {
                            w.keys[ki].htype = @fromBackingInt(@intCast(std.mem.readInt(u16, e.data[0..2], native_endian)));
                        },
                        TCA_PEDIT_KEY_EX.CMD => if (e.data.len >= 2) {
                            w.keys[ki].cmd = @fromBackingInt(@intCast(std.mem.readInt(u16, e.data[0..2], native_endian)));
                        },
                        else => {},
                    };
                }
                ki += 1;
            }
        },
        TCA_PEDIT.TM => a.tm = parseTm(attr.data),
        else => {},
    };
    a.ext = .{ .pedit = w };
}

fn parseCtOptions(a: *Action, data: []const u8) codec.Error!void {
    var w: CtWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |attr| switch (attr.type) {
        TCA_CT.PARMS => try readGen(a, attr.data, tc_ct_len),
        TCA_CT.ACTION => if (attr.data.len >= 2) {
            w.ct_action = std.mem.readInt(u16, attr.data[0..2], native_endian);
        },
        TCA_CT.ZONE => if (attr.data.len >= 2) {
            w.zone = std.mem.readInt(u16, attr.data[0..2], native_endian);
        },
        TCA_CT.MARK => if (attr.data.len >= 4) {
            w.mark = std.mem.readInt(u32, attr.data[0..4], native_endian);
        },
        TCA_CT.MARK_MASK => if (attr.data.len >= 4) {
            w.mark_mask = std.mem.readInt(u32, attr.data[0..4], native_endian);
        },
        TCA_CT.LABELS => w.labels = copyArray(16, attr.data),
        TCA_CT.LABELS_MASK => w.labels_mask = copyArray(16, attr.data),
        TCA_CT.NAT_IPV4_MIN => w.nat_ipv4_min = copyArray(4, attr.data),
        TCA_CT.NAT_IPV4_MAX => w.nat_ipv4_max = copyArray(4, attr.data),
        TCA_CT.NAT_IPV6_MIN => w.nat_ipv6_min = copyArray(16, attr.data),
        TCA_CT.NAT_IPV6_MAX => w.nat_ipv6_max = copyArray(16, attr.data),
        TCA_CT.NAT_PORT_MIN => if (attr.data.len >= 2) {
            w.nat_port_min = std.mem.readInt(u16, attr.data[0..2], .big);
        },
        TCA_CT.NAT_PORT_MAX => if (attr.data.len >= 2) {
            w.nat_port_max = std.mem.readInt(u16, attr.data[0..2], .big);
        },
        TCA_CT.HELPER_FAMILY => if (attr.data.len >= 1) {
            w.helper_family = attr.data[0];
        },
        TCA_CT.HELPER_PROTO => if (attr.data.len >= 1) {
            w.helper_proto = attr.data[0];
        },
        TCA_CT.HELPER_NAME => {
            const s = attr.asString();
            const n = @min(s.len, ct_helper_name_max);
            @memcpy(w.helper_name_buf[0..n], s[0..n]);
            w.helper_name_len = @intCast(n);
        },
        TCA_CT.TM => a.tm = parseTm(attr.data),
        else => {},
    };
    a.ext = .{ .ct = w };
}

/// Parse one ordinal entry of an action list (the payload of the nest whose
/// attribute type is the 1-based ordinal).
pub fn parseAction(order: u16, data: []const u8) codec.Error!Action {
    var a: Action = .{ .order = order };
    var options: ?[]const u8 = null;
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |attr| switch (attr.type) {
        TCA_ACT.KIND => try copyKind(&a.kind_buf, &a.kind_len, attr.asString()),
        TCA_ACT.OPTIONS => options = attr.data,
        TCA_ACT.INDEX => if (attr.data.len >= 4) {
            a.index_attr = std.mem.readInt(u32, attr.data[0..4], native_endian);
        },
        TCA_ACT.COOKIE => {
            const n = @min(attr.data.len, max_cookie_len);
            @memcpy(a.cookie_buf[0..n], attr.data[0..n]);
            a.cookie_len = @intCast(n);
        },
        TCA_ACT.STATS => a.stats = try parseStats(attr.data),
        TCA_ACT.FLAGS => a.flags = Bitfield32.decode(attr.data),
        TCA_ACT.HW_STATS => a.hw_stats = Bitfield32.decode(attr.data),
        TCA_ACT.USED_HW_STATS => a.used_hw_stats = Bitfield32.decode(attr.data),
        TCA_ACT.IN_HW_COUNT => if (attr.data.len >= 4) {
            a.in_hw_count = std.mem.readInt(u32, attr.data[0..4], native_endian);
        },
        else => {},
    };
    if (options) |opt| {
        const k = a.kind();
        if (std.mem.eql(u8, k, kind_gact)) {
            try parseGactOptions(&a, opt);
        } else if (std.mem.eql(u8, k, kind_mirred)) {
            try parseMirredOptions(&a, opt);
        } else if (std.mem.eql(u8, k, kind_police)) {
            try parsePoliceOptions(&a, opt);
        } else if (std.mem.eql(u8, k, kind_skbedit)) {
            try parseSkbeditOptions(&a, opt);
        } else if (std.mem.eql(u8, k, kind_vlan)) {
            try parseVlanOptions(&a, opt);
        } else if (std.mem.eql(u8, k, kind_connmark)) {
            try parseConnmarkOptions(&a, opt);
        } else if (std.mem.eql(u8, k, kind_csum)) {
            try parseCsumOptions(&a, opt);
        } else if (std.mem.eql(u8, k, kind_sample)) {
            try parseSampleOptions(&a, opt);
        } else if (std.mem.eql(u8, k, kind_tunnel_key)) {
            try parseTunnelKeyOptions(&a, opt);
        } else if (std.mem.eql(u8, k, kind_mpls)) {
            try parseMplsOptions(&a, opt);
        } else if (std.mem.eql(u8, k, kind_nat)) {
            try parseNatOptions(&a, opt);
        } else if (std.mem.eql(u8, k, kind_pedit)) {
            try parsePeditOptions(&a, opt);
        } else if (std.mem.eql(u8, k, kind_ct)) {
            try parseCtOptions(&a, opt);
        }
    }
    return a;
}

/// Walk the ordinal entries of an action-list nest (`TCA_U32_ACT`,
/// `TCA_FLOWER_ACT`, `TCA_ACT_TAB`), decoding each into an `Action`.
pub const ActionIterator = struct {
    it: codec.AttrIterator,

    pub fn init(list_payload: []const u8) ActionIterator {
        return .{ .it = .{ .buf = list_payload } };
    }

    pub fn next(self: *ActionIterator) codec.Error!?Action {
        const attr = (try self.it.next()) orelse return null;
        return try parseAction(attr.type, attr.data);
    }
};

/// A bounded decode of a whole action list, for embedding in a dumped filter.
pub const ActionList = struct {
    items: [max_actions_decoded]Action = @splat(.{}),
    /// How many entries `items` holds.
    len: u8 = 0,
    /// How many the kernel actually sent (may exceed `len`).
    total: u8 = 0,

    pub fn slice(l: *const ActionList) []const Action {
        return l.items[0..l.len];
    }
};

/// Decode an action-list nest into at most `max_actions_decoded` entries.
pub fn parseActionList(data: []const u8) codec.Error!ActionList {
    var out: ActionList = .{};
    var it: ActionIterator = .init(data);
    while (try it.next()) |a| {
        out.total +|= 1;
        if (out.len < out.items.len) {
            out.items[out.len] = a;
            out.len += 1;
        }
    }
    return out;
}

/// Find the `TCA_ACT_TAB` nest inside a standalone action message's payload
/// (an `RTM_*ACTION` body: `struct tcamsg` then attributes) and return an
/// iterator over its entries. Returns null when the message carries no table.
pub fn actionsOf(payload: []const u8) codec.Error!?ActionIterator {
    if (payload.len < tcamsg_len) return error.Truncated;
    var it: codec.AttrIterator = .{ .buf = payload[tcamsg_len..] };
    while (try it.next()) |a| {
        if (a.type == TCA_ROOT.TAB) return .init(a.data);
    }
    return null;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "action attribute constants agree with the kernel UAPI" {
    try testing.expectEqual(@as(u16, 1), TCA_ACT.KIND);
    try testing.expectEqual(@as(u16, 2), TCA_ACT.OPTIONS);
    try testing.expectEqual(@as(u16, 3), TCA_ACT.INDEX);
    try testing.expectEqual(@as(u16, 4), TCA_ACT.STATS);
    try testing.expectEqual(@as(u16, 6), TCA_ACT.COOKIE);
    try testing.expectEqual(@as(u16, 1), TCA_ROOT.TAB);
    try testing.expectEqual(@as(u16, 2), TCA_ROOT.FLAGS);
    try testing.expectEqual(@as(u16, 2), TCA_GACT.PARMS);
    try testing.expectEqual(@as(u16, 3), TCA_GACT.PROB);
    try testing.expectEqual(@as(u16, 2), TCA_MIRRED.PARMS);
    try testing.expectEqual(@as(u16, 1), TCA_POLICE.TBF);
    try testing.expectEqual(@as(u16, 8), TCA_POLICE.RATE64);
    try testing.expectEqual(@as(u16, 9), TCA_POLICE.PEAKRATE64);
    try testing.expectEqual(@as(u16, 3), TCA_SKBEDIT.PRIORITY);
    try testing.expectEqual(@as(u16, 7), TCA_SKBEDIT.PTYPE);
    try testing.expectEqual(@as(u16, 6), TCA_VLAN.PUSH_VLAN_PRIORITY);
    try testing.expectEqual(@as(usize, 20), tc_gen_len);
    try testing.expectEqual(@as(usize, 28), tc_mirred_len);
    try testing.expectEqual(@as(usize, 24), tc_vlan_len);
    try testing.expectEqual(@as(usize, 56), tc_police_len);
    try testing.expectEqual(@as(usize, 4), tcamsg_len);
}

test "action.copyKind: kind_max is the delivered 16-byte TCA_KIND budget, and the boundary is exact" {
    // F5 in the A1 audit: `copyKind` exists twice, character-for-character
    // identical, in `qdisc.zig` and here in `action.zig` -- and this one had
    // NO dedicated test, so mutating ITS bound (`s.len > kind_max`) went
    // undetected. 16 pinned literally, same reasoning as the qdisc.zig test:
    // a change to the constant must be caught here, not read off the symbol
    // it is checked against.
    try testing.expectEqual(@as(usize, 16), kind_max);

    var buf: [kind_max]u8 = undefined;
    var len: u8 = 0;

    // Exactly at the boundary: accepted.
    const at_boundary = "0123456789abcdef"; // 16 bytes
    try testing.expectEqual(@as(usize, 16), at_boundary.len);
    try copyKind(&buf, &len, at_boundary);
    try testing.expectEqualStrings(at_boundary, buf[0..len]);

    // One byte over: rejected, not truncated.
    const over_boundary = "0123456789abcdefg"; // 17 bytes
    try testing.expectEqual(@as(usize, 17), over_boundary.len);
    try testing.expectError(error.BadLength, copyKind(&buf, &len, over_boundary));
}

test "TC_ACT verdicts round-trip through the non-exhaustive enum" {
    try testing.expectEqual(@as(i32, -1), Verdict.unspec.raw());
    try testing.expectEqual(@as(i32, 0), Verdict.ok.raw());
    try testing.expectEqual(@as(i32, 1), Verdict.reclassify.raw());
    try testing.expectEqual(@as(i32, 2), Verdict.shot.raw());
    try testing.expectEqual(@as(i32, 3), Verdict.pipe.raw());
    try testing.expectEqual(@as(i32, 4), Verdict.stolen.raw());
    try testing.expectEqual(@as(i32, 8), Verdict.trap.raw());
    try testing.expectEqual(Verdict.shot, Verdict.fromRaw(2));
    try testing.expectEqual(Verdict.unspec, Verdict.fromRaw(-1));
    // A verdict this module predates must decode, not panic.
    try testing.expectEqual(@as(i32, 99), Verdict.fromRaw(99).raw());
}

test "tc_gen encodes the shared prologue byte-exactly" {
    const g: Gen = .{ .index = 7, .action = .pipe };
    const enc = g.encode();
    if (native_endian == .little) {
        try testing.expectEqualSlices(u8, &.{
            0x07, 0, 0, 0, // index
            0, 0, 0, 0, // capab
            0x03, 0, 0, 0, // action = TC_ACT_PIPE
            0, 0, 0, 0, // refcnt
            0, 0, 0, 0, // bindcnt
        }, &enc);
    }
    try testing.expectEqual(g, Gen.decode(&enc));
    // TC_ACT_UNSPEC is -1 and must survive as such.
    const c: Gen = .{ .action = .unspec };
    try testing.expectEqual(Verdict.unspec, Gen.decode(&c.encode()).action);
}

test "mirred pairs each direction with the verdict tc sends" {
    try testing.expectEqual(Verdict.stolen, MirredAction.egress_redir.defaultVerdict());
    try testing.expectEqual(Verdict.stolen, MirredAction.ingress_redir.defaultVerdict());
    try testing.expectEqual(Verdict.pipe, MirredAction.egress_mirror.defaultVerdict());
    try testing.expectEqual(Verdict.pipe, MirredAction.ingress_mirror.defaultVerdict());
}

test "parseMirredOptions rejects a TCA_MIRRED_PARMS attribute shorter than tc_mirred_len (F3)" {
    // Wave-3 audit's F3 named this bound as untested fault-injection surface.
    // A too-short PARMS attribute here doesn't crash (the reads inside stay
    // in-bounds for anything a couple of bytes short), it silently produces
    // wrong `eaction`/`ifindex` fields — so crash-only fuzzing cannot see
    // whether the guard actually rejects it. Pinned directly instead.
    const gpa = testing.allocator;

    var short_list: std.ArrayList(u8) = .empty;
    defer short_list.deinit(gpa);
    try codec.appendAttr(gpa, &short_list, TCA_MIRRED.PARMS, &(@as([tc_mirred_len - 1]u8, @splat(0))));
    var a: Action = .{ .order = 1 };
    try testing.expectError(error.BadLength, parseMirredOptions(&a, short_list.items));

    // Positive control: exactly tc_mirred_len bytes must still parse.
    var ok_list: std.ArrayList(u8) = .empty;
    defer ok_list.deinit(gpa);
    try codec.appendAttr(gpa, &ok_list, TCA_MIRRED.PARMS, &(@as([tc_mirred_len]u8, @splat(0))));
    var a2: Action = .{ .order = 1 };
    try parseMirredOptions(&a2, ok_list.items);
}

test "parsePoliceOptions rejects a TCA_POLICE_TBF attribute shorter than tc_police_len (F3)" {
    // Same F3 gap, the police action's TBF parameter block.
    const gpa = testing.allocator;

    var short_list: std.ArrayList(u8) = .empty;
    defer short_list.deinit(gpa);
    try codec.appendAttr(gpa, &short_list, TCA_POLICE.TBF, &(@as([tc_police_len - 1]u8, @splat(0))));
    var a: Action = .{ .order = 1 };
    try testing.expectError(error.BadLength, parsePoliceOptions(&a, short_list.items));

    // Positive control: exactly tc_police_len bytes must still parse.
    var ok_list: std.ArrayList(u8) = .empty;
    defer ok_list.deinit(gpa);
    try codec.appendAttr(gpa, &ok_list, TCA_POLICE.TBF, &(@as([tc_police_len]u8, @splat(0))));
    var a2: Action = .{ .order = 1 };
    try parsePoliceOptions(&a2, ok_list.items);
}

test "action list ordinals are 1-based (the classic mistake)" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const acts = [_]ActionSpec{
        .{ .skbedit = .{ .mark = 7 } },
        .{ .mirred = .{ .eaction = .egress_redir, .ifindex = 1 } },
        .{ .gact = .{ .action = .shot } },
    };
    try appendActionList(gpa, &list, 7, &acts, ratespec.golden_psched);

    var outer: codec.AttrIterator = .{ .buf = list.items };
    const nest = (try outer.next()).?;
    try testing.expectEqual(@as(u16, 7), nest.raw_type); // no NLA_F_NESTED
    var inner: codec.AttrIterator = .{ .buf = nest.data };
    var want: u16 = 1;
    while (try inner.next()) |a| : (want += 1) {
        try testing.expectEqual(want, a.raw_type);
        const parsed = try parseAction(a.type, a.data);
        try testing.expectEqual(want, parsed.order);
    }
    try testing.expectEqual(@as(u16, 4), want); // three entries, numbered 1..3
}

test "an empty action list appends nothing" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendActionList(gpa, &list, 7, &.{}, ratespec.golden_psched);
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "action list rejects more than TCA_ACT_MAX_PRIO entries" {
    // F5 in the A1 audit: pinned literally FIRST, so a change to `max_actions`
    // itself is caught here rather than only read back off the symbol the
    // rest of this test derives `many`'s length from (a self-referential
    // `max_actions + 1` moves both sides of the comparison together).
    try testing.expectEqual(@as(usize, 32), max_actions);

    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const many = try gpa.alloc(ActionSpec, max_actions + 1);
    defer gpa.free(many);
    @memset(many, .{ .gact = .{} });
    try testing.expectError(
        error.TooManyActions,
        appendActionList(gpa, &list, 7, many, ratespec.golden_psched),
    );
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "a large-options action list hits the wire-length limit before max_actions (F9)" {
    // Wave-3 audit's F9: `max_actions` (32, `error.TooManyActions`) reads as
    // THE cap in SPEC.md's prose, but for an action kind with a large
    // options block (`police`'s rate tables), the real binding constraint is
    // `TCA_ACT_TAB`'s u16 nest length (64 KiB) — reached well below 32. This
    // is already fail-closed (no malformed request is ever sent, just a
    // different error than the one SPEC's prose implies), so nothing to fix
    // in the guard itself; pinning the audit's own boundary (30 succeeds, 31
    // fails on `OptionsTooLong`, never reaching `TooManyActions`) so this
    // stays true if either constant moves.
    // `peakrate` matters: it doubles the per-action rate-table payload (RTAB
    // + CTAB, 1 KiB each), which is what pulls the wire limit below 32 in
    // the first place — a `police` spec without it doesn't hit
    // `OptionsTooLong` until `TooManyActions` (33) would fire anyway
    // (checked while writing this test, not assumed).
    const gpa = testing.allocator;
    const spec: ActionSpec = .{ .police = .{ .rate = 125_000, .burst = 1024, .peakrate = 250_000, .mtu = 1500 } };

    var thirty: [30]ActionSpec = undefined;
    @memset(&thirty, spec);
    var list30: std.ArrayList(u8) = .empty;
    defer list30.deinit(gpa);
    try appendActionList(gpa, &list30, 7, &thirty, ratespec.golden_psched);

    var thirty_one: [31]ActionSpec = undefined;
    @memset(&thirty_one, spec);
    var list31: std.ArrayList(u8) = .empty;
    defer list31.deinit(gpa);
    try testing.expectError(
        error.OptionsTooLong,
        appendActionList(gpa, &list31, 7, &thirty_one, ratespec.golden_psched),
    );
}

test "a cookie longer than TC_COOKIE_MAX_SIZE is rejected before any output" {
    // F5: same reasoning as `max_actions` above -- pin the shipped limit
    // literally before using the symbol to build the oversized input.
    try testing.expectEqual(@as(usize, 16), max_cookie_len);

    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const acts = [_]ActionSpec{.{ .gact = .{ .cookie = &@as([max_cookie_len + 1]u8, @splat(0xAA)) } }};
    try testing.expectError(
        error.CookieTooLong,
        appendActionList(gpa, &list, 7, &acts, ratespec.golden_psched),
    );
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "police validates rate/burst/mtu before allocating" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try testing.expectError(error.MissingRate, appendPoliceOptions(
        .{ .rate = 0, .burst = 1024 },
        gpa,
        &list,
        ratespec.golden_psched,
    ));
    try testing.expectError(error.MissingBurst, appendPoliceOptions(
        .{ .rate = 125_000, .burst = 0 },
        gpa,
        &list,
        ratespec.golden_psched,
    ));
    try testing.expectError(error.MissingMtu, appendPoliceOptions(
        .{ .rate = 125_000, .burst = 1024, .peakrate = 250_000 },
        gpa,
        &list,
        ratespec.golden_psched,
    ));
    // F2: a caller-supplied cell_log >= 32 used to panic inside
    // `calcRateTable`'s `@intCast` to the shift amount's `u5`, in
    // ReleaseSafe -- reachable straight from this public entry point, no
    // privilege needed. `cell_log` and `pcell_log` are both wired.
    try testing.expectError(error.InvalidCellLog, appendPoliceOptions(
        .{ .rate = 125_000, .burst = 1024, .cell_log = 64 },
        gpa,
        &list,
        ratespec.golden_psched,
    ));
    try testing.expectError(error.InvalidCellLog, appendPoliceOptions(
        .{ .rate = 125_000, .burst = 1024, .peakrate = 250_000, .mtu = 1500, .pcell_log = 32 },
        gpa,
        &list,
        ratespec.golden_psched,
    ));
    // A byte rate and a packet rate together, a packet rate without a
    // burst, a peak rate without a rate: refused before anything is written.
    try testing.expectError(error.RateConflict, appendPoliceOptions(
        .{ .rate = 125_000, .burst = 1024, .pkt_rate = 10, .pkt_burst = 1 },
        gpa,
        &list,
        ratespec.golden_psched,
    ));
    try testing.expectError(error.MissingBurst, appendPoliceOptions(
        .{ .pkt_rate = 10 },
        gpa,
        &list,
        ratespec.golden_psched,
    ));
    try testing.expectError(error.MissingRate, appendPoliceOptions(
        .{ .peakrate = 250_000, .mtu = 1500 },
        gpa,
        &list,
        ratespec.golden_psched,
    ));
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "encode/decode round-trip: every modelled action kind" {
    // F5: pin `max_actions_decoded` literally before this test relies on it
    // below (`expectEqual(@as(u8, max_actions_decoded), decoded.len)` was
    // comparing the symbol to itself -- a change to the constant moved both
    // sides together and the assertion stayed green).
    try testing.expectEqual(@as(u8, 4), max_actions_decoded);

    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const acts = [_]ActionSpec{
        .{ .gact = .{
            .action = .shot,
            .index = 3,
            .random = .{ .ptype = .netrand, .pval = 4, .paction = .ok },
            .cookie = &.{ 0xde, 0xad, 0xbe, 0xef },
        } },
        .{ .mirred = .{ .eaction = .ingress_mirror, .ifindex = 42, .index = 5 } },
        .{ .police = .{
            .rate = 5_000_000_000,
            .burst = 10 * 1024,
            .peakrate = 10_000_000_000,
            .mtu = 1500,
            .exceed = .pipe,
            .notexceed = .shot,
        } },
        .{ .skbedit = .{
            .priority = Handle.init(1, 0x10),
            .mark = 9,
            .queue_mapping = 2,
            .ptype = PACKET.BROADCAST,
        } },
        .{ .vlan = .{ .v_action = .push, .id = 100, .proto = 0x8100, .prio = 3 } },
        .{ .raw = .{ .kind = "connmark" } },
    };
    try appendActionList(gpa, &list, 7, &acts, ratespec.golden_psched);

    var outer: codec.AttrIterator = .{ .buf = list.items };
    const nest = (try outer.next()).?;
    const decoded = try parseActionList(nest.data);
    try testing.expectEqual(@as(u8, acts.len), decoded.total);
    try testing.expectEqual(@as(u8, max_actions_decoded), decoded.len); // capped

    var it: ActionIterator = .init(nest.data);
    const g = (try it.next()).?;
    try testing.expectEqualStrings("gact", g.kind());
    try testing.expectEqual(@as(u16, 1), g.order);
    try testing.expectEqual(Verdict.shot, g.gen.action);
    try testing.expectEqual(@as(u32, 3), g.gen.index);
    try testing.expectEqual(ProbType.netrand, g.gact.?.random.?.ptype);
    try testing.expectEqual(@as(u16, 4), g.gact.?.random.?.pval);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, g.cookie());

    const m = (try it.next()).?;
    try testing.expectEqualStrings("mirred", m.kind());
    try testing.expectEqual(MirredAction.ingress_mirror, m.mirred.?.eaction);
    try testing.expectEqual(@as(u32, 42), m.mirred.?.ifindex);
    try testing.expectEqual(Verdict.pipe, m.gen.action); // mirror ⇒ pipe
    try testing.expectEqual(@as(u32, 5), m.gen.index);

    const p = (try it.next()).?;
    try testing.expectEqualStrings("police", p.kind());
    const pw = p.police.?;
    try testing.expectEqual(@as(u64, 5_000_000_000), pw.rate64);
    try testing.expectEqual(@as(u64, 10_000_000_000), pw.peakrate64);
    try testing.expectEqual(std.math.maxInt(u32), pw.rate.rate); // clamped
    try testing.expectEqual(@as(u32, 1500), pw.mtu);
    try testing.expectEqual(Verdict.pipe, pw.exceed);
    try testing.expectEqual(Verdict.shot, pw.notexceed.?);
    // 10240 B at 5 GB/s = 2.048 µs = 32 ticks on the golden calibration.
    try testing.expectEqual(@as(u32, 32), pw.burst);
    try testing.expectEqual(Verdict.pipe, p.gen.action);

    const s = (try it.next()).?;
    try testing.expectEqualStrings("skbedit", s.kind());
    try testing.expectEqual(Handle.init(1, 0x10).raw, s.skbedit.?.priority.?.raw);
    try testing.expectEqual(@as(u32, 9), s.skbedit.?.mark.?);
    try testing.expectEqual(@as(u16, 2), s.skbedit.?.queue_mapping.?);
    try testing.expectEqual(PACKET.BROADCAST, s.skbedit.?.ptype.?);
    try testing.expectEqual(Verdict.pipe, s.gen.action);

    const v = (try it.next()).?;
    try testing.expectEqualStrings("vlan", v.kind());
    try testing.expectEqual(VlanAction.push, v.vlan.?.v_action);
    try testing.expectEqual(@as(u16, 100), v.vlan.?.id.?);
    try testing.expectEqual(@as(u16, 0x8100), v.vlan.?.proto.?); // decoded from BE
    try testing.expectEqual(@as(u8, 3), v.vlan.?.prio.?);

    const r = (try it.next()).?;
    try testing.expectEqualStrings("connmark", r.kind());
    try testing.expectEqual(@as(?GactWire, null), r.gact);

    try testing.expectEqual(@as(?Action, null), try it.next());
}

test "action references encode the tc actions del|get shape" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendActionRefs(gpa, &list, TCA_ACT_TAB, &.{
        .{ .kind = "gact", .index = 1 },
        .{ .kind = "mirred" },
    });
    var outer: codec.AttrIterator = .{ .buf = list.items };
    const nest = (try outer.next()).?;
    var it: ActionIterator = .init(nest.data);
    const a = (try it.next()).?;
    try testing.expectEqualStrings("gact", a.kind());
    try testing.expectEqual(@as(u32, 1), a.index_attr.?);
    const b = (try it.next()).?;
    try testing.expectEqualStrings("mirred", b.kind());
    try testing.expectEqual(@as(?u32, null), b.index_attr);
}

test "an oversized caller-supplied action kind is OptionsTooLong, not a panic" {
    // `appendKind` folded `AttrTooLong` into `unreachable`; both pub paths
    // that carry a caller's kind reached it (message.zig had the same bug, F8).
    const gpa = testing.allocator;
    const huge_kind = try gpa.alloc(u8, 70_000);
    defer gpa.free(huge_kind);
    @memset(huge_kind, 'a');
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);

    try testing.expectError(error.OptionsTooLong, appendActionRefs(gpa, &list, TCA_ACT_TAB, &.{
        .{ .kind = huge_kind },
    }));
    list.clearRetainingCapacity();
    try testing.expectError(error.OptionsTooLong, appendActionList(gpa, &list, TCA_ACT_TAB, &.{
        .{ .raw = .{ .kind = huge_kind } },
    }, Psched.fallback));
}

test "TCA_ACT_STATS and the per-kind TM attribute decode" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);

    // Hand-build what a kernel dump looks like: one gact with PARMS + TM,
    // plus an action-level STATS nest.
    const entry = try codec.nestBegin(gpa, &list, 1);
    try appendKind(gpa, &list, "gact");
    {
        const opts = try codec.nestBegin(gpa, &list, TCA_ACT.OPTIONS | codec.NLA_F_NESTED);
        const gen: Gen = .{ .action = .shot, .refcnt = 2, .bindcnt = 1 };
        try appendAttr(gpa, &list, TCA_GACT.PARMS, &gen.encode());
        var tm: [tcf_t_len]u8 = @splat(0);
        std.mem.writeInt(u64, tm[0..8], 11, native_endian);
        std.mem.writeInt(u64, tm[8..16], 22, native_endian);
        std.mem.writeInt(u64, tm[16..24], 33, native_endian);
        std.mem.writeInt(u64, tm[24..32], 44, native_endian);
        try appendAttr(gpa, &list, TCA_GACT.TM, &tm);
        codec.nestEnd(&list, opts) catch return error.OptionsTooLong;
    }
    {
        const st = try codec.nestBegin(gpa, &list, TCA_ACT.STATS);
        var basic: [16]u8 = @splat(0);
        std.mem.writeInt(u64, basic[0..8], 4096, native_endian);
        std.mem.writeInt(u32, basic[8..12], 8, native_endian);
        try appendAttr(gpa, &list, TCA_STATS.BASIC, &basic);
        var queue: [20]u8 = @splat(0);
        std.mem.writeInt(u32, queue[8..12], 3, native_endian); // drops
        std.mem.writeInt(u32, queue[16..20], 5, native_endian); // overlimits
        try appendAttr(gpa, &list, TCA_STATS.QUEUE, &queue);
        codec.nestEnd(&list, st) catch return error.OptionsTooLong;
    }
    codec.nestEnd(&list, entry) catch return error.OptionsTooLong;

    var it: codec.AttrIterator = .{ .buf = list.items };
    const a = (try it.next()).?;
    const parsed = try parseAction(a.type, a.data);
    try testing.expectEqualStrings("gact", parsed.kind());
    try testing.expectEqual(@as(i32, 2), parsed.gen.refcnt);
    try testing.expectEqual(@as(u64, 4096), parsed.stats.?.bytes);
    try testing.expectEqual(@as(u64, 8), parsed.stats.?.packets);
    try testing.expectEqual(@as(u32, 3), parsed.stats.?.drops);
    try testing.expectEqual(@as(u32, 5), parsed.stats.?.overlimits);
    try testing.expectEqual(@as(u64, 11), parsed.tm.?.install);
    try testing.expectEqual(@as(u64, 44), parsed.tm.?.firstuse);
}

test "police burst uses the full 64-bit rate, the table the clamped one" {
    const ps = ratespec.golden_psched;
    // 10240 B at 125000 B/s = 81920 µs = 1280000 ticks.
    try testing.expectEqual(@as(u32, 1_280_000), ps.calcXmitTime(125_000, 10 * 1024));
    // The same burst at 5 GB/s is 32 ticks — not the 38 the clamped ~0U rate
    // would give, which is what pins the split.
    try testing.expectEqual(@as(u32, 32), ps.calcXmitTime(5_000_000_000, 10 * 1024));
    try testing.expectEqual(@as(u32, 38), ps.calcXmitTime(std.math.maxInt(u32), 10 * 1024));
}

/// Action entry bodies, whole `TCA_ACT_TAB` nests and `RTM_*ACTION` payloads
/// for `fuzzParseAction`, laid out the way its draws read them: a
/// `testkit.fuzz` slice seed (u32 length + frame) and then an eight-octet
/// little-endian word carrying the ordinal handed to `parseAction`.
///
/// ⭐ Built at run time by this file's own encoders rather than quoted as hex:
/// an action attribute is a netlink TLV whose length and scalars are HOST byte
/// order, so a hex corpus would be a little-endian one and the counts pinned
/// below would be false on a big-endian target instead of failing there.
///
/// ⛔ The ordinal is not decoration. `parseAction`'s first parameter is the
/// entry's 1-based position in the list, and it used to be drawn with
/// `smith.value(u16)` — a draw made AFTER the byte draw had eaten the seed, so
/// it was **0 on every seed**, which is `TCA_ACT_UNSPEC`, the one ordinal the
/// kernel will not accept. It travels in the seed now.
const ActionCorpus = struct {
    scratch: [16384]u8 = undefined,
    store: [16384]u8 = undefined,
    used: usize = 0,
    entries: [12][]const u8 = undefined,
    orders: [12]u16 = undefined,
    n: usize = 0,

    fn push(self: *ActionCorpus, frame: []const u8, order: u16) void {
        const head = testkit.fuzz.seedInto(self.store[self.used..], frame);
        std.mem.writeInt(u64, self.store[self.used + head.len ..][0..8], order, .little);
        self.entries[self.n] = self.store[self.used..][0 .. head.len + 8];
        self.orders[self.n] = order;
        self.used += head.len + 8;
        self.n += 1;
    }

    /// One level in from `appendActionList`'s output: the outer nest's data
    /// is the list `parseActionList` takes.
    fn listBody(list: *std.ArrayList(u8)) ![]const u8 {
        var it: codec.AttrIterator = .{ .buf = list.items };
        return ((try it.next()) orelse return error.BadLength).data;
    }

    /// Two levels in: the first ordinal entry's data, which is what
    /// `parseAction` takes.
    fn entryBody(list: *std.ArrayList(u8)) ![]const u8 {
        var it: codec.AttrIterator = .{ .buf = try listBody(list) };
        return ((try it.next()) orelse return error.BadLength).data;
    }

    fn build(self: *ActionCorpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();
        const ps = ratespec.golden_psched;

        // ── one entry per kind, as `parseAction` receives it ───────────────
        var gact: std.ArrayList(u8) = .empty;
        try appendActionList(gpa, &gact, 1, &.{.{ .gact = .{
            .action = .shot,
            .index = 7,
            .random = .{ .ptype = .netrand, .pval = 4, .paction = .ok },
            .cookie = "abcdefgh",
        } }}, ps);
        self.push(try entryBody(&gact), 1);

        var mirred: std.ArrayList(u8) = .empty;
        try appendActionList(gpa, &mirred, 1, &.{.{ .mirred = .{
            .eaction = .egress_redir,
            .ifindex = 3,
            .index = 11,
        } }}, ps);
        self.push(try entryBody(&mirred), 1);

        // police is the one kind whose options are not a `tc_gen` prologue,
        // and the only one carrying rate tables and RATE64/PEAKRATE64.
        var police: std.ArrayList(u8) = .empty;
        try appendActionList(gpa, &police, 1, &.{.{ .police = .{
            .rate = 5_000_000_000,
            .burst = 10 * 1024,
            .peakrate = 10_000_000_000,
            .mtu = 1500,
            .exceed = .shot,
            .notexceed = .ok,
        } }}, ps);
        self.push(try entryBody(&police), 1);

        var vlan: std.ArrayList(u8) = .empty;
        try appendActionList(gpa, &vlan, 1, &.{.{ .vlan = .{
            .v_action = .push,
            .id = 42,
            .proto = 0x8100,
            .prio = 5,
        } }}, ps);
        self.push(try entryBody(&vlan), 2);

        var skbedit: std.ArrayList(u8) = .empty;
        try appendActionList(gpa, &skbedit, 1, &.{.{ .skbedit = .{
            .priority = Handle.init(1, 0x10),
            .mark = 0xdead,
            .ptype = PACKET.HOST,
        } }}, ps);
        self.push(try entryBody(&skbedit), 3);

        // ── a whole list nest, longer than `max_actions_decoded` ───────────
        // The cap is 4 and this sends 6, so `total` and `len` disagree — the
        // one seed that proves the bound is a cap and not a truncation bug.
        var six: std.ArrayList(u8) = .empty;
        try appendActionList(gpa, &six, 1, &.{
            .{ .vlan = .{ .v_action = .pop } },
            .{ .skbedit = .{ .mark = 1 } },
            .{ .vlan = .{ .v_action = .push, .id = 2 } },
            .{ .mirred = .{ .eaction = .egress_mirror, .ifindex = 4 } },
            .{ .skbedit = .{ .mark = 5 } },
            .{ .gact = .{ .action = .ok } },
        }, ps);
        self.push(try listBody(&six), 6);

        // ── an `RTM_NEWACTION` payload, which is what `actionsOf` takes ────
        var tab: std.ArrayList(u8) = .empty;
        try codec.appendPadded(gpa, &tab, &[_]u8{ 0, 0, 0, 0 }); // struct tcamsg
        try appendActionList(gpa, &tab, TCA_ROOT.TAB, &.{
            .{ .gact = .{ .action = .shot } },
            .{ .mirred = .{ .eaction = .ingress_redir, .ifindex = 9 } },
        }, ps);
        self.push(tab.items, 1);

        // ── a dumped action's statistics ───────────────────────────────────
        var stats: std.ArrayList(u8) = .empty;
        {
            var basic: [16]u8 = @splat(0);
            std.mem.writeInt(u64, basic[0..8], 123_456, native_endian);
            std.mem.writeInt(u32, basic[8..12], 789, native_endian);
            try codec.appendAttr(gpa, &stats, TCA_STATS.BASIC, &basic);
            var queue: [20]u8 = @splat(0);
            std.mem.writeInt(u32, queue[8..12], 5, native_endian);
            std.mem.writeInt(u32, queue[16..20], 6, native_endian);
            try codec.appendAttr(gpa, &stats, TCA_STATS.QUEUE, &queue);
            var pkt64: [8]u8 = @splat(0);
            std.mem.writeInt(u64, &pkt64, 1_000_000, native_endian);
            try codec.appendAttr(gpa, &stats, TCA_STATS.PKT64, &pkt64);
        }
        self.push(stats.items, 1);

        // ── attributes that arrive with the WRONG length ───────────────────
        // Every `if (a.data.len >= N)` in `parseStats` and `parseAction` is a
        // bound a well-formed dump cannot exercise.
        var short: std.ArrayList(u8) = .empty;
        try codec.appendAttr(gpa, &short, TCA_STATS.BASIC, &@as([8]u8, @splat(0)));
        try codec.appendAttr(gpa, &short, TCA_STATS.QUEUE, &@as([12]u8, @splat(0)));
        try codec.appendAttr(gpa, &short, TCA_STATS.PKT64, &@as([4]u8, @splat(0)));
        try codec.appendAttr(gpa, &short, TCA_ACT.INDEX, &@as([2]u8, @splat(0)));
        self.push(short.items, 1);

        // A cookie twice `max_cookie_len`: the `@min` in `parseAction` is the
        // only thing between a 32-octet attribute and a 16-octet buffer.
        var big_cookie: std.ArrayList(u8) = .empty;
        try codec.appendAttrString(gpa, &big_cookie, TCA_ACT.KIND, kind_gact);
        try codec.appendAttr(gpa, &big_cookie, TCA_ACT.COOKIE, &@as([max_cookie_len * 2]u8, @splat(0xAA)));
        self.push(big_cookie.items, 4);

        // ── the refusals ───────────────────────────────────────────────────
        // A KIND string one octet past `kind_max`, which `copyKind` refuses.
        var long_kind: std.ArrayList(u8) = .empty;
        try codec.appendAttrString(gpa, &long_kind, TCA_ACT.KIND, "0123456789abcdefg");
        self.push(long_kind.items, 1);
        // An attribute header declaring 0x40 octets over a 2-octet buffer,
        // and a payload shorter than `struct tcamsg`.
        self.push(&[_]u8{ 0x40, 0x00 }, 1);

        return self.entries[0..self.n];
    }
};

test "an unknown gact probability type from the wire is carried, not a panic" {
    // Regression (fuzz driver TC_FUZZ seed 202): `GactProb.decode` did
    // `@enumFromInt` on an exhaustive enum.
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const acts = [_]ActionSpec{.{ .gact = .{
        .random = .{ .ptype = .netrand, .pval = 4, .paction = .ok },
    } }};
    try appendActionList(gpa, &list, 7, &acts, ratespec.golden_psched);
    const probe = (GactProb{ .ptype = .netrand, .pval = 4, .paction = .ok }).encode();
    const at = std.mem.find(u8, list.items, &probe).?;
    std.mem.writeInt(u16, list.items[at..][0..2], 0x7777, native_endian);

    var outer: codec.AttrIterator = .{ .buf = list.items };
    const nest = (try outer.next()).?;
    var it: ActionIterator = .init(nest.data);
    const g = (try it.next()).?;
    try testing.expectEqual(@as(u16, 0x7777), @backingInt(g.gact.?.random.?.ptype));
    try testing.expectEqual(@as(u16, 4), g.gact.?.random.?.pval);
}

const fz = @import("fuzz_test.zig");
const ActionMark = fz.Marker(enum { action, action_refused, list, stats, iterated, refused });

test "fuzz: action parsers never crash on arbitrary payloads" {
    var corpus: ActionCorpus = .{};
    try testing.fuzz({}, fuzzParseActionSmith, .{ .corpus = try corpus.build() });
}

test "fuzz driver: TC_FUZZ (action)" {
    try fz.fuzz_driver.run(fuzzParseAction, .{ .prefix = "TC_FUZZ", .name = "tc-action" });
}

test "fuzz harness: action, 500 seeds, reaches every outcome" {
    try ActionMark.reach(fuzzParseAction, "tc-action", 500);
}

fn fuzzParseActionSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzParseAction(std.testing.Smith, smith, testing.allocator);
}

fn fuzzParseAction(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var corpus: ActionCorpus = .{};
    const entries = corpus.build() catch return;
    // 4096, not 256: a police action carries two 1 KiB rate tables, and a seed
    // longer than the buffer is not a big seed — `Smith.slice` reads it back
    // as the EMPTY one. The one action kind with a loop worth fuzzing could
    // not have passed through this module's own harness at 256.
    var raw: [4096]u8 = undefined;
    // ⚠ One `src.slice` call, never `src.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and all four parsers were handed an EMPTY
    // slice with the action sitting unread in `raw`.
    //
    // ⛔ Measured over the corpus above: **0 of 12 seeds non-empty,
    // 0 kinds read, 0 list entries walked and 0 statistics counters decoded
    // before; 12 of 12 non-empty, 7 kinds, 6 list entries, 8 statistics
    // counters and 2 actions iterated out of an RTM_NEWACTION after.**
    // `parseAction`, `parseActionList` and `parseStats` all SUCCEED on the
    // empty slice — an action with no attributes is a legal (if useless)
    // entry — so an acceptance count called this harness healthy while it
    // walked nothing.
    const len: usize = fz.drawInput(S, src, &raw, entries);
    const buf = raw[0..len];
    // ⚠ `value(u64)` truncated, not `value(u16)`: a `u16` draw reads eight
    // input octets as a little-endian u64 and only survives if the whole word
    // fits in 16 bits, so the ordinal was 0 — `TCA_ACT_UNSPEC` — for every
    // seed. The ordinal travels in the seed's tail now.
    const order: u16 = @truncate(src.value(u64));
    if (parseAction(order, buf)) |a| {
        std.mem.doNotOptimizeAway(a.kind().len);
        ActionMark.mark(.action);
    } else |_| ActionMark.mark(.action_refused);
    if (parseActionList(buf)) |l| {
        std.mem.doNotOptimizeAway(l.total);
        if (l.total != 0) ActionMark.mark(.list);
    } else |_| ActionMark.mark(.refused);
    if (parseStats(buf)) |s| {
        std.mem.doNotOptimizeAway(s.packets);
        if (s.packets != 0 or s.bytes != 0) ActionMark.mark(.stats);
    } else |_| {}
    if (actionsOf(buf)) |maybe| {
        if (maybe) |it_const| {
            var it = it_const;
            while (it.next() catch null) |_| ActionMark.mark(.iterated);
        }
    } else |_| {}
}

test "corpus: every action seed reaches the parsers, and the decoded counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. `nonempty` is the reach claim and the only
    // check that catches a seed grown past the harness's buffer, which
    // `Smith.slice` reads back as the EMPTY one, silently. `kinds`, `walked`
    // and `counters` are the numbers an empty payload cannot produce, and
    // `orders` pins that the ordinal arrived as written — without it the
    // `parseAction` half quietly goes back to asking about `TCA_ACT_UNSPEC`.
    var corpus: ActionCorpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var kinds: usize = 0;
    var walked: usize = 0;
    var counters: usize = 0;
    var orders: usize = 0;
    var iterated: usize = 0;
    for (entries, corpus.orders[0..corpus.n]) |sd, want_order| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [4096]u8 = undefined;
        const len: usize = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        const buf = raw[0..len];
        const order: u16 = @truncate(smith.value(u64));
        if (order == want_order) orders += 1;
        if (parseAction(order, buf)) |a| {
            if (a.kind().len != 0) kinds += 1;
        } else |_| {}
        if (parseActionList(buf)) |l| walked += l.total else |_| {}
        if (parseStats(buf)) |s| {
            if (s.bytes != 0) counters += 1;
            if (s.packets != 0) counters += 1;
            if (s.drops != 0) counters += 1;
            if (s.overlimits != 0) counters += 1;
        } else |_| {}
        if (actionsOf(buf)) |maybe| {
            if (maybe) |it_const| {
                var it = it_const;
                while (it.next() catch null) |_| iterated += 1;
            }
        } else |_| {}
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(entries.len, orders);
    try testing.expectEqual(@as(usize, 7), kinds);
    try testing.expectEqual(@as(usize, 6), walked);
    try testing.expectEqual(@as(usize, 8), counters);
    try testing.expectEqual(@as(usize, 2), iterated);
}
