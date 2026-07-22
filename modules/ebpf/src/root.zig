// SPDX-License-Identifier: MIT
//! ebpf — eBPF program generation, loading, attaching, and ring-buffer
//! consumption for a fixed, named set of small programs (`kprobe-counter`,
//! `xdp-filter`, `ringbuf-emit`). Built entirely on `std.os.linux.BPF`
//! (instruction encoders, the `bpf()` syscall's `Cmd`/`Attr` types, and the
//! working `map_create`/`prog_load`/`map_*_elem` wrappers std already
//! ships) plus this repo's sibling `netlink` module for the XDP attach
//! path — nothing here duplicates a std primitive.
//!
//! **Status: complete** — the four parts (build / load / attach / consume)
//! are all implemented; nothing in this module panics as a placeholder.
//!
//! - **`programs.zig`.** The genuinely hard part: three program builders
//!   (`kprobeCounter`, `xdpFilter`, `ringbufEmit`) whose instruction
//!   sequences satisfy the in-kernel verifier's constraints (stack-slot
//!   initialization before `bpf_map_lookup_elem`, mandatory null-checks on
//!   `PTR_TO_MAP_VALUE_OR_NULL`/`PTR_TO_ALLOC_MEM_OR_NULL`, XDP's
//!   bounds-check-dominance rule for direct packet access, ringbuf's
//!   whole-CFG "unreleased reference" tracking). Golden-vector tested.
//! - **`load.zig`.** `std.os.linux.BPF.prog_load` already implements
//!   `BPF_PROG_LOAD` end-to-end; this file is a thin wrapper over it
//!   (proven by its own tests against a real kernel, gated on CAP_BPF/root).
//! - **`attach.zig`.** Three hooks, one uniform `Link` handle:
//!   `perf_event_open` + `ioctl(SET_BPF)`/`ioctl(ENABLE)` for
//!   kprobe/kretprobe, a nested netlink `RTM_SETLINK`/`IFLA_XDP` message for
//!   XDP, and the `BPF_PROG_ATTACH`/`_DETACH` wrapper std never grew for
//!   cgroups. Lifetime rules differ per hook (a perf fd close detaches; XDP
//!   and cgroup attachments persist until explicitly detached) — see that
//!   file's header table.
//! - **`ringbuf.zig`.** The `BPF_MAP_TYPE_RINGBUF` consumer: the kernel's
//!   mmap layout (consumer page / producer page / kernel-double-mapped data
//!   area), acquire/release-ordered position handling, bounds-checked record
//!   framing, and `epoll`-based polling.
//!
//! ```zig
//! const ebpf = @import("ebpf");
//!
//! const map_fd = try std.os.linux.BPF.map_create(.array, 4, 8, 1);
//! const prog = ebpf.Program{ .prog_type = .kprobe, .insns = ebpf.kprobeCounter(map_fd) };
//! const prog_fd = try ebpf.load(prog, "MIT");
//! var kp = try ebpf.attachKprobe(gpa, "do_sys_openat2", prog_fd);
//! defer kp.detach();
//! ```
//!
//! Provenance: clean-room from the kernel UAPI (`linux/bpf.h`,
//! `linux/perf_event.h`, `linux/if_link.h`) and public verifier-behavior
//! documentation (kernel `Documentation/bpf/`, `bpf-docs`); design modeled
//! after libbpf's shape (program builders + load + attach + ring-buffer
//! consumer as the four-part API) without porting any of its source — see
//! `NOTICE` if a specific design reference needs recording once
//! implemented.

const std = @import("std");
const linux = std.os.linux;
const BPF = linux.BPF;

pub const meta = .{
    .platform = .linux, // raw std.os.linux.BPF syscalls — a conscious ceiling
    .role = .util,
    // One Reader/attach handle per owner; no shared globals. Not
    // .threadsafe (mmap'd ring-buffer state and perf/epoll fds are not
    // internally synchronized).
    .concurrency = .single_owner,
    .model_after = "libbpf (C) — program-builder + load + attach + ring-buffer-consumer API shape, design reference only, no source ported; wire ABI from linux/bpf.h + linux/perf_event.h + linux/if_link.h",
    .deps = .{"netlink"}, // XDP attach (RTM_SETLINK) reuses its nlmsghdr/nlattr codec
};

// ── public API ──────────────────────────────────────────────────────────────

/// `std.os.linux.BPF.Insn` — re-exported so callers don't need a second
/// import for it.
pub const Insn = BPF.Insn;

const programs = @import("programs.zig");
pub const Program = programs.Program;
pub const XdpFilterOptions = programs.XdpFilterOptions;
pub const RingbufEmitOptions = programs.RingbufEmitOptions;
pub const BuildError = programs.BuildError;

/// Build the `kprobe-counter` program — see `programs.zig`.
pub const kprobeCounter = programs.kprobeCounter;
/// Build the `xdp-filter` program — see `programs.zig`.
pub const xdpFilter = programs.xdpFilter;
/// Build the `ringbuf-emit` program — see `programs.zig`.
pub const ringbufEmit = programs.ringbufEmit;

const load_mod = @import("load.zig");
/// `BPF_PROG_LOAD` — see `load.zig`.
pub const load = load_mod.load;
/// `BPF_PROG_LOAD` capturing the verifier log — see `load.zig`.
pub const loadWithLog = load_mod.loadWithLog;

pub const attach = @import("attach.zig");

/// The uniform attachment handle: one `detach()`/`deinit()` for all three
/// hooks. See `attach.zig`'s header for the per-hook lifetime rules.
pub const Link = attach.Link;
pub const DetachError = attach.DetachError;

pub const KprobeHandle = attach.KprobeHandle;
pub const KprobeOptions = attach.KprobeOptions;
pub const KprobeAttachError = attach.KprobeAttachError;
pub const XdpHandle = attach.XdpHandle;
pub const XdpFlags = attach.XdpFlags;
pub const XdpAttachError = attach.XdpAttachError;
pub const CgroupHandle = attach.CgroupHandle;
pub const CgroupAttachFlags = attach.CgroupAttachFlags;
pub const CgroupAttachError = attach.CgroupAttachError;

/// Attach to a kernel function's entry (`perf_event_open` on the kprobe PMU).
pub const attachKprobe = attach.attachKprobe;
/// Attach to a kernel function's return.
pub const attachKretprobe = attach.attachKretprobe;
/// `attachKprobe` with every knob exposed (`KprobeOptions`).
pub const attachKprobeOpts = attach.attachKprobeOpts;
/// Attach as an interface's XDP program (netlink `RTM_SETLINK`+`IFLA_XDP`).
pub const attachXdp = attach.attachXdp;
/// Remove an interface's XDP program without holding its `XdpHandle`.
pub const detachXdp = attach.detachXdp;
/// Attach to a cgroup-v2 directory fd (`bpf(BPF_PROG_ATTACH)`).
pub const attachCgroup = attach.attachCgroup;
/// `attachCgroup` with explicit `BPF_F_ALLOW_*` semantics.
pub const attachCgroupOpts = attach.attachCgroupOpts;
/// `bpf(BPF_PROG_DETACH)` without holding the `CgroupHandle`.
pub const detachCgroup = attach.detachCgroup;

pub const ringbuf = @import("ringbuf.zig");
/// `BPF_MAP_TYPE_RINGBUF` consumer — see `ringbuf.zig`.
pub const RingbufReader = ringbuf.Reader;
pub const RingbufRecord = ringbuf.Record;
pub const RingbufAction = ringbuf.Action;
pub const RingbufSampleFn = ringbuf.SampleFn;
pub const RingbufOpenError = ringbuf.OpenError;
pub const RingbufPollError = ringbuf.PollError;
pub const RingbufConsumeError = ringbuf.ConsumeError;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────────
//
// refAllDecls walks every pub declaration reachable from this file
// (including the sub-module re-exports above), which is what pulls
// programs.zig/load.zig/attach.zig/ringbuf.zig's own `test` blocks into
// `zig build test-ebpf` — a bare `pub const x = @import("x.zig")` alone
// does NOT do this (see CONVENTIONS.md's "dark-tests rule").

test {
    std.testing.refAllDecls(@This());
}

test "smoke: module imports and re-exports resolve" {
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(Insn));
}
