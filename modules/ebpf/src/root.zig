// SPDX-License-Identifier: MIT
//! ebpf — eBPF program generation, loading, attaching, and ring-buffer
//! consumption for a fixed, named set of small programs (`kprobe-counter`,
//! `xdp-filter`, `ringbuf-emit`). Built entirely on `std.os.linux.BPF`
//! (instruction encoders, the `bpf()` syscall's `Cmd`/`Attr` types, and the
//! working `map_create`/`prog_load`/`map_*_elem` wrappers std already
//! ships) plus this repo's sibling `netlink` module for the XDP attach
//! path — nothing here duplicates a std primitive.
//!
//! **Status: scaffold, split by difficulty tier so two different follow-up
//! passes can pick it up independently.**
//!
//! - **`programs.zig` — FABLE tier.** The genuinely hard part: each of the
//!   three program builders (`kprobeCounter`, `xdpFilter`, `ringbufEmit`) is
//!   a `@panic("TODO(fable/core): ...")` stub with a doc comment spelling
//!   out the SPECIFIC in-kernel verifier constraints that program's
//!   instruction sequence must satisfy (stack-slot initialization before
//!   `bpf_map_lookup_elem`, mandatory null-checks on
//!   `PTR_TO_MAP_VALUE_OR_NULL`/`PTR_TO_ALLOC_MEM_OR_NULL`, XDP's
//!   bounds-check-dominance rule for direct packet access, ringbuf's
//!   whole-CFG "unreleased reference" tracking). This is a
//!   constraint-satisfaction problem against the verifier's abstract
//!   interpreter, not boilerplate — see each function's doc comment and the
//!   module's difficulty verdict in `README.md`.
//! - **`load.zig` — NOT a stub.** `std.os.linux.BPF.prog_load` already
//!   implements `BPF_PROG_LOAD` end-to-end; this file is a real, working
//!   thin wrapper (proven by its own tests against a real kernel, gated on
//!   CAP_BPF/root).
//! - **`attach.zig` / `ringbuf.zig` — OPUS tier.** Mechanical syscall
//!   plumbing: `perf_event_open` + two ioctls for kprobe attach, a nested
//!   netlink `RTM_SETLINK`/`IFLA_XDP` message for XDP attach, the one
//!   missing `BPF_PROG_ATTACH` wrapper std never grew for cgroup attach,
//!   and an mmap+epoll ring-buffer consumer. No verifier subtlety anywhere
//!   in this tier — every stub's doc comment names the exact syscalls,
//!   struct fields, and (where relevant) the ioctl request numbers std
//!   doesn't define, in enough detail that filling the body is transcription
//!   against the kernel UAPI headers, not design work.
//!
//! ```zig
//! const ebpf = @import("ebpf");
//!
//! const map_fd = try std.os.linux.BPF.map_create(.array, 4, 8, 1);
//! const prog = ebpf.Program{ .prog_type = .kprobe, .insns = ebpf.kprobeCounter(map_fd) };
//! const prog_fd = try ebpf.load(prog, "MIT");
//! var kp = try ebpf.attachKprobe(gpa, "do_sys_openat2", prog_fd);
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

/// FABLE tier — see `programs.zig`.
pub const kprobeCounter = programs.kprobeCounter;
/// FABLE tier — see `programs.zig`.
pub const xdpFilter = programs.xdpFilter;
/// FABLE tier — see `programs.zig`.
pub const ringbufEmit = programs.ringbufEmit;

const load_mod = @import("load.zig");
/// Real, working — see `load.zig`.
pub const load = load_mod.load;
/// Real, working — see `load.zig`.
pub const loadWithLog = load_mod.loadWithLog;

const attach = @import("attach.zig");
pub const KprobeHandle = attach.KprobeHandle;
pub const KprobeAttachError = attach.KprobeAttachError;
pub const XdpFlags = attach.XdpFlags;
pub const XdpAttachError = attach.XdpAttachError;
pub const CgroupAttachError = attach.CgroupAttachError;
/// OPUS tier — see `attach.zig`.
pub const attachKprobe = attach.attachKprobe;
/// OPUS tier — see `attach.zig`.
pub const attachXdp = attach.attachXdp;
/// OPUS tier — see `attach.zig`.
pub const attachCgroup = attach.attachCgroup;

pub const ringbuf = @import("ringbuf.zig");
/// OPUS tier — see `ringbuf.zig`.
pub const RingbufReader = ringbuf.Reader;
pub const RingbufRecord = ringbuf.Record;

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
