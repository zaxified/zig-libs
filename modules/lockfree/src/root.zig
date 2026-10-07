// SPDX-License-Identifier: MIT

//! lockfree — lock-free concurrency primitives for shared-memory worker
//! pools: **epoch-based reclamation** (`ebr`), a **Michael-Scott MPMC
//! queue** (`mpmc`, generic `Queue(T)`) built on it, a **bounded,
//! allocation-free MPMC ring** (`bounded`, Vyukov) that needs no reclamation,
//! and a **Chase-Lev work-stealing deque** (`deque`). The immediate consumer is the in-process
//! worker pool (P2 DL4); this is the workspace's first lock-free structure.
//!
//! **Status: core implemented.** The mechanical layer (Phase-1 scaffold) —
//! typed atomic helpers + backoff + an oracle spinlock (`atomic`), a
//! poisoning node pool whose canary catches use-after-free (`pool`), the EBR
//! domain/participant *storage* + registration (`ebr`), the queue node types
//! + init/deinit (`mpmc`), and the entire concurrent-stress harness with its
//! correct oracle, its deliberately-broken positive controls, and its
//! deterministic invariant-checker teeth (`harness`) — is complete, and the
//! irreducible concurrency-correctness CORE — EBR's pin/unpin/retire/advance
//! and the queue's enqueue/dequeue CAS loops — is now implemented
//! (`gate.fable_core_implemented = true`). Every core function documents its
//! memory-ordering argument in place; the grace-period safety theorem lives
//! at `ebr.Domain.tryAdvance`. The gated stress tests run for real.
//!
//! See `SPEC.md` for the EBR-vs-hazard decision, the verification strategy
//! (and its honest probabilistic-vs-deterministic breakdown), the exact
//! Fable-core boundary, and the out-of-scope next increments (a lock-free
//! hash map; hazard-pointer reclamation).

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Lock-free concurrency primitives for shared-memory worker pools — generic Michael & Scott MPMC queue + Fraser/crossbeam epoch-based reclamation under a strict seq_cst discipline, a bounded allocation-free Vyukov MPMC ring, and a growable Chase-Lev work-stealing deque",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    // std.Thread + std.atomic are cross-OS (kv/resilience use them the same
    // way); the module logic is portable. The optional off-tree sanitizer
    // lane discussed in SPEC is x86_64-linux, but that is a build-lane detail,
    // not a ceiling on the module — so `.any`, not `.linux`.
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    // Internally synchronized, lock-free: the queue is safe for M producers +
    // N consumers with no mutex; EBR makes reclamation safe without one.
    .concurrency = .threadsafe,
    .model_after = "Michael & Scott MPMC queue (PODC 1996) + Fraser/crossbeam epoch reclamation + Chase-Lev deque (SPAA 2005)",
    .deps = .{}, // std only
};

pub const gate = @import("gate.zig");

const atomic = @import("atomic.zig");
pub const Atomic = atomic.Atomic;
pub const Backoff = atomic.Backoff;
pub const SpinLock = atomic.SpinLock;
pub const CachePadded = atomic.CachePadded;
pub const cache_line = atomic.cache_line;

const pool = @import("pool.zig");
pub const NodePool = pool.NodePool;
pub const PoolError = pool.Error;

const ebr = @import("ebr.zig");
pub const Domain = ebr.Domain;
pub const Participant = ebr.Participant;
pub const Guard = ebr.Guard;
pub const Retired = ebr.Retired;
pub const Config = ebr.Config;

const mpmc = @import("mpmc.zig");
pub const Queue = mpmc.Queue;
pub const MpmcQueue = mpmc.MpmcQueue;
pub const Node = mpmc.MpmcQueue.Node;

const bounded = @import("bounded.zig");
pub const BoundedQueue = bounded.BoundedQueue;
pub const BoundedOptions = bounded.Options;
pub const Consumers = bounded.Consumers;

const deque = @import("deque.zig");
pub const Deque = deque.Deque;
pub const Steal = deque.Steal;

const harness = @import("harness.zig");
pub const StressConfig = harness.StressConfig;
pub const Verdict = harness.Verdict;
pub const runStress = harness.runStress;
pub const RefQueue = harness.RefQueue;
pub const BrokenRing = harness.BrokenRing;

// Dark-tests rule (CONVENTIONS §6.3): a bare re-export does NOT pull a
// submodule's tests into the test binary — they must be aggregated here.
test {
    _ = atomic;
    _ = pool;
    _ = ebr;
    _ = mpmc;
    _ = bounded;
    _ = deque;
    _ = harness;
}

test "meta is well-formed" {
    try std.testing.expect(meta.platform == .any);
    try std.testing.expect(gate.fable_core_implemented); // core is live
}
