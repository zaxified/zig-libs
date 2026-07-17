// SPDX-License-Identifier: MIT

//! lockfree — lock-free concurrency primitives for shared-memory worker
//! pools: **epoch-based reclamation** (`ebr`) plus a **Michael-Scott MPMC
//! queue** (`mpmc`) built on it. The immediate consumer is the in-process
//! worker pool (P2 DL4); this is the workspace's first lock-free structure.
//!
//! **Phase-1 SCAFFOLD status.** The mechanical layer is complete and tested:
//! typed atomic helpers + backoff + an oracle spinlock (`atomic`), a
//! poisoning node pool whose canary catches use-after-free (`pool`), the EBR
//! domain/participant *storage* + registration (`ebr`), the queue node types
//! + init/deinit (`mpmc`), and the entire concurrent-stress harness with its
//! correct oracle, its deliberately-broken positive controls, and its
//! deterministic invariant-checker teeth (`harness`). The irreducible
//! concurrency-correctness CORE — EBR's pin/unpin/retire/advance and the
//! queue's enqueue/dequeue CAS loops — is left as `@panic("TODO(fable/core)")`
//! stubs behind `gate.fable_core_implemented` (currently `false`), for a
//! later Fable agent. Core-dependent tests report SKIP; everything else,
//! including the harness's proof-of-teeth, runs and passes today.
//!
//! See `SPEC.md` for the EBR-vs-hazard decision, the verification strategy
//! (and its honest probabilistic-vs-deterministic breakdown), the exact
//! Fable-core boundary, and the out-of-scope next increments (a lock-free
//! hash map; hazard-pointer reclamation; a bounded ring variant).

const std = @import("std");

pub const meta = .{
    // std.Thread + std.atomic are cross-OS (kv/resilience use them the same
    // way); the module logic is portable. The optional off-tree sanitizer
    // lane discussed in SPEC is x86_64-linux, but that is a build-lane detail,
    // not a ceiling on the module — so `.any`, not `.linux`.
    .platform = .any,
    .role = .util,
    // Internally synchronized, lock-free: the queue is safe for M producers +
    // N consumers with no mutex; EBR makes reclamation safe without one.
    .concurrency = .threadsafe,
    .model_after = "Michael & Scott MPMC queue (PODC 1996) + Fraser/crossbeam epoch reclamation",
    .deps = .{}, // std only
};

pub const gate = @import("gate.zig");

const atomic = @import("atomic.zig");
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
pub const MpmcQueue = mpmc.MpmcQueue;
pub const Node = mpmc.Node;

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
    _ = harness;
}

test "meta is well-formed" {
    try std.testing.expect(meta.platform == .any);
    try std.testing.expect(!gate.fable_core_implemented); // Phase-1 scaffold
}
