// SPDX-License-Identifier: MIT

//! gate — the switch for the tests that exercise the lock-free core:
//! `ebr.zig`'s reclamation kernel (`enterCritical` / `exitCritical` /
//! `retire` / `tryAdvance`) and `mpmc.zig`'s CAS-loop `enqueue` / `dequeue`.
//!
//! The flag is `true`: the core functions are real, memory-ordering-correct
//! implementations (each carries its ordering argument in its doc comment;
//! the grace-period safety theorem lives at `Domain.tryAdvance`), and the
//! gated harness tests hammer the real MPMC queue + EBR domain under N
//! producer / M consumer threads in ReleaseFast, enforcing the no-lost /
//! no-duplicated / no-corrupted multiset invariant and the pool's
//! no-use-after-free canary. The ungated parts of the module (typed atomic
//! helpers + backoff + oracle spinlock in `atomic.zig`, the canary node pool
//! in `pool.zig`, the EBR storage structs, the queue node types, and the
//! stress harness with its oracle `RefQueue`, its deliberately-broken
//! positive controls `BrokenQueue` / `BrokenReclaim` and its deterministic
//! invariant-checker teeth in `harness.zig`) run regardless of the flag.
//! Were it set to `false`, the gated tests would report SKIP
//! (`error.SkipZigTest`), which is not a green light.
pub const fable_core_implemented = true;
