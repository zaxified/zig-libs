// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising the real,
//! Fable-authored lock-free core: `ebr.zig`'s reclamation kernel
//! (`enterCritical` / `exitCritical` / `retire` / `tryAdvance`) and
//! `mpmc.zig`'s CAS-loop `enqueue` / `dequeue`. Everything ELSE in this
//! module — the typed atomic helpers + backoff + oracle spinlock
//! (`atomic.zig`), the poisoning node pool with its canary UAF detector
//! (`pool.zig`), the EBR *storage/bookkeeping* structs and participant
//! registration (the non-safety half of `ebr.zig`), the queue node types
//! and init/deinit, and the ENTIRE concurrent-stress harness with its
//! correct spinlock oracle (`RefQueue`), its deliberately-broken positive
//! controls (`BrokenQueue`, `BrokenReclaim`) and the deterministic
//! invariant-checker teeth (`harness.zig`) — is fully real today and needs
//! no gate. That is the proof the harness has teeth independent of whether
//! the lock-free core is filled in yet.
//!
//! While this is `false`, the core functions in `ebr.zig`/`mpmc.zig` are
//! `@panic("TODO(fable/core): …")` stubs, and the harness tests that would
//! drive them report **SKIP** (via `error.SkipZigTest`) — a skip is not a
//! green light. A skipped test still compiles, so the core's signatures are
//! type-checked; it just never calls into the panicking body. The positive
//! controls and the checker/canary teeth run for real regardless.
//!
//! Flipped to `true`: the six core stubs have been replaced with real,
//! memory-ordering-correct implementations (each carries its ordering
//! argument in its doc comment; the grace-period safety theorem lives at
//! `Domain.tryAdvance`). The gated harness tests now hammer the real MPMC
//! queue + EBR domain under N producer / M consumer threads in ReleaseFast,
//! enforcing the no-lost / no-duplicated / no-corrupted multiset invariant
//! and the pool's no-use-after-free canary.
pub const fable_core_implemented = true;
