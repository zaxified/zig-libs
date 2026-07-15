// SPDX-License-Identifier: MIT

//! Shared scalar types for the netsim engine. Kept in their own file so
//! `sim.zig` (the engine) and `fault.zig` (the fault-schedule model) can both
//! name them without an import cycle.

/// A node's stable identity in the topology — its index in insertion order.
pub const NodeId = u32;

/// Simulated time, in abstract ticks. There is NO wall clock anywhere in the
/// engine: every duration (link latency, timer delay, fault schedule) is a
/// tick count, so a run is a pure function of (seed, topology, fault trace).
pub const Time = u64;
