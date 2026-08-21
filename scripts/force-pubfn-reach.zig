//! Forcing root for `zig build check-pubfn-reach`.
//!
//! Zig analyses a function body only when something references it. So a `pub
//! fn` that no test reaches can be outright non-compiling and still pass a
//! fully green gate — the compiler never looks inside it. That is not
//! hypothetical: `diskusage`'s `readMounts` and `readMountinfo` did not compile
//! on Zig 0.16 and an outside consumer found it, not this repo's CI.
//!
//! This file is compiled once per module, with the module under test imported
//! as `m`, and takes a reference to every public declaration it can see. A
//! reference is what forces analysis, so anything broken in there becomes a
//! compile error here.
//!
//! Two things this deliberately does NOT do:
//!
//!   * It never matches on names. `std.meta.declarations` is the compiler's own
//!     view of what is public, so short-name collisions (`init`, `next`,
//!     `deinit`, `push`) cannot hide a declaration behind a same-named one
//!     elsewhere. A measurement on 2026-08-21 found 247 of 403 unreachable
//!     public functions were reachable-looking only because some other module
//!     had a function of the same name — a name-based gate would have lost 61%
//!     of the finding.
//!
//!   * It never uses `zig build-obj` over a library root, and it is not a plain
//!     `addTest` over the module root either. Neither analyses an unreferenced
//!     body: the latter IS the compile that ships green today, which is the
//!     whole problem.
//!
//! Reflective dispatch (`jsonStringify`, `format`, anything reached through
//! `std.testing.refAllDecls`) needs no special case: those declarations are
//! public, so they get referenced here like any other.
//!
//! ## What a reference does and does not analyse — measured, not assumed
//!
//! Taking a reference analyses a *non-generic* body completely, including code
//! in branches no call would take. It cannot analyse a generic body at all,
//! because a generic function has no body until it is instantiated. Measured on
//! 0.16 over five shapes of deliberate error, reference vs. call:
//!
//! | error sits in                              | `_ = &f` | a real call |
//! |--------------------------------------------|----------|-------------|
//! | the body, top level                        | caught   | caught      |
//! | a runtime `if` branch                      | caught   | caught      |
//! | an `inline for` over a `comptime T`'s fields | missed | caught      |
//! | a body taking `anytype`                    | missed   | caught      |
//! | a branch selected by a `comptime` parameter| missed   | caught      |
//!
//! So this step's claim is exactly: **every non-generic public declaration is
//! analysed.** 171 of the collection's 9603 public functions (1.8%) are generic
//! and stay outside it; they are analysed whenever some test instantiates them,
//! and not at all when none does. Upstream has the same observation open as
//! ziglang/zig#22953. Narrowing the claim is deliberate — a step that says it
//! covers those 171 would be the very thing this file exists to prevent.

const std = @import("std");

/// The module under test. `build.zig` supplies a different one per compilation.
const m = @import("m");

fn isContainer(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => true,
        else => false,
    };
}

/// Is `Child` declared *inside this module*, rather than re-exported from std
/// or from a sibling module?
///
/// `@typeName` answers it without a name list. A container this module declares
/// is either one of its own files (`field`, `state` — a single segment, no dot)
/// or a type nested in the container being walked (`field.Fe`, whose prefix is
/// exactly `@typeName(Parent)`). Anything re-exported keeps the fully-qualified
/// name of where it was declared: `crypto.pcurves.secp256k1.scalar.Scalar`
/// matches neither test.
///
/// This matters because forcing a foreign type tests its owner, not us. Without
/// it, five modules that re-export a `std.crypto.pcurves` curve type went red on
/// `sqrt`, which **std itself** guards with `@compileError("unimplemented")` for
/// field orders not ≡ 3 (mod 4). A sibling zig-libs module re-exported whole
/// keeps the type name `root`, and is likewise skipped — its own compilation of
/// this same step already covers it.
fn declaredHere(comptime Parent: type, comptime Child: type) bool {
    const name = @typeName(Child);
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse
        return !std.mem.eql(u8, name, "root"); // own file namespace
    return std.mem.eql(u8, name[0..dot], @typeName(Parent)); // nested in Parent
}

/// Reference every public declaration of `T`, recursing into public containers.
///
/// `seen` breaks reference cycles (a type that publishes itself, or two types
/// that publish each other); `depth` is a backstop for a cycle `seen` cannot
/// express. `std` and `builtin` are skipped: a module that re-exports either
/// would otherwise drag the whole standard library into this compilation for no
/// added coverage.
fn forceAll(comptime T: type, comptime depth: u8, comptime seen: []const type) void {
    if (depth == 0) return;
    inline for (seen) |s| if (s == T) return;
    const next_seen = seen ++ [_]type{T};

    // ⚠ No `continue` in here. This `inline for` is expanded inside a runtime
    // block, so a `continue` is comptime control flow in a runtime context and
    // the compiler rejects it ("comptime control flow inside runtime block").
    // The dispatch has to be a plain if/else chain.
    inline for (comptime std.meta.declarations(T)) |decl| {
        const d = @field(T, decl.name);
        const is_type = @TypeOf(d) == type;
        // ⚠ Both conditions must be forced to comptime. `isContainer` is an
        // ordinary function, so `is_type and isContainer(d)` is a RUNTIME bool
        // — and Zig then analyses both arms of the `if`, which sends non-container
        // declarations (`[32]u8`, `u64`, error sets) into `forceAll` and blows up
        // inside `std.meta.declarations`. `comptime` also restores short-circuit
        // evaluation, so `isContainer(d)` is never reached when `d` is not a type.
        // A container is either walked or dropped — never referenced. `_ = &Type`
        // proves nothing about the functions inside it, and on a foreign generic
        // it forces an instantiation this module may never have asked for.
        const is_container = comptime is_type and isContainer(d);
        const skip = comptime (is_type and (d == std or d == @import("builtin"))) or
            (is_container and !declaredHere(T, d));
        if (!skip) {
            if (comptime is_container) {
                forceAll(d, depth - 1, next_seen);
            } else {
                // Taking the address is what forces the body through semantic
                // analysis; naming the declaration alone does not.
                _ = &@field(T, decl.name);
            }
        }
    }
}

test "every public declaration is analysed" {
    // The walk is entirely comptime and the widest modules (`iec61850`, `ebpf`,
    // `tc`, `opcua`, `jwt`) blow the default 1000-branch budget just enumerating
    // their declarations. This is a compile-time budget, not a runtime one — it
    // costs nothing at the default, and a module the walk cannot finish would
    // otherwise fail for a reason that has nothing to do with the class.
    @setEvalBranchQuota(200_000);
    forceAll(m, 8, &.{});
}
