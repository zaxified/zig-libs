//! Forcing root for `zig build check-pubfn-reach`.
//!
//! Zig analyses a function body only when something references it. So a `pub
//! fn` that no test reaches can be outright non-compiling and still pass a
//! fully green gate — the compiler never looks inside it. That is not
//! hypothetical: `diskfree`'s `readMounts` and `readMountinfo` did not compile
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
//! analysed.** Upstream has the same observation open as ziglang/zig#22953.
//!
//! ⭐ That claim was measured again on 2026-08-23, after an audit found it false
//! twice over, and both holes are closed here:
//!
//! | shape                              | before   | now    |
//! |------------------------------------|----------|--------|
//! | `pub fn`                           | caught   | caught |
//! | `pub noinline fn`                  | caught   | caught |
//! | `pub export fn`                    | caught   | caught |
//! | `pub inline fn`                    | **missed** | caught (see `force`) |
//! | container from a sibling FILE      | **missed** | caught (see `declaredHere`) |
//!
//! Each row is a deliberate type error injected into `raft`, run against this
//! gate, and removed again — not a reading of the code. `pub extern fn` has no
//! body to analyse and is therefore not a row.
//!
//! ⚠ One thing the sibling-file row does NOT buy, stated so it is not read as
//! more than it is: the walk starts at the module ROOT, so a file the root never
//! re-exports is never reached, and a `pub fn` inside it stays unanalysed no
//! matter what this file does. `lockfree`'s `atomic.zig` is the live example —
//! `root.zig` imports it as a PRIVATE const and re-exports four of its five
//! declarations, so the fifth (`Atomic`) is `pub` in its own file and reachable
//! from nowhere. That is arguably the correct scope for a gate about the
//! PUBLISHED surface, but "every non-generic public declaration is analysed"
//! should be read as "every one reachable from the module root", and the two are
//! not the same sentence.
//! Narrowing the claim is deliberate — a step that claimed the generic half
//! would be the very thing this file exists to prevent.
//!
//! Measured over the same walk this file performs: **418 distinct generic
//! bodies**, reachable by 529 qualified public paths, in 67 modules. (A `grep`
//! over signatures lands far short of that — 124 of the 418 have a multi-line
//! signature and 111 of the paths are aliases onto a body already counted.)
//! They are analysed whenever some test instantiates them, and not at all when
//! none does — so the question that matters is not how many are generic but how
//! many nothing instantiates. On 2026-08-21 that was **six**, in four modules,
//! each confirmed by injecting a deliberate error and watching the module's own
//! suite stay green. All six now have a test that instantiates them, and the
//! same injection turns every one of those suites red. Re-measure when the
//! collection grows; the technique is a `@compileLog` probe in the body, since
//! a probe in a generic body only fires once something instantiates it.

const std = @import("std");

/// The module under test. `build.zig` supplies a different one per compilation.
const m = @import("m");

/// This module's own source files, as `@typeName` spells them: `src/wire.zig`
/// is `wire`. Generated per compilation by `build.zig` from the tree, so the
/// list cannot drift from the files it describes. See `declaredHere`.
const own_files: []const []const u8 = @import("own_files").names;

fn isContainer(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => true,
        else => false,
    };
}

/// Is `Child` declared *inside this module*, rather than re-exported from std
/// or from a sibling module?
///
/// This matters because forcing a foreign type tests its owner, not us. Without
/// it, five modules that re-export a `std.crypto.pcurves` curve type went red on
/// `sqrt`, which **std itself** guards with `@compileError("unimplemented")` for
/// field orders not ≡ 3 (mod 4). A sibling zig-libs module re-exported whole
/// keeps the type name `root`, and is likewise skipped — its own compilation of
/// this same step already covers it.
///
/// ⭐ The two shapes this used to get wrong, both found by audit on 2026-08-23
/// and both proven by mutation:
///
///  1. **A container declared in a sibling FILE of this module.** The old test
///     compared the prefix before the LAST dot against `@typeName(Parent)`, so
///     `types.LogEntry` re-exported from `root.zig` as `pub const LogEntry =
///     types.LogEntry` compared `"types"` against `"root"` and was dropped. The
///     stated reason for dropping a non-matching prefix — "its own compilation
///     of this step already covers it" — is true of a sibling MODULE, which is
///     walked separately, and false of a sibling FILE, which is not walked at
///     all. A deliberate type error in `raft.LogEntry` left `test-raft`,
///     `check-pubfn-reach` AND `example-raft` all green.
///  2. **A generic instantiated inside the container being walked.** Generic
///     ARGUMENTS contain dots, so the last dot in
///     `socket.Socket.List(wire.TableInfo)` sits inside the parentheses and the
///     computed prefix was `socket.Socket.List(wire`, matching nothing.
///
/// Both are fixed by asking two positive questions instead of one negative one:
/// is `Child` nested in `Parent` (prefix match at a `.` boundary, so generic
/// arguments cannot move it), or does its first path segment name one of THIS
/// module's own source files?
///
/// `own_files` is derived from the tree by `build.zig` — the files are their own
/// declaration, so a new file needs no edit here. It has to be derived and not
/// guessed from the name, because the collection contains modules whose own
/// files are called `os.zig`, `json.zig`, `atomic.zig` and `crypto.zig`: the
/// same first segment means "ours" in one module and "std's" in the next.
///
/// **The limit, stated rather than papered over:** a module that owns a file
/// named like a std top-level namespace AND re-exports a container from std's
/// namespace of that name would have the std one walked as if it were ours. No
/// module does today (`mls`'s `crypto.zig` is the only such file, and every
/// `crypto.` name it re-exports is its own).
fn declaredHere(comptime Parent: type, comptime Child: type) bool {
    const name = @typeName(Child);
    const parent = @typeName(Parent);

    // Nested in the container being walked: `field.Fe` under `field`. Compared
    // at a `.` boundary so a generic argument's dots cannot fake a match.
    if (name.len > parent.len and
        std.mem.startsWith(u8, name, parent) and
        name[parent.len] == '.') return true;

    // Otherwise: does the first path segment name one of this module's files?
    const head = name[0 .. std.mem.indexOfAny(u8, name, ".(") orelse name.len];
    // `root` is the one segment that is ambiguous by construction: every
    // module's root file is called `root`, so a sibling zig-libs module
    // re-exported whole is indistinguishable from ours by name. Ours is the
    // walk's own starting point and is already covered; a sibling module has
    // its own compilation of this step.
    if (std.mem.eql(u8, head, "root")) return false;
    for (own_files) |f| if (std.mem.eql(u8, f, head)) return true;
    return false;
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
                force(T, decl.name);
            }
        }
    }
}

/// Reference one non-container declaration hard enough that its body is
/// analysed.
///
/// ⭐ `_ = &decl` is enough for an ordinary function and NOT enough for an
/// `inline` one: an inline function has no address to take, so the reference
/// resolves without the compiler ever looking inside. Measured 2026-08-23 —
/// a `pub inline fn` returning `[]const u8` from a `u8` signature left this
/// gate green, and the same body as a plain `pub fn` turned it red. The
/// collection has 23 such declarations and they sit in the hottest crypto code
/// it owns (`rescue`'s field arithmetic, `tfhe`'s NTT, `bfv`'s modular
/// reduction), which is the worst place to be carrying an unanalysed body.
///
/// A CALL analyses it, so the inline function is wrapped in an ordinary one and
/// the ORDINARY one has its address taken. The wrapper's parameters supply the
/// arguments, which is what makes this work where the obvious version does not:
/// calling with `undefined` arguments fails outright ("use of undefined value
/// here causes illegal behavior", measured on `bfv`'s `modarith.zig`), because
/// an inline body is expanded at the call site and the compiler then sees the
/// undefined values in real code.
///
/// Generic and variadic functions are left to the address-of path exactly as
/// before: a generic body has nothing to analyse until something instantiates
/// it, which is the limit stated at the top of this file and not a new one.
fn force(comptime T: type, comptime name: []const u8) void {
    const d = @field(T, name);
    const info = @typeInfo(@TypeOf(d));
    if (comptime info == .@"fn" and info.@"fn".calling_convention == .@"inline" and
        !info.@"fn".is_generic and !info.@"fn".is_var_args)
    {
        const F = @TypeOf(d);
        const wrapper = struct {
            fn call(args: std.meta.ArgsTuple(F)) @typeInfo(F).@"fn".return_type.? {
                return @call(.auto, d, args);
            }
        };
        _ = &wrapper.call;
        return;
    }
    _ = &@field(T, name);
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
