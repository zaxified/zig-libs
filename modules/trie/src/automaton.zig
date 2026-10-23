// SPDX-License-Identifier: MIT

//! automaton — byte automata searched over a frozen index (BurntSushi/fst's
//! `Map::search` / `Set::search`, `src/automaton/mod.rs`).
//!
//! An automaton is any type `A` with
//!
//! ```zig
//! pub const State = <copyable value type>;
//! pub fn start(a: *const A) State;
//! pub fn isMatch(a: *const A, s: State) bool;
//! pub fn canMatch(a: *const A, s: State) bool;
//! pub fn willAlwaysMatch(a: *const A, s: State) bool;
//! pub fn accept(a: *const A, s: State, byte: u8) State;
//! ```
//!
//! All five functions are required (fst gives `canMatch` / `willAlwaysMatch`
//! defaults; here a forgotten one is a compile error from `checkAutomaton`
//! rather than a silently slow or wrong search). Contract, as in fst
//! (`automaton/mod.rs:41-66`):
//!
//!   * `canMatch(s)` false ⇒ no continuation of `s` is ever a match, the empty
//!     one included (`isMatch(s)` is false too): the search prunes the node
//!     and its whole subtree there without asking `isMatch`. Returning true
//!     too often is only slow.
//!   * `willAlwaysMatch(s)` true ⇒ every continuation of `s` is a match. The
//!     search then stops feeding bytes below that point. Returning false too
//!     often is only slow. (fst declares this hook but its own stream never
//!     calls it — `raw/mod.rs:1195-1245` uses `can_match` and `is_match` only;
//!     here it is used.)
//!   * `start` always returns the same value.
//!
//! Not built in: Levenshtein (the sibling `fuzzysearch` module already walks
//! this index with a Levenshtein automaton, `fuzzysearch/src/search.zig`) and
//! regular expressions (the `regex` module exposes no byte-stepping DFA state;
//! any type satisfying the interface above can be searched).

const std = @import("std");

/// Compile-time interface check: every required declaration present with the
/// expected shape. Called by `Frozen.search`; call it in your own automaton's
/// test to get the message at the definition site.
pub fn checkAutomaton(comptime A: type) void {
    if (!@hasDecl(A, "State"))
        @compileError("automaton " ++ @typeName(A) ++ ": missing `pub const State = <value type>;`");
    const S = A.State;
    inline for (.{ "start", "isMatch", "canMatch", "willAlwaysMatch", "accept" }) |name| {
        if (!@hasDecl(A, name))
            @compileError("automaton " ++ @typeName(A) ++ ": missing `pub fn " ++ name ++ "`");
    }
    checkFn(A, "start", &.{*const A}, S);
    checkFn(A, "isMatch", &.{ *const A, S }, bool);
    checkFn(A, "canMatch", &.{ *const A, S }, bool);
    checkFn(A, "willAlwaysMatch", &.{ *const A, S }, bool);
    checkFn(A, "accept", &.{ *const A, S, u8 }, S);
}

fn checkFn(comptime A: type, comptime name: []const u8, comptime params: []const type, comptime ret: type) void {
    const info = @typeInfo(@TypeOf(@field(A, name)));
    if (info != .@"fn")
        @compileError("automaton " ++ @typeName(A) ++ ": `" ++ name ++ "` must be a function");
    const f = info.@"fn";
    if (f.param_types.len != params.len)
        @compileError("automaton " ++ @typeName(A) ++ ": `" ++ name ++ "` takes the wrong number of parameters");
    inline for (params, 0..) |p, i| {
        if (f.param_types[i] != p)
            @compileError("automaton " ++ @typeName(A) ++ ": parameter " ++ std.fmt.comptimePrint("{d}", .{i}) ++ " of `" ++ name ++ "` must be `" ++ @typeName(p) ++ "`");
    }
    if (f.return_type != ret)
        @compileError("automaton " ++ @typeName(A) ++ ": `" ++ name ++ "` must return `" ++ @typeName(ret) ++ "`");
}

/// Matches exactly one key (fst `Str`, `automaton/mod.rs:168-212`). Combine
/// with `startsWith` for a prefix search.
pub const Str = struct {
    string: []const u8,

    /// The position in `string`, or null once the input has left it.
    pub const State = ?usize;

    pub fn start(_: *const Str) State {
        return 0;
    }
    pub fn isMatch(a: *const Str, s: State) bool {
        return s != null and s.? == a.string.len;
    }
    pub fn canMatch(_: *const Str, s: State) bool {
        return s != null;
    }
    pub fn willAlwaysMatch(_: *const Str, _: State) bool {
        return false;
    }
    pub fn accept(a: *const Str, s: State, byte: u8) State {
        const pos = s orelse return null;
        if (pos < a.string.len and a.string[pos] == byte) return pos + 1;
        return null;
    }
};

/// Matches every key that contains `subseq` as a (not necessarily contiguous)
/// subsequence (fst `Subsequence`, `automaton/mod.rs:240-284`).
pub const Subsequence = struct {
    subseq: []const u8,

    /// How many bytes of `subseq` have been seen so far.
    pub const State = usize;

    pub fn start(_: *const Subsequence) State {
        return 0;
    }
    pub fn isMatch(a: *const Subsequence, s: State) bool {
        return s == a.subseq.len;
    }
    pub fn canMatch(_: *const Subsequence, _: State) bool {
        return true;
    }
    pub fn willAlwaysMatch(a: *const Subsequence, s: State) bool {
        return s == a.subseq.len;
    }
    pub fn accept(a: *const Subsequence, s: State, byte: u8) State {
        if (s == a.subseq.len) return s;
        return s + @intFromBool(byte == a.subseq[s]);
    }
};

/// Matches every key (fst `AlwaysMatch`, `automaton/mod.rs:290-316`): the
/// "no automaton" case of a generic search.
pub const AlwaysMatch = struct {
    pub const State = void;

    pub fn start(_: *const AlwaysMatch) State {}
    pub fn isMatch(_: *const AlwaysMatch, _: State) bool {
        return true;
    }
    pub fn canMatch(_: *const AlwaysMatch, _: State) bool {
        return true;
    }
    pub fn willAlwaysMatch(_: *const AlwaysMatch, _: State) bool {
        return true;
    }
    pub fn accept(_: *const AlwaysMatch, _: State, _: u8) State {}
};

/// Matches every key that starts with something `A` matches (fst
/// `StartsWith`, `automaton/mod.rs:320-383`).
pub fn StartsWith(comptime A: type) type {
    comptime checkAutomaton(A);
    return struct {
        const Self = @This();
        inner: A,

        pub const State = union(enum) { done, running: A.State };

        pub fn start(a: *const Self) State {
            const s = a.inner.start();
            return if (a.inner.isMatch(s)) .done else .{ .running = s };
        }
        pub fn isMatch(_: *const Self, s: State) bool {
            return s == .done;
        }
        pub fn canMatch(a: *const Self, s: State) bool {
            return switch (s) {
                .done => true,
                .running => |r| a.inner.canMatch(r),
            };
        }
        pub fn willAlwaysMatch(_: *const Self, s: State) bool {
            return s == .done;
        }
        pub fn accept(a: *const Self, s: State, byte: u8) State {
            return switch (s) {
                .done => .done,
                .running => |r| blk: {
                    const n = a.inner.accept(r, byte);
                    break :blk if (a.inner.isMatch(n)) .done else .{ .running = n };
                },
            };
        }
    };
}

/// Matches what either `A` or `B` matches (fst `Union`, `automaton/mod.rs:387-418`).
pub fn Union(comptime A: type, comptime B: type) type {
    comptime checkAutomaton(A);
    comptime checkAutomaton(B);
    return struct {
        const Self = @This();
        a: A,
        b: B,

        pub const State = struct { a: A.State, b: B.State };

        pub fn start(x: *const Self) State {
            return .{ .a = x.a.start(), .b = x.b.start() };
        }
        pub fn isMatch(x: *const Self, s: State) bool {
            return x.a.isMatch(s.a) or x.b.isMatch(s.b);
        }
        pub fn canMatch(x: *const Self, s: State) bool {
            return x.a.canMatch(s.a) or x.b.canMatch(s.b);
        }
        pub fn willAlwaysMatch(x: *const Self, s: State) bool {
            return x.a.willAlwaysMatch(s.a) or x.b.willAlwaysMatch(s.b);
        }
        pub fn accept(x: *const Self, s: State, byte: u8) State {
            return .{ .a = x.a.accept(s.a, byte), .b = x.b.accept(s.b, byte) };
        }
    };
}

/// Matches what both `A` and `B` match (fst `Intersection`,
/// `automaton/mod.rs:422-457`).
pub fn Intersection(comptime A: type, comptime B: type) type {
    comptime checkAutomaton(A);
    comptime checkAutomaton(B);
    return struct {
        const Self = @This();
        a: A,
        b: B,

        pub const State = struct { a: A.State, b: B.State };

        pub fn start(x: *const Self) State {
            return .{ .a = x.a.start(), .b = x.b.start() };
        }
        pub fn isMatch(x: *const Self, s: State) bool {
            return x.a.isMatch(s.a) and x.b.isMatch(s.b);
        }
        pub fn canMatch(x: *const Self, s: State) bool {
            return x.a.canMatch(s.a) and x.b.canMatch(s.b);
        }
        pub fn willAlwaysMatch(x: *const Self, s: State) bool {
            return x.a.willAlwaysMatch(s.a) and x.b.willAlwaysMatch(s.b);
        }
        pub fn accept(x: *const Self, s: State, byte: u8) State {
            return .{ .a = x.a.accept(s.a, byte), .b = x.b.accept(s.b, byte) };
        }
    };
}

/// Matches exactly what `A` does not (fst `Complement`,
/// `automaton/mod.rs:461-492`): `canMatch` and `willAlwaysMatch` swap roles.
pub fn Complement(comptime A: type) type {
    comptime checkAutomaton(A);
    return struct {
        const Self = @This();
        inner: A,

        pub const State = A.State;

        pub fn start(a: *const Self) State {
            return a.inner.start();
        }
        pub fn isMatch(a: *const Self, s: State) bool {
            return !a.inner.isMatch(s);
        }
        pub fn canMatch(a: *const Self, s: State) bool {
            return !a.inner.willAlwaysMatch(s);
        }
        pub fn willAlwaysMatch(a: *const Self, s: State) bool {
            return !a.inner.canMatch(s);
        }
        pub fn accept(a: *const Self, s: State, byte: u8) State {
            return a.inner.accept(s, byte);
        }
    };
}

pub fn startsWith(a: anytype) StartsWith(@TypeOf(a)) {
    return .{ .inner = a };
}

pub fn unionOf(a: anytype, b: anytype) Union(@TypeOf(a), @TypeOf(b)) {
    return .{ .a = a, .b = b };
}

pub fn intersectionOf(a: anytype, b: anytype) Intersection(@TypeOf(a), @TypeOf(b)) {
    return .{ .a = a, .b = b };
}

pub fn complementOf(a: anytype) Complement(@TypeOf(a)) {
    return .{ .inner = a };
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Run `aut` over a whole key: the naive per-key evaluation every test below
/// (and the trie differential in root.zig) compares the search against.
pub fn evalKey(comptime A: type, aut: *const A, key: []const u8) bool {
    var s = aut.start();
    for (key) |b| s = aut.accept(s, b);
    return aut.isMatch(s);
}

test "Str: exact key only" {
    const a = Str{ .string = "abc" };
    try testing.expect(evalKey(Str, &a, "abc"));
    try testing.expect(!evalKey(Str, &a, "ab"));
    try testing.expect(!evalKey(Str, &a, "abcd"));
    try testing.expect(!evalKey(Str, &a, "abd"));
    const e = Str{ .string = "" };
    try testing.expect(evalKey(Str, &e, ""));
    try testing.expect(!evalKey(Str, &e, "a"));
    // Once off the string it never comes back.
    const s = a.accept(a.accept(a.start(), 'x'), 'a');
    try testing.expect(!a.canMatch(s));
}

test "Subsequence: contained in order, not contiguous" {
    const a = Subsequence{ .subseq = "hpf" };
    try testing.expect(evalKey(Subsequence, &a, "/home/projects/foo"));
    try testing.expect(!evalKey(Subsequence, &a, "/tmp/foo"));
    try testing.expect(!evalKey(Subsequence, &a, "fph"));
    try testing.expect(evalKey(Subsequence, &Subsequence{ .subseq = "" }, ""));
    // Reaching the end of the subsequence is final.
    var s = a.start();
    for ("hpf") |b| s = a.accept(s, b);
    try testing.expect(a.willAlwaysMatch(s));
    try testing.expect(a.isMatch(a.accept(s, 'z')));
}

test "AlwaysMatch, StartsWith, Union, Intersection, Complement follow fst's truth tables" {
    const am = AlwaysMatch{};
    try testing.expect(evalKey(AlwaysMatch, &am, "anything"));

    const sw = startsWith(Str{ .string = "ab" });
    const SW = @TypeOf(sw);
    try testing.expect(evalKey(SW, &sw, "ab"));
    try testing.expect(evalKey(SW, &sw, "abzz"));
    try testing.expect(!evalKey(SW, &sw, "a"));
    try testing.expect(!evalKey(SW, &sw, "xab"));
    // The empty inner match makes the start state final.
    const sw0 = startsWith(Str{ .string = "" });
    try testing.expect(sw0.isMatch(sw0.start()) and sw0.willAlwaysMatch(sw0.start()));

    const u = unionOf(Str{ .string = "a" }, Str{ .string = "b" });
    const U = @TypeOf(u);
    try testing.expect(evalKey(U, &u, "a") and evalKey(U, &u, "b") and !evalKey(U, &u, "c"));

    const i = intersectionOf(Subsequence{ .subseq = "a" }, Subsequence{ .subseq = "b" });
    const I = @TypeOf(i);
    try testing.expect(evalKey(I, &i, "xaxb") and evalKey(I, &i, "ba") and !evalKey(I, &i, "aa"));

    const c = complementOf(Str{ .string = "a" });
    const C = @TypeOf(c);
    try testing.expect(!evalKey(C, &c, "a") and evalKey(C, &c, "b") and evalKey(C, &c, ""));
    // Complement swaps the pruning hooks: a dead inner state always matches.
    const dead = c.accept(c.start(), 'z');
    try testing.expect(c.willAlwaysMatch(dead));
    try testing.expect(!c.willAlwaysMatch(c.start()));
}

test "checkAutomaton accepts every built-in and a composed one" {
    comptime {
        checkAutomaton(Str);
        checkAutomaton(Subsequence);
        checkAutomaton(AlwaysMatch);
        checkAutomaton(StartsWith(Str));
        checkAutomaton(Union(Str, Subsequence));
        checkAutomaton(Intersection(Str, Subsequence));
        checkAutomaton(Complement(StartsWith(Subsequence)));
    }
}
