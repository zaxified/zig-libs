// SPDX-License-Identifier: MIT
//! Replay of codespan-reporting 0.13.1's own test inputs against the snippet
//! renderer.
//!
//! Inputs: `tests/term.rs` of brendanzab/codespan commit
//! decb0a0727e45bf2f04dcd3e4b4deb9517349fdc (Apache-2.0), transcribed below
//! (the original is vendored in tools/codespan-goldens/term.rs). Expected
//! text: the upstream insta snapshots, ASCII charset, no colour, via
//! `codespan_vectors.zig` (generated, see tools/codespan-goldens/README.md).
//!
//! Every case is either byte-identical (after the two normalisations below) or
//! listed in `deviations` with the reason; a deviation case is still rendered
//! (no crash, no leak, bounded) but not compared.
//!
//! Normalisations (both applied to the expected text only):
//!   - trailing newlines are ignored (insta trims them);
//!   - the severities `bug`, `note`, `help` do not exist here: the input maps
//!     them to error / info / info and the header word of the expected text is
//!     rewritten the same way (`bug:` -> `error:`, `note:`/`help:` -> `info:`).

const std = @import("std");
const dg = @import("root.zig");
const vectors = @import("codespan_vectors.zig").vectors;

const Sev = enum { bug, @"error", warning, note, help };

/// A codespan label: byte range of a file.
const L = struct {
    primary: bool,
    file: usize = 0,
    start: usize,
    end: usize,
    msg: []const u8 = "",
};

fn P(file: usize, start: usize, end: usize, msg: []const u8) L {
    return .{ .primary = true, .file = file, .start = start, .end = end, .msg = msg };
}

fn S(file: usize, start: usize, end: usize, msg: []const u8) L {
    return .{ .primary = false, .file = file, .start = start, .end = end, .msg = msg };
}

const Cs = struct {
    sev: Sev,
    code: ?[]const u8 = null,
    msg: []const u8 = "",
    labels: []const L = &.{},
    notes: []const []const u8 = &.{},
};

const File = struct { name: []const u8, text: []const u8 };

const Case = struct {
    name: []const u8,
    files: []const File = &.{},
    diags: []const Cs,
    start_context_lines: u32 = 3,
    end_context_lines: u32 = 1,
};

/// 1-based line and byte column of a byte offset.
fn at(text: []const u8, off: usize) struct { line: u32, col: u32 } {
    const o = @min(off, text.len);
    const line: u32 = @intCast(std.mem.count(u8, text[0..o], "\n") + 1);
    const ls = if (std.mem.findScalarLast(u8, text[0..o], '\n')) |nl| nl + 1 else 0;
    return .{ .line = line, .col = @intCast(o - ls + 1) };
}

fn mapSev(s: Sev) dg.Severity {
    return switch (s) {
        .bug, .@"error" => .@"error",
        .warning => .warning,
        .note, .help => .info,
    };
}

/// Our `Diagnostic` for a codespan one: its first primary label becomes the
/// primary span (`span_message` is its message), the others are `labels`.
fn convert(arena: std.mem.Allocator, files: []const File, cs: Cs) !dg.Diagnostic {
    var d: dg.Diagnostic = .{
        .path = "",
        .severity = mapSev(cs.sev),
        .code = cs.code orelse "",
        .message = cs.msg,
    };
    var labels: std.ArrayList(dg.Label) = .empty;
    var have_primary = false;
    for (cs.labels) |l| {
        const text = files[l.file].text;
        const a = at(text, l.start);
        const b = at(text, l.end);
        if (l.primary and !have_primary) {
            have_primary = true;
            d.file = files[l.file].name;
            d.line = a.line;
            d.col = a.col;
            d.end_line = b.line;
            d.end_col = b.col;
            d.span_message = l.msg;
        } else try labels.append(arena, .{
            .file = files[l.file].name,
            .line = a.line,
            .col = a.col,
            .end_line = b.line,
            .end_col = b.col,
            .message = l.msg,
            .primary = l.primary,
        });
    }
    if (labels.items.len > 0) d.labels = labels.items;
    if (cs.notes.len > 0) {
        const notes = try arena.alloc(dg.Note, cs.notes.len);
        for (cs.notes, notes) |n, *out| out.* = .{ .kind = .plain, .message = n };
        d.notes = notes;
    }
    return d;
}

/// Our output for every diagnostic of the case, concatenated.
fn renderCase(arena: std.mem.Allocator, c: Case) ![]u8 {
    const sources = try arena.alloc(dg.Source, c.files.len);
    for (c.files, sources) |f, *s| s.* = .{ .file = f.name, .text = f.text };
    var out: std.Io.Writer.Allocating = .init(arena);
    for (c.diags) |cs| {
        const d = try convert(arena, c.files, cs);
        try dg.renderOne(&out.writer, d, .{
            .style = .snippet,
            .sources = sources,
            .start_context_lines = c.start_context_lines,
            .end_context_lines = c.end_context_lines,
        });
    }
    return out.written();
}

/// The expected text with the severity words of headers mapped to ours.
fn normalise(arena: std.mem.Allocator, expected: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, expected, '\n');
    var first = true;
    while (lines.next()) |line| {
        if (!first) try out.append(arena, '\n');
        first = false;
        const map = [_]struct { from: []const u8, to: []const u8 }{
            .{ .from = "bug", .to = "error" },
            .{ .from = "note", .to = "info" },
            .{ .from = "help", .to = "info" },
        };
        var done = false;
        for (map) |m| {
            if (std.mem.startsWith(u8, line, m.from) and line.len > m.from.len and (line[m.from.len] == ':' or line[m.from.len] == '[')) {
                try out.appendSlice(arena, m.to);
                try out.appendSlice(arena, line[m.from.len..]);
                done = true;
                break;
            }
        }
        if (!done) try out.appendSlice(arena, line);
    }
    return out.items;
}

fn expectedOf(name: []const u8) []const u8 {
    for (vectors) |v| if (std.mem.eql(u8, v.name, name)) return v.expected;
    @panic("no vector for case");
}

// ── the cases (tests/term.rs) ────────────────────────────────────────────────

const empty: Case = .{ .name = "empty", .diags = &.{
    .{ .sev = .bug }, .{ .sev = .@"error" }, .{ .sev = .warning }, .{ .sev = .note }, .{ .sev = .help }, .{ .sev = .bug },
} };

const message: Case = .{ .name = "message", .diags = &.{
    .{ .sev = .@"error", .msg = "a message" },
    .{ .sev = .warning, .msg = "a message" },
    .{ .sev = .note, .msg = "a message" },
    .{ .sev = .help, .msg = "a message" },
} };

const message_and_notes: Case = .{ .name = "message_and_notes", .diags = &.{
    .{ .sev = .@"error", .msg = "a message", .notes = &.{"a note"} },
    .{ .sev = .warning, .msg = "a message", .notes = &.{"a note"} },
    .{ .sev = .note, .msg = "a message", .notes = &.{"a note"} },
    .{ .sev = .help, .msg = "a message", .notes = &.{"a note"} },
} };

const message_errorcode: Case = .{ .name = "message_errorcode", .diags = &.{
    .{ .sev = .@"error", .msg = "a message", .code = "E0001" },
    .{ .sev = .warning, .msg = "a message", .code = "W001" },
    .{ .sev = .note, .msg = "a message", .code = "N0815" },
    .{ .sev = .help, .msg = "a message", .code = "H4711" },
    .{ .sev = .@"error", .msg = "where did my errorcode go?", .code = "" },
    .{ .sev = .warning, .msg = "where did my errorcode go?", .code = "" },
    .{ .sev = .note, .msg = "where did my errorcode go?", .code = "" },
    .{ .sev = .help, .msg = "where did my errorcode go?", .code = "" },
} };

const hello_text = "Hello world!\nBye world!\n   ";

const empty_ranges: Case = .{
    .name = "empty_ranges",
    .files = &.{.{ .name = "hello", .text = hello_text }},
    .diags = &.{
        .{ .sev = .note, .msg = "middle", .labels = &.{P(0, 6, 6, "middle")} },
        .{ .sev = .note, .msg = "end of line", .labels = &.{P(0, 12, 12, "end of line")} },
        .{ .sev = .note, .msg = "end of line", .labels = &.{P(0, 23, 23, "end of line")} },
        .{ .sev = .note, .msg = "end of file", .labels = &.{P(0, hello_text.len, hello_text.len, "end of file")} },
    },
};

const same_ranges: Case = .{
    .name = "same_ranges",
    .files = &.{.{ .name = "same_range", .text = "::S { }" }},
    .diags = &.{.{ .sev = .@"error", .msg = "Unexpected token", .labels = &.{
        P(0, 4, 4, "Unexpected '{'"),
        S(0, 4, 4, "Expected '('"),
    } }},
};

const same_line: Case = .{
    .name = "same_line",
    .files = &.{.{ .name = "one_line.rs", .text =
    \\fn main() {
    \\    let mut v = vec![Some("foo"), Some("bar")];
    \\    v.push(v.pop().unwrap());
    \\}
    \\
    }},
    .diags = &.{
        .{
            .sev = .@"error",
            .code = "E0499",
            .msg = "cannot borrow `v` as mutable more than once at a time",
            .labels = &.{
                P(0, 71, 72, "second mutable borrow occurs here"),
                S(0, 64, 65, "first borrow later used by call"),
                S(0, 66, 70, "first mutable borrow occurs here"),
            },
        },
        .{
            .sev = .@"error",
            .msg = "aborting due to previous error",
            .notes = &.{"For more information about this error, try `rustc --explain E0499`."},
        },
    },
};

const overlapping: Case = .{
    .name = "overlapping",
    .files = &.{
        .{ .name = "nested_impl_trait.rs", .text =
        \\use std::fmt::Debug;
        \\
        \\fn fine(x: impl Into<u32>) -> impl Into<u32> { x }
        \\
        \\fn bad_in_ret_position(x: impl Into<u32>) -> impl Into<impl Debug> { x }
        \\
        },
        .{ .name = "typeck_type_placeholder_item.rs", .text =
        \\fn fn_test1() -> _ { 5 }
        \\fn fn_test2(x: i32) -> (_, _) { (x, x) }
        \\
        },
        .{ .name = "libstd/thread/mod.rs", .text =
        \\#[stable(feature = "rust1", since = "1.0.0")]
        \\pub fn spawn<F, T>(self, f: F) -> io::Result<JoinHandle<T>>
        \\where
        \\    F: FnOnce() -> T,
        \\    F: Send + 'static,
        \\    T: Send + 'static,
        \\{
        \\    unsafe { self.spawn_unchecked(f) }
        \\}
        \\
        },
        .{ .name = "no_send_res_ports.rs", .text =
        \\use std::thread;
        \\use std::rc::Rc;
        \\
        \\#[derive(Debug)]
        \\struct Port<T>(Rc<T>);
        \\
        \\fn main() {
        \\    #[derive(Debug)]
        \\    struct Foo {
        \\        _x: Port<()>,
        \\    }
        \\
        \\    impl Drop for Foo {
        \\        fn drop(&mut self) {}
        \\    }
        \\
        \\    fn foo(x: Port<()>) -> Foo {
        \\        Foo {
        \\            _x: x
        \\        }
        \\    }
        \\
        \\    let x = foo(Port(Rc::new(())));
        \\
        \\    thread::spawn(move|| {
        \\        let y = x;
        \\        println!("{:?}", y);
        \\    });
        \\}
        \\
        },
    },
    .diags = &.{
        .{ .sev = .@"error", .code = "E0666", .msg = "nested `impl Trait` is not allowed", .labels = &.{
            P(0, 129, 139, "nested `impl Trait` here"),
            S(0, 119, 140, "outer `impl Trait`"),
        } },
        .{ .sev = .@"error", .code = "E0121", .msg = "the type placeholder `_` is not allowed within types on item signatures", .labels = &.{
            P(1, 17, 18, "not allowed in type signatures"),
            S(1, 17, 18, "help: replace with the correct return type: `i32`"),
        } },
        .{ .sev = .@"error", .code = "E0121", .msg = "the type placeholder `_` is not allowed within types on item signatures", .labels = &.{
            P(1, 49, 50, "not allowed in type signatures"),
            P(1, 52, 53, "not allowed in type signatures"),
            S(1, 48, 54, "help: replace with the correct return type: `(i32, i32)`"),
        } },
        .{
            .sev = .@"error",
            .code = "E0277",
            .msg = "`std::rc::Rc<()>` cannot be sent between threads safely",
            .labels = &.{
                P(3, 339, 352, "`std::rc::Rc<()>` cannot be sent between threads safely"),
                S(3, 353, 416, "within this `[closure@no_send_res_ports.rs:29:19: 33:6 x:main::Foo]`"),
                S(2, 141, 145, "required by this bound in `std::thread::spawn`"),
            },
            .notes = &.{
                "help: within `[closure@no_send_res_ports.rs:29:19: 33:6 x:main::Foo]`, the trait `std::marker::Send` is not implemented for `std::rc::Rc<()>`",
                "note: required because it appears within the type `Port<()>`",
                "note: required because it appears within the type `main::Foo`",
                "note: required because it appears within the type `[closure@no_send_res_ports.rs:29:19: 33:6 x:main::Foo]`",
            },
        },
        .{ .sev = .@"error", .msg = "aborting due 5 previous errors", .notes = &.{
            "Some errors have detailed explanations: E0121, E0277, E0666.",
            "For more information about an error, try `rustc --explain E0121`.",
        } },
    },
};

const multifile: Case = .{
    .name = "multifile",
    .files = &.{
        .{ .name = "Data/Nat.fun", .text =
        \\module Data.Nat where
        \\
        \\data Nat : Type where
        \\    zero : Nat
        \\    succ : Nat → Nat
        \\
        \\{-# BUILTIN NATRAL Nat #-}
        \\
        \\infixl 6 _+_ _-_
        \\
        \\_+_ : Nat → Nat → Nat
        \\zero    + n₂ = n₂
        \\succ n₁ + n₂ = succ (n₁ + n₂)
        \\
        \\_-_ : Nat → Nat → Nat
        \\n₁      - zero    = n₁
        \\zero    - succ n₂ = zero
        \\succ n₁ - succ n₂ = n₁ - n₂
        \\
        },
        .{ .name = "Test.fun", .text =
        \\module Test where
        \\
        \\_ : Nat
        \\_ = 123 + "hello"
        \\
        },
    },
    .diags = &.{
        .{
            .sev = .@"error",
            .msg = "unknown builtin: `NATRAL`",
            .labels = &.{P(0, 96, 102, "unknown builtin")},
            .notes = &.{"there is a builtin with a similar name: `NATURAL`"},
        },
        .{
            .sev = .warning,
            .msg = "unused parameter pattern: `n₂`",
            .labels = &.{P(0, 285, 289, "unused parameter")},
            .notes = &.{"consider using a wildcard pattern: `_`"},
        },
        .{
            .sev = .@"error",
            .code = "E0001",
            .msg = "unexpected type in application of `_+_`",
            .labels = &.{
                P(1, 37, 44, "expected `Nat`, found `String`"),
                S(0, 130, 155, "based on the definition of `_+_`"),
            },
            .notes = &.{"expected type `Nat`\n   found type `String`\n"},
        },
    },
};

const fizz_buzz: Case = .{
    .name = "fizz_buzz",
    .files = &.{.{ .name = "FizzBuzz.fun", .text =
    \\module FizzBuzz where
    \\
    \\fizz₁ : Nat → String
    \\fizz₁ num = case (mod num 5) (mod num 3) of
    \\    0 0 => "FizzBuzz"
    \\    0 _ => "Fizz"
    \\    _ 0 => "Buzz"
    \\    _ _ => num
    \\
    \\fizz₂ : Nat → String
    \\fizz₂ num =
    \\    case (mod num 5) (mod num 3) of
    \\        0 0 => "FizzBuzz"
    \\        0 _ => "Fizz"
    \\        _ 0 => "Buzz"
    \\        _ _ => num
    \\
    }},
    .diags = &.{
        .{
            .sev = .@"error",
            .msg = "`case` clauses have incompatible types",
            .code = "E0308",
            .labels = &.{
                P(0, 163, 166, "expected `String`, found `Nat`"),
                S(0, 62, 166, "`case` clauses have incompatible types"),
                S(0, 41, 47, "expected type `String` found here"),
            },
            .notes = &.{"expected type `String`\n   found type `Nat`\n"},
        },
        .{
            .sev = .@"error",
            .msg = "`case` clauses have incompatible types",
            .code = "E0308",
            .labels = &.{
                P(0, 328, 331, "expected `String`, found `Nat`"),
                S(0, 211, 331, "`case` clauses have incompatible types"),
                S(0, 258, 268, "this is found to be of type `String`"),
                S(0, 284, 290, "this is found to be of type `String`"),
                S(0, 306, 312, "this is found to be of type `String`"),
                S(0, 186, 192, "expected type `String` found here"),
            },
            .notes = &.{"expected type `String`\n   found type `Nat`\n"},
        },
    },
};

const multiline_overlapping: Case = .{
    .name = "multiline_overlapping",
    .files = &.{.{ .name = "codespan/src/file.rs", .text =
    \\        match line_index.compare(self.last_line_index()) {
    \\            Ordering::Less => Ok(self.line_starts()[line_index.to_usize()]),
    \\            Ordering::Equal => Ok(self.source_span().end()),
    \\            Ordering::Greater => LineIndexOutOfBoundsError {
    \\                given: line_index,
    \\                max: self.last_line_index(),
    \\            },
    \\        }
    }},
    .diags = &.{.{
        .sev = .@"error",
        .msg = "match arms have incompatible types",
        .code = "E0308",
        // The secondary label before the primary one is part of upstream's
        // test (the locus must still be the primary's, issue #259).
        .labels = &.{
            S(0, 89, 134, "this is found to be of type `Result<ByteIndex, LineIndexOutOfBoundsError>`"),
            P(0, 230, 351, "expected enum `Result`, found struct `LineIndexOutOfBoundsError`"),
            S(0, 8, 362, "`match` arms have incompatible types"),
            S(0, 167, 195, "this is found to be of type `Result<ByteIndex, LineIndexOutOfBoundsError>`"),
        },
        .notes = &.{"expected type `Result<ByteIndex, LineIndexOutOfBoundsError>`\n   found type `LineIndexOutOfBoundsError`\n"},
    }},
};

const position_indicator: Case = .{
    .name = "position_indicator",
    .files = &.{.{ .name = "tests/main.js", .text =
    \\"use strict";
    \\let zero=0;
    \\function foo() {
    \\  "use strict";
    \\  one=1;
    \\}
    }},
    .diags = &.{.{
        .sev = .warning,
        .code = "ParserWarning",
        .msg = "The strict mode declaration in the body of function `foo` is redundant, as the outer scope is already in strict mode",
        .labels = &.{
            P(0, 45, 57, "This strict mode declaration is redundant"),
            S(0, 0, 12, "Strict mode is first declared here"),
        },
    }},
};

const multiline_omit: Case = .{
    .name = "multiline_omit",
    .start_context_lines = 2,
    .end_context_lines = 1,
    .files = &.{
        .{ .name = "empty_if_comments.lua", .text = "elseif 3 then\n\n\n\n\n\n\n\n\nelse" },
        .{ .name = "src/lib.rs", .text =
        \\fn main() {
        \\    1
        \\    + 1
        \\    + 1
        \\    + 1
        \\    + 1
        \\    +1
        \\    + 1
        \\    + 1
        \\    + 1
        \\}
        },
    },
    .diags = &.{
        .{ .sev = .@"error", .msg = "empty elseif block", .code = "empty_if", .labels = &.{
            P(0, 0, 23, ""),
            S(0, 15, 21, "content should be in here"),
        } },
        .{
            .sev = .@"error",
            .msg = "mismatched types",
            .code = "E0308",
            .labels = &.{
                P(1, 17, 80, "expected (), found integer"),
                S(1, 55, 55, "missing whitespace"),
            },
            .notes = &.{"note:\texpected type `()`\n\tfound type `{integer}`"},
        },
    },
};

const unicode_prefix = "extern ";
const unicode_abi = "\"路濫狼á́́\"";
const unicode_text = unicode_prefix ++ unicode_abi ++ " fn foo() {}";

const unicode: Case = .{
    .name = "unicode",
    .files = &.{.{ .name = "unicode.rs", .text = unicode_text }},
    .diags = &.{
        .{
            .sev = .@"error",
            .code = "E0703",
            .msg = "invalid ABI: found `路濫狼á́́`",
            .labels = &.{P(0, unicode_prefix.len, unicode_prefix.len + unicode_abi.len, "invalid ABI")},
            .notes = &.{"valid ABIs:\n  - aapcs\n  - amdgpu-kernel\n  - C\n  - cdecl\n  - efiapi\n  - fastcall\n  - msp430-interrupt\n  - platform-intrinsic\n  - ptx-kernel\n  - Rust\n  - rust-call\n  - rust-intrinsic\n  - stdcall\n  - system\n  - sysv64\n  - thiscall\n  - unadjusted\n  - vectorcall\n  - win64\n  - x86-interrupt\n"},
        },
        .{ .sev = .@"error", .msg = "aborting due to previous error", .notes = &.{"For more information about this error, try `rustc --explain E0703`."} },
    },
};

const moon = "🐄🌑🐄🌒🐄🌓🐄🌔🐄🌕🐄🌖🐄🌗🐄🌘🐄";

const unicode_spans: Case = .{
    .name = "unicode_spans",
    .files = &.{.{ .name = "moon_jump.rs", .text = moon }},
    .diags = &.{
        .{ .sev = .@"error", .code = "E01", .msg = "cow may not jump during new moon.", .labels = &.{P(0, 1, 3, "Invalid jump")} },
        .{ .sev = .note, .msg = "invalid unicode range", .labels = &.{S(0, 1, 4, "Cow range does not start at boundary.")} },
        .{ .sev = .note, .msg = "invalid unicode range", .labels = &.{S(0, 8, 11, "Cow range does not end at boundary.")} },
        .{ .sev = .note, .msg = "invalid unicode range", .labels = &.{S(0, 1, 11, "Cow does not start or end at boundary.")} },
    },
};

const surrounding_lines: Case = .{
    .name = "surrounding_lines",
    .files = &.{.{ .name = "surroundingLines.fun", .text =
    \\#[foo]
    \\fn main() {
    \\    println!(
    \\        "{}",
    \\        Foo
    \\    );
    \\}
    \\
    \\struct Foo
    }},
    .diags = &.{
        .{ .sev = .@"error", .msg = "Unknown attribute macro", .labels = &.{P(0, 2, 5, "No attribute macro `foo` known")} },
        .{ .sev = .@"error", .msg = "Missing argument for format", .labels = &.{
            P(0, 55, 58, "No instance of std::fmt::Display exists for type Foo"),
            S(0, 42, 44, "Unable to use `{}`-directive to display `Foo`"),
        } },
        .{ .sev = .@"error", .msg = "Syntax error", .labels = &.{P(0, 79, 79, "Missing a semicolon")} },
    },
};

const cases = [_]Case{
    empty,          empty_ranges, message,       message_and_notes, message_errorcode,     same_line,
    same_ranges,    overlapping,  multifile,     fizz_buzz,         multiline_overlapping, position_indicator,
    multiline_omit, unicode,      unicode_spans, surrounding_lines,
};

/// Case -> why it is not byte-identical. Kept in step with
/// tools/codespan-goldens/README.md.
const deviations = [_]struct { name: []const u8, why: []const u8 }{
    .{ .name = "unicode", .why = "R5: no East-Asian wide / zero-width combining characters, every code point is one column" },
    .{ .name = "unicode_spans", .why = "R5 (emoji are two columns upstream) and spans that start or end inside a code point" },
    .{ .name = "surrounding_lines", .why = "R10: before_label_lines / after_label_lines context is not ported" },
};

fn deviation(name: []const u8) ?[]const u8 {
    for (deviations) |d| if (std.mem.eql(u8, d.name, name)) return d.why;
    return null;
}

test "codespan-reporting 0.13.1 cases render byte-identically (deviations listed)" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var failed: usize = 0;
    var compared: usize = 0;
    for (cases) |c| {
        const got = try renderCase(arena, c);
        if (deviation(c.name) != null) continue;
        compared += 1;
        const want = try normalise(arena, expectedOf(c.name));
        const a = std.mem.trimEnd(u8, got, "\n");
        const b = std.mem.trimEnd(u8, want, "\n");
        if (!std.mem.eql(u8, a, b)) {
            failed += 1;
            std.debug.print("\n=== {s}: expected\n{s}\n=== found\n{s}\n", .{ c.name, b, a });
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failed);
    try std.testing.expectEqual(cases.len - deviations.len, compared);
}

// ── bounds, hostile text, random spans ───────────────────────────────────────

fn render(alloc: std.mem.Allocator, d: dg.Diagnostic, o: dg.RenderOptions) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    try dg.renderOne(&out.writer, d, o);
    return out.toOwnedSlice();
}

fn countOf(hay: []const u8, needle: []const u8) usize {
    return std.mem.count(u8, hay, needle);
}

test "bounds: spans past 64 and a 17th multi-line span of a file are location lines, nothing is lost silently" {
    const text = "one\ntwo\nthree\nfour\nfive\nsix\n";
    const src = [_]dg.Source{.{ .file = "f", .text = text }};
    // 70 single-line labels on line 1: the primary + 63 are drawn, 7 are listed.
    var many: [70]dg.Label = undefined;
    for (&many) |*l| l.* = .{ .line = 1, .col = 1, .end_col = 2, .end_line = 1, .message = "m" };
    const d: dg.Diagnostic = .{ .path = "", .file = "f", .line = 1, .col = 1, .severity = .@"error", .code = "", .message = "x", .labels = &many };
    const got = try render(std.testing.allocator, d, .{ .style = .snippet, .sources = &src });
    defer std.testing.allocator.free(got);
    try std.testing.expectEqual(@as(usize, 7), countOf(got, "--> f:1:1: m\n"));
    try std.testing.expectEqual(@as(usize, 1), countOf(got, "--> f:1:1\n"));

    // 17 multi-line spans (lines 1..2) in one file: 16 get a gutter column,
    // the 17th is a location line; the other 16 still render.
    var multi: [16]dg.Label = undefined;
    for (&multi) |*l| l.* = .{ .line = 1, .col = 1, .end_line = 2, .end_col = 3, .message = "mm" };
    const d2: dg.Diagnostic = .{ .path = "", .file = "f", .line = 1, .col = 1, .end_line = 2, .end_col = 3, .severity = .warning, .code = "", .message = "x", .labels = &multi };
    const got2 = try render(std.testing.allocator, d2, .{ .style = .snippet, .sources = &src });
    defer std.testing.allocator.free(got2);
    try std.testing.expectEqual(@as(usize, 1), countOf(got2, "--> f:1:1: mm\n"));
}

test "hostile text in labels, plain notes and sources never emits a raw escape; a tab survives in a plain note" {
    const src = [_]dg.Source{.{ .file = "f", .text = "a\x1b[2Jb\n\x07x\n" }};
    const d: dg.Diagnostic = .{
        .path = "",
        .file = "f",
        .line = 1,
        .col = 1,
        .end_line = 2,
        .end_col = 3,
        .severity = .@"error",
        .code = "",
        .message = "m\x1b[31m",
        .span_message = "end\x1b[0m\n",
        .labels = &.{
            .{ .line = 1, .col = 2, .end_line = 1, .end_col = 3, .message = "hang\x1b]0;x\x07" },
            .{ .line = 1, .col = 4, .end_line = 1, .end_col = 5, .message = "hang2\n" },
        },
        .notes = &.{.{ .kind = .plain, .message = "n1\x1b[2J\n\tn2\r\nn3\n" }},
    };
    const got = try render(std.testing.allocator, d, .{ .style = .snippet, .sources = &src });
    defer std.testing.allocator.free(got);
    try std.testing.expect(std.mem.findScalar(u8, got, 0x1b) == null);
    try std.testing.expect(std.mem.findScalar(u8, got, 0x07) == null);
    try std.testing.expect(std.mem.find(u8, got, "= n1\\x1b[2J\n    \tn2\n    n3\n") != null);
}

test "tab_width and the context lines are options" {
    const src = [_]dg.Source{.{ .file = "f", .text = "\tab\nl2\nl3\nl4\nl5\nl6\nl7\n" }};
    const d: dg.Diagnostic = .{ .path = "", .file = "f", .line = 1, .col = 2, .end_line = 7, .end_col = 2, .severity = .info, .code = "", .message = "m" };
    const got = try render(std.testing.allocator, d, .{ .style = .snippet, .sources = &src, .tab_width = 2, .start_context_lines = 0, .end_context_lines = 0 });
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings(
        "info: m\n  --> f:1:2\n  |  \n1 | /   ab\n  . |\n7 | | l7\n  | \\-^\n\n",
        got,
    );
}

test "random spans: no crash, no raw escape, colour only adds SGR sequences, bounded" {
    var prng: std.Random.DefaultPrng = .init(0xC0DE5);
    const rnd = prng.random();
    const texts = [_][]const u8{
        "",
        "a",
        "ab\ncd\n",
        "\tx\xC3\xA9y\r\nline2\n\nline4 \x1b[2J\n",
        "abc\xFF\xC3\nz",
        "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\n",
    };
    const msgs = [_][]const u8{ "", "m", "msg\nx\x1b", "a longer message that hangs" };
    var labels: [90]dg.Label = undefined;
    for (0..4000) |_| {
        const text = texts[rnd.uintLessThan(usize, texts.len)];
        const src = [_]dg.Source{.{ .file = "f", .text = text }};
        const n = if (rnd.uintLessThan(u8, 40) == 0) 70 + rnd.uintLessThan(usize, 20) else rnd.uintLessThan(usize, 8);
        for (labels[0..n]) |*l| {
            const line = rnd.uintLessThan(u32, 15);
            l.* = .{
                .line = line,
                .col = if (rnd.boolean()) rnd.uintLessThan(u32, 14) else null,
                .end_line = if (rnd.boolean()) line + rnd.uintLessThan(u32, 8) -| 1 else null,
                .end_col = if (rnd.boolean()) rnd.uintLessThan(u32, 14) else null,
                .message = msgs[rnd.uintLessThan(usize, msgs.len)],
                .primary = if (rnd.boolean()) rnd.boolean() else null,
            };
        }
        const d: dg.Diagnostic = .{
            .path = if (rnd.boolean()) "a.b" else "",
            .file = if (rnd.boolean()) "f" else null,
            .line = if (rnd.uintLessThan(u8, 8) == 0) null else rnd.uintLessThan(u32, 15),
            .col = if (rnd.boolean()) rnd.uintLessThan(u32, 14) else null,
            .end_line = if (rnd.boolean()) rnd.uintLessThan(u32, 15) else null,
            .end_col = if (rnd.boolean()) rnd.uintLessThan(u32, 14) else null,
            .severity = .warning,
            .code = "c",
            .message = "m",
            .span_message = msgs[rnd.uintLessThan(usize, msgs.len)],
            .labels = labels[0..n],
            .notes = &.{.{ .kind = .plain, .message = "n\n\tx" }},
        };
        const o: dg.RenderOptions = .{
            .style = .snippet,
            .sources = &src,
            .tab_width = rnd.uintLessThan(u8, 9),
            .start_context_lines = rnd.uintLessThan(u32, 4),
            .end_context_lines = rnd.uintLessThan(u32, 4),
        };
        const plain = try render(std.testing.allocator, d, o);
        defer std.testing.allocator.free(plain);
        var oc = o;
        oc.color = true;
        const col = try render(std.testing.allocator, d, oc);
        defer std.testing.allocator.free(col);
        try std.testing.expect(std.mem.findScalar(u8, plain, 0x1b) == null);
        try std.testing.expect(std.mem.endsWith(u8, plain, "\n\n"));
        var stripped: std.ArrayList(u8) = .empty;
        defer stripped.deinit(std.testing.allocator);
        var i: usize = 0;
        while (i < col.len) {
            if (col[i] == 0x1b) {
                i = std.mem.findScalarPos(u8, col, i, 'm').? + 1;
                continue;
            }
            try stripped.append(std.testing.allocator, col[i]);
            i += 1;
        }
        try std.testing.expectEqualStrings(plain, stripped.items);
    }
}
