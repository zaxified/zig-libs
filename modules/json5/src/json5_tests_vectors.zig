// SPDX-License-Identifier: MIT
//! Generated vector list over the vendored json5/json5-tests corpus (see ../../NOTICE
//! for provenance). One entry per fixture file; DO NOT hand-edit the `content` field --
//! regenerate from testdata/json5-tests/ if the corpus is ever re-vendored.
//!
//! `expect` is derived mechanically from the upstream extension convention (see
//! json5-tests/README.md): `.json`/`.json5` must parse, `.js`/`.txt` must be rejected.
//!
//! `out_of_scope`, when non-null, names a specific README "Deferred" bullet this module
//! has never claimed to implement -- these entries are NOT asserted against `expect` by
//! json5_tests_test.zig, but they ARE counted, so silently dropping one changes a checked
//! total instead of vanishing quietly.

pub const Expect = enum { must_parse, must_reject };

pub const Vector = struct {
    path: []const u8,
    expect: Expect,
    content: []const u8,
    out_of_scope: ?[]const u8 = null,
};

pub const vectors = [_]Vector{
    .{
        .path = "arrays/empty-array.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/arrays/empty-array.json"),
    },
    .{
        .path = "arrays/leading-comma-array.js",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/arrays/leading-comma-array.js"),
    },
    .{
        .path = "arrays/lone-trailing-comma-array.js",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/arrays/lone-trailing-comma-array.js"),
    },
    .{
        .path = "arrays/no-comma-array.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/arrays/no-comma-array.txt"),
    },
    .{
        .path = "arrays/regular-array.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/arrays/regular-array.json"),
    },
    .{
        .path = "arrays/trailing-comma-array.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/arrays/trailing-comma-array.json5"),
    },
    .{
        .path = "comments/block-comment-following-array-element.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/comments/block-comment-following-array-element.json5"),
    },
    .{
        .path = "comments/block-comment-following-top-level-value.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/comments/block-comment-following-top-level-value.json5"),
    },
    .{
        .path = "comments/block-comment-in-string.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/comments/block-comment-in-string.json"),
    },
    .{
        .path = "comments/block-comment-preceding-top-level-value.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/comments/block-comment-preceding-top-level-value.json5"),
    },
    .{
        .path = "comments/block-comment-with-asterisks.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/comments/block-comment-with-asterisks.json5"),
    },
    .{
        .path = "comments/inline-comment-following-array-element.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/comments/inline-comment-following-array-element.json5"),
    },
    .{
        .path = "comments/inline-comment-following-top-level-value.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/comments/inline-comment-following-top-level-value.json5"),
    },
    .{
        .path = "comments/inline-comment-in-string.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/comments/inline-comment-in-string.json"),
    },
    .{
        .path = "comments/inline-comment-preceding-top-level-value.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/comments/inline-comment-preceding-top-level-value.json5"),
    },
    .{
        .path = "comments/irregular-block-comment.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/comments/irregular-block-comment.json"),
    },
    .{
        .path = "comments/top-level-block-comment.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/comments/top-level-block-comment.txt"),
    },
    .{
        .path = "comments/top-level-inline-comment.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/comments/top-level-inline-comment.txt"),
    },
    .{
        .path = "comments/unterminated-block-comment.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/comments/unterminated-block-comment.txt"),
    },
    .{
        .path = "misc/empty.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/misc/empty.txt"),
    },
    .{
        .path = "misc/npm-package.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/misc/npm-package.json"),
    },
    .{
        .path = "misc/npm-package.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/misc/npm-package.json5"),
    },
    .{
        .path = "misc/readme-example.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/misc/readme-example.json5"),
        .out_of_scope = "combines hex + leading-dot + Infinity + leading-plus numeric extensions (README Deferred #1/2/3/5) -- the JSON5.org spec's own canonical example",
    },
    .{
        .path = "misc/valid-whitespace.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/misc/valid-whitespace.json5"),
        .out_of_scope = "JSON5-only extra whitespace character (form feed, U+000C) before a token -- README Deferred #6 (newly documented; this preprocessor never claimed to rewrite whitespace, only comments/keys/commas/quotes, and std.json's whitespace grammar is ASCII space/tab/CR/LF only)",
    },
    .{
        .path = "new-lines/comment-cr.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/new-lines/comment-cr.json5"),
    },
    .{
        .path = "new-lines/comment-crlf.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/new-lines/comment-crlf.json5"),
    },
    .{
        .path = "new-lines/comment-lf.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/new-lines/comment-lf.json5"),
    },
    .{
        .path = "new-lines/escaped-cr.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/new-lines/escaped-cr.json5"),
        .out_of_scope = "backslash-newline line continuation inside strings -- README Deferred #4 (not implemented)",
    },
    .{
        .path = "new-lines/escaped-crlf.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/new-lines/escaped-crlf.json5"),
        .out_of_scope = "backslash-newline line continuation inside strings -- README Deferred #4 (not implemented)",
    },
    .{
        .path = "new-lines/escaped-lf.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/new-lines/escaped-lf.json5"),
        .out_of_scope = "backslash-newline line continuation inside strings -- README Deferred #4 (not implemented)",
    },
    .{
        .path = "numbers/float-leading-decimal-point.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/float-leading-decimal-point.json5"),
        .out_of_scope = "leading/trailing-dot numbers -- README Deferred #2 (not implemented)",
    },
    .{
        .path = "numbers/float-leading-zero.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/float-leading-zero.json"),
    },
    .{
        .path = "numbers/float-trailing-decimal-point-with-integer-exponent.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/float-trailing-decimal-point-with-integer-exponent.json5"),
        .out_of_scope = "leading/trailing-dot numbers -- README Deferred #2 (not implemented)",
    },
    .{
        .path = "numbers/float-trailing-decimal-point.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/float-trailing-decimal-point.json5"),
        .out_of_scope = "leading/trailing-dot numbers -- README Deferred #2 (not implemented)",
    },
    .{
        .path = "numbers/float-with-integer-exponent.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/float-with-integer-exponent.json"),
    },
    .{
        .path = "numbers/float.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/float.json"),
    },
    .{
        .path = "numbers/hexadecimal-empty.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/hexadecimal-empty.txt"),
    },
    .{
        .path = "numbers/hexadecimal-lowercase-letter.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/hexadecimal-lowercase-letter.json5"),
        .out_of_scope = "hex numeric literals -- README Deferred #1 (not implemented; preprocessor never touches numeric bytes)",
    },
    .{
        .path = "numbers/hexadecimal-uppercase-x.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/hexadecimal-uppercase-x.json5"),
        .out_of_scope = "hex numeric literals -- README Deferred #1 (not implemented; preprocessor never touches numeric bytes)",
    },
    .{
        .path = "numbers/hexadecimal-with-integer-exponent.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/hexadecimal-with-integer-exponent.json5"),
        .out_of_scope = "hex numeric literals -- README Deferred #1 (not implemented; preprocessor never touches numeric bytes)",
    },
    .{
        .path = "numbers/hexadecimal.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/hexadecimal.json5"),
        .out_of_scope = "hex numeric literals -- README Deferred #1 (not implemented; preprocessor never touches numeric bytes)",
    },
    .{
        .path = "numbers/infinity.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/infinity.json5"),
        .out_of_scope = "+Infinity/-Infinity/NaN literals -- README Deferred #3 (not implemented)",
    },
    .{
        .path = "numbers/integer-with-float-exponent.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/integer-with-float-exponent.txt"),
    },
    .{
        .path = "numbers/integer-with-hexadecimal-exponent.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/integer-with-hexadecimal-exponent.txt"),
    },
    .{
        .path = "numbers/integer-with-integer-exponent.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/integer-with-integer-exponent.json"),
    },
    .{
        .path = "numbers/integer-with-negative-float-exponent.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/integer-with-negative-float-exponent.txt"),
    },
    .{
        .path = "numbers/integer-with-negative-hexadecimal-exponent.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/integer-with-negative-hexadecimal-exponent.txt"),
    },
    .{
        .path = "numbers/integer-with-negative-integer-exponent.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/integer-with-negative-integer-exponent.json"),
    },
    .{
        .path = "numbers/integer-with-negative-zero-integer-exponent.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/integer-with-negative-zero-integer-exponent.json"),
    },
    .{
        .path = "numbers/integer-with-positive-float-exponent.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/integer-with-positive-float-exponent.txt"),
    },
    .{
        .path = "numbers/integer-with-positive-hexadecimal-exponent.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/integer-with-positive-hexadecimal-exponent.txt"),
    },
    .{
        .path = "numbers/integer-with-positive-integer-exponent.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/integer-with-positive-integer-exponent.json"),
    },
    .{
        .path = "numbers/integer-with-positive-zero-integer-exponent.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/integer-with-positive-zero-integer-exponent.json"),
    },
    .{
        .path = "numbers/integer-with-zero-integer-exponent.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/integer-with-zero-integer-exponent.json"),
    },
    .{
        .path = "numbers/integer.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/integer.json"),
    },
    .{
        .path = "numbers/lone-decimal-point.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/lone-decimal-point.txt"),
    },
    .{
        .path = "numbers/nan.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/nan.json5"),
        .out_of_scope = "+Infinity/-Infinity/NaN literals -- README Deferred #3 (not implemented)",
    },
    .{
        .path = "numbers/negative-float-leading-decimal-point.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/negative-float-leading-decimal-point.json5"),
        .out_of_scope = "leading/trailing-dot numbers -- README Deferred #2 (not implemented)",
    },
    .{
        .path = "numbers/negative-float-leading-zero.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/negative-float-leading-zero.json"),
    },
    .{
        .path = "numbers/negative-float-trailing-decimal-point.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/negative-float-trailing-decimal-point.json5"),
        .out_of_scope = "leading/trailing-dot numbers -- README Deferred #2 (not implemented)",
    },
    .{
        .path = "numbers/negative-float.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/negative-float.json"),
    },
    .{
        .path = "numbers/negative-hexadecimal.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/negative-hexadecimal.json5"),
        .out_of_scope = "hex numeric literals -- README Deferred #1 (not implemented; preprocessor never touches numeric bytes)",
    },
    .{
        .path = "numbers/negative-infinity.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/negative-infinity.json5"),
        .out_of_scope = "+Infinity/-Infinity/NaN literals -- README Deferred #3 (not implemented)",
    },
    .{
        .path = "numbers/negative-integer.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/negative-integer.json"),
    },
    .{
        .path = "numbers/negative-noctal.js",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/negative-noctal.js"),
    },
    .{
        .path = "numbers/negative-octal.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/negative-octal.txt"),
    },
    .{
        .path = "numbers/negative-zero-float-leading-decimal-point.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/negative-zero-float-leading-decimal-point.json5"),
        .out_of_scope = "leading/trailing-dot numbers -- README Deferred #2 (not implemented)",
    },
    .{
        .path = "numbers/negative-zero-float-trailing-decimal-point.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/negative-zero-float-trailing-decimal-point.json5"),
        .out_of_scope = "leading/trailing-dot numbers -- README Deferred #2 (not implemented)",
    },
    .{
        .path = "numbers/negative-zero-float.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/negative-zero-float.json"),
    },
    .{
        .path = "numbers/negative-zero-hexadecimal.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/negative-zero-hexadecimal.json5"),
        .out_of_scope = "hex numeric literals -- README Deferred #1 (not implemented; preprocessor never touches numeric bytes)",
    },
    .{
        .path = "numbers/negative-zero-integer.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/negative-zero-integer.json"),
    },
    .{
        .path = "numbers/negative-zero-octal.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/negative-zero-octal.txt"),
    },
    .{
        .path = "numbers/noctal-with-leading-octal-digit.js",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/noctal-with-leading-octal-digit.js"),
    },
    .{
        .path = "numbers/noctal.js",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/noctal.js"),
    },
    .{
        .path = "numbers/octal.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/octal.txt"),
    },
    .{
        .path = "numbers/positive-float-leading-decimal-point.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/positive-float-leading-decimal-point.json5"),
        .out_of_scope = "leading/trailing-dot numbers -- README Deferred #2 (not implemented)",
    },
    .{
        .path = "numbers/positive-float-leading-zero.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/positive-float-leading-zero.json5"),
        .out_of_scope = "leading '+' sign on numbers -- README Deferred #5 (newly documented by this sweep; preprocessor never touches numeric bytes, and JSON/std.json disallows a leading '+')",
    },
    .{
        .path = "numbers/positive-float-trailing-decimal-point.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/positive-float-trailing-decimal-point.json5"),
        .out_of_scope = "leading/trailing-dot numbers -- README Deferred #2 (not implemented)",
    },
    .{
        .path = "numbers/positive-float.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/positive-float.json5"),
        .out_of_scope = "leading '+' sign on numbers -- README Deferred #5 (newly documented by this sweep; preprocessor never touches numeric bytes, and JSON/std.json disallows a leading '+')",
    },
    .{
        .path = "numbers/positive-hexadecimal.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/positive-hexadecimal.json5"),
        .out_of_scope = "hex numeric literals -- README Deferred #1 (not implemented; preprocessor never touches numeric bytes)",
    },
    .{
        .path = "numbers/positive-infinity.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/positive-infinity.json5"),
        .out_of_scope = "+Infinity/-Infinity/NaN literals -- README Deferred #3 (not implemented)",
    },
    .{
        .path = "numbers/positive-integer.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/positive-integer.json5"),
        .out_of_scope = "leading '+' sign on numbers -- README Deferred #5 (newly documented by this sweep; preprocessor never touches numeric bytes, and JSON/std.json disallows a leading '+')",
    },
    .{
        .path = "numbers/positive-noctal.js",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/positive-noctal.js"),
    },
    .{
        .path = "numbers/positive-octal.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/positive-octal.txt"),
    },
    .{
        .path = "numbers/positive-zero-float-leading-decimal-point.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/positive-zero-float-leading-decimal-point.json5"),
        .out_of_scope = "leading/trailing-dot numbers -- README Deferred #2 (not implemented)",
    },
    .{
        .path = "numbers/positive-zero-float-trailing-decimal-point.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/positive-zero-float-trailing-decimal-point.json5"),
        .out_of_scope = "leading/trailing-dot numbers -- README Deferred #2 (not implemented)",
    },
    .{
        .path = "numbers/positive-zero-float.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/positive-zero-float.json5"),
        .out_of_scope = "leading '+' sign on numbers -- README Deferred #5 (newly documented by this sweep; preprocessor never touches numeric bytes, and JSON/std.json disallows a leading '+')",
    },
    .{
        .path = "numbers/positive-zero-hexadecimal.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/positive-zero-hexadecimal.json5"),
        .out_of_scope = "hex numeric literals -- README Deferred #1 (not implemented; preprocessor never touches numeric bytes)",
    },
    .{
        .path = "numbers/positive-zero-integer.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/positive-zero-integer.json5"),
        .out_of_scope = "leading '+' sign on numbers -- README Deferred #5 (newly documented by this sweep; preprocessor never touches numeric bytes, and JSON/std.json disallows a leading '+')",
    },
    .{
        .path = "numbers/positive-zero-octal.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/positive-zero-octal.txt"),
    },
    .{
        .path = "numbers/zero-float-leading-decimal-point.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/zero-float-leading-decimal-point.json5"),
        .out_of_scope = "leading/trailing-dot numbers -- README Deferred #2 (not implemented)",
    },
    .{
        .path = "numbers/zero-float-trailing-decimal-point.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/zero-float-trailing-decimal-point.json5"),
        .out_of_scope = "leading/trailing-dot numbers -- README Deferred #2 (not implemented)",
    },
    .{
        .path = "numbers/zero-float.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/zero-float.json"),
    },
    .{
        .path = "numbers/zero-hexadecimal.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/zero-hexadecimal.json5"),
        .out_of_scope = "hex numeric literals -- README Deferred #1 (not implemented; preprocessor never touches numeric bytes)",
    },
    .{
        .path = "numbers/zero-integer-with-integer-exponent.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/zero-integer-with-integer-exponent.json"),
    },
    .{
        .path = "numbers/zero-integer.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/numbers/zero-integer.json"),
    },
    .{
        .path = "numbers/zero-octal.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/numbers/zero-octal.txt"),
    },
    .{
        .path = "objects/duplicate-keys.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/objects/duplicate-keys.json"),
    },
    .{
        .path = "objects/empty-object.json",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/objects/empty-object.json"),
    },
    .{
        .path = "objects/illegal-unquoted-key-number.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/objects/illegal-unquoted-key-number.txt"),
    },
    .{
        .path = "objects/illegal-unquoted-key-symbol.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/objects/illegal-unquoted-key-symbol.txt"),
    },
    .{
        .path = "objects/leading-comma-object.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/objects/leading-comma-object.txt"),
    },
    .{
        .path = "objects/lone-trailing-comma-object.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/objects/lone-trailing-comma-object.txt"),
    },
    .{
        .path = "objects/no-comma-object.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/objects/no-comma-object.txt"),
    },
    .{
        .path = "objects/reserved-unquoted-key.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/objects/reserved-unquoted-key.json5"),
    },
    .{
        .path = "objects/single-quoted-key.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/objects/single-quoted-key.json5"),
    },
    .{
        .path = "objects/trailing-comma-object.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/objects/trailing-comma-object.json5"),
    },
    .{
        .path = "objects/unquoted-keys.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/objects/unquoted-keys.json5"),
    },
    .{
        .path = "strings/escaped-single-quoted-string.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/strings/escaped-single-quoted-string.json5"),
    },
    .{
        .path = "strings/multi-line-string.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/strings/multi-line-string.json5"),
        .out_of_scope = "backslash-newline line continuation inside strings -- README Deferred #4 (not implemented)",
    },
    .{
        .path = "strings/single-quoted-string.json5",
        .expect = .must_parse,
        .content = @embedFile("testdata/json5-tests/strings/single-quoted-string.json5"),
    },
    .{
        .path = "strings/unescaped-multi-line-string.txt",
        .expect = .must_reject,
        .content = @embedFile("testdata/json5-tests/strings/unescaped-multi-line-string.txt"),
    },
};
