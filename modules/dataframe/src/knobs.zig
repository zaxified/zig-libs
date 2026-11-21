// SPDX-License-Identifier: MIT
//! The module's consumer build options (CONVENTIONS §4.2): `-Ddataframe-regex` and
//! `-Ddataframe-unicode`, both default `true` (the graded build) and both explicit-only
//! (`-Dprofile=small` leaves them alone). Off, the sibling module is not imported at all:
//! `regex` and `unitext` and their Unicode tables are not in the binary. The stand-ins below
//! have the surface the module uses, so no call site branches: a stand-in `regex` cannot
//! compile a pattern (every one is `error.BadPattern` / `error.BadArgument` where it is
//! used), a stand-in `unitext` makes every text "not valid UTF-8" for the case functions
//! (their ASCII path, the former behaviour) and answers `false` for the `is*` classes of
//! non-ASCII text. `normalize` and `unaccent` of non-ASCII text check `unicode_enabled`
//! themselves (`error.UnicodeNotBuilt`).

const std = @import("std");
const zl_options = @import("zl_options");

/// `-Ddataframe-regex`: the regex functions are built in.
pub const regex_enabled: bool = zl_options.dataframe_regex orelse true;
/// `-Ddataframe-unicode`: the Unicode text functions are built in.
pub const unicode_enabled: bool = zl_options.dataframe_unicode orelse true;

pub const regex = if (regex_enabled) @import("regex") else regex_off;
pub const ut = if (unicode_enabled) @import("unitext") else ut_off;

/// `regex` as far as the module uses it, for `-Ddataframe-regex=false`: nothing compiles, so
/// no `Regex` or `Matcher` ever exists and the other members are never reached.
const regex_off = struct {
    pub const Options = struct { syntax: enum { rust } = .rust };

    pub const Span = struct {
        start: usize,
        end: usize,

        pub fn slice(s: Span, input: []const u8) []const u8 {
            return input[s.start..s.end];
        }
    };

    pub const Regex = struct {
        names: []const []const u8 = &.{},

        pub fn compileOptions(_: std.mem.Allocator, _: []const u8, _: anytype) error{ OutOfMemory, RegexNotBuilt }!Regex {
            return error.RegexNotBuilt;
        }
        pub fn deinit(_: *Regex, _: std.mem.Allocator) void {}
        pub fn groupCount(_: *const Regex) usize {
            return 0;
        }
        pub fn isMatch(_: *const Regex, _: []const u8) bool {
            return false;
        }
        pub fn replaceN(_: *const Regex, a: std.mem.Allocator, input: []const u8, _: []const u8, _: ?usize) std.mem.Allocator.Error![]u8 {
            return a.dupe(u8, input);
        }
    };

    pub const Matcher = struct {
        re: *const Regex,
        pub fn init(_: std.mem.Allocator, re: *const Regex) std.mem.Allocator.Error!Matcher {
            return .{ .re = re };
        }
        pub fn deinit(_: *Matcher) void {}
        pub fn find(_: *Matcher, _: []const u8, _: usize) ?Span {
            return null;
        }
        pub fn captures(_: *Matcher, _: []const u8, _: usize, _: []?Span) bool {
            return false;
        }
        pub const Iterator = struct {
            pub fn next(_: *Iterator) ?Span {
                return null;
            }
            pub fn nextCaptures(_: *Iterator, _: []?Span) ?Span {
                return null;
            }
        };
        pub fn iterator(_: *Matcher, _: []const u8) Iterator {
            return .{};
        }
        pub const SplitIterator = struct {
            pub fn next(_: *SplitIterator) ?[]const u8 {
                return null;
            }
        };
        pub fn split(_: *Matcher, _: []const u8, _: ?usize) SplitIterator {
            return .{};
        }
        pub fn replaceN(_: *Matcher, _: *std.Io.Writer, _: []const u8, _: []const u8, _: ?usize) std.Io.Writer.Error!void {}
        pub fn replaceNLiteral(_: *Matcher, _: *std.Io.Writer, _: []const u8, _: []const u8, _: ?usize) std.Io.Writer.Error!void {}
    };

    pub fn quoteMetaAlloc(a: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]u8 {
        return a.dupe(u8, text);
    }
};

/// `unitext` as far as the module uses it, for `-Ddataframe-unicode=false`.
const ut_off = struct {
    pub const Form = enum { nfc, nfd, nfkc, nfkd };
    pub const Options = struct {
        invalid_utf8: enum { reject } = .reject,
        max_output: usize = 0,
    };
    const Err = error{ OutOfMemory, TooLarge, InvalidUtf8 };

    // Every mapping reports its text as not valid UTF-8: the caller's byte (ASCII) path answers.
    pub fn lower(_: std.mem.Allocator, _: []const u8, _: Options) Err![]u8 {
        return error.InvalidUtf8;
    }
    pub const upper = lower;
    pub const casefold = lower;
    pub const capitalize = lower;
    pub const title = lower;
    pub const swapcase = lower;
    pub fn normalize(_: std.mem.Allocator, _: []const u8, _: Form, _: Options) Err![]u8 {
        return error.InvalidUtf8;
    }
    pub const unaccent = lower;

    pub fn isAlpha(_: []const u8, _: Options) Err!bool {
        return false;
    }
    pub const isDigit = isAlpha;
    pub const isAlnum = isAlpha;
    pub const isSpace = isAlpha;
    pub const isLower = isAlpha;
    pub const isUpper = isAlpha;
    pub const isTitle = isAlpha;
    pub const isDecimal = isAlpha;
    pub const isNumeric = isAlpha;

    pub fn isSpaceCp(cp: u21) bool {
        return cp < 0x80 and (std.ascii.isWhitespace(@intCast(cp)) or (cp >= 0x1c and cp <= 0x1f));
    }
    pub fn isAlphabeticCp(cp: u21) bool {
        return cp < 0x80 and std.ascii.isAlphabetic(@intCast(cp));
    }
    pub fn isDecimalCp(cp: u21) bool {
        return cp < 0x80 and std.ascii.isDigit(@intCast(cp));
    }
};
