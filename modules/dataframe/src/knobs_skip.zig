// SPDX-License-Identifier: MIT
//! Test support for the build size knobs (`knobs.zig`): a test that needs the regex module or the
//! Unicode tables starts with one of these and is skipped when the build left them out
//! (`scripts/modtest dataframe -Ddataframe-regex=false -Ddataframe-unicode=false`).

const testkit = @import("testkit");
const knobs = @import("knobs.zig");

/// Skip unless `-Ddataframe-regex` is on.
pub fn needRegex() error{SkipZigTest}!void {
    if (!knobs.regex_enabled) return testkit.skip("-Ddataframe-regex=false", .{});
}

/// Skip unless `-Ddataframe-unicode` is on.
pub fn needUnicode() error{SkipZigTest}!void {
    if (!knobs.unicode_enabled) return testkit.skip("-Ddataframe-unicode=false", .{});
}

/// Skip unless both knobs are on (a replay of engine answers that mixes both kinds of text function).
pub fn needBoth() error{SkipZigTest}!void {
    try needRegex();
    try needUnicode();
}
