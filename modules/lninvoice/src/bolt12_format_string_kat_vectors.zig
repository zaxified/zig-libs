// SPDX-License-Identifier: MIT
// Generated mechanically from lightning/bolts `bolt12/format-string-test.json` --
// see modules/lninvoice/NOTICE for the required CC-BY 4.0 attribution.
//!
//! All 12 rows: the `+`-continuation-marker / upper-vs-lowercase acceptance
//! rules for the checksum-less BOLT#12 string encoding -- exercises
//! `bech32_raw.stripContinuation`/`splitHrp` directly, decoded via `decodeOffer`.

pub const Vector = struct { comment: []const u8, valid: bool, string: []const u8 };

pub const vectors = [_]Vector{
    .{ .comment = "A complete string is valid", .valid = true, .string = "lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg" },
    .{ .comment = "Uppercase is valid", .valid = true, .string = "LNO1PQPS7SJQPGTYZM3QV4UXZMTSD3JJQER9WD3HY6TSW35K7MSJZFPY7NZ5YQCNYGRFDEJ82UM5WF5K2UCKYYPWA3EYT44H6TXTXQUQH7LZ5DJGE4AFGFJN7K4RGRKUAG0JSD5XVXG" },
    .{ .comment = "+ can join anywhere", .valid = true, .string = "l+no1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg" },
    .{ .comment = "Multiple + can join", .valid = true, .string = "lno1pqps7sjqpgt+yzm3qv4uxzmtsd3jjqer9wd3hy6tsw3+5k7msjzfpy7nz5yqcn+ygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd+5xvxg" },
    .{ .comment = "+ can be followed by whitespace", .valid = true, .string = "lno1pqps7sjqpgt+ yzm3qv4uxzmtsd3jjqer9wd3hy6tsw3+  5k7msjzfpy7nz5yqcn+\nygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd+\r\n 5xvxg" },
    .{ .comment = "+ can be followed by whitespace, UPPERCASE", .valid = true, .string = "LNO1PQPS7SJQPGT+ YZM3QV4UXZMTSD3JJQER9WD3HY6TSW3+  5K7MSJZFPY7NZ5YQCN+\nYGRFDEJ82UM5WF5K2UCKYYPWA3EYT44H6TXTXQUQH7LZ5DJGE4AFGFJN7K4RGRKUAG0JSD+\r\n 5XVXG" },
    .{ .comment = "Mixed case is invalid", .valid = false, .string = "LnO1PqPs7sJqPgTyZm3qV4UxZmTsD3JjQeR9Wd3hY6TsW35k7mSjZfPy7nZ5YqCnYgRfDeJ82uM5Wf5k2uCkYyPwA3EyT44h6tXtXqUqH7Lz5dJgE4AfGfJn7k4rGrKuAg0jSd5xVxG" },
    .{ .comment = "+ must be surrounded by bech32 characters", .valid = false, .string = "lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg+" },
    .{ .comment = "+ must be surrounded by bech32 characters", .valid = false, .string = "lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg+ " },
    .{ .comment = "+ must be surrounded by bech32 characters", .valid = false, .string = "+lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg" },
    .{ .comment = "+ must be surrounded by bech32 characters", .valid = false, .string = "+ lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg" },
    .{ .comment = "+ must be surrounded by bech32 characters", .valid = false, .string = "ln++o1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg" },
};
