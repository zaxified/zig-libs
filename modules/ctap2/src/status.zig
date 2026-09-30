// SPDX-License-Identifier: MIT
//! CTAP status codes (CTAP 2.1 §8.2) as one table and one typed error set.
//!
//! The first byte of every CTAP2 response is a status byte; `0x00` is success
//! and every other value is an error. `check` turns the byte into `void` or a
//! named Zig error, so a caller can `switch` on `error.PinInvalid`,
//! `error.PinBlocked`, ... instead of comparing magic numbers.

const std = @import("std");

/// Every status code the CTAP 2.1 specification assigns a name to, plus
/// `UnknownStatus` for anything else (the reserved `0x38`, the extension range
/// `0xE0..0xEF`, the vendor range `0xF0..0xFF`, or a value from a later spec).
pub const StatusError = error{
    // CTAP1 codes reused by CTAP2
    InvalidCommand, // 0x01 CTAP1_ERR_INVALID_COMMAND
    InvalidParameter, // 0x02 CTAP1_ERR_INVALID_PARAMETER
    InvalidLength, // 0x03 CTAP1_ERR_INVALID_LENGTH
    InvalidSeq, // 0x04 CTAP1_ERR_INVALID_SEQ
    Timeout, // 0x05 CTAP1_ERR_TIMEOUT
    ChannelBusy, // 0x06 CTAP1_ERR_CHANNEL_BUSY
    LockRequired, // 0x0A CTAP1_ERR_LOCK_REQUIRED
    InvalidChannel, // 0x0B CTAP1_ERR_INVALID_CHANNEL
    // CTAP2 codes
    CborUnexpectedType, // 0x11
    InvalidCbor, // 0x12
    MissingParameter, // 0x14
    LimitExceeded, // 0x15
    FpDatabaseFull, // 0x17
    LargeBlobStorageFull, // 0x18
    CredentialExcluded, // 0x19
    Processing, // 0x21
    InvalidCredential, // 0x22
    UserActionPending, // 0x23
    OperationPending, // 0x24
    NoOperations, // 0x25
    UnsupportedAlgorithm, // 0x26
    OperationDenied, // 0x27
    KeyStoreFull, // 0x28
    UnsupportedOption, // 0x2B
    InvalidOption, // 0x2C
    KeepaliveCancel, // 0x2D
    NoCredentials, // 0x2E
    UserActionTimeout, // 0x2F
    NotAllowed, // 0x30
    PinInvalid, // 0x31
    PinBlocked, // 0x32
    PinAuthInvalid, // 0x33
    PinAuthBlocked, // 0x34
    PinNotSet, // 0x35
    PuatRequired, // 0x36
    PinPolicyViolation, // 0x37
    RequestTooLarge, // 0x39
    ActionTimeout, // 0x3A
    UpRequired, // 0x3B
    UvBlocked, // 0x3C
    IntegrityFailure, // 0x3D
    InvalidSubcommand, // 0x3E
    UvInvalid, // 0x3F
    UnauthorizedPermission, // 0x40
    Other, // 0x7F CTAP1_ERR_OTHER
    /// A status byte the specification gives no name (reserved, extension,
    /// vendor or newer than CTAP 2.1). The raw byte is still in the response.
    UnknownStatus,
};

pub const Entry = struct { code: u8, name: []const u8 };

/// The spec table, code to error name. `check` and `codeOf` are both driven
/// from it; a test asserts every name is a member of `StatusError` and every
/// member (bar `UnknownStatus`) is in the table.
pub const table = [_]Entry{
    .{ .code = 0x01, .name = "InvalidCommand" },
    .{ .code = 0x02, .name = "InvalidParameter" },
    .{ .code = 0x03, .name = "InvalidLength" },
    .{ .code = 0x04, .name = "InvalidSeq" },
    .{ .code = 0x05, .name = "Timeout" },
    .{ .code = 0x06, .name = "ChannelBusy" },
    .{ .code = 0x0A, .name = "LockRequired" },
    .{ .code = 0x0B, .name = "InvalidChannel" },
    .{ .code = 0x11, .name = "CborUnexpectedType" },
    .{ .code = 0x12, .name = "InvalidCbor" },
    .{ .code = 0x14, .name = "MissingParameter" },
    .{ .code = 0x15, .name = "LimitExceeded" },
    .{ .code = 0x17, .name = "FpDatabaseFull" },
    .{ .code = 0x18, .name = "LargeBlobStorageFull" },
    .{ .code = 0x19, .name = "CredentialExcluded" },
    .{ .code = 0x21, .name = "Processing" },
    .{ .code = 0x22, .name = "InvalidCredential" },
    .{ .code = 0x23, .name = "UserActionPending" },
    .{ .code = 0x24, .name = "OperationPending" },
    .{ .code = 0x25, .name = "NoOperations" },
    .{ .code = 0x26, .name = "UnsupportedAlgorithm" },
    .{ .code = 0x27, .name = "OperationDenied" },
    .{ .code = 0x28, .name = "KeyStoreFull" },
    .{ .code = 0x2B, .name = "UnsupportedOption" },
    .{ .code = 0x2C, .name = "InvalidOption" },
    .{ .code = 0x2D, .name = "KeepaliveCancel" },
    .{ .code = 0x2E, .name = "NoCredentials" },
    .{ .code = 0x2F, .name = "UserActionTimeout" },
    .{ .code = 0x30, .name = "NotAllowed" },
    .{ .code = 0x31, .name = "PinInvalid" },
    .{ .code = 0x32, .name = "PinBlocked" },
    .{ .code = 0x33, .name = "PinAuthInvalid" },
    .{ .code = 0x34, .name = "PinAuthBlocked" },
    .{ .code = 0x35, .name = "PinNotSet" },
    .{ .code = 0x36, .name = "PuatRequired" },
    .{ .code = 0x37, .name = "PinPolicyViolation" },
    .{ .code = 0x39, .name = "RequestTooLarge" },
    .{ .code = 0x3A, .name = "ActionTimeout" },
    .{ .code = 0x3B, .name = "UpRequired" },
    .{ .code = 0x3C, .name = "UvBlocked" },
    .{ .code = 0x3D, .name = "IntegrityFailure" },
    .{ .code = 0x3E, .name = "InvalidSubcommand" },
    .{ .code = 0x3F, .name = "UvInvalid" },
    .{ .code = 0x40, .name = "UnauthorizedPermission" },
    .{ .code = 0x7F, .name = "Other" },
};

/// `0x00` (CTAP2_OK) is `void`; every other byte is an error.
pub fn check(code: u8) StatusError!void {
    if (code == 0) return;
    inline for (table) |e| {
        if (code == e.code) return @field(StatusError, e.name);
    }
    return error.UnknownStatus;
}

/// The status byte a named error corresponds to (`null` for `UnknownStatus`
/// and for errors outside `StatusError`). Useful for logging and for tests.
pub fn codeOf(err: anyerror) ?u8 {
    inline for (table) |e| {
        if (err == @field(StatusError, e.name)) return e.code;
    }
    return null;
}

test "every table row maps to its named error and back" {
    try check(0x00);
    inline for (table) |e| {
        try std.testing.expectError(@field(StatusError, e.name), check(e.code));
        try std.testing.expectEqual(@as(?u8, e.code), codeOf(@field(StatusError, e.name)));
    }
}

test "the table covers the whole error set (bar UnknownStatus) with unique codes" {
    const names = @typeInfo(StatusError).error_set.?;
    try std.testing.expectEqual(names.len - 1, table.len);
    for (table, 0..) |a, i| {
        for (table[i + 1 ..]) |b| try std.testing.expect(a.code != b.code);
    }
}

test "the PIN-related codes have the spec's values" {
    try std.testing.expectError(error.PinInvalid, check(0x31));
    try std.testing.expectError(error.PinBlocked, check(0x32));
    try std.testing.expectError(error.PinAuthInvalid, check(0x33));
    try std.testing.expectError(error.PinAuthBlocked, check(0x34));
    try std.testing.expectError(error.PinNotSet, check(0x35));
    try std.testing.expectError(error.PuatRequired, check(0x36));
    try std.testing.expectError(error.PinPolicyViolation, check(0x37));
    try std.testing.expectError(error.UvBlocked, check(0x3C));
    try std.testing.expectError(error.UvInvalid, check(0x3F));
    try std.testing.expectError(error.UnauthorizedPermission, check(0x40));
}

test "reserved, extension, vendor and unassigned codes are UnknownStatus, never a panic" {
    var code: u16 = 0;
    while (code < 256) : (code += 1) {
        const c: u8 = @intCast(code);
        const named = for (table) |e| {
            if (e.code == c) break true;
        } else false;
        if (c == 0 or named) continue;
        try std.testing.expectError(error.UnknownStatus, check(c));
    }
    try std.testing.expectError(error.UnknownStatus, check(0x38)); // reserved for future use
    try std.testing.expectError(error.UnknownStatus, check(0xDF)); // CTAP2_ERR_SPEC_LAST
    try std.testing.expectError(error.UnknownStatus, check(0xE0)); // CTAP2_ERR_EXTENSION_FIRST
    try std.testing.expectError(error.UnknownStatus, check(0xF0)); // CTAP2_ERR_VENDOR_FIRST
}
