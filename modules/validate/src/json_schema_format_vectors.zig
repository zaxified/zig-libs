// SPDX-License-Identifier: MIT
//! Vendored corpus list over json-schema-org/JSON-Schema-Test-Suite's
//! `tests/draft2020-12/optional/format/` directory (see ../../NOTICE for
//! provenance). One entry per fixture file whose `format` value is one this
//! module's `Format` enum implements.
//!
//! Deliberately NOT vendored (whole files, not present here at all): formats
//! this module does not implement --
//!   idn-email.json, idn-hostname.json, iri.json, iri-reference.json,
//!   uri-template.json, relative-json-pointer.json, regex.json,
//!   ecmascript-regex.json, unknown.json
//! -- see json_schema_format_test.zig's "vendored file count matches
//! expectation" canary, which fails loudly if the upstream directory changes
//! shape without this list being reconsidered.

const validate = @import("root.zig");

pub const FileVector = struct {
    /// Vendored filename under testdata/json-schema-test-suite/optional/format/.
    path: []const u8,
    /// The `Format` this file's schema(s) declare (`schema.format`) -- every
    /// group in a vendored file uses the same format value.
    format: validate.Format,
    content: []const u8,
};

pub const files = [_]FileVector{
    .{
        .path = "date.json",
        .format = .date,
        .content = @embedFile("testdata/json-schema-test-suite/optional/format/date.json"),
    },
    .{
        .path = "date-time.json",
        .format = .date_time,
        .content = @embedFile("testdata/json-schema-test-suite/optional/format/date-time.json"),
    },
    .{
        .path = "duration.json",
        .format = .duration,
        .content = @embedFile("testdata/json-schema-test-suite/optional/format/duration.json"),
    },
    .{
        .path = "email.json",
        .format = .email,
        .content = @embedFile("testdata/json-schema-test-suite/optional/format/email.json"),
    },
    .{
        .path = "hostname.json",
        .format = .hostname,
        .content = @embedFile("testdata/json-schema-test-suite/optional/format/hostname.json"),
    },
    .{
        .path = "ipv4.json",
        .format = .ipv4,
        .content = @embedFile("testdata/json-schema-test-suite/optional/format/ipv4.json"),
    },
    .{
        .path = "ipv6.json",
        .format = .ipv6,
        .content = @embedFile("testdata/json-schema-test-suite/optional/format/ipv6.json"),
    },
    .{
        .path = "json-pointer.json",
        .format = .json_pointer,
        .content = @embedFile("testdata/json-schema-test-suite/optional/format/json-pointer.json"),
    },
    .{
        .path = "time.json",
        .format = .time,
        .content = @embedFile("testdata/json-schema-test-suite/optional/format/time.json"),
    },
    .{
        .path = "uri.json",
        .format = .uri,
        .content = @embedFile("testdata/json-schema-test-suite/optional/format/uri.json"),
    },
    .{
        .path = "uri-reference.json",
        .format = .uri_reference,
        .content = @embedFile("testdata/json-schema-test-suite/optional/format/uri-reference.json"),
    },
    .{
        .path = "uuid.json",
        .format = .uuid,
        .content = @embedFile("testdata/json-schema-test-suite/optional/format/uuid.json"),
    },
};
