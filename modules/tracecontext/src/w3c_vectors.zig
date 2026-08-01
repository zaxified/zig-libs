// SPDX-License-Identifier: BSD-3-Clause (W3C 3-clause test-suite license — see ../../NOTICE)
//! Hand-transcribed conformance vectors from the W3C `trace-context` test
//! suite (see ../NOTICE for provenance), pinned at commit
//! `acab820be9db7b3433668baa5cdd43f57f4c4be0` (`main`, 2026-06-29),
//! `test/test.py` (classes `TraceContextTest`, `AdvancedTest`,
//! `TraceContext2Test`).
//!
//! The upstream suite is a LIVE two-way HTTP conformance harness (Python
//! `client.py`/`server.py` drive a running vendor service over the network
//! and inspect its outgoing headers) — there is no static JSON/CSV corpus to
//! `@embedFile`, unlike e.g. `csvstream`/`json5`. Each vector below
//! reproduces one `self.make_single_request_and_get_tracecontext(...)` (or
//! `self.make_request(...)`) call's request headers, transcribed by hand
//! from the cited `source_test` function and cross-checked line-by-line
//! against the fetched source (kept in the task record, not in this repo).
//! DO NOT hand-edit `vectors` without re-checking against upstream — see the
//! count canary in `w3c_conformance_test.zig`, which fails loudly if the
//! vendored/executed/excluded totals drift without a matching
//! reclassification.
//!
//! `out_of_scope`, when non-null, names the reason a vector is COUNTED but
//! NOT asserted — see `w3c_conformance_test.zig`'s header comment for the
//! full explanation of each exclusion category.

pub const Header = struct { name: []const u8, value: []const u8 };

/// Verdict for the outgoing `traceparent`'s trace-id.
pub const TraceparentVerdict = union(enum) {
    /// The trace-id must equal this lowercase-hex string (a trusted incoming
    /// traceparent was continued).
    preserved: []const u8,
    /// The trace-id must differ from EVERY one of these hex-ish strings (the
    /// incoming traceparent(s) were rejected; a fresh trace was started).
    changed_from: []const []const u8,
    /// No assertion beyond "a well-formed traceparent was emitted" — upstream
    /// itself makes no stronger claim for this case.
    any_valid,
};

/// Verdict for the outgoing `tracestate`.
pub const TracestateVerdict = union(enum) {
    /// No assertion made about tracestate for this vector.
    none,
    /// tracestate must be entirely absent from the response.
    absent,
    /// tracestate must equal exactly this string.
    exact: []const u8,
    /// Every one of these substrings must appear in the combined tracestate
    /// value. When `Vector.ordered` is true they must appear at strictly
    /// increasing byte offsets (mirrors upstream's own chained
    /// `str.index(a) < str.index(b)` assertions).
    contains: []const []const u8,
};

pub const Vector = struct {
    /// Exact upstream `test_*` function name — the citation.
    source_test: []const u8,
    /// Short paraphrase of the upstream docstring/intent.
    doc: []const u8,
    /// Request headers, in wire order. Repeated names are the point for
    /// several vectors (duplicated traceparent, multi-instance tracestate).
    headers: []const Header,
    traceparent: TraceparentVerdict,
    tracestate: TracestateVerdict = .none,
    ordered: bool = false,
    /// Non-null: this vector is COUNTED but not asserted.
    out_of_scope: ?[]const u8 = null,
};

const trace_id_a = "12345678901234567890123456789012";
const parent_id_a = "1234567890123456";

// Reason strings for excluded categories, named once so every vector that
// shares a reason is provably consistent (a typo in one copy would no longer
// silently diverge from the others).
const reason_forward_compat =
    "traceparent versions other than \"00\" are not implemented: our parser " ++
    "rejects any non-\"00\" version outright (ParseError.BadVersion), rather " ++
    "than attempting the spec's documented forward-compatible fallback parse " ++
    "for higher versions (spec 20-http_request_header_format.md, " ++
    "\"Versioning of traceparent\"). That section uses SHOULD, not MUST, for " ++
    "the fallback-parse behavior, so rejecting an unknown version outright " ++
    "is spec-conformant — just not what this specific conformance-suite test " ++
    "asserts. Recorded as a deliberate scope decision in SPEC.md's Backlog, " ++
    "not silently dropped.";
const reason_strict_grammar =
    "full tracestate list-member GRAMMAR validation (per-key charset, the " ++
    "lcalpha/DIGIT-leading rule, 256-char key length cap, 32-member cap) is " ++
    "deliberately not implemented -- see root.zig's isValidState doc: " ++
    "\"a light guard -- full grammar validation is intentionally left to the " ++
    "tracing backend.\" This mirrors the suite's OWN STRICT_LEVEL knob: every " ++
    "excluded vector here comes from a test method the suite itself guards " ++
    "with `@unittest.skipIf(STRICT_LEVEL < 2, \"strict\")`, i.e. upstream " ++
    "already treats this as an opt-in stricter tier, not a Level-1 baseline.";
const reason_session_repetition =
    "tests repeated-callback / connection-reuse behavior of a stateful " ++
    "vendor HTTP service (multiple round trips over one make_request call), " ++
    "not a header-parsing edge case. This module validates one request at a " ++
    "time; the underlying claims (same trace-id across hops, a fresh " ++
    "parent-id/span-id each time, ids never collide) are already covered by " ++
    "this module's own pre-existing \"childOf keeps the trace and generated " ++
    "ids are unique / non-zero\" test.";
const reason_level2 =
    "Trace Context Level 2 (the random-trace-id flag, spec_flags bit 1) is " ++
    "explicitly out of this module's documented scope -- see root.zig's " ++
    "module doc (\"W3C does not require randomness of trace-ids\") and " ++
    "SPEC.md's Threat model (\"Only Level 1 is implemented\"). Upstream itself " ++
    "gates this test behind `@unittest.skipIf(SPEC_LEVEL < 2, ...)`, off by " ++
    "default.";

pub const vectors = [_]Vector{
    // ---- TraceContextTest -------------------------------------------------

    .{
        .source_test = "test_both_traceparent_and_tracestate_missing",
        .doc = "no traceparent/tracestate sent -> a valid fresh traceparent is emitted, no tracestate",
        .headers = &.{},
        .traceparent = .any_valid,
        .tracestate = .absent,
    },
    .{
        .source_test = "test_traceparent_included_tracestate_missing",
        .doc = "valid traceparent, no tracestate -> trace-id kept, fresh parent-id",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .absent,
    },
    .{
        .source_test = "test_traceparent_duplicated",
        .doc = "two traceparent headers (different trace-ids) -> ambiguous, discarded, fresh trace-id (the change under teeth-check #1)",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-12345678901234567890123456789011-" ++ parent_id_a ++ "-01" },
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" },
        },
        .traceparent = .{ .changed_from = &.{ "12345678901234567890123456789011", trace_id_a } },
    },
    .{
        .source_test = "test_traceparent_header_name",
        .doc = "wrong header name 'trace-parent' -> not recognized, fresh trace-id",
        .headers = &.{.{ .name = "trace-parent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_header_name",
        .doc = "wrong header name 'trace.parent' -> not recognized, fresh trace-id",
        .headers = &.{.{ .name = "trace.parent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_header_name_valid_casing",
        .doc = "'TraceParent' casing -> recognized, trace-id kept",
        .headers = &.{.{ .name = "TraceParent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .preserved = trace_id_a },
    },
    .{
        .source_test = "test_traceparent_header_name_valid_casing",
        .doc = "'TrAcEpArEnT' mixed casing -> recognized, trace-id kept",
        .headers = &.{.{ .name = "TrAcEpArEnT", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .preserved = trace_id_a },
    },
    .{
        .source_test = "test_traceparent_header_name_valid_casing",
        .doc = "'TRACEPARENT' all-caps -> recognized, trace-id kept",
        .headers = &.{.{ .name = "TRACEPARENT", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .preserved = trace_id_a },
    },
    .{
        .source_test = "test_traceparent_version_0x00",
        .doc = "version 00 with a trailing '.' -> extra bytes make it the wrong length, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01." }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_version_0x00",
        .doc = "version 00 with trailing free text -> extra bytes, rejected (v00 has no forward-compat allowance)",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01-what-the-future-will-be-like" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_version_0xcc",
        .doc = "higher version 'cc' -> spec's forward-compatible fallback parse SHOULD keep the trace-id; not implemented here",
        .headers = &.{.{ .name = "traceparent", .value = "cc-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .preserved = trace_id_a },
        .out_of_scope = reason_forward_compat,
    },
    .{
        .source_test = "test_traceparent_version_0xcc",
        .doc = "higher version 'cc' with additive trailing fields -> still parseable per the forward-compat rule; not implemented here",
        .headers = &.{.{ .name = "traceparent", .value = "cc-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01-what-the-future-will-be-like" }},
        .traceparent = .{ .preserved = trace_id_a },
        .out_of_scope = reason_forward_compat,
    },
    .{
        .source_test = "test_traceparent_version_0xcc",
        .doc = "higher version 'cc' but the flags field is followed by '.' not '-' -> malformed even under the forward-compat rule, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "cc-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01.what-the-future-will-be-like" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
        // Not excluded for the forward-compat reason: our all-non-"00"-rejected
        // parser already produces the expected verdict here by coincidence
        // (both "don't understand cc" and "correctly detect this cc is
        // malformed" reject it) — grouped with its sibling cases anyway so the
        // whole test_traceparent_version_0xcc method reads as one exclusion,
        // not two in-scope stragglers plus one excluded.
        .out_of_scope = reason_forward_compat,
    },
    .{
        .source_test = "test_traceparent_version_0xff",
        .doc = "version 'ff' is explicitly forbidden by the spec -> rejected, fresh trace-id",
        .headers = &.{.{ .name = "traceparent", .value = "ff-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_version_illegal_characters",
        .doc = "'.0' as version -> illegal hex, rejected",
        .headers = &.{.{ .name = "traceparent", .value = ".0-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_version_illegal_characters",
        .doc = "'0.' as version -> illegal hex, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "0.-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_version_too_long",
        .doc = "3-hex version '000' -> BadLength, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "000-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_version_too_long",
        .doc = "4-hex version '0000' -> BadLength, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "0000-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_version_too_short",
        .doc = "1-hex version '0' -> BadLength, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "0-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_trace_id_all_zero",
        .doc = "all-zero trace-id is explicitly invalid -> rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-00000000000000000000000000000000-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .changed_from = &.{"00000000000000000000000000000000"} },
    },
    .{
        .source_test = "test_traceparent_trace_id_illegal_characters",
        .doc = "leading '.' in trace-id -> illegal hex, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-.2345678901234567890123456789012-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .changed_from = &.{".2345678901234567890123456789012"} },
    },
    .{
        .source_test = "test_traceparent_trace_id_illegal_characters",
        .doc = "trailing '.' in trace-id -> illegal hex, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-1234567890123456789012345678901.-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .changed_from = &.{"1234567890123456789012345678901."} },
    },
    .{
        .source_test = "test_traceparent_trace_id_too_long",
        .doc = "33-hex trace-id -> BadLength, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-123456789012345678901234567890123-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .changed_from = &.{ "123456789012345678901234567890123", trace_id_a, "23456789012345678901234567890123" } },
    },
    .{
        .source_test = "test_traceparent_trace_id_too_short",
        .doc = "31-hex trace-id -> BadLength, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-1234567890123456789012345678901-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .changed_from = &.{"1234567890123456789012345678901"} },
    },
    .{
        .source_test = "test_traceparent_parent_id_all_zero",
        .doc = "all-zero parent-id is explicitly invalid -> the whole traceparent is rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-0000000000000000-01" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_parent_id_illegal_characters",
        .doc = "leading '.' in parent-id -> illegal hex, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-.234567890123456-01" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_parent_id_illegal_characters",
        .doc = "trailing '.' in parent-id -> illegal hex, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-123456789012345.-01" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_parent_id_too_long",
        .doc = "17-hex parent-id -> BadLength, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-12345678901234567-01" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_parent_id_too_short",
        .doc = "15-hex parent-id -> BadLength, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-123456789012345-01" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_trace_flags_illegal_characters",
        .doc = "leading '.' in trace-flags -> illegal hex, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-.0" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_trace_flags_illegal_characters",
        .doc = "trailing '.' in trace-flags -> illegal hex, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-0." }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_trace_flags_too_long",
        .doc = "3-hex trace-flags -> BadLength, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-001" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_trace_flags_too_short",
        .doc = "1-hex trace-flags -> BadLength, rejected",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-1" }},
        .traceparent = .{ .changed_from = &.{trace_id_a} },
    },
    .{
        .source_test = "test_traceparent_ows_handling",
        .doc = "leading space around a valid traceparent -> OWS trimmed at the header-line level (by the `http` module), still recognized",
        .headers = &.{.{ .name = "traceparent", .value = " 00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .preserved = trace_id_a },
    },
    .{
        .source_test = "test_traceparent_ows_handling",
        .doc = "leading tab around a valid traceparent -> OWS trimmed, still recognized",
        .headers = &.{.{ .name = "traceparent", .value = "\t00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .preserved = trace_id_a },
    },
    .{
        .source_test = "test_traceparent_ows_handling",
        .doc = "trailing space around a valid traceparent -> OWS trimmed, still recognized",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01 " }},
        .traceparent = .{ .preserved = trace_id_a },
    },
    .{
        .source_test = "test_traceparent_ows_handling",
        .doc = "trailing tab around a valid traceparent -> OWS trimmed, still recognized",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01\t" }},
        .traceparent = .{ .preserved = trace_id_a },
    },
    .{
        .source_test = "test_traceparent_ows_handling",
        .doc = "mixed leading/trailing OWS around a valid traceparent -> trimmed, still recognized",
        .headers = &.{.{ .name = "traceparent", .value = "\t 00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-01 \t" }},
        .traceparent = .{ .preserved = trace_id_a },
    },
    .{
        .source_test = "test_tracestate_included_traceparent_missing",
        .doc = "tracestate sent WITHOUT a traceparent -> per spec, a vendor that fails to parse traceparent MUST NOT attempt to parse tracestate; it must be dropped (teeth-check #4 -- the additional bug this audit found and fixed)",
        .headers = &.{.{ .name = "tracestate", .value = "foo=1" }},
        .traceparent = .any_valid,
        .tracestate = .absent,
    },
    .{
        .source_test = "test_tracestate_included_traceparent_included",
        .doc = "valid traceparent + tracestate -> both inherited",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo=1,bar=2" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .exact = "foo=1,bar=2" },
    },
    .{
        .source_test = "test_tracestate_header_name",
        .doc = "wrong header name 'trace-state' -> tracestate not recognized, dropped",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "trace-state", .value = "foo=1" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .absent,
    },
    .{
        .source_test = "test_tracestate_header_name",
        .doc = "wrong header name 'trace.state' -> tracestate not recognized, dropped",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "trace.state", .value = "foo=1" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .absent,
    },
    .{
        .source_test = "test_tracestate_header_name_valid_casing",
        .doc = "'TraceState' casing -> recognized, inherited",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "TraceState", .value = "foo=1" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .exact = "foo=1" },
    },
    .{
        .source_test = "test_tracestate_header_name_valid_casing",
        .doc = "'TrAcEsTaTe' mixed casing -> recognized, inherited",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "TrAcEsTaTe", .value = "foo=1" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .exact = "foo=1" },
    },
    .{
        .source_test = "test_tracestate_empty_header",
        .doc = "a single empty tracestate header -> discarded (empty string fails the non-empty guard)",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .absent,
    },
    .{
        .source_test = "test_tracestate_empty_header",
        .doc = "'foo=1' then an empty instance -> combined has a trailing comma but 'foo=1' survives",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo=1" },
            .{ .name = "tracestate", .value = "" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .contains = &.{"foo=1"} },
    },
    .{
        .source_test = "test_tracestate_empty_header",
        .doc = "an empty instance then 'foo=1' -> combined has a leading comma but 'foo=1' survives",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "" },
            .{ .name = "tracestate", .value = "foo=1" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .contains = &.{"foo=1"} },
    },
    .{
        .source_test = "test_tracestate_multiple_headers_different_keys",
        .doc = "three tracestate header instances with disjoint keys -> combined, comma-joined, IN WIRE ORDER (the change under teeth-check #2)",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo=1,bar=2" },
            .{ .name = "tracestate", .value = "rojo=1,congo=2" },
            .{ .name = "tracestate", .value = "baz=3" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .exact = "foo=1,bar=2,rojo=1,congo=2,baz=3" },
    },
    .{
        .source_test = "test_tracestate_duplicated_keys",
        .doc = "single header 'foo=1,foo=1' -> upstream allows either kept-as-is or deduplicated; this module never dedupes, so exactly 'foo=1,foo=1' survives",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo=1,foo=1" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .exact = "foo=1,foo=1" },
    },
    .{
        .source_test = "test_tracestate_duplicated_keys",
        .doc = "single header 'foo=1,foo=2' -> both values pass through unchanged (no member-level parsing)",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo=1,foo=2" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .exact = "foo=1,foo=2" },
    },
    .{
        .source_test = "test_tracestate_duplicated_keys",
        .doc = "two headers, each 'foo=1' -> combined 'foo=1,foo=1'",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo=1" },
            .{ .name = "tracestate", .value = "foo=1" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .exact = "foo=1,foo=1" },
    },
    .{
        .source_test = "test_tracestate_duplicated_keys",
        .doc = "two headers, 'foo=1' then 'foo=2' -> combined 'foo=1,foo=2'",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo=1" },
            .{ .name = "tracestate", .value = "foo=2" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .exact = "foo=1,foo=2" },
    },
    .{
        .source_test = "test_tracestate_all_allowed_characters",
        .doc = "a key using the full non-vendor keychar set + a value using the full legal value charset -> accepted verbatim",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "abcdefghijklmnopqrstuvwxyz0123456789_-*/=" ++
                " !\"#$%&'()*+-./0123456789:;<>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .contains = &.{"abcdefghijklmnopqrstuvwxyz0123456789_-*/="} },
    },
    .{
        .source_test = "test_tracestate_all_allowed_characters",
        .doc = "same, with an '@'-vendor-tagged key -> accepted verbatim",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "abcdefghijklmnopqrstuvwxyz0123456789_-*/@a-z0-9_-*/=" ++
                " !\"#$%&'()*+-./0123456789:;<>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .contains = &.{"abcdefghijklmnopqrstuvwxyz0123456789_-*/@a-z0-9_-*/="} },
    },
    .{
        .source_test = "test_tracestate_ows_handling",
        .doc = "OWS (space and tab) surrounding commas within one header line -> all three members survive (the change under teeth-check #3)",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo=1 \t , \t bar=2, \t baz=3" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .contains = &.{ "foo=1", "bar=2", "baz=3" } },
        .ordered = true,
    },
    .{
        .source_test = "test_tracestate_ows_handling",
        .doc = "denser OWS mixes (tab-space-tab) around commas -> still survives",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo=1\t \t,\t \tbar=2,\t \tbaz=3" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .contains = &.{ "foo=1", "bar=2", "baz=3" } },
        .ordered = true,
    },
    .{
        .source_test = "test_tracestate_ows_handling",
        .doc = "leading space before the only member -> survives",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = " foo=1" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .contains = &.{"foo=1"} },
    },
    .{
        .source_test = "test_tracestate_ows_handling",
        .doc = "leading tab before the only member -> survives",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "\tfoo=1" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .contains = &.{"foo=1"} },
    },
    .{
        .source_test = "test_tracestate_ows_handling",
        .doc = "trailing space after the only member -> survives",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo=1 " },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .contains = &.{"foo=1"} },
    },
    .{
        .source_test = "test_tracestate_ows_handling",
        .doc = "trailing tab after the only member -> survives",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo=1\t" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .contains = &.{"foo=1"} },
    },
    .{
        .source_test = "test_tracestate_ows_handling",
        .doc = "tab+space on both sides of the only member -> survives",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "\t foo=1 \t" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .{ .contains = &.{"foo=1"} },
    },
    .{
        .source_test = "test_tracestate_key_illegal_characters",
        .doc = "STRICT_LEVEL 2: a key containing a space must be discarded -- requires per-member key-grammar parsing",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo =1" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .absent,
        .out_of_scope = reason_strict_grammar,
    },
    .{
        .source_test = "test_tracestate_key_illegal_characters",
        .doc = "STRICT_LEVEL 2: an uppercase key must be discarded -- requires per-member key-grammar parsing",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "FOO=1" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .absent,
        .out_of_scope = reason_strict_grammar,
    },
    .{
        .source_test = "test_tracestate_key_illegal_characters",
        .doc = "STRICT_LEVEL 2: a dotted key must be discarded -- requires per-member key-grammar parsing",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo.bar=1" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .absent,
        .out_of_scope = reason_strict_grammar,
    },
    .{
        .source_test = "test_tracestate_key_illegal_vendor_format",
        .doc = "STRICT_LEVEL 2: a key starting with '@' must be discarded -- requires per-member key-grammar parsing",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "@foo=1,bar=2" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .absent,
        .out_of_scope = reason_strict_grammar,
    },
    .{
        .source_test = "test_tracestate_member_count_limit",
        .doc = "STRICT_LEVEL 2: 33 list-members must be discarded (32 max) -- requires per-member counting",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "bar01=01,bar02=02,bar03=03,bar04=04,bar05=05,bar06=06,bar07=07,bar08=08,bar09=09,bar10=10" },
            .{ .name = "tracestate", .value = "bar11=11,bar12=12,bar13=13,bar14=14,bar15=15,bar16=16,bar17=17,bar18=18,bar19=19,bar20=20" },
            .{ .name = "tracestate", .value = "bar21=21,bar22=22,bar23=23,bar24=24,bar25=25,bar26=26,bar27=27,bar28=28,bar29=29,bar30=30" },
            .{ .name = "tracestate", .value = "bar31=31,bar32=32,bar33=33" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .absent,
        .out_of_scope = reason_strict_grammar,
    },
    .{
        .source_test = "test_tracestate_key_length_limit",
        .doc = "STRICT_LEVEL 2: a 257-char key must be discarded (256 max) -- requires per-member key-length checking",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo=1" },
            .{ .name = "tracestate", .value = "z" ** 257 ++ "=1" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .absent,
        .out_of_scope = reason_strict_grammar,
    },
    .{
        .source_test = "test_tracestate_value_illegal_characters",
        .doc = "STRICT_LEVEL 2: a value containing a second '=' must be discarded -- requires per-member value-grammar parsing",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo=bar=baz" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .absent,
        .out_of_scope = reason_strict_grammar,
    },
    .{
        .source_test = "test_tracestate_value_illegal_characters",
        .doc = "STRICT_LEVEL 2: an empty value ('foo=,bar=3') must discard the WHOLE header -- requires per-member value-grammar parsing",
        .headers = &.{
            .{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-00" },
            .{ .name = "tracestate", .value = "foo=,bar=3" },
        },
        .traceparent = .{ .preserved = trace_id_a },
        .tracestate = .absent,
        .out_of_scope = reason_strict_grammar,
    },

    // ---- AdvancedTest -------------------------------------------------------

    .{
        .source_test = "test_multiple_requests_with_valid_traceparent",
        .doc = "3 callbacks over one incoming traceparent -> same trace-id, 3 distinct parent-ids",
        .headers = &.{},
        .traceparent = .any_valid,
        .out_of_scope = reason_session_repetition,
    },
    .{
        .source_test = "test_multiple_requests_without_traceparent",
        .doc = "3 callbacks with no incoming traceparent -> 3 distinct parent-ids",
        .headers = &.{},
        .traceparent = .any_valid,
        .out_of_scope = reason_session_repetition,
    },
    .{
        .source_test = "test_multiple_requests_with_illegal_traceparent",
        .doc = "3 callbacks over an all-zero trace-id -> rejected each time, 3 distinct fresh trace/parent-ids",
        .headers = &.{.{ .name = "traceparent", .value = "00-00000000000000000000000000000000-" ++ parent_id_a ++ "-01" }},
        .traceparent = .{ .changed_from = &.{"00000000000000000000000000000000"} },
        .out_of_scope = reason_session_repetition,
    },

    // ---- TraceContext2Test (Level 2, gated by SPEC_LEVEL >= 2 upstream) ----

    .{
        .source_test = "test_propagates_random_flag",
        .doc = "trace-flags bit 1 (random-trace-id) set on a continued trace must remain set",
        .headers = &.{.{ .name = "traceparent", .value = "00-" ++ trace_id_a ++ "-" ++ parent_id_a ++ "-02" }},
        .traceparent = .{ .preserved = trace_id_a },
        .out_of_scope = reason_level2,
    },
};
