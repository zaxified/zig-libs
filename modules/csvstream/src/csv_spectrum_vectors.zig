// SPDX-License-Identifier: MIT
//! Generated vector list over the vendored maxogden/csv-spectrum corpus (see
//! ../NOTICE for provenance). One entry per `csvs/<name>.csv` +
//! `json/<name>.json` pair, matched by basename -- that pairing convention is
//! taken from the corpus's own `index.js` (`path.basename(csvs[i].name,
//! path.extname(csvs[i].name))`), not assumed. DO NOT hand-edit `csv`/`json`
//! -- regenerate from testdata/csv-spectrum/ if the corpus is ever re-vendored.
//!
//! `out_of_scope`, when non-null, names why a case cannot be asserted -- one
//! case, a defect in the corpus fixture pair itself. (The three multi-line
//! cases were out of scope too until `.span` mode existed; they are now
//! `needs_span`.) These entries are NOT
//! asserted against the expected JSON by csv_spectrum_test.zig, but they ARE
//! counted, so silently dropping one changes a checked total instead of
//! vanishing quietly.

pub const Vector = struct {
    name: []const u8,
    csv: []const u8,
    json: []const u8,
    out_of_scope: ?[]const u8 = null,
    /// The fixture has a quoted field spanning a newline: it is asserted
    /// only in `.span` mode (`QuotedNewlines.span`). The default
    /// `.end_record` mode reads it differently by design — SPEC.md
    /// "Deliberate RFC 4180 deviation".
    needs_span: bool = false,
};

pub const vectors = [_]Vector{
    .{
        .name = "comma_in_quotes",
        .csv = @embedFile("testdata/csv-spectrum/csvs/comma_in_quotes.csv"),
        .json = @embedFile("testdata/csv-spectrum/json/comma_in_quotes.json"),
    },
    .{
        .name = "empty",
        .csv = @embedFile("testdata/csv-spectrum/csvs/empty.csv"),
        .json = @embedFile("testdata/csv-spectrum/json/empty.json"),
    },
    .{
        .name = "empty_crlf",
        .csv = @embedFile("testdata/csv-spectrum/csvs/empty_crlf.csv"),
        .json = @embedFile("testdata/csv-spectrum/json/empty_crlf.json"),
    },
    .{
        .name = "escaped_quotes",
        .csv = @embedFile("testdata/csv-spectrum/csvs/escaped_quotes.csv"),
        .json = @embedFile("testdata/csv-spectrum/json/escaped_quotes.json"),
    },
    .{
        .name = "json",
        .csv = @embedFile("testdata/csv-spectrum/csvs/json.csv"),
        .json = @embedFile("testdata/csv-spectrum/json/json.json"),
    },
    .{
        .name = "location_coordinates",
        .csv = @embedFile("testdata/csv-spectrum/csvs/location_coordinates.csv"),
        .json = @embedFile("testdata/csv-spectrum/json/location_coordinates.json"),
        .out_of_scope = "the corpus fixture pair itself is internally inconsistent: " ++
            "json/location_coordinates.json's phone number (\"1234567890\") " ++
            "does not match its own csvs/location_coordinates.csv row " ++
            "(\"2095257564\"), and its JSON is a bare object -- every other " ++
            "fixture in this corpus is an array of row-objects. This is a " ++
            "defect in the corpus's own oracle for this one case, not a " ++
            "signal about this parser, so it cannot be asserted against.",
    },
    .{
        .name = "newlines",
        .csv = @embedFile("testdata/csv-spectrum/csvs/newlines.csv"),
        .json = @embedFile("testdata/csv-spectrum/json/newlines.json"),
        .needs_span = true,
    },
    .{
        .name = "newlines_crlf",
        .csv = @embedFile("testdata/csv-spectrum/csvs/newlines_crlf.csv"),
        .json = @embedFile("testdata/csv-spectrum/json/newlines_crlf.json"),
        .needs_span = true,
    },
    .{
        .name = "quotes_and_newlines",
        .csv = @embedFile("testdata/csv-spectrum/csvs/quotes_and_newlines.csv"),
        .json = @embedFile("testdata/csv-spectrum/json/quotes_and_newlines.json"),
        .needs_span = true,
    },
    .{
        .name = "simple",
        .csv = @embedFile("testdata/csv-spectrum/csvs/simple.csv"),
        .json = @embedFile("testdata/csv-spectrum/json/simple.json"),
    },
    .{
        .name = "simple_crlf",
        .csv = @embedFile("testdata/csv-spectrum/csvs/simple_crlf.csv"),
        .json = @embedFile("testdata/csv-spectrum/json/simple_crlf.json"),
    },
    .{
        .name = "utf8",
        .csv = @embedFile("testdata/csv-spectrum/csvs/utf8.csv"),
        .json = @embedFile("testdata/csv-spectrum/json/utf8.json"),
    },
};
