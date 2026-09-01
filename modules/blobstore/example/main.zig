// SPDX-License-Identifier: MIT

//! What a consumer validates BEFORE ever opening a `blobstore.Store`: a batch
//! manifest of objects to ingest, each naming a `(namespace, key)` pair for
//! the raw/named layers and (for content-addressed entries) the SHA-256 the
//! uploader claims for the bytes. Rejecting a bad manifest entry here is
//! cheap and offline; discovering it inside `casCommit`/`putNamed` would mean
//! it already touched disk.
//!
//! `Store` itself is out of reach for an in-memory example: every non-trivial
//! method (`init`, `put`, `casCommit`, `putNamed`, `gc`, ...) takes a live
//! `std.Io` and calls straight through to `std.Io.Dir.cwd()` — there is no
//! injectable in-memory filesystem seam (unlike `writebehind`'s `SimStorage`
//! or `kv`'s `SimStorage`). This example is deliberately confined to the
//! parts of the public API that need no I/O at all: `Digest` and
//! `segmentSafe`. See the note at the bottom of this file.
//!
//! Built against the PUBLISHED module (`@import("blobstore")`), plus the
//! `hashdigest` dependency it declares (a real manifest validator needs the
//! same hash the store will recompute on `put`).

const std = @import("std");
const blobstore = @import("blobstore");
const hashdigest = @import("hashdigest");

const ManifestEntry = struct {
    ns: []const u8,
    key: []const u8,
    content: []const u8,
    /// The digest the uploader claims for `content` — checked against a
    /// freshly computed one, the same way `Store.put` would catch a
    /// mismatch, but before any bytes reach a temp file.
    claimed_digest_hex: []const u8,
};

pub fn main() !void {
    const manifest = [_]ManifestEntry{
        .{ .ns = "reports", .key = "2026-08-quarterly.pdf", .content = "quarterly numbers", .claimed_digest_hex = &hashdigest.sha256HexBuf("quarterly numbers") },
        .{ .ns = "reports", .key = "../escape", .content = "x", .claimed_digest_hex = &hashdigest.sha256HexBuf("x") }, // path traversal
        .{ .ns = "reports", .key = "tampered.bin", .content = "real bytes", .claimed_digest_hex = "0" ** 64 }, // wrong digest
    };

    var accepted: usize = 0;
    for (manifest) |e| {
        // 1. `ns`/`key` must be single, safe path segments. Every `Store`
        //    entry point that takes a segment runs this same check before
        //    touching disk -- and as of 2026-09-01 that really is every one
        //    of them: `scratchCreate` used to interpolate its name unchecked,
        //    and the five raw-hex CAS functions took `hex` verbatim, so
        //    `casDelete("../victim")` wrote a sidecar outside the store.
        //    Checking here anyway is still the right shape for a caller: it
        //    rejects the entry by name instead of discovering it at the
        //    filesystem.
        if (!blobstore.segmentSafe(e.ns) or !blobstore.segmentSafe(e.key)) {
            std.debug.print("reject {s}/{s}: unsafe path segment\n", .{ e.ns, e.key });
            continue;
        }

        // 2. The claimed digest must both PARSE (`Digest.fromHex` rejects a
        //    wrong length or non-hex byte without panicking) and MATCH the
        //    content's actual SHA-256.
        const claimed = blobstore.Digest.fromHex(e.claimed_digest_hex) catch {
            std.debug.print("reject {s}/{s}: malformed digest\n", .{ e.ns, e.key });
            continue;
        };
        var actual: blobstore.Digest = .{ .hex = hashdigest.sha256HexBuf(e.content) };
        if (!std.mem.eql(u8, claimed.slice(), actual.slice())) {
            std.debug.print("reject {s}/{s}: digest mismatch (claimed {s}, actual {s})\n", .{
                e.ns, e.key, claimed.slice(), actual.slice(),
            });
            continue;
        }

        accepted += 1;
        std.debug.print("accept {s}/{s}: digest {s}\n", .{ e.ns, e.key, actual.slice() });
    }

    std.debug.print("{d}/{d} manifest entries accepted\n", .{ accepted, manifest.len });
}

// `Store.init`/`put`/`casCommit`/`putNamed`/`gc` all take a `std.Io` and go
// straight to `std.Io.Dir.cwd()` -- there is no in-memory `Io`/filesystem
// double this module offers (contrast `writebehind`, whose WAL storage and
// sink both have a `Sim`/`Map` in-memory implementation reachable from
// outside). An example that actually stores a blob would have to touch a
// real directory, which is out of scope here (see the task's I/O rule) --
// so the CAS/raw/named store, `gc`, and the cross-process ingest lock are
// untested by any example, only by the module's own on-disk test suite.
