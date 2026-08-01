// SPDX-License-Identifier: MIT

//! Real WHOIS replies captured live over port 43 from the actual IANA
//! bootstrap server and the actual Verisign `.com` registry — closing the
//! gap that every fixture in `root.zig` (`iana_reply`, `verisign_reply`,
//! `terminal_reply`, the `ScriptedTransport` entries) is hand-typed prose
//! "modeled on the real line conventions", never bytes an actual server
//! sent.
//!
//! ## Why this file exists
//!
//! Hand-typed WHOIS fixtures agree with whoever wrote them about which line
//! conventions matter. A real server's reply carries operational detail no
//! one writes by hand: Verisign's real replies are CRLF-terminated (RFC
//! 3912-conventional but never exercised by the hand-typed fixtures, which
//! are plain `\n` Zig string literals); IANA's real reply for `COM` uses
//! bare `\n`. And — the actual find here — asking the real chain about
//! `example.com` produces a genuine SELF-REFERENTIAL loop: IANA reserves
//! `example.com` for its own use, so Verisign's real reply answers
//! `Registrar WHOIS Server: whois.iana.org` — literally the chain's own
//! root — which `lookup`'s cycle guard must (and does) catch. No hand-typed
//! fixture in `root.zig` models a *real* domain whose registrar happens to
//! be the bootstrap server itself; the closest hand-built test
//! ("two-server cycle stops at the guard") had to invent `a.example` /
//! `b.example` to construct one.
//!
//! ## Capture recipe
//!
//! ```python
//! import socket
//! def query(server, q, port=43, timeout=8):
//!     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
//!     s.connect((server, port)); s.sendall((q + "\r\n").encode())
//!     chunks = []
//!     while True:
//!         d = s.recv(4096)
//!         if not d: break
//!         chunks.append(d)
//!     return b"".join(chunks)
//! query("whois.iana.org", "com")               # -> iana_com_reply
//! query("whois.verisign-grs.com", "domain example.com")  # -> verisign_example_com_reply
//! ```
//!
//! Captured 2026-08-01. Both replies are reproduced byte-for-byte below,
//! including their actual (and actually DIFFERENT) line endings.
//!
//! ## Time-varying fields: how they're pinned
//!
//! Both replies carry real dates (`Updated Date`, `Creation Date`,
//! `Registry Expiry Date`, `>>> Last update of whois database: ... <<<`).
//! `fieldValue` never parses or compares these against the wall clock — it
//! returns the server's text verbatim — so the captured strings are
//! asserted exactly, byte for byte, and stay correct regardless of when
//! this test suite runs. Nothing needed re-pinning.
//!
//! ## Registry-specific text: explicitly not asserted
//!
//! WHOIS has no schema; each registry's boilerplate (Verisign's multi-
//! paragraph "NOTICE"/"TERMS OF USE", IANA's `%`-comment banner, contact
//! addresses, `ds-rdata`/`DNSSEC DS Data` key material, `nserver` glue
//! records) is registry house style, not something any consumer of this
//! module extracts or should rely on — only the keys `fieldValue`/
//! `nextServer` actually define contracts for are asserted below.
//!
//! ## Attribution
//!
//! None required — same reasoning as `ocsp`'s `NOTICE` (root NOTICE §0's
//! black-box-oracle relationship): this is the observable text output of
//! public WHOIS servers answering stock RFC 3912 queries over a public
//! protocol, not a third-party implementation's source or design. No root
//! NOTICE change accompanies this addition.

const std = @import("std");
const testing = std.testing;
const whois = @import("root.zig");

/// Real reply from `whois.iana.org` for query `com`, captured 2026-08-01.
/// Bare `\n` line endings, exactly as sent.
pub const iana_com_reply = "% IANA WHOIS server\n" ++
    "% for more information on IANA, visit http://www.iana.org\n" ++
    "% This query returned 1 object\n" ++
    "\n" ++
    "domain:       COM\n" ++
    "\n" ++
    "organisation: VeriSign Global Registry Services\n" ++
    "address:      12061 Bluemont Way\n" ++
    "address:      Reston VA 20190\n" ++
    "address:      United States of America (the)\n" ++
    "\n" ++
    "contact:      administrative\n" ++
    "name:         Registry Customer Service\n" ++
    "organisation: VeriSign Global Registry Services\n" ++
    "address:      12061 Bluemont Way\n" ++
    "address:      Reston VA 20190\n" ++
    "address:      United States of America (the)\n" ++
    "phone:        +1 703 925-6999\n" ++
    "fax-no:       +1 703 948 3978\n" ++
    "e-mail:       info@verisign-grs.com\n" ++
    "\n" ++
    "contact:      technical\n" ++
    "name:         Registry Customer Service\n" ++
    "organisation: VeriSign Global Registry Services\n" ++
    "address:      12061 Bluemont Way\n" ++
    "address:      Reston VA 20190\n" ++
    "address:      United States of America (the)\n" ++
    "phone:        +1 703 925-6999\n" ++
    "fax-no:       +1 703 948 3978\n" ++
    "e-mail:       info@verisign-grs.com\n" ++
    "\n" ++
    "nserver:      A.GTLD-SERVERS.NET 192.5.6.30 2001:503:a83e:0:0:0:2:30\n" ++
    "nserver:      B.GTLD-SERVERS.NET 192.33.14.30 2001:503:231d:0:0:0:2:30\n" ++
    "nserver:      C.GTLD-SERVERS.NET 192.26.92.30 2001:503:83eb:0:0:0:0:30\n" ++
    "nserver:      D.GTLD-SERVERS.NET 192.31.80.30 2001:500:856e:0:0:0:0:30\n" ++
    "nserver:      E.GTLD-SERVERS.NET 192.12.94.30 2001:502:1ca1:0:0:0:0:30\n" ++
    "nserver:      F.GTLD-SERVERS.NET 192.35.51.30 2001:503:d414:0:0:0:0:30\n" ++
    "nserver:      G.GTLD-SERVERS.NET 192.42.93.30 2001:503:eea3:0:0:0:0:30\n" ++
    "nserver:      H.GTLD-SERVERS.NET 192.54.112.30 2001:502:8cc:0:0:0:0:30\n" ++
    "nserver:      I.GTLD-SERVERS.NET 192.43.172.30 2001:503:39c1:0:0:0:0:30\n" ++
    "nserver:      J.GTLD-SERVERS.NET 192.48.79.30 2001:502:7094:0:0:0:0:30\n" ++
    "nserver:      K.GTLD-SERVERS.NET 192.52.178.30 2001:503:d2d:0:0:0:0:30\n" ++
    "nserver:      L.GTLD-SERVERS.NET 192.41.162.30 2001:500:d937:0:0:0:0:30\n" ++
    "nserver:      M.GTLD-SERVERS.NET 192.55.83.30 2001:501:b1f9:0:0:0:0:30\n" ++
    "ds-rdata:     19718 13 2 8acbb0cd28f41250a80a491389424d341522d946b0da0c0291f2d3d771d7805a\n" ++
    "\n" ++
    "whois:        whois.verisign-grs.com\n" ++
    "\n" ++
    "status:       ACTIVE\n" ++
    "remarks:      Registration information: http://www.verisigninc.com\n" ++
    "\n" ++
    "created:      1985-01-01\n" ++
    "changed:      2026-03-10\n" ++
    "source:       IANA\n" ++
    "\n";

/// Real reply from `whois.verisign-grs.com` for query `domain example.com`,
/// captured 2026-08-01. CRLF line endings, exactly as sent (RFC
/// 3912-conventional; contrast `iana_com_reply`'s bare `\n`).
pub const verisign_example_com_reply = "   Domain Name: EXAMPLE.COM\r\n" ++
    "   Registry Domain ID: 2336799_DOMAIN_COM-VRSN\r\n" ++
    "   Registrar WHOIS Server: whois.iana.org\r\n" ++
    "   Registrar URL: http://res-dom.iana.org\r\n" ++
    "   Updated Date: 2026-01-16T18:26:50Z\r\n" ++
    "   Creation Date: 1995-08-14T04:00:00Z\r\n" ++
    "   Registry Expiry Date: 2026-08-13T04:00:00Z\r\n" ++
    "   Registrar: RESERVED-Internet Assigned Numbers Authority\r\n" ++
    "   Registrar IANA ID: 376\r\n" ++
    "   Registrar Abuse Contact Email:\r\n" ++
    "   Registrar Abuse Contact Phone:\r\n" ++
    "   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\r\n" ++
    "   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\r\n" ++
    "   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\r\n" ++
    "   Name Server: ELLIOTT.NS.CLOUDFLARE.COM\r\n" ++
    "   Name Server: HERA.NS.CLOUDFLARE.COM\r\n" ++
    "   DNSSEC: signedDelegation\r\n" ++
    "   DNSSEC DS Data: 2371 13 2 C988EC423E3880EB8DD8A46FE06CA230EE23F35B578D64E78B29C3E1C83D245A\r\n" ++
    "   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\r\n" ++
    ">>> Last update of whois database: 2026-08-01T12:51:17Z <<<\r\n" ++
    "\r\n" ++
    "For more information on Whois status codes, please visit https://icann.org/epp\r\n" ++
    "\r\n" ++
    "NOTICE: The expiration date displayed in this record is the date the\r\n" ++
    "registrar's sponsorship of the domain name registration in the registry is\r\n" ++
    "currently set to expire. This date does not necessarily reflect the expiration\r\n" ++
    "date of the domain name registrant's agreement with the sponsoring\r\n" ++
    "registrar.  Users may consult the sponsoring registrar's Whois database to\r\n" ++
    "view the registrar's reported date of expiration for this registration.\r\n" ++
    "\r\n" ++
    "TERMS OF USE: You are not authorized to access or query our Whois\r\n" ++
    "database through the use of electronic processes that are high-volume and\r\n" ++
    "automated except as reasonably necessary to register domain names or\r\n" ++
    "modify existing registrations; the Data in VeriSign Global Registry\r\n" ++
    "Services' (\"VeriSign\") Whois database is provided by VeriSign for\r\n" ++
    "information purposes only, and to assist persons in obtaining information\r\n" ++
    "about or related to a domain name registration record. VeriSign does not\r\n" ++
    "guarantee its accuracy. By submitting a Whois query, you agree to abide\r\n" ++
    "by the following terms of use: You agree that you may use this Data only\r\n" ++
    "for lawful purposes and that under no circumstances will you use this Data\r\n" ++
    "to: (1) allow, enable, or otherwise support the transmission of mass\r\n" ++
    "unsolicited, commercial advertising or solicitations via e-mail, telephone,\r\n" ++
    "or facsimile; or (2) enable high volume, automated, electronic processes\r\n" ++
    "that apply to VeriSign (or its computer systems). The compilation,\r\n" ++
    "repackaging, dissemination or other use of this Data is expressly\r\n" ++
    "prohibited without the prior written consent of VeriSign. You agree not to\r\n" ++
    "use electronic processes that are automated and high-volume to access or\r\n" ++
    "query the Whois database except as reasonably necessary to register\r\n" ++
    "domain names or modify existing registrations. VeriSign reserves the right\r\n" ++
    "to restrict your access to the Whois database in its sole discretion to ensure\r\n" ++
    "operational stability.  VeriSign may restrict or terminate your access to the\r\n" ++
    "Whois database for failure to abide by these terms of use. VeriSign\r\n" ++
    "reserves the right to modify these terms at any time.\r\n" ++
    "\r\n" ++
    "The Registry database contains ONLY .COM, .NET, .EDU domains and\r\n" ++
    "Registrars.\r\n";

// ── tests: assert real, registry-specific content via fieldValue ───────────

test "golden: real IANA `com` reply — key fields" {
    try testing.expectEqualStrings("COM", whois.fieldValue(iana_com_reply, "domain").?);
    try testing.expectEqualStrings(
        "VeriSign Global Registry Services",
        whois.fieldValue(iana_com_reply, "organisation").?,
    );
    try testing.expectEqualStrings(
        "info@verisign-grs.com",
        whois.fieldValue(iana_com_reply, "e-mail").?,
    );
    try testing.expectEqualStrings("ACTIVE", whois.fieldValue(iana_com_reply, "status").?);
    try testing.expectEqualStrings("IANA", whois.fieldValue(iana_com_reply, "source").?);
}

test "golden: real IANA `com` reply — referral extraction" {
    const ref = whois.nextServer(iana_com_reply).?;
    try testing.expectEqualStrings("whois.verisign-grs.com", ref.host);
    try testing.expectEqual(whois.default_port, ref.port);
}

test "golden: real Verisign `example.com` reply — key fields, CRLF intact" {
    // Confirms the capture really is CRLF (distinct from iana_com_reply's
    // bare \n above) and that fieldValue's "\r" trim handles it.
    try testing.expect(std.mem.indexOf(u8, verisign_example_com_reply, "\r\n") != null);

    try testing.expectEqualStrings(
        "2336799_DOMAIN_COM-VRSN",
        whois.fieldValue(verisign_example_com_reply, "Registry Domain ID").?,
    );
    try testing.expectEqualStrings(
        "1995-08-14T04:00:00Z",
        whois.fieldValue(verisign_example_com_reply, "Creation Date").?,
    );
    try testing.expectEqualStrings(
        "2026-08-13T04:00:00Z",
        whois.fieldValue(verisign_example_com_reply, "Registry Expiry Date").?,
    );
    // "Registrar" is a strict prefix of FIVE other real lines in this same
    // reply ("Registrar WHOIS Server", "Registrar URL", "Registrar IANA ID",
    // "Registrar Abuse Contact Email/Phone") — the colon-immediately-after-
    // key boundary check must skip all five and land on the bare
    // "Registrar:" line. No hand-typed fixture in root.zig has more than one
    // same-prefix decoy at once.
    try testing.expectEqualStrings(
        "RESERVED-Internet Assigned Numbers Authority",
        whois.fieldValue(verisign_example_com_reply, "Registrar").?,
    );
    // Empty-value lines (real, not contrived) are correctly treated as absent.
    try testing.expect(whois.fieldValue(verisign_example_com_reply, "Registrar Abuse Contact Email") == null);
}

test "golden: real Verisign `example.com` reply — referral extraction" {
    const ref = whois.nextServer(verisign_example_com_reply).?;
    try testing.expectEqualStrings("whois.iana.org", ref.host);
}

// Scripted transport reusing the exact real captures (offline; no network).
const RealChainTransport = struct {
    fn transport(s: *RealChainTransport) whois.Transport {
        return .{ .ctx = s, .exchangeFn = exchangeFn };
    }

    fn exchangeFn(
        _: *anyopaque,
        server: []const u8,
        _: u16,
        _: []const u8,
        response_buf: []u8,
    ) whois.TransportError!usize {
        const reply = if (std.ascii.eqlIgnoreCase(server, "whois.iana.org"))
            iana_com_reply
        else if (std.ascii.eqlIgnoreCase(server, "whois.verisign-grs.com"))
            verisign_example_com_reply
        else
            return error.TransportFailed;
        if (reply.len > response_buf.len) return error.ResponseTooLarge;
        @memcpy(response_buf[0..reply.len], reply);
        return reply.len;
    }
};

test "golden: full real chain — IANA to Verisign, then a REAL self-referral cycle" {
    // example.com is reserved BY IANA, so the real Verisign registry record
    // names whois.iana.org — the chain's own root — as the registrar WHOIS
    // server. This is not a contrived cycle fixture; it is what querying
    // the real chain for this real domain actually returns.
    var rc: RealChainTransport = .{};
    var buf: [8192]u8 = undefined;
    const result = try whois.lookup(rc.transport(), "example.com", .{}, &buf);

    try testing.expectEqual(@as(usize, 2), result.chain.count);
    try testing.expectEqualStrings("whois.iana.org", result.chain.get(0));
    try testing.expectEqualStrings("whois.verisign-grs.com", result.chain.get(1));
    // The cycle guard stops cleanly (not a depth-cap truncation) because
    // whois.iana.org is already in the chain.
    try testing.expect(!result.truncated);
    try testing.expectEqualStrings(verisign_example_com_reply, result.response);
}

test "golden: fixture count canary — 2 real WHOIS captures (LF + CRLF)" {
    const captures = [_][]const u8{ iana_com_reply, verisign_example_com_reply };
    try testing.expectEqual(@as(usize, 2), captures.len);
    for (captures) |c| try testing.expect(c.len > 0);
}

// ── not covered here, with reasons ──────────────────────────────────────────
//
// - A real terminal (non-referring) registrar reply: not captured — the
//   real chain above happens to terminate on a cycle, not a plain terminal
//   reply, before ever reaching a third (registrar-level) server. The
//   hand-built `terminal_reply` fixture already covers the plain-terminal
//   shape structurally; no real registrar server was queried a third time
//   to avoid an unnecessary extra live round-trip for a shape that isn't
//   this file's point (the cycle is).
// - A real referral via `refer:` or `ReferralServer:` (the two highest-
//   priority keys): not observed live — both real replies captured here
//   happen to use `whois:` (IANA) and `Registrar WHOIS Server:` (Verisign).
//   `refer:`/`ReferralServer:` are ARIN/RIPE conventions; querying those
//   registries was out of scope for closing the `dns`/`rdap`/`whois` anchor
//   gap set and would duplicate the priority-ordering the hand-built
//   `nextServer` KAT already asserts against all four keys.
