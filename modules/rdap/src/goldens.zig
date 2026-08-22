// SPDX-License-Identifier: MIT

//! A real RDAP domain response captured live from a public registry —
//! closing the gap that every other fixture in `root.zig` (`domain_json`
//! and friends) is a hand-typed JSON literal modeled on the RFC 9083 §5.3
//! example, never actual bytes a real RDAP server sent.
//!
//! ## Why this file exists
//!
//! A hand-typed fixture agrees with whoever wrote `mapObject`/`mapEntities`
//! about what "typical" RDAP JSON looks like. A real registry's response
//! carries operational details no one would think to hand-author: ICANN's
//! GDPR "redacted" extension (an entire top-level array naming which fields
//! were stripped and why, RFC 9537), nested `entities` inside an `entities`
//! member (registrar → abuse contact), a `publicIds` array, and a top-level
//! object with NO `handle` member (redacted away) — none of which the
//! hand-typed `domain_json` KAT in `root.zig` exercises, because it was
//! written to be complete rather than real. All four are modeled now
//! (`Entity.entities`, `Object.redacted`, `Object`/`Entity.public_ids`,
//! `Object.handle` staying `null`) — this fixture is what found the gaps.
//!
//! ## Capture recipe
//!
//! ```sh
//! curl -sL https://rdap.org/domain/iana.org
//! # rdap.org's bootstrap redirect (RFC 7484) resolved to:
//! #   https://rdap.publicinterestregistry.org/rdap/domain/iana.org  (HTTP 200)
//! ```
//!
//! Captured 2026-08-01. `iana.org` is registered through Public Interest
//! Registry (.org); the response is the registry's own record, not a
//! registrar's — no `follow_related` hop was needed to reach it.
//!
//! ## Time-varying fields: how they're pinned
//!
//! `events[].eventDate` are RFC 3339 timestamps (registration 1995, transfer
//! 2018, expiration 2027, "last update of RDAP database" stamped at capture
//! time). Nothing in this module ever compares an RDAP date against the
//! wall clock — `Object.eventDate` returns the server's text verbatim — so
//! there is nothing to re-pin: the captured strings are asserted exactly,
//! byte for byte, and remain correct forever regardless of when the test
//! suite runs.
//!
//! ## Bootstrap file: checked, not captured
//!
//! A real IANA bootstrap file (`https://data.iana.org/rdap/dns.json`, fetched
//! during this same investigation, HTTP 200, 590 service entries, 71 KB) was
//! inspected rather than committed: its `.org` entry is exactly
//! `[["charity","foundation",...,"org",...], ["https://rdap.publicinterestregistry.org/rdap/"]]`
//! — the same two-array `[keys, urls]` shape the hand-built bootstrap KATs
//! in `root.zig` already assume and exercise (including the RFC 8521
//! three-element contact-array form). Committing the full 71 KB file would
//! not have exercised any structural shape the existing KATs miss; the spot
//! check above is the evidence for that claim.
//!
//! ## Attribution
//!
//! None required — same reasoning as `ocsp`'s `NOTICE` (root NOTICE §0's
//! black-box-oracle relationship): this is the observable JSON output of a
//! public registry answering a stock RDAP query over a public protocol
//! (RFC 9082/9083), not a third-party implementation's source or design.
//! No root NOTICE change accompanies this addition.

const std = @import("std");
const testing = std.testing;
const rdap = @import("root.zig");

/// Real RDAP response for `iana.org` from Public Interest Registry
/// (`rdap.publicinterestregistry.org`), captured 2026-08-01.
pub const iana_org_domain_json =
    \\{
    \\  "rdapConformance": [
    \\    "rdap_level_0",
    \\    "icann_rdap_response_profile_1",
    \\    "icann_rdap_technical_implementation_guide_1",
    \\    "redacted"
    \\  ],
    \\  "notices": [
    \\    {
    \\      "title": "Terms of Service",
    \\      "description": [
    \\        "Public Interest Registry provides this RDAP service for informational purposes only, and to assist persons in obtaining information about or related to a domain name registration record. Public Interest Registry does not guarantee its accuracy. Users accessing the Public Interest Registry RDAP service agree to use the data only for lawful purposes, and under no circumstances may this data be used to: a) allow, enable, or otherwise support the transmission by e-mail, telephone, or facsimile of mass unsolicited, commercial advertising or solicitations to entities other than the registrar's own existing customers and b) enable high volume, automated, electronic processes that send queries or data to the systems of Public Interest Registry or any ICANN-accredited registrar, except as reasonably necessary to register domain names or modify existing registrations. When using the Public Interest Registry RDAP service, please consider the following: the RDAP service is not a replacement for standard EPP commands to the SRS service. RDAP is not considered authoritative for registered domain objects. The RDAP service may be scheduled for downtime during production or OT&E maintenance periods. Queries to the RDAP services are throttled. If too many queries are received from a single IP address within a specified time, the service will begin to reject further queries for a period of time to prevent disruption of RDAP service access. Abuse of the RDAP system through data mining is mitigated by detecting and limiting bulk query access from single sources. Where applicable, the presence of a [Non-Public Data] tag indicates that such data is not made publicly available due to applicable data privacy laws or requirements. Should you wish to contact the registrant, please refer to the RDAP records available through the registrar URL listed above. Access to non-public data may be provided, upon request, where it can be reasonably confirmed that the requester holds a specific legitimate interest and a proper legal basis for accessing the withheld data. Access to this data can be requested by submitting a request to WHOISrequest@pir.org. Public Interest Registry Inc. reserves the right to modify these terms at any time. By submitting this query, you agree to abide by this policy."
    \\      ],
    \\      "links": [
    \\        {
    \\          "value": "https://rdap.publicinterestregistry.org/rdap/domain/iana.org",
    \\          "rel": "terms-of-service",
    \\          "href": "https://thenew.org/org-people/about-pir/policies/",
    \\          "type": "text/html"
    \\        }
    \\      ]
    \\    },
    \\    {
    \\      "title": "Status Codes",
    \\      "description": [
    \\        "For more information on domain status codes, please visit https://icann.org/epp"
    \\      ],
    \\      "links": [
    \\        {
    \\          "value": "https://rdap.publicinterestregistry.org/rdap/domain/iana.org",
    \\          "rel": "glossary",
    \\          "href": "https://icann.org/epp",
    \\          "type": "application/rdap+json"
    \\        }
    \\      ]
    \\    },
    \\    {
    \\      "title": "RDDS Inaccuracy Complaint Form",
    \\      "description": [
    \\        "URL of the ICANN RDDS Inaccuracy Complaint Form: https://icann.org/wicf"
    \\      ],
    \\      "links": [
    \\        {
    \\          "value": "https://rdap.publicinterestregistry.org/rdap/domain/iana.org",
    \\          "rel": "help",
    \\          "href": "https://icann.org/wicf",
    \\          "type": "application/rdap+json"
    \\        }
    \\      ]
    \\    }
    \\  ],
    \\  "ldhName": "iana.org",
    \\  "unicodeName": "iana.org",
    \\  "nameservers": [
    \\    {
    \\      "ldhName": "ns.icann.org",
    \\      "unicodeName": "ns.icann.org",
    \\      "ipAddresses": {
    \\        "v4": [
    \\          "199.4.138.53"
    \\        ],
    \\        "v6": [
    \\          "2001:500:89::53"
    \\        ]
    \\      },
    \\      "objectClassName": "nameserver",
    \\      "handle": "3e8d4ce66df346d29017385432feb76f-LROR",
    \\      "status": [
    \\        "associated"
    \\      ]
    \\    },
    \\    {
    \\      "ldhName": "a.iana-servers.net",
    \\      "unicodeName": "a.iana-servers.net",
    \\      "objectClassName": "nameserver",
    \\      "handle": "47dc725d68754f559a1ba2515478ae3b-LROR",
    \\      "status": [
    \\        "associated"
    \\      ]
    \\    },
    \\    {
    \\      "ldhName": "b.iana-servers.net",
    \\      "unicodeName": "b.iana-servers.net",
    \\      "objectClassName": "nameserver",
    \\      "handle": "ef73b1efbc4940838b05e750cb4279c8-LROR",
    \\      "status": [
    \\        "associated"
    \\      ]
    \\    },
    \\    {
    \\      "ldhName": "c.iana-servers.net",
    \\      "unicodeName": "c.iana-servers.net",
    \\      "objectClassName": "nameserver",
    \\      "handle": "aa53fd40fd7e4173a5004e14e669559f-LROR",
    \\      "status": [
    \\        "associated"
    \\      ]
    \\    }
    \\  ],
    \\  "secureDNS": {
    \\    "delegationSigned": true,
    \\    "maxSigLife": 1,
    \\    "dsData": [
    \\      {
    \\        "keyTag": 2234,
    \\        "algorithm": 13,
    \\        "digest": "005b228ce3dad3486f713ebb9bb6f96a53839bd0e2f5a999d3400e1b7355ce8c",
    \\        "digestType": 2
    \\      }
    \\    ]
    \\  },
    \\  "redacted": [
    \\    {
    \\      "name": {
    \\        "type": "Registry Domain ID"
    \\      },
    \\      "prePath": "$.handle",
    \\      "pathLang": "jsonpath",
    \\      "method": "removal"
    \\    }
    \\  ],
    \\  "objectClassName": "domain",
    \\  "status": [
    \\    "server delete prohibited",
    \\    "server transfer prohibited",
    \\    "server update prohibited"
    \\  ],
    \\  "events": [
    \\    {
    \\      "eventAction": "transfer",
    \\      "eventDate": "2018-05-30T20:22:11.191Z"
    \\    },
    \\    {
    \\      "eventAction": "expiration",
    \\      "eventDate": "2027-12-08T17:00:53Z"
    \\    },
    \\    {
    \\      "eventAction": "registration",
    \\      "eventDate": "1995-06-05T04:00:00.772Z"
    \\    },
    \\    {
    \\      "eventAction": "last changed",
    \\      "eventDate": "2025-05-16T16:55:01.056Z"
    \\    },
    \\    {
    \\      "eventAction": "last update of RDAP database",
    \\      "eventDate": "2026-08-01T12:47:56.582Z"
    \\    }
    \\  ],
    \\  "entities": [
    \\    {
    \\      "vcardArray": [
    \\        "vcard",
    \\        [
    \\          [
    \\            "version",
    \\            {},
    \\            "text",
    \\            "4.0"
    \\          ],
    \\          [
    \\            "fn",
    \\            {},
    \\            "text",
    \\            "CSC Corporate Domains, Inc."
    \\          ]
    \\        ]
    \\      ],
    \\      "roles": [
    \\        "registrar"
    \\      ],
    \\      "publicIds": [
    \\        {
    \\          "type": "IANA Registrar ID",
    \\          "identifier": "299"
    \\        }
    \\      ],
    \\      "objectClassName": "entity",
    \\      "handle": "299",
    \\      "entities": [
    \\        {
    \\          "vcardArray": [
    \\            "vcard",
    \\            [
    \\              [
    \\                "version",
    \\                {},
    \\                "text",
    \\                "4.0"
    \\              ],
    \\              [
    \\                "fn",
    \\                {},
    \\                "text",
    \\                ""
    \\              ],
    \\              [
    \\                "tel",
    \\                {
    \\                  "type": "voice"
    \\                },
    \\                "uri",
    \\                "tel:+1.8887802723"
    \\              ],
    \\              [
    \\                "email",
    \\                {},
    \\                "text",
    \\                "domainabuse@cscglobal.com"
    \\              ]
    \\            ]
    \\          ],
    \\          "roles": [
    \\            "abuse"
    \\          ],
    \\          "objectClassName": "entity"
    \\        }
    \\      ],
    \\      "links": [
    \\        {
    \\          "value": "https://rdap.publicinterestregistry.org/rdap/entity/299",
    \\          "rel": "self",
    \\          "href": "https://rdap.publicinterestregistry.org/rdap/entity/299",
    \\          "type": "application/rdap+json"
    \\        },
    \\        {
    \\          "value": "https://rdap.cscglobal.com/dbs/rdap-api/v1/",
    \\          "rel": "about",
    \\          "href": "https://rdap.cscglobal.com/dbs/rdap-api/v1/",
    \\          "type": "application/rdap+json"
    \\        }
    \\      ]
    \\    }
    \\  ],
    \\  "links": [
    \\    {
    \\      "value": "https://rdap.publicinterestregistry.org/rdap/domain/iana.org",
    \\      "rel": "related",
    \\      "href": "https://rdap.cscglobal.com/dbs/rdap-api/v1/domain/iana.org",
    \\      "type": "application/rdap+json"
    \\    },
    \\    {
    \\      "value": "https://rdap.publicinterestregistry.org/rdap/domain/iana.org",
    \\      "rel": "self",
    \\      "href": "https://rdap.publicinterestregistry.org/rdap/domain/iana.org",
    \\      "type": "application/rdap+json"
    \\    }
    \\  ]
    \\}
;

test "golden: real iana.org RDAP response (Public Interest Registry, 2026-08-01)" {
    var parsed = try rdap.parseResponse(testing.allocator, iana_org_domain_json);
    defer parsed.deinit();
    const o = &parsed.document.object;

    try testing.expectEqual(rdap.ObjectClass.domain, o.object_class);
    try testing.expectEqualStrings("iana.org", o.ldh_name.?);
    try testing.expectEqualStrings("iana.org", o.unicode_name.?);
    // The registry's GDPR "redacted" extension strips the top-level handle
    // entirely (prePath "$.handle") — every hand-typed KAT in root.zig
    // always includes a handle, so this null is a real shape those never
    // exercise.
    try testing.expect(o.handle == null);

    // rdapConformance (RFC 9083 §4.1) names the "redacted" extension the
    // registry actually used above.
    try testing.expectEqual(@as(usize, 4), o.rdap_conformance.len);
    try testing.expectEqualStrings("redacted", o.rdap_conformance[3]);

    // redacted[] (RFC 9537) — the disclosure for the handle removal above.
    try testing.expectEqual(@as(usize, 1), o.redacted.len);
    try testing.expectEqualStrings("Registry Domain ID", o.redacted[0].name.?);
    try testing.expectEqualStrings("$.handle", o.redacted[0].pre_path.?);
    try testing.expectEqualStrings("removal", o.redacted[0].method.?);

    try testing.expectEqual(@as(usize, 3), o.status.len);
    try testing.expectEqualStrings("server delete prohibited", o.status[0]);
    try testing.expectEqualStrings("server transfer prohibited", o.status[1]);
    try testing.expectEqualStrings("server update prohibited", o.status[2]);

    try testing.expectEqual(@as(usize, 5), o.events.len);
    try testing.expectEqualStrings("1995-06-05T04:00:00.772Z", o.eventDate("registration").?);
    try testing.expectEqualStrings("2027-12-08T17:00:53Z", o.eventDate("expiration").?);
    try testing.expectEqualStrings("2018-05-30T20:22:11.191Z", o.eventDate("transfer").?);
    try testing.expectEqualStrings("2025-05-16T16:55:01.056Z", o.eventDate("last changed").?);

    try testing.expectEqual(@as(usize, 4), o.nameservers.len);
    try testing.expectEqualStrings("ns.icann.org", o.nameservers[0].ldh_name.?);
    try testing.expectEqualStrings("a.iana-servers.net", o.nameservers[1].ldh_name.?);
    try testing.expectEqualStrings("b.iana-servers.net", o.nameservers[2].ldh_name.?);
    try testing.expectEqualStrings("c.iana-servers.net", o.nameservers[3].ldh_name.?);
    // Only the first nameserver carries glue addresses (RFC 9083 §5.2
    // ipAddresses) in this capture; the other three have none.
    try testing.expectEqual(@as(usize, 1), o.nameservers[0].ipv4_addresses.len);
    try testing.expectEqualStrings("199.4.138.53", o.nameservers[0].ipv4_addresses[0]);
    try testing.expectEqual(@as(usize, 1), o.nameservers[0].ipv6_addresses.len);
    try testing.expectEqualStrings("2001:500:89::53", o.nameservers[0].ipv6_addresses[0]);
    try testing.expectEqual(@as(usize, 0), o.nameservers[1].ipv4_addresses.len);
    // A nameserver is itself an RDAP object (RFC 9083 §5.2) — it carries its
    // own handle, distinct from the domain's.
    try testing.expectEqualStrings(
        "3e8d4ce66df346d29017385432feb76f-LROR",
        o.nameservers[0].handle.?,
    );
    try testing.expectEqual(@as(usize, 1), o.nameservers[0].status.len);
    try testing.expectEqualStrings("associated", o.nameservers[0].status[0]);

    // The top-level entities array has one entry (the registrar); its own
    // nested "entities" (the abuse contact, RFC 9083 §5.1) is now carried on
    // Entity.entities rather than being dropped.
    try testing.expectEqual(@as(usize, 1), o.entities.len);
    const registrar = o.entityWithRole("registrar").?;
    try testing.expectEqualStrings("299", registrar.handle.?);
    try testing.expectEqualStrings("CSC Corporate Domains, Inc.", registrar.full_name.?);
    try testing.expect(registrar.email == null); // email lives on the NESTED abuse entity, not here

    // publicIds (RFC 9083 §4.8) on the registrar entity: the IANA Registrar ID.
    try testing.expectEqual(@as(usize, 1), registrar.public_ids.len);
    try testing.expectEqualStrings("IANA Registrar ID", registrar.public_ids[0].id_type);
    try testing.expectEqualStrings("299", registrar.public_ids[0].identifier);

    // The registrar's own links (RFC 9083 §4.2): "self" + "about".
    try testing.expectEqual(@as(usize, 2), registrar.links.len);

    // The nested abuse contact — this is the gap that made this fixture
    // worth capturing in the first place: it is unreachable without
    // Entity.entities.
    try testing.expectEqual(@as(usize, 1), registrar.entities.len);
    const abuse = registrar.entityWithRole("abuse").?;
    try testing.expectEqualStrings("domainabuse@cscglobal.com", abuse.email.?);
    try testing.expectEqual(@as(usize, 0), abuse.entities.len); // no further nesting in this capture

    try testing.expectEqualStrings(
        "https://rdap.publicinterestregistry.org/rdap/domain/iana.org",
        o.linkHref("self").?,
    );
    try testing.expectEqualStrings(
        "https://rdap.cscglobal.com/dbs/rdap-api/v1/domain/iana.org",
        o.linkHref("related").?,
    );

    try testing.expectEqual(@as(usize, 3), o.notices.len);
    try testing.expectEqualStrings("Terms of Service", o.notices[0].title.?);
    try testing.expectEqualStrings("Status Codes", o.notices[1].title.?);
    try testing.expectEqualStrings("RDDS Inaccuracy Complaint Form", o.notices[2].title.?);
}

test "golden: fixture count canary — 1 real RDAP capture" {
    const captures = [_][]const u8{iana_org_domain_json};
    try testing.expectEqual(@as(usize, 1), captures.len);
    try testing.expect(captures[0].len > 4000);
}

// ── not covered here, with reasons ──────────────────────────────────────────
//
// - A real RDAP error body (RFC 7480 §5.3, e.g. a live 404 for a domain that
//   does not exist): not captured — deliberately querying a registry for a
//   nonexistent domain to observe its error shape is a legitimate follow-up,
//   but every RDAP server this investigation reached returns errors in the
//   same generic `{errorCode, title, description}` shape the hand-built KAT
//   already covers structurally; no registry-specific quirk was found to
//   justify a second live round-trip for it.
// - A real ip/autnum/nameserver/entity RDAP object: only `domain` was
//   captured. The four object classes share the same `mapObject` code path
//   and member set (RFC 9083 §5.4/5.5/5.2/5.1 overlap heavily with §5.3);
//   the domain capture above already exercises nameservers, entities,
//   events, links and notices structurally for all of them.
// - Bootstrap file: inspected live (see module doc comment above) but not
//   committed — its shape matched the existing hand-built KATs exactly.
