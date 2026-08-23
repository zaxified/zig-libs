// SPDX-License-Identifier: MIT

//! What a TLS server's OCSP-stapling path does with `ocsp`: build a real
//! `OCSPRequest` for a real certificate pair and check it is byte-identical
//! to what `openssl ocsp` itself sent for the same pair, then parse and
//! cryptographically VERIFY two real, `openssl ocsp`-signed responses — one
//! `good`, one `revoked` with a reason code — and see a bit-flipped copy of
//! the good response rejected by name. External judge: `openssl` (a
//! genuinely independent OCSP implementation), run entirely offline —
//! `openssl ocsp` itself printed "Response verify OK" for both responses
//! below before this module ever saw the bytes.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling.
//!
//! ## Fixture provenance
//!
//! All key material below is THROWAWAY, generated for this example only,
//! private keys discarded once the fixtures were produced. Exact recipe
//! (openssl 3.5.5, run entirely offline, no network):
//!
//! ```sh
//! # 1. A throwaway CA (self-signed, RSA-2048/SHA-256).
//! openssl genrsa -out ca.key 2048
//! openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
//!     -out ca.pem -subj "/CN=zig-libs test CA"
//!
//! # 2. Two leaf certs issued by that CA via a minimal file-backed CA
//! #    database (index.txt/serial/newcerts), one to stay good, one to
//! #    revoke.
//! openssl genrsa -out good.key 2048
//! openssl req -new -key good.key -out good.csr -subj "/CN=good.example"
//! openssl genrsa -out revoked.key 2048
//! openssl req -new -key revoked.key -out revoked.csr -subj "/CN=revoked.example"
//! openssl ca -config openssl.cnf -in good.csr -out good.pem -batch -extensions v3_ee
//! openssl ca -config openssl.cnf -in revoked.csr -out revoked.pem -batch -extensions v3_ee
//! openssl ca -config openssl.cnf -revoke revoked.pem -crl_reason keyCompromise -batch
//!
//! # 3. A real DER OCSPRequest for the good cert (SHA-1 CertID, the
//! #    profile's classic default -- also this module's buildRequest
//! #    default) -- this is the exact request `good_req_hex` below embeds,
//! #    and what buildRequest is checked to reproduce byte-for-byte.
//! openssl ocsp -issuer ca.pem -cert good.pem -reqout good_req.der -no_nonce
//!
//! # 4. Real, offline-signed OCSPResponses, using -index/-CA/-rsigner/-rkey
//! #    file mode (a direct responder: the CA itself signs, no delegate
//! #    cert -- resp_no_certs keeps the fixture minimal). Direct issuer
//! #    signing was picked so the `certs` field can stay empty (the module's
//! #    "authorized by issuer name/key directly" path); the delegated-
//! #    responder path is already covered by this module's own hermetic test
//! #    suite (`ocsp_test.zig`).
//! openssl ocsp -index index.txt -CA ca.pem -rsigner ca.pem -rkey ca.key \
//!     -reqin good_req.der -respout good_resp.der \
//!     -no_nonce -resp_no_certs -ndays 30
//! openssl ocsp -index index.txt -CA ca.pem -rsigner ca.pem -rkey ca.key \
//!     -reqin revoked_req.der -respout revoked_resp.der \
//!     -no_nonce -resp_no_certs -ndays 30
//!
//! # 5. Independent verification BEFORE this module ever saw the bytes:
//! openssl ocsp -respin good_resp.der -CAfile ca.pem -verify_other ca.pem -no_nonce
//! openssl ocsp -respin revoked_resp.der -CAfile ca.pem -verify_other ca.pem -no_nonce
//! # both printed: "Response verify OK"
//! ```
//!
//! `thisUpdate`/`nextUpdate` on both real responses are 2026-08-23T06:44:40Z
//! / 2026-09-22T06:44:40Z (independently computed via
//! `date -u -d '<RFC-3339>' +%s`, never this module's own time parser);
//! `now_unix` below is pinned inside that window so this example never goes
//! stale as wall-clock time passes. The revoked response's `revocationTime`
//! is 2026-08-23T06:44:17Z, reason `keyCompromise` (CRLReason 1).

const std = @import("std");
const ocsp = @import("ocsp");

/// Decode a comptime hex literal into a fixed-size byte array — the local
/// idiom this repo's other modules use for embedding binary fixtures
/// (`aeskw`/`bitcoinscript`/`dnp3`'s own `hexToBytes` helpers).
fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(1 << 16);
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// ── the throwaway CA + the two leaf certs it issued ─────────────────────
const ca_der = hexToBytes("30820317308201ffa00302010202145bbdfaff31b430c602c6321f5a361890255412c4300d06092a864886f70d01010b0500301b3119301706035504030c107a69672d6c6962732074657374204341301e170d3236303832333036343431305a170d3336303832303036343431305a301b3119301706035504030c107a69672d6c696273207465737420434130820122300d06092a864886f70d01010105000382010f003082010a0282010100d1d869155aa1250a1980b5188b5a19fc1f15603fc2be190beaa821ff17b71922b11443973dded705bffe45917a3dcbd5186ada67be38240e3874473e39cf2b7e78687fc55b3a4f514664c20cd17c2a356d8c1dbaa950e4199b2f9ddb1743dca495c278dd784518c1163a0bc39ece313dbcbed4baec437b4d248c8ec21e1afc907df4e88d57c4d595ccf6dee39c6b68f6aec1731e409275cadfdb7de92e6e64027128bc5a6fa5397b1269ae550df60097f001a5b9819f1f2fa2bc7a5da8ed64b4d8eaf4c05fba37f754fcdd14b90e410b53041a38666a7e4faff8fc2bb9346fcbd4a8a0a8d978b146a0e423d40e65436a2c492098b5644751e8560fee4eaa55190203010001a3533051301d0603551d0e04160414844e02cd8f6fee9ce07a3d642f20d7a4a26d4c7f301f0603551d23041830168014844e02cd8f6fee9ce07a3d642f20d7a4a26d4c7f300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101008c15481a1f591115a48d62faf75e02d93eef431f3018bfcf502b73cdf797f9cdbfd8a1acdeac0662aeaa47777235a88303f94900f0a925ff3c865794436623fa42c3184a67121123abcdd6b33a460af4b316e4c8a3e86c2731c2294cb608084e4f69357fc4a20ed166c1d8ee154ae1688518c11d1594ee43736a10c8cf7ec029fdf5244b1d6ee563727052e9ff7af80fc79438c6d62b91b4378d4dcfd7dc6087689f2d3f39e2d4eaf694189f94a0cd860c8de1c6b2da16b7670fdfb0e1cf1a5c7f393c0710800621305c68f6010e3206ff0c15fc93e29475cc51064862d9a30ec33ef27a0468a89495c5585b9724a1f3a0a208553873e33338973739ddcc841b");

const good_der = hexToBytes("3082031a30820202a0030201020214424216b5e6d847271aa8a884a737234aa7683531300d06092a864886f70d01010b0500301b3119301706035504030c107a69672d6c6962732074657374204341301e170d3236303832333036343431315a170d3336303832303036343431315a30173115301306035504030c0c676f6f642e6578616d706c6530820122300d06092a864886f70d01010105000382010f003082010a0282010100913984ab6aa04314ba365c9bf62af4b267927fb70ac5e4284da2a36ddd6d6f9439b8d2d192d47aa60caab76d7d94bad4ac58a064a6de0075e582ff2d0e729411fdd04ce7953c7bb931d4d7dfef0350e393d94d15d0ca615935bbc40fd605f8907b10fe1593ce1f4513619afce30b59cdf004fcf3d2d12a4fdca983551e8da8c2e65c30b38e5a17dbcec361b46075e49338b0791d71b7af98ca091112b2ae193ea24b0e9c0ec18675e5290f59745f24e01c76fc58a51bbc9537e2a1be67c4154e15e76629dfff45d36c641c186df45cf49f876bd53dfb7ef49f6e4780ed92f5902470053ed02232d76fee7d8d27eb62e318285183b221b02d2dc09ed2fc9ee2db0203010001a35a305830090603551d1304023000300b0603551d0f0404030205a0301d0603551d0e041604142bd0bc96f17298f929928fc0141a50cdecce5d05301f0603551d23041830168014844e02cd8f6fee9ce07a3d642f20d7a4a26d4c7f300d06092a864886f70d01010b0500038201010099cf1dcb3be4d1341b1e9caf1c9fdf2bff529d47d37e638dc6c8960410a627283b6892e2f51d00c13af8f08b1db7893b3c2f8a9d5aa71df11bdcaf57cc4e6729335b799250194d66bc20bf099b21f51aaec867f63cbc1674de4a7083c6256fc3098ef69967eb52c1c9616b4d41493fed367ba27f95968449e07c858d72406db984d0f457a1215102ded023fa7ce911bc14134218307318ad41dc65dedcde6202da8d0a84be71787b0d8a90dd3413ddb684bc3e6b57afca589ee94d19bf877545590926675ed7b783dfd344383283097afdc5162de79cef528dda3c7f4a3ed4d000a35688f17b1d80549229086174530d3dd01fe5a02d73cfd649b128b167cd9b");

const revoked_der = hexToBytes("3082031d30820205a0030201020214254869001a7fea89ca41a43244346ab450e0ed94300d06092a864886f70d01010b0500301b3119301706035504030c107a69672d6c6962732074657374204341301e170d3236303832333036343431315a170d3336303832303036343431315a301a3118301606035504030c0f7265766f6b65642e6578616d706c6530820122300d06092a864886f70d01010105000382010f003082010a02820101009f5f7741a1be05ec91774adb53e104b6a85a762b9906ca75d80fe001c792136da051ca9dd5f976525d4ed48c700d1bb6920a0cd140639617e955408495446c38342f204622bc663076d9e1d19cec0fcc82cf3f3491c835367779c44b18cc89f6344497559612e280b7832608938de40fd3c8c43dbcd1f225426aa9c01ec8dc3e26be3f6140475df2474574a8cc464ed759c1ea445766fc1e38bbee9db510f5d3c7934a04f6a4d98af5f3db3c0f194161db90d3bd6399979b60a31aa7a1d5ddaaecc50edf9d29101c8a8848b5448dc6faaf2497651fca47ce74709fdad42d42bbae692324d0d5866529bf9bd7dd60bfbafea12abbc76102a6cfb14060215edecb0203010001a35a305830090603551d1304023000300b0603551d0f0404030205a0301d0603551d0e04160414cf5326f1ae854b699a7157fdcad05c2d782ea5fe301f0603551d23041830168014844e02cd8f6fee9ce07a3d642f20d7a4a26d4c7f300d06092a864886f70d01010b0500038201010055e0e706643ecdc37e0e7085aedc6051b01d757c855b187ad9e21f8ac0d89218a2f7c4abe563f1d344eb40dbe76289e64fd30f8b12131f0a0f67e0e984552ccf1e7bcef42958d4e0d985d111751aa79dddb91ff900029acde09691dd24129e07a7ccf940303892249c06e6d7978efdc0efbe101fd65b717dcf2924239fdb4040ae80c3c513d812e6781cc4c112dd01b483a4ca4c342a8884db45f78179fc4c0325118abc627cd5fda1f6136c05e7f9b05b3df07f7b8b3f08a432dcff9f1000971d9afd1cc6aeef9ea439a2b5e5fc5e35ae1b6fd0fef0bbd1b78df94b8034bbb3e7eee6a38c072a4105208d9be19b78f03015cf2e8794ace072ea15623e94a60f");

// A real DER OCSPRequest, exactly as `openssl ocsp -issuer ca.pem -cert
// good.pem -reqout good_req.der -no_nonce` produced it — SHA-1 CertID
// (this module's own `buildRequest` default), no nonce.
const good_req_der = hexToBytes("305530533051304f304d300906052b0e03021a050004142dc4e102296fb7d8b58d5decdafced2895509d810414844e02cd8f6fee9ce07a3d642f20d7a4a26d4c7f0214424216b5e6d847271aa8a884a737234aa7683531");

// A real DER OCSPResponse, signed offline by the CA directly (no delegate),
// `Cert Status: good` — see the header comment for the exact `openssl ocsp`
// invocation and openssl's own independent "Response verify OK".
const good_resp_der = hexToBytes("308201de0a0100a08201d7308201d306092b0601050507300101048201c4308201c03081a9a11d301b3119301706035504030c107a69672d6c6962732074657374204341180f32303236303832333036343434305a30773075304d300906052b0e03021a050004142dc4e102296fb7d8b58d5decdafced2895509d810414844e02cd8f6fee9ce07a3d642f20d7a4a26d4c7f0214424216b5e6d847271aa8a884a737234aa76835318000180f32303236303832333036343434305aa011180f32303236303932323036343434305a300d06092a864886f70d01010b0500038201010090705ecc8c4f3a0268927fb57495ed4cfea338f56b90167692c9e759aa2ed9d39e0d78d98e7c1bf7b0cf5c6427a0717c46a331acedf7e7ad788fe18f9968407a302d9f3ccd9a0259815f14499ab605b2e4cd7aab879a43b9578719a9e2aa74d9908fe495c151e654455730539b8c7c4191b485010d71b35da2c556ab02806e13335d4295c1a45e4355d7ec7ff094c6da1cc954dd4b0b9af41b8344e023733838c979a29362d9940292b75fb67b74f54104f5701836d03783e16f8c5cf0c26a6dfbb9c7da2cc6a194268d98d3318984fb78759fba6594bb89b80d4f4cbbceb7e6439f7b26197dcdc44f3f5e04b8a33c4c41ab2e7f9c7e33e05336be15fcd19849");

// A real DER OCSPResponse for the revoked cert, `Cert Status: revoked`,
// `Revocation Reason: keyCompromise (0x1)` — same offline recipe.
const revoked_resp_der = hexToBytes("308201f60a0100a08201ef308201eb06092b0601050507300101048201dc308201d83081c1a11d301b3119301706035504030c107a69672d6c6962732074657374204341180f32303236303832333036343434305a30818e30818b304d300906052b0e03021a050004142dc4e102296fb7d8b58d5decdafced2895509d810414844e02cd8f6fee9ce07a3d642f20d7a4a26d4c7f0214254869001a7fea89ca41a43244346ab450e0ed94a116180f32303236303832333036343431375aa0030a0101180f32303236303832333036343434305aa011180f32303236303932323036343434305a300d06092a864886f70d01010b05000382010100a75a53e1da198fc77a028342e104fd55bf01a922aebe38aeb216050792a7ea1f4cf1f1410b6f1483968ebe0a9795f17cb16cc483c60f0e3d986c69cf46fd33f23bc9d5246c341c68b3fe59cc088a54e7d9fe2c02488d599215a9c166bb0039821c48817d7406de2a4ac06cf606869c22de25540f9fc7010113dba89b77661866de1cf2a105fda300be0ea1b92e6e84cae1c8681fac82ead3b4b6f2e53b3d52dbcf915ecc40894211dc6272e1da89b10423ad041bf723715bf5aba8483c2b01955ceb0a5165793eb332f4db02541423bf9f7c88b5d4c3e2bc16ab622d23c935816aaa8a639f492507bfbd961c577d4c9e30273518c74e2e14f892860b2f7d093c");

// thisUpdate/nextUpdate on both real responses (see header comment for how
// these were independently computed from the responses' own printed text).
const now_unix: i64 = 1787500000; // inside [thisUpdate 1787467480, nextUpdate 1790059480]
const revoked_at_unix: i64 = 1787467457; // the real response's revocationTime

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer if (gpa_state.deinit() == .leak) @panic("leak");
    const gpa = gpa_state.allocator();

    // ── buildRequest: the module's own request, byte-identical to the real
    //    request openssl actually sent for this exact cert pair ──────────
    {
        const req = try ocsp.buildRequest(gpa, &good_der, &ca_der, .{});
        defer gpa.free(req);
        if (!std.mem.eql(u8, req, &good_req_der)) return error.RequestMismatch;
        std.debug.print("buildRequest: byte-identical to openssl ocsp's own -reqout\n", .{});
    }

    // ── buildRequest under allocation failure: an early-return failure
    //    path that DOES allocate (the arena's first request), never
    //    leaking the caller-owned wrapper allocator's accounting ─────────
    {
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
        if (ocsp.buildRequest(failing.allocator(), &good_der, &ca_der, .{})) |bytes| {
            failing.allocator().free(bytes);
            return error.UnexpectedSuccess;
        } else |err| switch (err) {
            error.OutOfMemory => std.debug.print("buildRequest under OOM: OutOfMemory (expected)\n", .{}),
            else => return err,
        }
    }

    // ── a real, openssl-signed GOOD response, parsed and verified ────────
    {
        const resp = try ocsp.parseResponse(&good_resp_der);
        const verdict = try ocsp.verify(resp, &ca_der, &good_der, .{ .now_unix = now_unix });
        if (verdict.status != .good) return error.ExpectedGood;
        if (verdict.delegated) return error.ExpectedDirectResponder;
        std.debug.print("good.example: status=good, responder=direct (openssl-signed)\n", .{});
    }

    // ── a real, openssl-signed REVOKED response, with a reason code ──────
    {
        const resp = try ocsp.parseResponse(&revoked_resp_der);
        const verdict = try ocsp.verify(resp, &ca_der, &revoked_der, .{ .now_unix = now_unix });
        switch (verdict.status) {
            .revoked => |r| {
                if (r.reason != 1) return error.WrongRevocationReason; // CRLReason keyCompromise
                if (r.revocation_time_unix != revoked_at_unix) return error.WrongRevocationTime;
                std.debug.print("revoked.example: status=revoked, reason=keyCompromise(1)\n", .{});
            },
            else => return error.ExpectedRevoked,
        }
    }

    // ── a bit-flipped copy of the real good response: rejected by NAME ───
    // openssl's own responder produced the untampered bytes above ("Response
    // verify OK"); flipping the LAST byte lands inside the RSA signature
    // (the response is well under 256+something bytes, and the signature is
    // the final BIT STRING in the DER), so the DER structure is untouched
    // and only the cryptographic check fails.
    {
        var tampered = good_resp_der;
        tampered[tampered.len - 1] ^= 0xff;
        const resp = try ocsp.parseResponse(&tampered);
        if (ocsp.verify(resp, &ca_der, &good_der, .{ .now_unix = now_unix })) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.SignatureInvalid => std.debug.print("tampered response: SignatureInvalid (expected)\n", .{}),
            else => return err,
        }
    }
}
