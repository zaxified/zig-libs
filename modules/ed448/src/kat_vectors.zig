// SPDX-License-Identifier: MIT
//! Official RFC test vectors for X448 (RFC 7748 §5.2, §6.2) and Ed448/
//! Ed448ph (RFC 8032 §7.4, §7.5). Every vector is hex-encoded exactly as
//! printed in its RFC (whitespace/line-wrapping removed only); see the
//! comment above each one for its precise section. Cross-checked at
//! scaffold time by an independent extraction pass over the RFC text —
//! see `../NOTICE`'s "Verification performed" section.
//!
//! `kat_test.zig` exercises these against `x448.zig`/`ed448.zig`'s
//! public API — all byte-exact green.

const std = @import("std");

/// Decode a hex string into a fixed-size byte array at comptime.
fn hexN(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

pub const x448 = struct {
    pub const ScalarmultVec = struct {
        scalar: [56]u8,
        u: [56]u8,
        output: [56]u8,
    };

    /// RFC 7748 §5.2, "X448:" section, first and second test vectors.
    pub const scalarmult_vectors = [_]ScalarmultVec{
        .{
            .scalar = hexN(56, "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121" ++
                "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"),
            .u = hexN(56, "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9" ++
                "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"),
            .output = hexN(56, "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f" ++
                "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"),
        },
        .{
            .scalar = hexN(56, "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5" ++
                "38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f"),
            .u = hexN(56, "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b" ++
                "165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db"),
            .output = hexN(56, "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7" ++
                "ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"),
        },
    };

    /// RFC 7748 §5.2's iterated test, "For X448: [initial k=u=]
    /// 05000...00", "After one iteration:" — the k=u=5 starting point is
    /// `x448.base_u` itself.
    pub const iterated_1 = hexN(56, "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a" ++
        "4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113");

    /// RFC 7748 §6.2's Diffie-Hellman example.
    pub const dh = struct {
        pub const alice_private = hexN(56, "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d" ++
            "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
        pub const alice_public = hexN(56, "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c" ++
            "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
        pub const bob_private = hexN(56, "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d" ++
            "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
        pub const bob_public = hexN(56, "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430" ++
            "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
        pub const shared = hexN(56, "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b" ++
            "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");
    };
};

pub const ed448 = struct {
    pub const Vec = struct {
        sk: [57]u8,
        pk: [57]u8,
        msg: []const u8,
        ctx: []const u8,
        sig: [114]u8,
    };

    /// RFC 8032 §7.4, the "-----Blank" vector (message length 0 bytes).
    pub const blank = Vec{
        .sk = hexN(57, "6c82a562cb808d10d632be89c8513ebf" ++
            "6c929f34ddfa8c9f63c9960ef6e348a3" ++
            "528c8a3fcc2f044e39a3fc5b94492f8f" ++
            "032e7549a20098f95b"),
        .pk = hexN(57, "5fd7449b59b461fd2ce787ec616ad46a" ++
            "1da1342485a70e1f8a0ea75d80e96778" ++
            "edf124769b46c7061bd6783df1e50f6c" ++
            "d1fa1abeafe8256180"),
        .msg = "",
        .ctx = "",
        .sig = hexN(114, "533a37f6bbe457251f023c0d88f976ae" ++
            "2dfb504a843e34d2074fd823d41a591f" ++
            "2b233f034f628281f2fd7a22ddd47d78" ++
            "28c59bd0a21bfd3980ff0d2028d4b18a" ++
            "9df63e006c5d1c2d345b925d8dc00b41" ++
            "04852db99ac5c7cdda8530a113a0f4db" ++
            "b61149f05a7363268c71d95808ff2e65" ++
            "2600"),
    };

    /// RFC 8032 §7.4, the "-----1 octet" vector.
    pub const one_octet = Vec{
        .sk = hexN(57, "c4eab05d357007c632f3dbb48489924d" ++
            "552b08fe0c353a0d4a1f00acda2c463a" ++
            "fbea67c5e8d2877c5e3bc397a659949e" ++
            "f8021e954e0a12274e"),
        .pk = hexN(57, "43ba28f430cdff456ae531545f7ecd0a" ++
            "c834a55d9358c0372bfa0c6c6798c086" ++
            "6aea01eb00742802b8438ea4cb82169c" ++
            "235160627b4c3a9480"),
        .msg = &[_]u8{0x03},
        .ctx = "",
        .sig = hexN(114, "26b8f91727bd62897af15e41eb43c377" ++
            "efb9c610d48f2335cb0bd0087810f435" ++
            "2541b143c4b981b7e18f62de8ccdf633" ++
            "fc1bf037ab7cd779805e0dbcc0aae1cb" ++
            "cee1afb2e027df36bc04dcecbf154336" ++
            "c19f0af7e0a6472905e799f1953d2a0f" ++
            "f3348ab21aa4adafd1d234441cf807c0" ++
            "3a00"),
    };

    /// RFC 8032 §7.4, the "-----1 octet (with context)" vector — same
    /// key pair and message as `one_octet`, non-empty `CONTEXT`.
    pub const one_octet_with_context = Vec{
        .sk = one_octet.sk,
        .pk = one_octet.pk,
        .msg = &[_]u8{0x03},
        .ctx = "foo",
        .sig = hexN(114, "d4f8f6131770dd46f40867d6fd5d5055" ++
            "de43541f8c5e35abbcd001b32a89f7d2" ++
            "151f7647f11d8ca2ae279fb842d60721" ++
            "7fce6e042f6815ea000c85741de5c8da" ++
            "1144a6a1aba7f96de42505d7a7298524" ++
            "fda538fccbbb754f578c1cad10d54d0d" ++
            "5428407e85dcbc98a49155c13764e66c" ++
            "3c00"),
    };

    const eleven_octets_msg: [11]u8 = hexN(11, "0c3e544074ec63b0265e0c");

    /// RFC 8032 §7.4, the "-----11 octets" vector.
    pub const eleven_octets = Vec{
        .sk = hexN(57, "cd23d24f714274e744343237b93290f5" ++
            "11f6425f98e64459ff203e8985083ffd" ++
            "f60500553abc0e05cd02184bdb89c4cc" ++
            "d67e187951267eb328"),
        .pk = hexN(57, "dcea9e78f35a1bf3499a831b10b86c90" ++
            "aac01cd84b67a0109b55a36e9328b1e3" ++
            "65fce161d71ce7131a543ea4cb5f7e9f" ++
            "1d8b00696447001400"),
        .msg = &eleven_octets_msg,
        .ctx = "",
        .sig = hexN(114, "1f0a8888ce25e8d458a21130879b840a" ++
            "9089d999aaba039eaf3e3afa090a09d3" ++
            "89dba82c4ff2ae8ac5cdfb7c55e94d5d" ++
            "961a29fe0109941e00b8dbdeea6d3b05" ++
            "1068df7254c0cdc129cbe62db2dc957d" ++
            "bb47b51fd3f213fb8698f064774250a5" ++
            "028961c9bf8ffd973fe5d5c206492b14" ++
            "0e00"),
    };

    /// RFC 8032 §7.5, "-----TEST abc" — the canonical Ed448ph vector
    /// (message = ASCII "abc", `PH(x) = SHAKE256(x, 64)`, `phflag = 1`).
    pub const ph_test_abc = Vec{
        .sk = hexN(57, "833fe62409237b9d62ec77587520911e" ++
            "9a759cec1d19755b7da901b96dca3d42" ++
            "ef7822e0d5104127dc05d6dbefde69e3" ++
            "ab2cec7c867c6e2c49"),
        .pk = hexN(57, "259b71c19f83ef77a7abd26524cbdb31" ++
            "61b590a48f7d17de3ee0ba9c52beb743" ++
            "c09428a131d6b1b57303d90d8132c276" ++
            "d5ed3d5d01c0f53880"),
        .msg = "abc",
        .ctx = "",
        .sig = hexN(114, "822f6901f7480f3d5f562c592994d969" ++
            "3602875614483256505600bbc281ae38" ++
            "1f54d6bce2ea911574932f52a4e6cadd" ++
            "78769375ec3ffd1b801a0d9b3f4030cd" ++
            "433964b6457ea39476511214f97469b5" ++
            "7dd32dbc560a9a94d00bff07620464a3" ++
            "ad203df7dc7ce360c3cd3696d9d9fab9" ++
            "0f00"),
    };
};

test "hexN decodes to the expected fixed length (sanity)" {
    try std.testing.expectEqual(@as(usize, 56), x448.scalarmult_vectors[0].scalar.len);
    try std.testing.expectEqual(@as(usize, 57), ed448.blank.sk.len);
    try std.testing.expectEqual(@as(usize, 114), ed448.blank.sig.len);
}
