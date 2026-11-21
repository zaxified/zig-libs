// SPDX-License-Identifier: MIT
//! RFC 9380 Appendix J.7 vectors for `h2c.zig` (edwards448_XOF:SHAKE256_ELL2_RO_
//! and _NU_): `u`, the mapped point `Q` (the first one for `_RO_`) and the
//! output `P`, five messages per suite. Field elements are big-endian hex as
//! the RFC prints them.

const std = @import("std");
const h2c = @import("h2c.zig");
const field = @import("field.zig");
const ed = @import("ed448.zig");

const Fe = field.Fe;
const testing = std.testing;

const Vector = struct { msg: []const u8, u0: []const u8, u1: []const u8, q0x: []const u8, q0y: []const u8, px: []const u8, py: []const u8 };

fn feHex(s: []const u8) !Fe {
    var be: [field.encoded_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&be, s);
    var le: [field.encoded_bytes]u8 = undefined;
    for (be, 0..) |b, i| le[field.encoded_bytes - 1 - i] = b;
    return Fe.fromBytes(le);
}

fn expectAffine(p: ed.Point, x: []const u8, y: []const u8) !void {
    const zi = try p.z.invert();
    try testing.expect(p.x.mul(zi).eql(try feHex(x)));
    try testing.expect(p.y.mul(zi).eql(try feHex(y)));
}

const ro_vectors = [_]Vector{
    .{ .msg = "", .u0 = "0847c5ebf957d3370b1f98fde499fb3e659996d9fc9b5707176ade785ba72cd84b8a5597c12b1024be5f510fa5ba99642c4cec7f3f69d3e7", .u1 = "f8cbd8a7ae8c8deed071f3ac4b93e7cfcb8f1eac1645d699fd6d3881cb295a5d3006d9449ed7cad412a77a1fe61e84a9e41d59ef384d6f9a", .q0x = "c08177330869db17fb81a5e6e53b36d29086d806269760f2e4cabaa4015f5dbadb7ca2ba594d96a89d0ca4f0944489e1ef393d53db85096f", .q0y = "02e894598c050eeb7195f5791f1a5f65da3776b7534be37640bcbf95d4b915bd22333c50387583507169708fbd7bea0d7aa385dcc614be9c", .px = "73036d4a88949c032f01507005c133884e2f0d81f9a950826245dda9e844fc78186c39daaa7147ead3e462cff60e9c6340b58134480b4d17", .py = "94c1d61b43728e5d784ef4fcb1f38e1075f3aef5e99866911de5a234f1aafdc26b554344742e6ba0420b71b298671bbeb2b7736618634610" },
    .{ .msg = "abc", .u0 = "04d975cd938ab49be3e81703d6a57cca84ed80d2ff6d4756d3f22947fb5b70ab0231f0087cbfb4b7cae73b41b0c9396b356a4831d9a14322", .u1 = "2547ca887ac3db7b5fad3a098aa476e90078afe1358af6c63d677d6edfd2100bc004e0f5db94dd2560fc5b308e223241d00488c9ca6b0ef2", .q0x = "7544612a97f4419c94ab0f621a1ee8ccf46c6657b8e0778ec9718bf4b41bc774487ad87d9b1e617aa49d3a4dd35a3cf57cd390ebf0429952", .q0y = "d3ab703e60267d796b485bb58a28f934bd0133a6d1bbdfeda5277fa293310be262d7f653a5adffa608c37ed45c0e6008e54a16e1a342e4df", .px = "4e0158acacffa545adb818a6ed8e0b870e6abc24dfc1dc45cf9a052e98469275d9ff0c168d6a5ac7ec05b742412ee090581f12aa398f9f8c", .py = "894d3fa437b2d2e28cdc3bfaade035430f350ec5239b6b406b5501da6f6d6210ff26719cad83b63e97ab26a12df6dec851d6bf38e294af9a" },
    .{ .msg = "abcdef0123456789", .u0 = "10659ce25588db4e4be6f7c791a79eb21a7f24aaaca76a6ca3b83b80aaf95aa328fe7d569a1ac99f9cd216edf3915d72632f1a8b990e250c", .u1 = "9243e5b6c480683fd533e81f4a778349a309ce00bd163a29eb9fa8dbc8f549242bef33e030db21cffacd408d2c4264b93e476c6a8590e7aa", .q0x = "1457b60c12e00e47ceb3ce64b57e7c3c61636475443d704a8e2b2ab0a5ac7e4b3909435416784e16e19929c653b1bdcd9478a8e5331ca9ae", .q0y = "935d9f75f7a0babbc39c0a1c3b412518ed8a24bc2c4886722fb4b7d4a747af98e4e2528c75221e2dffd3424abb436e10539a74caaafa3ea3", .px = "2c25b4503fadc94b27391933b557abdecc601c13ed51c5de68389484f93dbd6c22e5f962d9babf7a39f39f994312f8ca23344847e1fbf176", .py = "d5e6f5350f430e53a110f5ac7fcc82a96cb865aeca982029522d32601e41c042a9dfbdfbefa2b0bdcdc3bc58cca8a7cd546803083d3a8548" },
    .{ .msg = "q128_" ++ @as([128]u8, @splat('q')), .u0 = "c80390020e578f009ead417029eff6cd0926110922db63ab98395e3bdfdd5d8a65b1a2b8d495dc8c5e59b7f3518731f7dfc0f93ace5dee4b", .u1 = "1c4dc6653a445bbef2add81d8e90a6c8591a788deb91d0d3f1519a2e4a460313041b77c1b0817f2e80b388e5c3e49f37d787dc1f85e4324a", .q0x = "9d355251e245e4b13ed4ea3e5a3c55bf9b7211f1704771f2e1d8f1a65610c468b1cf70c6c2ce30dcaad54ad9e5439471ec554b862ec8875a", .q0y = "6689ba36a242af69ac2aadb955d15e982d9b04f5d77f7609ebf7429587feb7e5ce27490b9c72114509f89565122074e46a614d7fd7c800bd", .px = "a1861a9464ae31249a0e60bf38791f3663049a3f5378998499a83292e159a2fecff838eb9bc6939e5c6ae76eb074ad4aae39b55b72ca0b9a", .py = "580a2798c5b904f8adfec5bd29fb49b4633cd9f8c2935eb4a0f12e5dfa0285680880296bb729c6405337525fb5ed3dff930c137314f60401" },
    .{ .msg = "a512_" ++ @as([512]u8, @splat('a')), .u0 = "163c79ab0210a4b5e4f44fb19437ea965bf5431ab233ef16606f0b03c5f16a3feb7d46a5a675ce8f606e9c2bf74ee5336c54a1e54919f13f", .u1 = "f99666bde4995c4088333d6c2734687e815f80a99c6da02c47df4b51f6c9d9ed466b4fecf7d9884990a8e0d0be6907fa437e0b1a27f49265", .q0x = "d1a5eba4a332514b69760948af09ceaeddbbb9fd4cb1f19b78349c2ee4cf9ee86dbcf9064659a4a0566fe9c34d90aec86f0801edc131ad9b", .q0y = "5d0a75a3014c3269c33b1b5da80706a4f097893461df286353484d8031cd607c98edc2a846c77a841f057c7251eb45077853c7b205957e52", .px = "987c5ac19dd4b47835466a50b2d9feba7c8491b8885a04edf577e15a9f2c98b203ec2cd3e5390b3d20bba0fa6fc3eecefb5029a317234401", .py = "5e273fcfff6b007bb6771e90509275a71ff1480c459ded26fc7b10664db0a68aaa98bc7ecb07e49cf05b80ae5ac653fbdd14276bbd35ccbc" },
};

const nu_vectors = [_]Vector{
    .{ .msg = "", .u0 = "1368aefc0416867ea2cfc515416bcbeecc9ec81c4ecbd52ccdb91e06996b3f359bc930eef6743c7a2dd7adb785bc7093ed044efed95086d7", .u1 = "", .q0x = "4b2abf8c0fca49d027c2a81bf73bb5990e05f3e76c7ba137cc0b89415ccd55ce7f191cc0c11b0560c1cdc2a8085dd56996079e05a3cd8dde", .q0y = "82532f5b0cb3bfb8542d3228d055bfe61129dbeae8bace80cf61f17725e8ec8226a24f0e687f78f01da88e3b2715194a03dca7c0a96bbf04", .px = "eb5a1fc376fd73230af2de0f3374087cc7f279f0460114cf0a6c12d6d044c16de34ec2350c34b26bf110377655ab77936869d085406af71e", .py = "df5dcea6d42e8f494b279a500d09e895d26ac703d75ca6d118e8ca58bf6f608a2a383f292fce1563ff995dce75aede1fdc8e7c0c737ae9ad" },
    .{ .msg = "abc", .u0 = "cda3b0ecfe054c4077007d7300969ec24f4c741300b630ec9188ebab31a5ae0065612ee22d9f793733179ffc2e10c53ca5b539057aafdc2f", .u1 = "", .q0x = "b1ca5bef2f157673a210f56c9b0039db8399e4749585abac64f831f74ed1ec5f591928976c687c06d57686bacb98440e77af878349cdf2d2", .q0y = "5bbfd6a3730d517b03c3cd9e2eed94af12891334ec090e0495c2edc588e9e10b6f63b03a62076808cbcd6da95adfb5af76c136b2d42e0dac", .px = "4623a64bceaba3202df76cd8b6e3daf70164f3fcbda6d6e340f7fab5cdf89140d955f722524f5fe4d968fef6ba2853ff4ea086c2f67d8110", .py = "abaac321a169761a8802ab5b5d10061fec1a83c670ac6bc95954700317ee5f82870120e0e2c5a21b12a0c7ad17ebd343363604c4bcecafd1" },
    .{ .msg = "abcdef0123456789", .u0 = "d36bae98351512c382c7a3e1eba22497574f11fef9867901b1a2700b39fa2cd0d38ed4380387a99162b7ba0240c743f0532ef60d577c413d", .u1 = "", .q0x = "958a51e2f02e0dfd3930709010d5d16f869adb9d8a8f7c01139911d206c20cdb7bfb40ee33ba30536a99f49362fa7633d0f417fc3914fe21", .q0y = "f4307a36ab6612fa97501497f01afa109733ce85875935551c3ca90f0fa7e0097a8640bb7e5dbcc38ab32b23b748790f2261f2c44c3bf3ba", .px = "e9eb562e76db093baa43a31b7edd04ec4aadcef3389a7b9c58a19cf87f8ae3d154e134b6b3ed45847a741e33df51903da681629a4b8bcc2e", .py = "0cf6606927ad7eb15dbc193993bc7e4dda744b311a8ec4274c8f738f74f605934582474c79260f60280fe35bd37d4347e59184cbfa12cbc4" },
    .{ .msg = "q128_" ++ @as([128]u8, @splat('q')), .u0 = "5945744d27122f89da3daf76ab4db9616053df64e25d30ec9a00667ee6710240579c1db8f8ef3386f3f4f413cfb325ac14094d582026a971", .u1 = "", .q0x = "e7e1f2d13548ac2c8fcd346e4c63606545bf93652011721e83ac3b64226f77a8823d3881e164bc6ca45505b236e8e3721c028052fcc9ade5", .q0y = "7e0f340501bf25f018b9d374c2acbdd43c07261d85a6ef3c855113d4e023634db59a87b8fab9efe04ed1fee302c8a4994e83bdda32bd9c0b", .px = "122a3234d34b26c69749f23356452bf9501efa2d94859d5ef741fef024156d9d191a03a2ad24c38186f93e02d05572575968b083d8a39738", .py = "ddf55e74eb4414c2c1fa4aa6bc37c4ab470a3fed6bb5af1e43570309b162fb61879bb15f9ea49c712efd42d0a71666430f9f0d4a20505050" },
    .{ .msg = "a512_" ++ @as([512]u8, @splat('a')), .u0 = "1192e378043f01cedc7ea0209321519213b0184ea0d8575816bcd9182a367823e1eecc2faf1df8f79b24027a4b9bfa208cd320e79bef06ea", .u1 = "", .q0x = "0fd3bb833c1d7a5b319d1d4117406a23b9aece976186ecb18a11a635e6fbdb920d47e04762b1f2a8c59d2f8435d0fdefe501f544cda23dbf", .q0y = "f13b0dad4d5eeb120f2443ac4392f8096a1396f5014ec2a3506a347fef8076a7282035cf619599b1919cf29df5ce87711c11688aab7700a6", .px = "221704949b1ce1ab8dd174dc9b8c56fcffa27179569ce9219c0c2fe183d3d23343a4c42a0e2e9d6b9d0feb1df3883ec489b6671d1fa64089", .py = "ebdecfdc87142d1a919034bf22ecfad934c9a85effff14b594ae2c00943ca62a39d6ee3be9df0bb504ce8a9e1669bc6959c42ad6a1d3b686" },
};

test "hashToCurve: RFC 9380 J.7.1 edwards448_XOF:SHAKE256_ELL2_RO_" {
    const dst = "QUUX-V01-CS02-with-edwards448_XOF:SHAKE256_ELL2_RO_";
    for (ro_vectors) |v| {
        const u = h2c.hashToField(2, &.{v.msg}, dst);
        try testing.expect(u[0].eql(try feHex(v.u0)));
        try testing.expect(u[1].eql(try feHex(v.u1)));
        try expectAffine(h2c.mapToCurve(u[0]), v.q0x, v.q0y);
        const p = h2c.hashToCurve(v.msg, dst);
        try expectAffine(p, v.px, v.py);
        // Round trip through the point encoding.
        try testing.expect((try ed.Point.fromBytes(p.toBytes())).equivalent(p));
    }
}

test "encodeToCurve: RFC 9380 J.7.2 edwards448_XOF:SHAKE256_ELL2_NU_" {
    const dst = "QUUX-V01-CS02-with-edwards448_XOF:SHAKE256_ELL2_NU_";
    for (nu_vectors) |v| {
        const u = h2c.hashToField(1, &.{v.msg}, dst);
        try testing.expect(u[0].eql(try feHex(v.u0)));
        try expectAffine(h2c.mapToCurve(u[0]), v.q0x, v.q0y);
        try expectAffine(h2c.encodeToCurve(v.msg, dst), v.px, v.py);
    }
}

test "hashToCurve: parts equal the concatenation; a DST over 255 bytes is reduced (RFC 9380 §5.3.3)" {
    const dst = "QUUX-V01-CS02-with-edwards448_XOF:SHAKE256_ELL2_RO_";
    const msg = "abcdef0123456789";
    try testing.expect(h2c.hashToCurveParts(&.{ msg[0..5], "", msg[5..] }, dst).equivalent(h2c.hashToCurve(msg, dst)));
    const long: [300]u8 = @splat('D');
    var reduced: [56]u8 = undefined;
    var s = std.crypto.hash.sha3.Shake256.init(.{});
    s.update("H2C-OVERSIZE-DST-");
    s.update(&long);
    s.squeeze(&reduced);
    try testing.expect(h2c.hashToCurve("m", &long).equivalent(h2c.hashToCurve("m", &reduced)));
}

test "mapToCurve: u = 0 and u = ±1 (tv1 = 1, the exceptional case) land on edwards448" {
    for ([_]Fe{ Fe.zero, Fe.one, Fe.one.neg() }) |u| {
        const q = h2c.mapToCurve(u);
        const zi = try q.z.invert();
        const x = q.x.mul(zi);
        const y = q.y.mul(zi);
        // x² + y² = 1 + d·x²·y²
        try testing.expect(x.square().add(y.square()).eql(Fe.one.add(ed.d.mul(x.square()).mul(y.square()))));
    }
}
