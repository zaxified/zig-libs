// SPDX-License-Identifier: MIT

//! Four-lane `log` and `exp` that answer, bit for bit, what Zig's own `@log` / `@exp` (compiler-rt's
//! `log` and `exp` for f64) answer, for the batch loops whose argument does not depend on the
//! previous bar's result (FRAMA, FISHER): the arguments are collected for a block of bars first, so
//! the four lanes of one call share the instruction stream and the table loads that the scalar
//! functions pay per call.
//!
//! The arithmetic is the scalar functions' own, operation for operation and in their order (no
//! contraction: a Zig build never fuses a multiply-add by itself, `@mulAdd` is the only fused op). `log`
//! is compiler-rt's table-driven routine (the ARM optimized-routines algorithm: 128 intervals of
//! `[0.7, 1.4)`, `invc`, `logc`, `chi`, `clo`; the tables below are its tables, MIT) and `exp` its
//! fdlibm-style one. A lane the fast formula does not cover (argument near 1, zero, subnormal, negative,
//! infinite, NaN for `log`; tiny, huge or NaN for `exp`) is answered by the scalar function, so the
//! block answers equal `@log` / `@exp` for every input. The tests compare the bits over millions of
//! random arguments, so a change of the library's algorithm shows up here as a failure.

const std = @import("std");
const xmath = @import("xmath.zig");

pub const V = @Vector(4, f64);
const VI = @Vector(4, i64);
const VU = @Vector(4, u64);

const log_invc = [128]f64{
    0x1.734f0c3e0de9fp+0, 0x1.713786a2ce91fp+0, 0x1.6f26008fab5a0p+0, 0x1.6d1a61f138c7dp+0,
    0x1.6b1490bc5b4d1p+0, 0x1.69147332f0cbap+0, 0x1.6719f18224223p+0, 0x1.6524f99a51ed9p+0,
    0x1.63356aa8f24c4p+0, 0x1.614b36b9ddc14p+0, 0x1.5f66452c65c4cp+0, 0x1.5d867b5912c4fp+0,
    0x1.5babccb5b90dep+0, 0x1.59d61f2d91a78p+0, 0x1.5805612465687p+0, 0x1.56397cee76bd3p+0,
    0x1.54725e2a77f93p+0, 0x1.52aff42064583p+0, 0x1.50f22dbb2bddfp+0, 0x1.4f38f4734ded7p+0,
    0x1.4d843cfde2840p+0, 0x1.4bd3ec078a3c8p+0, 0x1.4a27fc3e0258ap+0, 0x1.4880524d48434p+0,
    0x1.46dce1b192d0bp+0, 0x1.453d9d3391854p+0, 0x1.43a2744b4845ap+0, 0x1.420b54115f8fbp+0,
    0x1.40782da3ef4b1p+0, 0x1.3ee8f5d57fe8fp+0, 0x1.3d5d9a00b4ce9p+0, 0x1.3bd60c010c12bp+0,
    0x1.3a5242b75dab8p+0, 0x1.38d22cd9fd002p+0, 0x1.3755bc5847a1cp+0, 0x1.35dce49ad36e2p+0,
    0x1.34679984dd440p+0, 0x1.32f5cceffcb24p+0, 0x1.3187775a10d49p+0, 0x1.301c8373e3990p+0,
    0x1.2eb4ebb95f841p+0, 0x1.2d50a0219a9d1p+0, 0x1.2bef9a8b7fd2ap+0, 0x1.2a91c7a0c1babp+0,
    0x1.293726014b530p+0, 0x1.27dfa5757a1f5p+0, 0x1.268b39b1d3bbfp+0, 0x1.2539d838ff5bdp+0,
    0x1.23eb7aac9083bp+0, 0x1.22a012ba940b6p+0, 0x1.2157996cc4132p+0, 0x1.201201dd2fc9bp+0,
    0x1.1ecf4494d480bp+0, 0x1.1d8f5528f6569p+0, 0x1.1c52311577e7cp+0, 0x1.1b17c74cb26e9p+0,
    0x1.19e010c2c1ab6p+0, 0x1.18ab07bb670bdp+0, 0x1.1778a25efbcb6p+0, 0x1.1648d354c31dap+0,
    0x1.151b990275fddp+0, 0x1.13f0ea432d24cp+0, 0x1.12c8b7210f9dap+0, 0x1.11a3028ecb531p+0,
    0x1.107fbda8434afp+0, 0x1.0f5ee0f4e6bb3p+0, 0x1.0e4065d2a9fcep+0, 0x1.0d244632ca521p+0,
    0x1.0c0a77ce2981ap+0, 0x1.0af2f83c636d1p+0, 0x1.09ddb98a01339p+0, 0x1.08cabaf52e7dfp+0,
    0x1.07b9f2f4e28fbp+0, 0x1.06ab58c358f19p+0, 0x1.059eea5ecf92cp+0, 0x1.04949cdd12c90p+0,
    0x1.038c6c6f0ada9p+0, 0x1.02865137932a9p+0, 0x1.0182427ea7348p+0, 0x1.008040614b195p+0,
    0x1.fe01ff726fa1ap-1, 0x1.fa11cc261ea74p-1, 0x1.f6310b081992ep-1, 0x1.f25f63ceeadcdp-1,
    0x1.ee9c8039113e7p-1, 0x1.eae8078cbb1abp-1, 0x1.e741aa29d0c9bp-1, 0x1.e3a91830a99b5p-1,
    0x1.e01e009609a56p-1, 0x1.dca01e577bb98p-1, 0x1.d92f20b7c9103p-1, 0x1.d5cac66fb5ccep-1,
    0x1.d272caa5ede9dp-1, 0x1.cf26e3e6b2ccdp-1, 0x1.cbe6da2a77902p-1, 0x1.c8b266d37086dp-1,
    0x1.c5894bd5d5804p-1, 0x1.c26b533bb9f8cp-1, 0x1.bf583eeece73fp-1, 0x1.bc4fd75db96c1p-1,
    0x1.b951e0c864a28p-1, 0x1.b65e2c5ef3e2cp-1, 0x1.b374867c9888bp-1, 0x1.b094b211d304ap-1,
    0x1.adbe885f2ef7ep-1, 0x1.aaf1d31603da2p-1, 0x1.a82e63fd358a7p-1, 0x1.a5740ef09738bp-1,
    0x1.a2c2a90ab4b27p-1, 0x1.a01a01393f2d1p-1, 0x1.9d79f24db3c1bp-1, 0x1.9ae2505c7b190p-1,
    0x1.9852ef297ce2fp-1, 0x1.95cbaeea44b75p-1, 0x1.934c69de74838p-1, 0x1.90d4f2f6752e6p-1,
    0x1.8e6528effd79dp-1, 0x1.8bfce9fcc007cp-1, 0x1.899c0dabec30ep-1, 0x1.87427aa2317fbp-1,
    0x1.84f00acb39a08p-1, 0x1.82a49e8653e55p-1, 0x1.8060195f40260p-1, 0x1.7e22563e0a329p-1,
    0x1.7beb377dcb5adp-1, 0x1.79baa679725c2p-1, 0x1.77907f2170657p-1, 0x1.756cadbd6130cp-1,
};
const log_logc = [128]f64{
    -0x1.7cc7f79e69000p-2, -0x1.76feec20d0000p-2, -0x1.713e31351e000p-2, -0x1.6b85b38287800p-2,
    -0x1.65d5590807800p-2, -0x1.602d076180000p-2, -0x1.5a8ca86909000p-2, -0x1.54f4356035000p-2,
    -0x1.4f637c36b4000p-2, -0x1.49da7fda85000p-2, -0x1.445923989a800p-2, -0x1.3edf439b0b800p-2,
    -0x1.396ce448f7000p-2, -0x1.3401e17bda000p-2, -0x1.2e9e2ef468000p-2, -0x1.2941b3830e000p-2,
    -0x1.23ec58cda8800p-2, -0x1.1e9e129279000p-2, -0x1.1956d2b48f800p-2, -0x1.141679ab9f800p-2,
    -0x1.0edd094ef9800p-2, -0x1.09aa518db1000p-2, -0x1.047e65263b800p-2, -0x1.feb224586f000p-3,
    -0x1.f474a7517b000p-3, -0x1.ea4443d103000p-3, -0x1.e020d44e9b000p-3, -0x1.d60a22977f000p-3,
    -0x1.cc00104959000p-3, -0x1.c202956891000p-3, -0x1.b81178d811000p-3, -0x1.ae2c9ccd3d000p-3,
    -0x1.a45402e129000p-3, -0x1.9a877681df000p-3, -0x1.90c6d69483000p-3, -0x1.87120a645c000p-3,
    -0x1.7d68fb4143000p-3, -0x1.73cb83c627000p-3, -0x1.6a39a9b376000p-3, -0x1.60b3154b7a000p-3,
    -0x1.5737d76243000p-3, -0x1.4dc7b8fc23000p-3, -0x1.4462c51d20000p-3, -0x1.3b08abc830000p-3,
    -0x1.31b996b490000p-3, -0x1.2875490a44000p-3, -0x1.1f3b9f879a000p-3, -0x1.160c8252ca000p-3,
    -0x1.0ce7f57f72000p-3, -0x1.03cdc49fea000p-3, -0x1.f57bdbc4b8000p-4, -0x1.e370896404000p-4,
    -0x1.d17983ef94000p-4, -0x1.bf9674ed8a000p-4, -0x1.adc79202f6000p-4, -0x1.9c0c3e7288000p-4,
    -0x1.8a646b372c000p-4, -0x1.78d01b3ac0000p-4, -0x1.674f145380000p-4, -0x1.55e0e6d878000p-4,
    -0x1.4485cdea1e000p-4, -0x1.333d94d6aa000p-4, -0x1.22079f8c56000p-4, -0x1.10e4698622000p-4,
    -0x1.ffa6c6ad20000p-5, -0x1.dda8d4a774000p-5, -0x1.bbcece4850000p-5, -0x1.9a1894012c000p-5,
    -0x1.788583302c000p-5, -0x1.5715e67d68000p-5, -0x1.35c8a49658000p-5, -0x1.149e364154000p-5,
    -0x1.e72c082eb8000p-6, -0x1.a55f152528000p-6, -0x1.63d62cf818000p-6, -0x1.228fb8caa0000p-6,
    -0x1.c317b20f90000p-7, -0x1.419355daa0000p-7, -0x1.81203c2ec0000p-8, -0x1.0040979240000p-9,
    0x1.feff384900000p-9,  0x1.7dc41353d0000p-7,  0x1.3cea3c4c28000p-6,  0x1.b9fc114890000p-6,
    0x1.1b0d8ce110000p-5,  0x1.58a5bd001c000p-5,  0x1.95c8340d88000p-5,  0x1.d276aef578000p-5,
    0x1.07598e598c000p-4,  0x1.253f5e30d2000p-4,  0x1.42edd8b380000p-4,  0x1.606598757c000p-4,
    0x1.7da76356a0000p-4,  0x1.9ab434e1c6000p-4,  0x1.b78c7bb0d6000p-4,  0x1.d431332e72000p-4,
    0x1.f0a3171de6000p-4,  0x1.067152b914000p-3,  0x1.147858292b000p-3,  0x1.2266ecdca3000p-3,
    0x1.303d7a6c55000p-3,  0x1.3dfc33c331000p-3,  0x1.4ba366b7a8000p-3,  0x1.5933928d1f000p-3,
    0x1.66acd2418f000p-3,  0x1.740f8ec669000p-3,  0x1.815c0f51af000p-3,  0x1.8e92954f68000p-3,
    0x1.9bb3602f84000p-3,  0x1.a8bed1c2c0000p-3,  0x1.b5b515c01d000p-3,  0x1.c2967ccbcc000p-3,
    0x1.cf635d5486000p-3,  0x1.dc1bd3446c000p-3,  0x1.e8c01b8cfe000p-3,  0x1.f5509c0179000p-3,
    0x1.00e6c121fb800p-2,  0x1.071b80e93d000p-2,  0x1.0d46b9e867000p-2,  0x1.13687334bd000p-2,
    0x1.1980d67234800p-2,  0x1.1f8ffe0cc8000p-2,  0x1.2595fd7636800p-2,  0x1.2b9300914a800p-2,
    0x1.3187210436000p-2,  0x1.377266dec1800p-2,  0x1.3d54ffbaf3000p-2,  0x1.432eee32fe000p-2,
};
const log_chi = [128]f64{
    0x1.61000014fb66bp-1, 0x1.63000034db495p-1, 0x1.650000d94d478p-1, 0x1.67000074e6fadp-1,
    0x1.68ffffedf0faep-1, 0x1.6b0000763c5bcp-1, 0x1.6d0001e5cc1f6p-1, 0x1.6efffeb05f63ep-1,
    0x1.710000e86978p-1,  0x1.72ffffc67e912p-1, 0x1.74fffdf81116ap-1, 0x1.770000f679c9p-1,
    0x1.78ffffa7ec835p-1, 0x1.7affffe20c2e6p-1, 0x1.7cfffed3fc9p-1,   0x1.7efffe9261a76p-1,
    0x1.81000049ca3e8p-1, 0x1.8300017932c8fp-1, 0x1.850000633739cp-1, 0x1.87000204289c6p-1,
    0x1.88fffebf57904p-1, 0x1.8b00022bc04dfp-1, 0x1.8cfffe50c1b8ap-1, 0x1.8effffc918e43p-1,
    0x1.910001efa5fc7p-1, 0x1.9300013467bb9p-1, 0x1.94fffe6ee076fp-1, 0x1.96fffde3c12d1p-1,
    0x1.98ffff4458a0dp-1, 0x1.9afffdd982e3ep-1, 0x1.9cfffed49fb66p-1, 0x1.9f00020f19c51p-1,
    0x1.a10001145b006p-1, 0x1.a300007bbf6fap-1, 0x1.a500010971d79p-1, 0x1.a70001df52e48p-1,
    0x1.a90001c593352p-1, 0x1.ab0002a4f3e4bp-1, 0x1.acfffd7ae1ed1p-1, 0x1.aefffee510478p-1,
    0x1.b0fffdb650d5bp-1, 0x1.b2ffffeaaca57p-1, 0x1.b4fffd995badcp-1, 0x1.b7000249e659cp-1,
    0x1.b8ffff987164p-1,  0x1.bafffd204cb4fp-1, 0x1.bcfffd2415c45p-1, 0x1.beffff86309dfp-1,
    0x1.c0fffe1b57653p-1, 0x1.c2ffff1fa57e3p-1, 0x1.c4fffdcbfe424p-1, 0x1.c6fffed54b9f7p-1,
    0x1.c8fffeb998fd5p-1, 0x1.cb0002125219ap-1, 0x1.ccfffdd94469cp-1, 0x1.cefffeafdc476p-1,
    0x1.d1000169af82bp-1, 0x1.d30000d0ff71dp-1, 0x1.d4fffea790fc4p-1, 0x1.d70002edc87e5p-1,
    0x1.d900021dc82aap-1, 0x1.dafffd86b0283p-1, 0x1.dd000296c4739p-1, 0x1.defffe54490f5p-1,
    0x1.e0fffcdabf694p-1, 0x1.e2fffdb52c8ddp-1, 0x1.e4ffff24216efp-1, 0x1.e6fffe88a5e11p-1,
    0x1.e9000119eff0dp-1, 0x1.eafffdfa51744p-1, 0x1.ed0001a127fa1p-1, 0x1.ef00007babcc4p-1,
    0x1.f0ffff57a8d02p-1, 0x1.f30001ee58ac7p-1, 0x1.f4ffff5823494p-1, 0x1.f6ffffca94c6bp-1,
    0x1.f8fffe1f9c441p-1, 0x1.fafffd2e0e37ep-1, 0x1.fd0001c77e49ep-1, 0x1.feffff7e0c331p-1,
    0x1.00ffff465606ep+0, 0x1.02ffff3867a58p+0, 0x1.04ffffdfc0d17p+0, 0x1.0700003cd4d82p+0,
    0x1.08ffff9f2cbe8p+0, 0x1.0b000010cda65p+0, 0x1.0d00001a4d338p+0, 0x1.0effffadafdfdp+0,
    0x1.110000bbafd96p+0, 0x1.12ffffae5f45dp+0, 0x1.150000dd59ad9p+0, 0x1.170000f21559ap+0,
    0x1.18ffffc275426p+0, 0x1.1b000123d3c59p+0, 0x1.1cffff8299eb7p+0, 0x1.1effff48ad4p+0,
    0x1.210000c8b86a4p+0, 0x1.2300003854303p+0, 0x1.24fffffbcf684p+0, 0x1.26ffff52921d9p+0,
    0x1.2900014933a3cp+0, 0x1.2b00014556313p+0, 0x1.2cfffebfe523bp+0, 0x1.2f0000bb8ad96p+0,
    0x1.30ffffb7ae2afp+0, 0x1.32ffffeac5f7fp+0, 0x1.350000ca66756p+0, 0x1.3700011fbf721p+0,
    0x1.38ffff9592fb9p+0, 0x1.3b00004ddd242p+0, 0x1.3cffff5b2c957p+0, 0x1.3efffeab0b418p+0,
    0x1.410001532aff4p+0, 0x1.4300017478b29p+0, 0x1.44fffe795b463p+0, 0x1.46fffe80475ep+0,
    0x1.48fffef6fc1e7p+0, 0x1.4afffe5bea704p+0, 0x1.4d000171027dep+0, 0x1.4f0000ff03ee2p+0,
    0x1.5100012dc4bd1p+0, 0x1.530001605277ap+0, 0x1.54fffecdb704cp+0, 0x1.56fffef5f54a9p+0,
    0x1.5900017e61012p+0, 0x1.5b00003c93e92p+0, 0x1.5d0001d4919bcp+0, 0x1.5efffe7b87a89p+0,
};
const log_clo = [128]f64{
    0x1.e026c91425b3cp-56,  0x1.dbfea48005d41p-55,  0x1.e7fa786d6a5b7p-55,  0x1.1fcea6b54254cp-57,
    -0x1.c7e274c590efdp-56, -0x1.ac16848dcda01p-55, 0x1.33f1c9d499311p-55,  -0x1.e80041ae22d53p-56,
    0x1.bff6671097952p-56,  0x1.c00e226bd8724p-55,  -0x1.e02916ef101d2p-57, -0x1.7fc71cd549c74p-57,
    0x1.1bec19ef50483p-55,  -0x1.07e1729cc6465p-56, -0x1.08072087b8b1cp-55, 0x1.dc0286d9df9aep-55,
    0x1.97fd251e54c33p-55,  -0x1.afee9b630f381p-55, 0x1.9bfbf6b6535bcp-55,  -0x1.bbf65f3117b75p-55,
    -0x1.9006ea23dcb57p-55, -0x1.d00df38e04b0ap-56, -0x1.8007146ff9f05p-55, 0x1.3817bd07a7038p-55,
    0x1.93e9176dfb403p-55,  0x1.f804e4b980276p-56,  -0x1.f7ef0d9ff622ep-55, -0x1.082aa962638bap-56,
    -0x1.7801b9164a8efp-55, -0x1.740e08a5a9337p-55, 0x1.fce08c19bep-60,     -0x1.a3faa27885b0ap-55,
    0x1.4ff489958da56p-56,  0x1.cbeab8a2b6d18p-55,  0x1.8fecadd78793p-55,   -0x1.f41763dd8abdbp-55,
    -0x1.ebf0284c27612p-55, -0x1.9fd043cff3f5fp-57, -0x1.23ee7129070b4p-55, 0x1.a063ee00edea3p-57,
    0x1.a06c8381f0ab9p-58,  -0x1.9011e74233c1dp-56, -0x1.9ff1068862a9fp-56, 0x1.aff45d0864f3ep-55,
    0x1.cfe7796c2c3f9p-56,  -0x1.3ff27eef22bc4p-57, -0x1.cffb7ee3bea21p-57, -0x1.14103972e0b5cp-55,
    0x1.bc16494b76a19p-55,  -0x1.4feef8d30c6edp-57, -0x1.43f68bcec4775p-55, 0x1.47ea3f053e0ecp-55,
    0x1.383068df992f1p-56,  -0x1.8fd8e64180e04p-57, 0x1.e7ebe1cc7ea72p-55,  0x1.ebe39ad9f88fep-55,
    0x1.57d91a8b95a71p-56,  0x1.9c1906970c7dap-55,  -0x1.80e37c558fe0cp-58, -0x1.f80d64dc10f44p-56,
    -0x1.47c8f94fd5c5cp-56, 0x1.c7f1dc521617ep-55,  0x1.8019eb2ffb153p-55,  0x1.e00d2c652cc89p-57,
    -0x1.f8340202d69d2p-56, 0x1.b00c1ca1b0864p-56,  0x1.2ffa8b094ab51p-56,  -0x1.7f673b1efbe59p-58,
    -0x1.4808d5e0bc801p-55, 0x1.80006d54320b5p-56,  -0x1.002f860565c92p-58, -0x1.540445d35e611p-55,
    -0x1.ffb3139ef9105p-59, 0x1.a81acf2731155p-55,  0x1.a3f41d4d7c743p-55,  -0x1.202f41c987875p-57,
    0x1.77dd1f477e74bp-56,  -0x1.f01199a7ca331p-57, 0x1.181ee4bceacb1p-56,  -0x1.e05370170875ap-57,
    -0x1.a7ead491c0adap-55, -0x1.77f69c3fcb2ep-54,  0x1.7bffe34cb945bp-54,  0x1.20083c0e456cbp-55,
    -0x1.dffdfbe37751ap-57, -0x1.13f7faee626ebp-54, 0x1.07dfa79489ff7p-55,  -0x1.7040570d66bcp-56,
    0x1.e80d4846d0b62p-55,  0x1.dbffa64fd36efp-54,  0x1.a0077701250aep-54,  0x1.dfdf9e2e3deeep-55,
    0x1.10030dc3b7273p-54,  0x1.97f7980030188p-54,  -0x1.5f932ab9f8c67p-57, 0x1.37fbf9da75bebp-54,
    0x1.f806b91fd5b22p-54,  0x1.3ffc2eb9fbf33p-54,  0x1.601e77e2e2e72p-56,  0x1.ffcbb767f0c61p-56,
    -0x1.202ca3c02412bp-56, -0x1.2808233f21f02p-54, -0x1.8ff7e384fdcf2p-55, -0x1.5ff51503041c5p-55,
    -0x1.10071885e289dp-55, -0x1.1ff5d3fb7b715p-54, 0x1.57f82228b82bdp-54,  0x1.000bac40dd5ccp-55,
    -0x1.43f9d2db2a751p-54, 0x1.57f6b707638e1p-55,  0x1.a023a10bf1231p-56,  0x1.87f6d66b152bp-54,
    0x1.7f8375f198524p-57,  0x1.301e672dc5143p-55,  0x1.9ff69b8b2895ap-55,  -0x1.5c0b19bc2f254p-54,
    0x1.b4009f23a2a72p-54,  -0x1.4ffb7bf0d7d45p-54, -0x1.9c06471dc6a3dp-54, 0x1.77f890b85531cp-54,
    0x1.004657166a436p-57,  -0x1.6bfcece233209p-54, -0x1.902720505a1d7p-55, 0x1.bbfe60ec96412p-54,
    0x1.87ec581afef9p-55,   -0x1.f41080abf0ccp-54,  -0x1.8812afb254729p-54, -0x1.47eb780ed6904p-54,
};

inline fn splat(x: f64) V {
    return @splat(x);
}
inline fn splati(x: i64) VI {
    return @splat(x);
}

const log_poly = [5]f64{
    -0x1.0000000000001p-1,
    0x1.555555551305bp-2,
    -0x1.fffffffeb459p-3,
    0x1.999b324f10111p-3,
    -0x1.55575e506c89fp-3,
};

/// `@log(x)` for the four lanes.
pub fn log4(x: V) V {
    const ix: VI = @bitCast(x);
    const lo_b: i64 = @bitCast(@as(f64, 1.0 - 0x1p-4));
    const hi_b: i64 = @bitCast(@as(f64, 1.0 + 0x1.09p-4));
    const top: VU = @as(VU, @bitCast(ix)) >> @splat(48);
    const near1 = (ix >= splati(lo_b)) & (ix < splati(hi_b));
    const odd = (top < @as(VU, @splat(0x0010))) | (top >= @as(VU, @splat(0x7ff0)));
    const special = near1 | odd;
    const tmp = ix -% splati(0x3fe6000000000000);
    const idx: @Vector(4, u64) = (@as(VU, @bitCast(tmp)) >> @splat(45)) & @as(VU, @splat(0x7f));
    const k: VI = tmp >> @splat(52);
    const iz: VI = @bitCast(@as(VU, @bitCast(ix)) -% (@as(VU, @bitCast(k)) << @splat(52)));
    const z: V = @bitCast(iz);
    const i: [4]usize = .{ @intCast(idx[0]), @intCast(idx[1]), @intCast(idx[2]), @intCast(idx[3]) };
    const invc: V = .{ log_invc[i[0]], log_invc[i[1]], log_invc[i[2]], log_invc[i[3]] };
    const logc: V = .{ log_logc[i[0]], log_logc[i[1]], log_logc[i[2]], log_logc[i[3]] };
    const chi: V = .{ log_chi[i[0]], log_chi[i[1]], log_chi[i[2]], log_chi[i[3]] };
    const clo: V = .{ log_clo[i[0]], log_clo[i[1]], log_clo[i[2]], log_clo[i[3]] };
    const r = (z - chi - clo) * invc;
    const kd: V = @floatFromInt(k);
    const w = kd * splat(0x1.62e42fefa3800p-1) + logc;
    const hi = w + r;
    const lo = w - hi + r + kd * splat(0x1.ef35793c76730p-45);
    const r2 = r * r;
    const p = splat(log_poly[1]) + r * splat(log_poly[2]) + r2 * (splat(log_poly[3]) + r * splat(log_poly[4]));
    var y = lo + r2 * splat(log_poly[0]) + r * r2 * p + hi;
    if (@reduce(.Or, special)) {
        inline for (0..4) |l| {
            if (special[l]) y[l] = @log(x[l]);
        }
    }
    return y;
}

const exp_p = [5]f64{
    1.66666666666666019037e-01,
    -2.77777777770155933842e-03,
    6.61375632143793436117e-05,
    -1.65339022054652515390e-06,
    4.13813679705723846039e-08,
};

/// `@exp(x)` for the four lanes.
pub fn exp4(x_in: V) V {
    // A lane outside the fast range is computed on a stand-in and answered by the scalar function after.
    const ux0: VU = @bitCast(x_in);
    const hx0: VU = (ux0 >> @splat(32)) & @as(VU, @splat(0x7FFFFFFF));
    const ok = (hx0 > @as(VU, @splat(0x3E300000))) & (hx0 < @as(VU, @splat(0x40590000)));
    const x = @select(f64, ok, x_in, splat(-1.0));
    const ux: VU = @bitCast(x);
    const hx: VU = (ux >> @splat(32)) & @as(VU, @splat(0x7FFFFFFF));
    const sign: VU = ux >> @splat(63);
    const big = hx > @as(VU, @splat(0x3FD62E42));
    const mid = hx > @as(VU, @splat(0x3FF0A2B2));
    const half: V = @select(f64, sign == @as(VU, @splat(0)), splat(0.5), splat(-0.5));
    const k_far: VI = @intFromFloat(splat(1.44269504088896338700e+00) * x + half);
    const k_near: VI = splati(1) - @as(VI, @bitCast(sign)) - @as(VI, @bitCast(sign));
    const k = @select(i64, big, @select(i64, mid, k_far, k_near), splati(0));
    const dk: V = @floatFromInt(k);
    const hi_r = x - dk * splat(6.93147180369123816490e-01);
    const lo = dk * splat(1.90821492927058770002e-10);
    const xr = @select(f64, big, hi_r - lo, x);
    const hi = @select(f64, big, hi_r, x);
    const lo_s = @select(f64, big, lo, splat(0.0));
    const xx = xr * xr;
    const c = xr - xx * (splat(exp_p[0]) + xx * (splat(exp_p[1]) + xx * (splat(exp_p[2]) + xx * (splat(exp_p[3]) + xx * splat(exp_p[4])))));
    const y = splat(1.0) + (xr * c / (splat(2.0) - c) - lo_s + hi);
    const scale: V = @bitCast((k + splati(1023)) << @splat(52));
    var out = y * scale;
    // The fast formula covers 2^-28 < |x| < 100 (the reduction of the scalar's second and third regimes).
    if (!@reduce(.And, ok)) {
        inline for (0..4) |l| {
            if (!ok[l]) out[l] = @exp(x_in[l]);
        }
    }
    return out;
}

/// `@log10(x)` (compiler-rt's, fdlibm's `e_log10.c`) for the four lanes; the scalar function answers a lane
/// that is not a positive normal number other than 1.
pub fn log10_4(x_in: V) V {
    const ix: VU = @bitCast(x_in);
    const hx0: VU = ix >> @splat(32);
    const special = (hx0 < @as(VU, @splat(0x00100000))) | (hx0 >= @as(VU, @splat(0x7FF00000))) | (ix == @as(VU, @bitCast(splat(1.0))));
    var hx = hx0 +% @as(VU, @splat(0x3FF00000 - 0x3FE6A09E));
    const k: VI = @bitCast((hx >> @splat(20)) -% @as(VU, @splat(0x3FF)));
    hx = (hx & @as(VU, @splat(0x000FFFFF))) + @as(VU, @splat(0x3FE6A09E));
    const x: V = @bitCast((hx << @splat(32)) | (ix & @as(VU, @splat(0xFFFFFFFF))));
    const f = x - splat(1.0);
    const hfsq = splat(0.5) * f * f;
    const s = f / (splat(2.0) + f);
    const z = s * s;
    const w = z * z;
    const t1 = w * (splat(3.999999999940941908e-01) + w * (splat(2.222219843214978396e-01) + w * splat(1.531383769920937332e-01)));
    const t2 = z * (splat(6.666666666666735130e-01) + w * (splat(2.857142874366239149e-01) + w * (splat(1.818357216161805012e-01) + w * splat(1.479819860511658591e-01))));
    const R = t2 + t1;
    var hi = f - hfsq;
    hi = @bitCast(@as(VU, @bitCast(hi)) & @as(VU, @splat(0xFFFFFFFF00000000)));
    const lo = f - hi - hfsq + s * (hfsq + R);
    var val_hi = hi * splat(4.34294481878168880939e-01);
    const dk: V = @floatFromInt(k);
    const y = dk * splat(3.01029995663611771306e-01);
    var val_lo = dk * splat(3.69423907715893078616e-13) + (lo + hi) * splat(2.50829467116452752298e-11) + lo * splat(4.34294481878168880939e-01);
    const ww = y + val_hi;
    val_lo += (y - ww) + val_hi;
    val_hi = ww;
    var out = val_lo + val_hi;
    if (@reduce(.Or, special)) {
        inline for (0..4) |l| {
            if (special[l]) out[l] = @log10(x_in[l]);
        }
    }
    return out;
}

const expm1_q = [5]f64{
    -3.33333333333331316428e-02,
    1.58730158725481460165e-03,
    -7.93650757867487942473e-05,
    4.00821782732936239552e-06,
    -2.01099218183624371326e-07,
};

/// `std.math.expm1(x)` for lanes in 2^-54 < |x| < 38 whose reduction is not `k == 1` (the others are answered
/// by the scalar function, `ok` says which).
fn expm1x(x_in: V, ok_out: *@Vector(4, bool)) V {
    const ux0: VU = @bitCast(x_in);
    const hx0: VU = (ux0 >> @splat(32)) & @as(VU, @splat(0x7FFFFFFF));
    const sign0: VU = ux0 >> @splat(63);
    const ok = (hx0 >= @as(VU, @splat(0x3C900000))) & (hx0 < @as(VU, @splat(0x4043687A))) &
        ((sign0 != @as(VU, @splat(0))) | (hx0 <= @as(VU, @splat(0x3FD62E42))) | (hx0 >= @as(VU, @splat(0x3FF0A2B2))));
    ok_out.* = ok;
    const x0 = @select(f64, ok, x_in, splat(-0.1));
    const ux: VU = @bitCast(x0);
    const hx: VU = (ux >> @splat(32)) & @as(VU, @splat(0x7FFFFFFF));
    const sign: VU = ux >> @splat(63);
    const big = hx > @as(VU, @splat(0x3FD62E42));
    const near = hx < @as(VU, @splat(0x3FF0A2B2));
    const half: V = @select(f64, sign == @as(VU, @splat(0)), splat(0.5), splat(-0.5));
    const k_far: VI = @intFromFloat(splat(1.44269504088896338700e+00) * x0 + half);
    const k_near: VI = splati(1) - @as(VI, @bitCast(sign)) - @as(VI, @bitCast(sign));
    const k = @select(i64, big, @select(i64, near, k_near, k_far), splati(0));
    const t = @as(V, @floatFromInt(k));
    const hi = x0 - t * splat(6.93147180369123816490e-01);
    const lo = t * splat(1.90821492927058770002e-10);
    const x = @select(f64, big, hi - lo, x0);
    const c = @select(f64, big, (hi - x) - lo, splat(0.0));
    const hfx = splat(0.5) * x;
    const hxs = x * hfx;
    const r1 = splat(1.0) + hxs * (splat(expm1_q[0]) + hxs * (splat(expm1_q[1]) + hxs * (splat(expm1_q[2]) + hxs * (splat(expm1_q[3]) + hxs * splat(expm1_q[4])))));
    const tt = splat(3.0) - r1 * hfx;
    const e0 = hxs * ((r1 - tt) / (splat(6.0) - x * tt));
    const res0 = x - (x * e0 - hxs);
    const e1 = x * (e0 - c) - c;
    const e = e1 - hxs;
    const res_m1 = splat(0.5) * (x - e) - splat(0.5);
    const twopk: V = @bitCast((k +% splati(0x3FF)) << @splat(52));
    const y = (x - e + splat(1.0)) * twopk - splat(1.0);
    const uf: V = @bitCast((splati(0x3FF) -% k) << @splat(52));
    const mid_lo = (x - e + (splat(1.0) - uf)) * twopk;
    const mid_hi = (x - (e + uf) + splat(1.0)) * twopk;
    const neg_or_huge = (k < splati(0)) | (k > splati(56));
    var res = @select(f64, k < splati(20), mid_lo, mid_hi);
    res = @select(f64, neg_or_huge, y, res);
    res = @select(f64, k == splati(-1), res_m1, res);
    res = @select(f64, k == splati(0), res0, res);
    return res;
}

/// `xmath.tanh(x)` (fdlibm's: `expm1` below 22) for the four lanes; the scalar function answers a lane
/// outside the fast range.
pub fn tanh4(x_in: V) V {
    const ux: VU = @bitCast(x_in);
    const ix: VU = (ux >> @splat(32)) & @as(VU, @splat(0x7FFFFFFF));
    const in_range = (ix >= @as(VU, @splat(0x3c800000))) & (ix < @as(VU, @splat(0x40360000)));
    const x = @select(f64, in_range, x_in, splat(0.5));
    const ax = @abs(x);
    const ge1 = ix >= @as(VU, @splat(0x3ff00000));
    const arg = @select(f64, ge1, splat(2.0) * ax, splat(-2.0) * ax);
    var ok: @Vector(4, bool) = undefined;
    const t = expm1x(arg, &ok);
    const z = @select(f64, ge1, splat(1.0) - splat(2.0) / (t + splat(2.0)), -t / (t + splat(2.0)));
    const neg: @Vector(4, bool) = (ux >> @splat(63)) != @as(VU, @splat(0));
    var out = @select(f64, neg, -z, z);
    const good = in_range & ok;
    if (!@reduce(.And, good)) {
        inline for (0..4) |l| {
            if (!good[l]) out[l] = xmath.tanh(x_in[l]);
        }
    }
    return out;
}

// ── tests ───────────────────────────────────────────────────────────────────

fn sameBits(a: f64, b: f64) bool {
    return @as(u64, @bitCast(a)) == @as(u64, @bitCast(b)) or (std.math.isNan(a) and std.math.isNan(b));
}

test "log4 equals @log bit for bit (random positives over many binades, and the special lanes)" {
    var prng = std.Random.DefaultPrng.init(0x10c0ffee);
    const r = prng.random();
    var bad: usize = 0;
    for (0..250_000) |_| {
        var xa: [4]f64 = undefined;
        for (0..4) |l| {
            const mode = r.uintLessThan(u8, 8);
            xa[l] = switch (mode) {
                0 => r.float(f64) * 2.0,
                1 => 1.0 + (r.float(f64) - 0.5) * 0.2,
                2 => @exp((r.float(f64) - 0.5) * 1400.0),
                3 => 1.0 + r.float(f64) * 1999.0,
                4 => 0.0005 + r.float(f64) * 0.01,
                5 => @as(f64, @bitCast(r.int(u64))),
                else => (1.0 + r.float(f64)) * std.math.pow(f64, 2.0, @as(f64, @floatFromInt(r.intRangeAtMost(i32, -30, 30)))),
            };
        }
        const x: V = xa;
        const ga: [4]f64 = log4(x);
        for (0..4) |l| {
            if (!sameBits(ga[l], @log(xa[l]))) bad += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
    const sp: V = .{ 0.0, -1.0, std.math.inf(f64), 5e-324 };
    const gs: [4]f64 = log4(sp);
    const spa: [4]f64 = sp;
    for (0..4) |l| try std.testing.expect(sameBits(gs[l], @log(spa[l])));
    const sp2: V = .{ std.math.nan(f64), 1.0, -0.0, 1.0000001 };
    const g2: [4]f64 = log4(sp2);
    const sp2a: [4]f64 = sp2;
    for (0..4) |l| try std.testing.expect(sameBits(g2[l], @log(sp2a[l])));
}

test "exp4 equals @exp bit for bit (the FRAMA range, the wide range, and the scalar lanes)" {
    var prng = std.Random.DefaultPrng.init(0xe4e4e4);
    const r = prng.random();
    var bad: usize = 0;
    for (0..250_000) |_| {
        var xa: [4]f64 = undefined;
        for (0..4) |l| {
            const mode = r.uintLessThan(u8, 6);
            xa[l] = switch (mode) {
                0 => -r.float(f64) * 4.7,
                1 => (r.float(f64) - 0.5) * 200.0,
                2 => (r.float(f64) - 0.5) * 1.5,
                3 => (r.float(f64) - 0.5) * 1e-8,
                4 => (r.float(f64) - 0.5) * 1600.0,
                else => @as(f64, @bitCast(r.int(u64))),
            };
        }
        const x: V = xa;
        const ga: [4]f64 = exp4(x);
        for (0..4) |l| {
            if (!sameBits(ga[l], @exp(xa[l]))) bad += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "tanh4 equals the scalar tanh bit for bit (PSO's range, the wide range, and the scalar lanes)" {
    var prng = std.Random.DefaultPrng.init(0x7a47);
    const r = prng.random();
    var bad: usize = 0;
    for (0..250_000) |_| {
        var xa: [4]f64 = undefined;
        for (0..4) |l| {
            const mode = r.uintLessThan(u8, 7);
            xa[l] = switch (mode) {
                0 => (r.float(f64) - 0.5) * 5.0,
                1 => (r.float(f64) - 0.5) * 2.0,
                2 => (r.float(f64) - 0.5) * 60.0,
                3 => (r.float(f64) - 0.5) * 1e-6,
                4 => (r.float(f64) - 0.5) * 1e-12,
                5 => (r.float(f64) - 0.5) * 0.7,
                else => @as(f64, @bitCast(r.int(u64))),
            };
        }
        const ga: [4]f64 = tanh4(xa);
        for (0..4) |l| {
            if (!sameBits(ga[l], xmath.tanh(xa[l]))) bad += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "log10_4 equals @log10 bit for bit (random positives over many binades, and the special lanes)" {
    var prng = std.Random.DefaultPrng.init(0x10a10);
    const r = prng.random();
    var bad: usize = 0;
    for (0..250_000) |_| {
        var xa: [4]f64 = undefined;
        for (0..4) |l| {
            const mode = r.uintLessThan(u8, 7);
            xa[l] = switch (mode) {
                0 => r.float(f64) * 20.0,
                1 => 1.0 + (r.float(f64) - 0.5) * 0.2,
                2 => @exp((r.float(f64) - 0.5) * 1400.0),
                3 => 1.0 + r.float(f64) * 49.0,
                4 => 0.5 + r.float(f64),
                5 => @as(f64, @bitCast(r.int(u64))),
                else => 1.0,
            };
        }
        const x: V = xa;
        const ga: [4]f64 = log10_4(x);
        for (0..4) |l| {
            if (!sameBits(ga[l], @log10(xa[l]))) bad += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
    const sp: V = .{ 0.0, -1.0, std.math.inf(f64), 5e-324 };
    const gs: [4]f64 = log10_4(sp);
    const spa: [4]f64 = sp;
    for (0..4) |l| try std.testing.expect(sameBits(gs[l], @log10(spa[l])));
}
