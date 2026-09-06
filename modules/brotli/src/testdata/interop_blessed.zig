// SPDX-License-Identifier: MIT

//! What google/brotli said about THIS encoder's output, frozen.
//!
//! For every shape in `interop_corpus.zig`, the reference decompressed
//! the stream `brotli.compress` produced and got the input back, byte for
//! byte. `stream_sha256` identifies the exact stream that happened to;
//! `input_sha256` identifies the exact input, so a corpus generator that
//! drifts is told apart from an encoder that drifts.
//!
//! This is the only hermetic form the encoder direction can take. What
//! the reference judged is a stream, not a function of committed data:
//! replaying it without the reference means pinning the bytes it blessed
//! and checking we still emit them. So an encoder change that alters ANY
//! output turns `test-brotli` red until someone re-runs the interop
//! program against a real google/brotli — which is the point. The
//! alternative, checking our decoder against our encoder, is precisely
//! the self-round-trip this anchor exists to escape.
//!
//! GENERATED FILE. Regenerate:
//!
//!   zig build interop-brotli -- --capture
//!
//! Reference: python brotli 1.2.0 (google/brotli), Python 3.14.4, 2026-09-06

pub const Blessed = struct {
    name: []const u8,
    input_len: usize,
    /// SHA-256 of the input, lowercase hex.
    input_sha256: []const u8,
    stream_len: usize,
    /// SHA-256 of the stream google/brotli accepted, lowercase hex.
    stream_sha256: []const u8,
};

pub const entries = [_]Blessed{
    .{ .name = "empty", .input_len = 0, .input_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", .stream_len = 1, .stream_sha256 = "67586e98fad27da0b9968bc039a1ef34c939b9b8e523a8bef89d478608c5ecf6" },
    .{ .name = "one_byte", .input_len = 1, .input_sha256 = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881", .stream_len = 5, .stream_sha256 = "7db00a13672071146c5bd9ab5c00874237fb27d6200ba31f46f5961c89157edf" },
    .{ .name = "two_bytes", .input_len = 2, .input_sha256 = "769a4e6d0003189c7e96c5d9b7e810a0d11c3a12832527ec94b0f86d277f51ca", .stream_len = 6, .stream_sha256 = "df22eb8a6b7bba5692afb769a94bf314fb091d28831871c5b4861c1676328c94" },
    .{ .name = "three_bytes", .input_len = 3, .input_sha256 = "3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282", .stream_len = 7, .stream_sha256 = "9e811b6c544421f3a626809433145d1cb440d9a50a9738a799d5acd5f4c3e664" },
    .{ .name = "four_same", .input_len = 4, .input_sha256 = "61be55a8e2f6b4e172338bddf184d6dbee29c98853e0a0485ecee7f27b9af0b4", .stream_len = 8, .stream_sha256 = "d403163dc7b9c9dd70b9f4ea018c9c84442465495d9ce0257cd07ebc30bed38e" },
    .{ .name = "nul", .input_len = 1, .input_sha256 = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", .stream_len = 5, .stream_sha256 = "d6edcc757631c388a0f83d543a3cb09a9330d7efcfc7e34c4049b2831c84f4ca" },
    .{ .name = "five_ff", .input_len = 5, .input_sha256 = "132369a3b7f24fa619785c4e2eee68855f5d46cbe0aaa19eadd0dbc2dd592c39", .stream_len = 9, .stream_sha256 = "9dae2b2f626e9b373adf08e01c1967d1c7c8eb1736b4bd903d77cd1933b2144c" },
    .{ .name = "hello_repeated", .input_len = 35, .input_sha256 = "532e12b863dbff73eceee22061e43c1dac874dbe1a46e0a5a924e72f172a73a3", .stream_len = 23, .stream_sha256 = "1b609ecd2ea940cf5becbf255500e79a3afe3cbc94a0dc2f8f285a831e3e8717" },
    .{ .name = "run_1", .input_len = 1, .input_sha256 = "8e35c2cd3bf6641bdb0e2050b76932cbb2e6034a0ddacc1d9bea82a6ba57f7cf", .stream_len = 5, .stream_sha256 = "e2f2d816ba4949f4c5367e583b03105f0d9dd813cb80efa46818124f3107f04c" },
    .{ .name = "run_2", .input_len = 2, .input_sha256 = "d5ce2b19fbda14a25deac948154722f33efd37b369a32be8f03ec2be8ef7d3a5", .stream_len = 6, .stream_sha256 = "776794cec0ef9d3983d917539a8b4d01ace748627ab05b0533691dcf37ddd984" },
    .{ .name = "run_3", .input_len = 3, .input_sha256 = "a95bc16631ae2b6fadb455ee018da0adc2703e56d89e3eed074ce56d2f7b1b6a", .stream_len = 7, .stream_sha256 = "9eb0e1fdc4debe3e948f3c058a83163866d7196038ad54be567d690393f16785" },
    .{ .name = "run_4", .input_len = 4, .input_sha256 = "f98204ba6963009734f0398a80f8e44f9d3ef74ebb9c49e5d4f000bd1c102d29", .stream_len = 8, .stream_sha256 = "e43f941d9caaa488d74273fa6a93d21db615378b67aa5107a529f8d2546425f8" },
    .{ .name = "run_5", .input_len = 5, .input_sha256 = "ae118a7acd2ff2f77598c7316bced68d92bf8c8f0ca30ffb28f4edf6fc7c2f3d", .stream_len = 9, .stream_sha256 = "5b4d78a1ccf8a27b4e79cce692b3982c5cb2f3e3b065e5283ced1830c83f4f2d" },
    .{ .name = "run_6", .input_len = 6, .input_sha256 = "b6197fe0d62a4e463edd2925382d4d268c4fce0859378682608efa4fda326f26", .stream_len = 9, .stream_sha256 = "4d458236ccf409038c3a50ca85a5280f4ca79c4081c9ffb1fc918decdfb7282b" },
    .{ .name = "run_9", .input_len = 9, .input_sha256 = "e05db8688a0e247ab4ada686600d10b1460d8ceaa0adee919024bd99ebeead92", .stream_len = 9, .stream_sha256 = "7e56c953e5f0cd5cd8d022fc71dd0935f890f41a1684f49e18263f9c7c13b1fd" },
    .{ .name = "run_10", .input_len = 10, .input_sha256 = "56011e3f63396f612e354d39227bdd1fb87bbaa58a6ae293cad1d7f05c25e617", .stream_len = 9, .stream_sha256 = "fe4ec116268b7617edcc394832db9b4abfc864345d1c3a05b8c79670e8ebb089" },
    .{ .name = "run_63", .input_len = 63, .input_sha256 = "9b49777003a4143d8c3f4d3002eb631c6bda8b030a3ccc87f8a21d5f61c89e87", .stream_len = 10, .stream_sha256 = "74fb6c4e03dd8df82a62f9e19a785626cfe93d6743adf766a8045bcf65a08492" },
    .{ .name = "run_64", .input_len = 64, .input_sha256 = "ee8e658590c9a5e119400a774415a01db104de1ee6e2c29ec69aa73ef46544d2", .stream_len = 10, .stream_sha256 = "86825b844cc849dab39fb9ec97d61295702c1c99434edddfd4487f258fe20430" },
    .{ .name = "run_65", .input_len = 65, .input_sha256 = "2b6c3f7f12b1b12fc5409626dc4e5302d8d37082cbeddea7755eac43aba039c8", .stream_len = 10, .stream_sha256 = "35bf8da869be241f50897e560f1f8ac342c183b5b83cceb1989a2f5b166f168b" },
    .{ .name = "run_1000", .input_len = 1000, .input_sha256 = "2e6bba1f3cf48fe45fa1c56e25b47fb622dde50eba1e17e0a72464e32bf4ab41", .stream_len = 13, .stream_sha256 = "414b5570b1472fe17df27f54e39cb35622c7837635c4181ac714caf96c3c751b" },
    .{ .name = "run_22593", .input_len = 22593, .input_sha256 = "687be6c33f623df11836cd8b448965ec3fffb4c3c3c8abc1ab06717d912d9469", .stream_len = 68, .stream_sha256 = "ed2525813a006d469f134cb38c96ae306d2280dfc2c927d4742abf01981195fd" },
    .{ .name = "run_22594", .input_len = 22594, .input_sha256 = "1377f29de47ae06745bf77bf27159f6271aa692625398debac76ec930fbeb015", .stream_len = 68, .stream_sha256 = "0360c9667c637755e2b0f448a6d004b334ff974dd92fcfe356655df21610b725" },
    .{ .name = "run_22595", .input_len = 22595, .input_sha256 = "a58ffbd43d0cc81730ae0904a14aa70e2d1dde6a07624773cd31aaa8c0876fdd", .stream_len = 68, .stream_sha256 = "b35995f340c0f5c45d16ece9e3cf659362b3730312cd76185df42aa3c63dc755" },
    .{ .name = "ramp_256", .input_len = 256, .input_sha256 = "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880", .stream_len = 260, .stream_sha256 = "bd3f4eb4932e034aee7545be86f0071fcfd39021780961d9a599a1f76c2a4741" },
    .{ .name = "stride_10240", .input_len = 10240, .input_sha256 = "7ee4e43d4c2dae7abea33238100844adab98a0383a1b84b6ac0770a2cf16ca28", .stream_len = 419, .stream_sha256 = "bb8fde3ceb18c3d811145b88e169635cd6e1dc0284d0c005976301b9f5a74c50" },
    .{ .name = "alpha1_flat", .input_len = 30000, .input_sha256 = "74d351caf543882c67633b2ef76f875345f6213f7d81af41879f189759bbf4c5", .stream_len = 86, .stream_sha256 = "03c03354b4b238bbe60be93c240a51cb36acc6fa2a5effb9438da3c8ec2477ba" },
    .{ .name = "alpha1_skew", .input_len = 30000, .input_sha256 = "74d351caf543882c67633b2ef76f875345f6213f7d81af41879f189759bbf4c5", .stream_len = 86, .stream_sha256 = "03c03354b4b238bbe60be93c240a51cb36acc6fa2a5effb9438da3c8ec2477ba" },
    .{ .name = "alpha2_flat", .input_len = 30000, .input_sha256 = "9780a07d7f010f1e77282f50915acb42c32c44aa0197201da4b05530c29f34b0", .stream_len = 5211, .stream_sha256 = "4c5ac1f792df817988041669a13126edbfaa7defb170420c9abb76d34edec682" },
    .{ .name = "alpha2_skew", .input_len = 30000, .input_sha256 = "9031facee18bb0980e560758b18d539ac582db3817f8bf2950a590502750871d", .stream_len = 2179, .stream_sha256 = "49153799ac87dd4a19cecb6704795c444abf7776e10780203a4c0308fa84f11d" },
    .{ .name = "alpha3_flat", .input_len = 30000, .input_sha256 = "2d8339a07eda2f386cc6e00df0cd95bd48e7f20ed06325eaf01609c149b9cd9d", .stream_len = 7465, .stream_sha256 = "0bef20464b97baff5377de0f49273172e3fdd35b4dfbf033a67d4f8600a643e3" },
    .{ .name = "alpha3_skew", .input_len = 30000, .input_sha256 = "31edc7d6be30291f7457bd5143c6da55717914a743c75989f2a9d4f51df844d4", .stream_len = 3021, .stream_sha256 = "73b2714dc3575124f10bbdcc4ebdfaeccffb1778a52fbe257a583ab0d725ebca" },
    .{ .name = "alpha4_flat", .input_len = 30000, .input_sha256 = "186a0d27df494d46b8cd45e12ee20bdd3c77d21c90d9903c1d58c539135be462", .stream_len = 9094, .stream_sha256 = "f3c2724a3788034131e94ef2ae1cb7bac846b0f9836cd05fcc2c68578aec00ec" },
    .{ .name = "alpha4_skew", .input_len = 30000, .input_sha256 = "7388d382c13e776ae6bc2545941413632a8ce016451d2120ec5fe96ddf8805a4", .stream_len = 3408, .stream_sha256 = "e07b28e566d2079e3aa4c74ac4a5894cbd341a8ef33afa48d68930365fa4b518" },
    .{ .name = "alpha5_flat", .input_len = 30000, .input_sha256 = "78fbd28b18d663c0eb4fda32fd697c3ab57cd7e8bac04cb5899e229454694a12", .stream_len = 10431, .stream_sha256 = "d06995119a55197980b85c4f580c8f6aa633c90f553e4bc34176a7df50d2319c" },
    .{ .name = "alpha5_skew", .input_len = 30000, .input_sha256 = "8ec24e16ab50eaaa9573d5bfec5a13f59633ec5f601271f0b7610c0735e8d438", .stream_len = 3765, .stream_sha256 = "0b58ab161e4a4a95743f6f5228b9fc849917d56fba40137708fd29fb18261f56" },
    .{ .name = "random_16", .input_len = 16, .input_sha256 = "f5dc0afd5847e35c3ac2e42450ecb34656db8c3d2b055ae1c60ffa73910fe849", .stream_len = 20, .stream_sha256 = "3b5d464f22ea79c98a2de89d14905a1ccd97598a3f44abc92dcb8f34bbb099c8" },
    .{ .name = "random_1000", .input_len = 1000, .input_sha256 = "3a9db1b9104d41431239c3d652850e95e1fc55c806f118fe24ab127be24cc865", .stream_len = 1004, .stream_sha256 = "f86ad78f8e7273cde0c2bb344cae2fdc05d7ffaa96c12752b49b5b9c7680c889" },
    .{ .name = "random_70000", .input_len = 70000, .input_sha256 = "d74e11400d282829299aeca3cbddd6a56bc58f581951c5a6b0adbc430ab0cfb1", .stream_len = 70005, .stream_sha256 = "1f107cfe4c7353711765f8b844073284f20f43a10906c1d5c886a32d11ba7829" },
    .{ .name = "alice_65519", .input_len = 65519, .input_sha256 = "af50e2b6d21eb60cefcab01fcf9ee7e65d8604cfe6339219f7e55bc27f69bcc8", .stream_len = 24887, .stream_sha256 = "6c36dfef0e57f48e72dfba49fcbadd57217b6c879d3352053c580acf0817af09" },
    .{ .name = "alice_65521", .input_len = 65521, .input_sha256 = "6f81e4231d07dd1ba1cf9205d3fe0eae3dd291477ca33904f5364c58d9b76f02", .stream_len = 24888, .stream_sha256 = "0b8fb5da2a4b4831f79dfdb595dac91204b65c12a98ad013b82bc14782b80e2e" },
    .{ .name = "alice_full", .input_len = 152089, .input_sha256 = "7467306ee0feed4971260f3c87421154a05be571d944e9cb021a5713700c38f0", .stream_len = 54605, .stream_sha256 = "87233e7be59ff2b3987f731226ca648559f7097688b71b55ec016a39ae9a4202" },
    .{ .name = "mixed_random_first", .input_len = 1088576, .input_sha256 = "5214e8d08b2c96cb0c5ee29bce17869cb9ca14d0ef9fc82939930a46939836c4", .stream_len = 1064464, .stream_sha256 = "fc2bb9464ce7a236683f05d42d17f7ecfcb84accc4ba4222a3490bae56dd6ab2" },
    .{ .name = "mixed_text_first", .input_len = 1088576, .input_sha256 = "7d53f2169d3eecab22c199490f0d4fc9de122455d468e526b935191b0f11a592", .stream_len = 110431, .stream_sha256 = "52d6bef298f2a3b68a4f751d762d0458c9e4832ac873eec8da8da10e377c00a8" },
    .{ .name = "block_exact", .input_len = 1048576, .input_sha256 = "04b18ac774775dc12dd62bc7dc4bccad7f6d3e8a6f0dc860efc91ebc022b24e6", .stream_len = 70427, .stream_sha256 = "3f2b9423ef8a71a88709ad22848d9ccc420443b46c18d4339133eb0de45ddc68" },
    .{ .name = "block_plus_one", .input_len = 1048577, .input_sha256 = "b4e12997b7220bef5181116b471257115aed283ee73279411f1247eb363d4538", .stream_len = 70432, .stream_sha256 = "8f68412ebc4b380811f255074a2c50ae66b886cebfdc949102c0c6393a2223d1" },
};
