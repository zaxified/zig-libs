// SPDX-License-Identifier: MIT
//! Native **P2WPKH** finalize/extract vectors, captured from a real Bitcoin
//! Core regtest node on 2026-08-02.
//!
//! Why they exist: BIP174's worked example (`kat_vectors.zig`) has only two
//! inputs — bare P2SH multisig and P2SH-P2WSH multisig — and Bitcoin Core's
//! `test/functional/data/rpc_psbt.json` finalizer entry decodes
//! byte-identically to it. Neither reaches **native P2WPKH**, the most
//! common spend type in Bitcoin today, which left the most valuable shape in
//! this module without an outside oracle.
//!
//! Capture-and-freeze: Core ran ONCE. The test suite never starts a node or
//! touches the network. `bitcoind -version` -> `Bitcoin Core version
//! v28.0.0`. To re-derive (`$C` = `bitcoin-cli -regtest -datadir=$D`):
//!
//!     bitcoind -regtest -datadir=$D -daemon -fallbackfee=0.0002
//!     $C createwallet w
//!     A1=$($C -rpcwallet=w getnewaddress "" bech32)
//!     $C -rpcwallet=w generatetoaddress 101 "$A1"
//!     DEST=$($C -rpcwallet=w getnewaddress "" bech32)
//!     PSBT=$($C -rpcwallet=w walletcreatefundedpsbt '[]' \
//!              "[{\"$DEST\":1.0}]" 0 '{"fee_rate":10}')      # .psbt
//!     SIGNED=$($C -rpcwallet=w walletprocesspsbt "$PSBT" true "ALL" true false)
//!     $C finalizepsbt "$SIGNED" false                         # .psbt
//!     $C finalizepsbt "$SIGNED"                               # .hex
//!
//! ⚠ The trailing `false` on `walletprocesspsbt` is load-bearing: its
//! `finalize` parameter defaults to **true**, so without it Core hands back
//! an already-finalized PSBT carrying `FINAL_SCRIPTWITNESS` and no
//! `PARTIAL_SIG` — useless for testing a finalizer, and a trap this capture
//! fell into on the first attempt.
//!
//! The wallet picks its own keys and coinbase maturity fixes the input, so
//! these bytes are one concrete capture, not a spec constant.
//!
//! Licence: bytes Core *computed* for a wallet we created — not Core source
//! and not Core's own test fixtures. Core is MIT regardless; attribution for
//! the vendored `rpc_psbt.json` corpus lives in the module `NOTICE` and is
//! unaffected by this file.

/// `walletprocesspsbt … false`: signed, NOT finalized. Input 0 carries
/// NON_WITNESS_UTXO (0x00), WITNESS_UTXO (0x01), PARTIAL_SIG (0x02) and
/// BIP32_DERIVATION (0x06).
pub const p2wpkh_signed_hex =
    "70736274ff01007102000000013905cc427f3a71e24259bd91405686b5498b1d" ++
    "99eb5b2bde13d583f509d7def50000000000fdffffff0200e1f5050000000016" ++
    "001449411e17b296f2501e0d877ed95e347f8f69ace87e0b1024010000001600" ++
    "1431247a413effa28e82b516d9f955370c1aad568e0000000000010083020000" ++
    "0001000000000000000000000000000000000000000000000000000000000000" ++
    "0000ffffffff025100ffffffff0200f2052a01000000160014ccb3b14c9e2b14" ++
    "3617a52cbfb67ab09c7e49db3c0000000000000000266a24aa21a9ede2f61c3f" ++
    "71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000000" ++
    "01011f00f2052a01000000160014ccb3b14c9e2b143617a52cbfb67ab09c7e49" ++
    "db3c220202df91f4c7c7f80edc618288e2c15d38723e01d42ad9255d8b14bd1f" ++
    "37df566c8647304402204c09be5f2e2b6cfa4163aa9a73cbbed3868620b2683c" ++
    "826c249b3d1c8292888d02200a103353e28a979f2271f1529625a13df2ad8651" ++
    "bf4360a34fb5f6e64137e0d801220602df91f4c7c7f80edc618288e2c15d3872" ++
    "3e01d42ad9255d8b14bd1f37df566c8618c86607c15400008001000080000000" ++
    "800000000000000000002202026adb5a5c2732993edd3cb7c9e03edb18f377eb" ++
    "70c35c8b51e7cf3700c2b0478318c86607c15400008001000080000000800000" ++
    "00000100000000220203a58864ef18e4aaa6423182121ff93bc4eb10dbb85a97" ++
    "ba46580ea812b6efbc5e18c86607c15400008001000080000000800100000000" ++
    "00000000" ++
    "";

/// `finalizepsbt <psbt> false`: input 0 now has FINAL_SCRIPTWITNESS
/// (0x08); PARTIAL_SIG and BIP32_DERIVATION are gone, both UTXO records
/// kept — BIP174's Input Finalizer contract, as Core applies it.
pub const p2wpkh_finalized_hex =
    "70736274ff01007102000000013905cc427f3a71e24259bd91405686b5498b1d" ++
    "99eb5b2bde13d583f509d7def50000000000fdffffff0200e1f5050000000016" ++
    "001449411e17b296f2501e0d877ed95e347f8f69ace87e0b1024010000001600" ++
    "1431247a413effa28e82b516d9f955370c1aad568e0000000000010083020000" ++
    "0001000000000000000000000000000000000000000000000000000000000000" ++
    "0000ffffffff025100ffffffff0200f2052a01000000160014ccb3b14c9e2b14" ++
    "3617a52cbfb67ab09c7e49db3c0000000000000000266a24aa21a9ede2f61c3f" ++
    "71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000000" ++
    "01011f00f2052a01000000160014ccb3b14c9e2b143617a52cbfb67ab09c7e49" ++
    "db3c01086b0247304402204c09be5f2e2b6cfa4163aa9a73cbbed3868620b268" ++
    "3c826c249b3d1c8292888d02200a103353e28a979f2271f1529625a13df2ad86" ++
    "51bf4360a34fb5f6e64137e0d8012102df91f4c7c7f80edc618288e2c15d3872" ++
    "3e01d42ad9255d8b14bd1f37df566c86002202026adb5a5c2732993edd3cb7c9" ++
    "e03edb18f377eb70c35c8b51e7cf3700c2b0478318c86607c154000080010000" ++
    "8000000080000000000100000000220203a58864ef18e4aaa6423182121ff93b" ++
    "c4eb10dbb85a97ba46580ea812b6efbc5e18c86607c154000080010000800000" ++
    "0080010000000000000000" ++
    "";

/// `finalizepsbt <psbt>` `.hex`: the network-ready segwit transaction.
pub const p2wpkh_extracted_tx_hex =
    "020000000001013905cc427f3a71e24259bd91405686b5498b1d99eb5b2bde13" ++
    "d583f509d7def50000000000fdffffff0200e1f5050000000016001449411e17" ++
    "b296f2501e0d877ed95e347f8f69ace87e0b10240100000016001431247a413e" ++
    "ffa28e82b516d9f955370c1aad568e0247304402204c09be5f2e2b6cfa4163aa" ++
    "9a73cbbed3868620b2683c826c249b3d1c8292888d02200a103353e28a979f22" ++
    "71f1529625a13df2ad8651bf4360a34fb5f6e64137e0d8012102df91f4c7c7f8" ++
    "0edc618288e2c15d38723e01d42ad9255d8b14bd1f37df566c8600000000" ++
    "";
