// SPDX-License-Identifier: MIT
//! Native **P2WPKH** finalize/extract vectors, captured from a real Bitcoin
//! Core regtest node on 2026-08-02. (A second capture further down this file
//! adds native **P2WSH 2-of-3 multisig** vectors, from 2026-08-05 -- see the
//! "Native P2WSH 2-of-3 multisig" section banner below for its own
//! provenance and capture recipe.)
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

// ── Native P2WSH 2-of-3 multisig ────────────────────────────────────────
//
// Captured from the same class of real Bitcoin Core regtest node on
// 2026-08-05.
//
// Why they exist: this is the ONE spend shape in this module without an
// outside oracle at all. BIP174's own worked Finalizer/Extractor example
// (`kat_vectors.zig`) covers bare P2SH and P2SH-P2WSH multisig, but not
// *native* P2WSH; Bitcoin Core's `rpc_psbt.json` finalizer/extractor entries
// turned out to be byte-identical to that same BIP174 example (see
// `SPEC.md`), so they don't add native P2WSH either. Without this capture,
// native P2WSH multisig `finalize`/`extract` would be verified only against
// this module's own idea of the format -- an encoder/decoder pair sharing a
// misreading would satisfy its own test.
//
// Capture-and-freeze: Core ran ONCE. The test suite never starts a node or
// touches the network. `bitcoind -version` -> `Bitcoin Core version
// v28.0.0` (`/Satoshi:28.0.0/`). To re-derive (`$C` = `bitcoin-cli -regtest
// -datadir=$D`):
//
//     bitcoind -regtest -datadir=$D -daemon -fallbackfee=0.0002
//     $C createwallet funding
//     $C createwallet signer1
//     $C createwallet signer2
//     $C createwallet signer3
//     $C createwallet multisig true true     # disable_private_keys, blank
//
//     FADDR=$($C -rpcwallet=funding getnewaddress "" bech32)
//     $C -rpcwallet=funding generatetoaddress 101 "$FADDR"
//
//     A1=$($C -rpcwallet=signer1 getnewaddress "" bech32)
//     A2=$($C -rpcwallet=signer2 getnewaddress "" bech32)
//     A3=$($C -rpcwallet=signer3 getnewaddress "" bech32)
//     PK1=$($C -rpcwallet=signer1 getaddressinfo "$A1" | jq -r .pubkey)
//     PK2=$($C -rpcwallet=signer2 getaddressinfo "$A2" | jq -r .pubkey)
//     PK3=$($C -rpcwallet=signer3 getaddressinfo "$A3" | jq -r .pubkey)
//
//     DESC=$($C getdescriptorinfo "wsh(multi(2,$PK1,$PK2,$PK3))" | jq -r \
//              '.descriptor + "#" + .checksum')
//     $C -rpcwallet=multisig importdescriptors \
//         "[{\"desc\":\"$DESC\",\"active\":false,\"internal\":false,\"timestamp\":\"now\"}]"
//     MSADDR=$($C deriveaddresses "$DESC" | jq -r .[0])
//
//     $C -rpcwallet=funding sendtoaddress "$MSADDR" 1.0
//     $C -rpcwallet=funding generatetoaddress 6 "$FADDR"
//     $C -rpcwallet=multisig getbalances                # confirm visible!
//     $C -rpcwallet=multisig listunspent                 # confirm visible!
//
//     DEST=$($C -rpcwallet=funding getnewaddress "" bech32)
//     PSBT=$($C -rpcwallet=multisig walletcreatefundedpsbt '[]' \
//              "[{\"$DEST\":1.0}]" 0 \
//              '{"fee_rate":10,"subtractFeeFromOutputs":[0]}' | jq -r .psbt)
//     S1=$($C -rpcwallet=signer1 walletprocesspsbt "$PSBT" true "ALL" true false | jq -r .psbt)
//     S2=$($C -rpcwallet=signer2 walletprocesspsbt "$PSBT" true "ALL" true false | jq -r .psbt)
//     COMBINED=$($C combinepsbt "[\"$S1\",\"$S2\"]")       # .psbt
//     $C finalizepsbt "$COMBINED" false                    # .psbt
//     $C finalizepsbt "$COMBINED"                           # .hex
//     $C testmempoolaccept "[\"<the .hex above>\"]"        # allowed: true
//
// Two traps this capture fell into, both load-bearing for the recipe above:
//
//  1. `importdescriptors` with `"active": true` on a raw-pubkey `multi(...)`
//     descriptor fails with `"Active descriptors must be ranged"` -- there
//     is no wildcard to range over, so it must be imported `"active":
//     false"`. This is the direct cause of the prior attempt's `Insufficient
//     funds`: an inactive-but-never-successfully-imported descriptor left
//     the watch-only wallet blind to the funded UTXO. `active: false` is
//     sufficient for the wallet to see and spend a UTXO at a *specific*
//     derived address (`deriveaddresses`) via `listunspent`/
//     `walletcreatefundedpsbt` -- "active" only controls whether the
//     wallet auto-generates *new* addresses from the descriptor, which this
//     capture never needs (one fixed multisig address, sent to explicitly).
//  2. The watch-only `multisig` wallet holds no keys at all, so
//     `walletcreatefundedpsbt`'s default change output fails with `"we
//     can't generate it. No bech32 addresses available"` -- worked around
//     with `subtractFeeFromOutputs: [0]` so the single destination output
//     absorbs the fee and no change output is needed.
//
// Funding the multisig address by mining 101 blocks to a SEPARATE funding
// wallet, then `sendtoaddress`-ing 1 BTC to the multisig address (rather
// than mining directly to it), sidesteps the coinbase-maturity trap
// entirely -- the spent coin is an ordinary confirmed P2WPKH output by the
// time it funds the multisig UTXO, not an immature coinbase.
//
// The wallets pick their own keys and coinbase maturity fixes the input, so
// these bytes are one concrete capture, not a spec constant.
//
// Licence: bytes Core *computed* for wallets we created -- not Core source
// and not Core's own test fixtures. Core is MIT regardless; attribution for
// the vendored `rpc_psbt.json` corpus lives in the module `NOTICE` and is
// unaffected by this file.

/// `combinepsbt` of both signers' `walletprocesspsbt … false` outputs:
/// signed by 2 of 3 (`PARTIAL_SIG`), NOT finalized. The sole input carries
/// NON_WITNESS_UTXO (0x00), WITNESS_UTXO (0x01), two PARTIAL_SIG (0x02)
/// records, WITNESS_SCRIPT (0x05, the `OP_2 <pk1> <pk2> <pk3> OP_3
/// OP_CHECKMULTISIG` script), and three BIP32_DERIVATION (0x06) records.
pub const p2wsh_multisig_signed_hex =
    "70736274ff01005202000000010dbb6fba8edfbdfe380f1f5d9fc5179c0e74d73a6d" ++
    "2378f0996359d9284da14a0000000000fdffffff014cdbf50500000000160014969a" ++
    "83b56fd2fea713deee77a4f4a7ff7ee60e1200000000000100890200000001f99968" ++
    "17c66f3ba6edad29ff6d0420977e7b9d242aeff71a98e622ce6f473e8a0000000000" ++
    "fdffffff0200e1f5050000000022002002782c4b9841e562f8499c10fba7390ab501" ++
    "d43f76f4bfb7aa68306f07e9bd171c04102401000000225120ec9a9d06d9052a43c1" ++
    "486327eed25839eab0d2885c2e79a4ad800c59f9aeb3bd6500000001012b00e1f505" ++
    "0000000022002002782c4b9841e562f8499c10fba7390ab501d43f76f4bfb7aa6830" ++
    "6f07e9bd17220202d84766937c31b25e793a71f1107f48fb6a8ce0b5006b4cc399ce" ++
    "90dd7c6603f94730440220263879eebd941fb30d83f31151e796198d7e3bab4efbd8" ++
    "b9869be78cd4de31350220307eadef7d48133198a7338ac2a5169fcd4008e3c3b730" ++
    "c0bf8cfa378c345bb9012202020555bc61f7690c7adcdba7ac67624cef1c15c138c8" ++
    "a4ff6b8b7dcbc78af3395d47304402205c5f2162bdd6c4467fcb98b2961a34333a70" ++
    "da13e036b9d84b1410255b0302f4022058816560ffae2c830fb18da6dac957234e5a" ++
    "f2888468f16138ea12c9192c4667010105695221020555bc61f7690c7adcdba7ac67" ++
    "624cef1c15c138c8a4ff6b8b7dcbc78af3395d2102d84766937c31b25e793a71f110" ++
    "7f48fb6a8ce0b5006b4cc399ce90dd7c6603f92102478a07672e08032e9872f64977" ++
    "e651e95c1c5fbb7656aa0b6ecc2eedaf9fa96e53ae2206020555bc61f7690c7adcdb" ++
    "a7ac67624cef1c15c138c8a4ff6b8b7dcbc78af3395d048253dc37220602478a0767" ++
    "2e08032e9872f64977e651e95c1c5fbb7656aa0b6ecc2eedaf9fa96e0482ca8e9e22" ++
    "0602d84766937c31b25e793a71f1107f48fb6a8ce0b5006b4cc399ce90dd7c6603f9" ++
    "043da8392b0000" ++
    "";

/// `finalizepsbt <combined> false`: the sole input now has
/// FINAL_SCRIPTWITNESS (0x08); both PARTIAL_SIG and all three
/// BIP32_DERIVATION records are gone; WITNESS_SCRIPT is gone too (BIP174's
/// Input Finalizer clears it -- it's now embedded in the witness itself);
/// both UTXO records are kept.
pub const p2wsh_multisig_finalized_hex =
    "70736274ff01005202000000010dbb6fba8edfbdfe380f1f5d9fc5179c0e74d73a6d" ++
    "2378f0996359d9284da14a0000000000fdffffff014cdbf50500000000160014969a" ++
    "83b56fd2fea713deee77a4f4a7ff7ee60e1200000000000100890200000001f99968" ++
    "17c66f3ba6edad29ff6d0420977e7b9d242aeff71a98e622ce6f473e8a0000000000" ++
    "fdffffff0200e1f5050000000022002002782c4b9841e562f8499c10fba7390ab501" ++
    "d43f76f4bfb7aa68306f07e9bd171c04102401000000225120ec9a9d06d9052a43c1" ++
    "486327eed25839eab0d2885c2e79a4ad800c59f9aeb3bd6500000001012b00e1f505" ++
    "0000000022002002782c4b9841e562f8499c10fba7390ab501d43f76f4bfb7aa6830" ++
    "6f07e9bd170108fc040047304402205c5f2162bdd6c4467fcb98b2961a34333a70da" ++
    "13e036b9d84b1410255b0302f4022058816560ffae2c830fb18da6dac957234e5af2" ++
    "888468f16138ea12c9192c4667014730440220263879eebd941fb30d83f31151e796" ++
    "198d7e3bab4efbd8b9869be78cd4de31350220307eadef7d48133198a7338ac2a516" ++
    "9fcd4008e3c3b730c0bf8cfa378c345bb901695221020555bc61f7690c7adcdba7ac" ++
    "67624cef1c15c138c8a4ff6b8b7dcbc78af3395d2102d84766937c31b25e793a71f1" ++
    "107f48fb6a8ce0b5006b4cc399ce90dd7c6603f92102478a07672e08032e9872f649" ++
    "77e651e95c1c5fbb7656aa0b6ecc2eedaf9fa96e53ae0000" ++
    "";

/// `finalizepsbt <combined>` `.hex`: the network-ready segwit transaction.
/// `testmempoolaccept` on this exact hex against the node that produced it
/// returned `"allowed": true` -- the node itself, not just this module,
/// accepts it as a valid 2-of-3 CHECKMULTISIG spend.
pub const p2wsh_multisig_extracted_tx_hex =
    "020000000001010dbb6fba8edfbdfe380f1f5d9fc5179c0e74d73a6d2378f0996359" ++
    "d9284da14a0000000000fdffffff014cdbf50500000000160014969a83b56fd2fea7" ++
    "13deee77a4f4a7ff7ee60e12040047304402205c5f2162bdd6c4467fcb98b2961a34" ++
    "333a70da13e036b9d84b1410255b0302f4022058816560ffae2c830fb18da6dac957" ++
    "234e5af2888468f16138ea12c9192c4667014730440220263879eebd941fb30d83f3" ++
    "1151e796198d7e3bab4efbd8b9869be78cd4de31350220307eadef7d48133198a733" ++
    "8ac2a5169fcd4008e3c3b730c0bf8cfa378c345bb901695221020555bc61f7690c7a" ++
    "dcdba7ac67624cef1c15c138c8a4ff6b8b7dcbc78af3395d2102d84766937c31b25e" ++
    "793a71f1107f48fb6a8ce0b5006b4cc399ce90dd7c6603f92102478a07672e08032e" ++
    "9872f64977e651e95c1c5fbb7656aa0b6ecc2eedaf9fa96e53ae00000000" ++
    "";
