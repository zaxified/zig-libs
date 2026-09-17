// SPDX-License-Identifier: MIT
//
// The driver behind `modules/signal/src/interop_vectors.zig`. It is OUR code
// (MIT); it only runs inside a throwaway libsignal checkout, which stays outside
// this repository (libsignal is AGPL-3.0 -- see ../NOTICE). Nothing from
// libsignal is copied here.
//
// How to use (see interop_vectors.zig for the exact commit and command):
//   git clone https://github.com/signalapp/libsignal && git -C libsignal checkout 857c4dc
//   append this file to libsignal/rust/protocol/src/ratchet/keys.rs
//   PROTOC=<cargo-vendored protoc> cargo test -p libsignal-protocol --lib zig_libs_dump -- --nocapture
//
// ── zig-libs vector capture (LOCAL ONLY -- never committed upstream) ────
// Drives libsignal's own ChainKey/RootKey to print the numeric outputs of
// the Double Ratchet KDFs for fixed inputs. Nothing here is copied into
// zig-libs; only the printed numbers are.
#[cfg(test)]
mod zig_libs_dump {
    use super::*;

    fn fixed32(tag: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = tag.wrapping_mul(37).wrapping_add((i as u8).wrapping_mul(11)).wrapping_add(3);
        }
        b
    }

    #[test]
    fn zig_libs_dump_vectors() {
        println!("### CHAIN_LADDERS");
        for tag in 0u8..3 {
            let start = fixed32(tag);
            let mut ck = ChainKey::new(start, 0);
            println!("LADDER start={}", hex::encode_upper(start));
            for _ in 0..5 {
                let mk_seed = ck.calculate_base_material(ChainKey::MESSAGE_KEY_SEED);
                let next = ck.next_chain_key();
                println!(
                    "STEP index={} ck={} mk={} next_ck={}",
                    ck.index(),
                    hex::encode_upper(ck.key()),
                    hex::encode_upper(mk_seed),
                    hex::encode_upper(next.key())
                );
                ck = next;
            }
        }

        println!("### ROOT_RATCHETS");
        for tag in 3u8..6 {
            let rk_bytes = fixed32(tag);
            let their_priv = PrivateKey::deserialize(&fixed32(tag.wrapping_add(10))).unwrap();
            let their_pub = their_priv.public_key().unwrap();
            let our_old = PrivateKey::deserialize(&fixed32(tag.wrapping_add(20))).unwrap();
            let our_new = PrivateKey::deserialize(&fixed32(tag.wrapping_add(30))).unwrap();

            let dh_recv = our_old.calculate_agreement(&their_pub).unwrap();
            let dh_send = our_new.calculate_agreement(&their_pub).unwrap();

            let rk = RootKey::new(rk_bytes);
            let (rk1, ckr) = rk.create_chain(&their_pub, &our_old).unwrap();
            let (rk2, cks) = rk1.clone().create_chain(&their_pub, &our_new).unwrap();

            println!(
                "RATCHET rk={} dh_recv={} dh_send={} rk1={} ckr={} rk2={} cks={}",
                hex::encode_upper(rk_bytes),
                hex::encode_upper(&dh_recv),
                hex::encode_upper(&dh_send),
                hex::encode_upper(rk1.key()),
                hex::encode_upper(ckr.key()),
                hex::encode_upper(rk2.key()),
                hex::encode_upper(cks.key())
            );
        }
    }
}
