// SPDX-License-Identifier: MIT

//! The reference side of `tools/slip.sh`: does proptest 1.11.0's shrinker
//! keep the failure it started from? The property (the same in all three
//! tools, `twoBugsCheck` in `src/shrink.zig`): a byte string fails "deep"
//! when it is at least 16 long and sums to 1500 or more, and "shallow" when
//! it starts with a zero. A random string that fails is almost always deep;
//! zeroing its first byte -- a step every shrinker takes -- makes it
//! shallow.
//!
//! For seeds 0..20 (ChaCha `TestRng`, default `Config` but no failure
//! persistence) one `TestRunner::run` over `vec(any::<u8>(), 0..=64)`
//! (uniform length, as the driver's `Rng.slice` over 64 bytes). Prints one
//! line per seed: `seed \t first failure \t reported failure \t reported
//! length`, the reported value classified again by the same property.

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestError, TestRng, TestRunner};
use std::cell::Cell;

fn class(b: &[u8]) -> &'static str {
    if b.len() >= 2 && b[0] == 0 {
        return "shallow";
    }
    if b.len() >= 16 && b.iter().map(|&x| x as u32).sum::<u32>() >= 1500 {
        return "deep";
    }
    "pass"
}

fn main() {
    for seed in 0u8..20 {
        let mut runner = TestRunner::new_with_rng(
            Config {
                failure_persistence: None,
                ..Config::default()
            },
            TestRng::from_seed(RngAlgorithm::ChaCha, &[seed; 32]),
        );
        let first: Cell<Option<&'static str>> = Cell::new(None);
        let r = runner.run(&vec(any::<u8>(), 0..=64), |v| {
            let c = class(&v);
            if c == "pass" {
                return Ok(());
            }
            if first.get().is_none() {
                first.set(Some(c));
            }
            Err(TestCaseError::fail(c))
        });
        match r {
            Err(TestError::Fail(_, v)) => {
                println!("{seed}\t{}\t{}\t{}", first.get().unwrap(), class(&v), v.len())
            }
            other => println!("{seed}\tno failure: {other:?}"),
        }
    }
}
