// SPDX-License-Identifier: MIT

// Lead probe behind the json5 card's `**Ahead:**` correctness line: how the
// fastest JSON5 reader in the field (the json5 crate 1.3.1) and json-five 0.3.1
// read three documents that json5/json5 2.2.3 (the reference) and this module
// agree on. Run: `cargo run --release --offline --bin lead` in this directory.
// Expected (2026-10-24):
//   "{a: 1} /* unterminated"   json5 crate Ok({"a":1})  -- a truncated block
//                              comment accepted; reference and we refuse
//   "'\9'"                     json5 crate Ok("9")      -- `\9` is not a JSON5
//                              escape (ES5.1 §7.8.4); reference and we refuse
//   42-digit integer           both crates Err("number too large ...") --
//                              JSON5 numbers are IEEE 754 doubles; reference
//                              and we read 1.2345678901234568e41
use serde_json::Value;

fn main() {
    let docs: &[&str] = &[
        "{a: 1} /* unterminated",
        "'\\9'",
        "123456789012345678901234567890123456789012",
    ];
    for d in docs {
        let a: Result<Value, _> = json5::from_str(d);
        let b: Result<Value, _> = json_five::from_str(d);
        println!(
            "{:?}\n  json5 crate 1.3.1: {:?}\n  json-five 0.3.1:   {:?}",
            d,
            a.map(|v| v.to_string()).map_err(|e| e.to_string()),
            b.map(|v| v.to_string()).map_err(|e| e.to_string())
        );
    }
}
