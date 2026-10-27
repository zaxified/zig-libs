// SPDX-License-Identifier: MIT
//
// Writes seccompiler 0.5.0's program for the syscall numbers in the file argv[1]
// (one per line) -- allow them, kill the process otherwise -- as raw sock_filter
// bytes to argv[2]. Run by modules/sandbox/tools/bench.zig, which counts the
// BPF instructions a syscall costs in it.
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
use std::collections::BTreeMap;
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let text = std::fs::read_to_string(&args[1]).unwrap();
    let mut rules = BTreeMap::new();
    for l in text.lines() {
        let t = l.trim();
        if !t.is_empty() {
            rules.insert(t.parse::<i64>().unwrap(), vec![]);
        }
    }
    let f = SeccompFilter::new(rules, SeccompAction::KillProcess, SeccompAction::Allow, TargetArch::x86_64).unwrap();
    let prog: BpfProgram = f.try_into().unwrap();
    let mut out = std::fs::File::create(&args[2]).unwrap();
    for i in prog {
        out.write_all(&i.code.to_le_bytes()).unwrap();
        out.write_all(&[i.jt, i.jf]).unwrap();
        out.write_all(&i.k.to_le_bytes()).unwrap();
    }
}
