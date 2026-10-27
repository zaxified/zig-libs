// SPDX-License-Identifier: MIT
//
// Writes go-seccomp-bpf v1.6.0's program for the syscall names in the file
// argv[1] (one per line) -- allow them, kill the process otherwise -- as raw
// sock_filter bytes to argv[2]. Run by modules/sandbox/tools/bench.zig, which
// counts the BPF instructions a syscall costs in it.
package main

import (
	"bufio"
	"encoding/binary"
	"os"
	"strings"

	seccomp "github.com/elastic/go-seccomp-bpf"
	"golang.org/x/net/bpf"
)

func main() {
	var names []string
	in, err := os.Open(os.Args[1])
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		if n := strings.TrimSpace(sc.Text()); n != "" {
			names = append(names, n)
		}
	}
	p := seccomp.Policy{DefaultAction: seccomp.ActionKillProcess, Syscalls: []seccomp.SyscallGroup{{Names: names, Action: seccomp.ActionAllow}}}
	insts, err := p.Assemble()
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	raw, err := bpf.Assemble(insts)
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	out, err := os.Create(os.Args[2])
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	for _, r := range raw {
		binary.Write(w, binary.LittleEndian, r.Op)
		w.WriteByte(r.Jt)
		w.WriteByte(r.Jf)
		binary.Write(w, binary.LittleEndian, r.K)
	}
	w.Flush()
}
