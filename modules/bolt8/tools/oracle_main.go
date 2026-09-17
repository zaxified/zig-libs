// SPDX-License-Identifier: MIT
//
// BOLT#8 interop oracle: drives lnd's `brontide` Machine over stdin/stdout so
// this repo's `bolt8` module can be paired against it as a live peer
// (CONVENTIONS.md §9 differential oracle). `fetch-oracle.sh` (this
// directory) fetches `brontide`/`keychain` straight from lnd's own
// repository -- nothing from lnd is vendored, which is what keeps this
// module's clean-room `NOTICE` true.
//
// Roles (-role flag):
//   pub         print the pubkey for -priv (helper, no handshake)
//   init / resp handshake + exchange -n messages each way as that party
//   evil-resp   accept Act One, answer with a well-formed-LOOKING but
//               unverifiable forged Act Two -- a correct initiator must
//               reject on the MAC
//   evil-init   send a forged Act One (valid curve point, made-up tag)
//   truncate    answer Act One with 49 of 50 Act Two bytes, then go silent
// The three `evil-`/`truncate` roles are wire-level adversaries (attacks on
// the PROTOCOL, not on brontide's own code) -- they ask whether `bolt8`
// rejects a hostile peer, which is exactly the wire-format question a class A
// anchor is for.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"

	"oracle/brontide"
	"oracle/keychain"
)

// payloadLens is the length ladder both sides walk in lockstep. It includes 0
// and the 65535 maximum so the extremes are exercised on the wire.
var payloadLens = []int{0, 1, 5, 17, 64, 255, 1366, 65535, 32, 3}

// payload deterministically derives message i for direction tag. The zig side
// (`peer.zig`) implements exactly the same function, so a mismatch
// anywhere is loud.
func payload(tag string, i int) []byte {
	n := payloadLens[i%len(payloadLens)]
	out := make([]byte, n)
	var ctr [8]byte
	binary.LittleEndian.PutUint64(ctr[:], uint64(i))
	seed := sha256.Sum256(append([]byte(tag), ctr[:]...))
	off := 0
	blk := seed
	for off < n {
		blk = sha256.Sum256(blk[:])
		c := copy(out[off:], blk[:])
		off += c
	}
	return out
}

func main() {
	role := flag.String("role", "", "init|resp|pub|evil-resp|evil-init|truncate")
	privHex := flag.String("priv", "", "32-byte local static privkey, hex")
	remoteHex := flag.String("remote", "", "33-byte remote static pubkey, hex (initiator only)")
	n := flag.Int("n", 1100, "messages per direction")
	flag.Parse()

	privBytes, err := hex.DecodeString(*privHex)
	must(err)
	priv, _ := btcec.PrivKeyFromBytes(privBytes)
	localKey := &keychain.PrivKeyECDH{PrivKey: priv}

	if *role == "pub" {
		fmt.Println(hex.EncodeToString(priv.PubKey().SerializeCompressed()))
		return
	}

	// Wire-level adversaries (not brontide — these are attacks, not an oracle).
	if *role == "evil-resp" {
		// Accept Act One, then answer with a well-formed-looking Act Two we
		// cannot possibly have derived: version 0, a VALID curve point, a
		// random tag. A correct initiator must reject on the MAC.
		var a1 [50]byte
		if _, err := io.ReadFull(os.Stdin, a1[:]); err != nil {
			fatal("evil-resp: " + err.Error())
		}
		k, _ := btcec.PrivKeyFromBytes([]byte("\x07evil-ephemeral-key-32-bytes---xx"))
		var a2 [50]byte
		a2[0] = 0
		copy(a2[1:34], k.PubKey().SerializeCompressed())
		for i := 34; i < 50; i++ {
			a2[i] = byte(i * 7)
		}
		os.Stdout.Write(a2[:])
		fmt.Fprintln(os.Stderr, "go: evil-resp sent a forged Act Two")
		var junk [1]byte
		os.Stdin.Read(junk[:])
		return
	}
	if *role == "evil-init" {
		// Send Act One with a valid point but a tag we made up.
		k, _ := btcec.PrivKeyFromBytes([]byte("\x07evil-ephemeral-key-32-bytes---xx"))
		var a1 [50]byte
		a1[0] = 0
		copy(a1[1:34], k.PubKey().SerializeCompressed())
		for i := 34; i < 50; i++ {
			a1[i] = byte(i * 3)
		}
		os.Stdout.Write(a1[:])
		fmt.Fprintln(os.Stderr, "go: evil-init sent a forged Act One")
		var junk [1]byte
		os.Stdin.Read(junk[:])
		return
	}
	if *role == "truncate" {
		// Answer Act One with 49 of the 50 Act Two bytes, then go silent.
		var a1 [50]byte
		io.ReadFull(os.Stdin, a1[:])
		var a2 [49]byte
		os.Stdout.Write(a2[:])
		fmt.Fprintln(os.Stderr, "go: sent 49/50 act2 bytes, now silent")
		var junk [1]byte
		os.Stdin.Read(junk[:])
		return
	}

	initiator := *role == "init"
	var remote *btcec.PublicKey
	if initiator {
		rb, err := hex.DecodeString(*remoteHex)
		must(err)
		remote, err = btcec.ParsePubKey(rb)
		must(err)
	}

	m := brontide.NewBrontideMachine(initiator, localKey, remote)

	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	outw := bufio.NewWriterSize(os.Stdout, 1<<20)
	wireHash := sha256.New()
	out := io.MultiWriter(outw, wireHash)

	if initiator {
		a1, err := m.GenActOne()
		must(err)
		_, err = out.Write(a1[:])
		must(err)
		must(outw.Flush())

		var a2 [brontide.ActTwoSize]byte
		_, err = io.ReadFull(in, a2[:])
		must(err)
		must(m.RecvActTwo(a2))

		a3, err := m.GenActThree()
		must(err)
		_, err = out.Write(a3[:])
		must(err)
		must(outw.Flush())
	} else {
		var a1 [brontide.ActOneSize]byte
		_, err := io.ReadFull(in, a1[:])
		must(err)
		must(m.RecvActOne(a1))

		a2, err := m.GenActTwo()
		must(err)
		_, err = out.Write(a2[:])
		must(err)
		must(outw.Flush())

		var a3 [brontide.ActThreeSize]byte
		_, err = io.ReadFull(in, a3[:])
		must(err)
		must(m.RecvActThree(a3))
	}
	fmt.Fprintf(os.Stderr, "go: handshake ok (initiator=%v)\n", initiator)

	send := func(i int) {
		tag := "i2r"
		if !initiator {
			tag = "r2i"
		}
		p := payload(tag, i)
		must(m.WriteMessage(p))
		_, err := m.Flush(out)
		must(err)
		must(outw.Flush())
	}
	recv := func(i int) {
		tag := "r2i"
		if !initiator {
			tag = "i2r"
		}
		want := payload(tag, i)
		pktLen, err := m.ReadHeader(in)
		must(err)
		if int(pktLen) != len(want)+16 {
			fatal(fmt.Sprintf("msg %d: header says %d, want %d", i, pktLen, len(want)+16))
		}
		buf := make([]byte, pktLen)
		got, err := m.ReadBody(in, buf)
		must(err)
		if string(got) != string(want) {
			fatal(fmt.Sprintf("msg %d: body mismatch (%d bytes)", i, len(got)))
		}
	}

	for i := 0; i < *n; i++ {
		if initiator {
			send(i)
			recv(i)
		} else {
			recv(i)
			send(i)
		}
	}
	must(outw.Flush())
	fmt.Fprintf(os.Stderr, "go: OK %d msgs each way; wire-out sha256=%s\n",
		*n, hex.EncodeToString(wireHash.Sum(nil)))
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "go: FATAL %v\n", err)
		os.Exit(3)
	}
}

func fatal(s string) {
	fmt.Fprintf(os.Stderr, "go: FATAL %s\n", s)
	os.Exit(3)
}
