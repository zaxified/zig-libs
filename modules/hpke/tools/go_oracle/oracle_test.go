// SPDX-License-Identifier: MIT
//
// Go side of `zig build interop-hpke` (modules/hpke/tools/interop.zig): the
// Go 1.26 standard library's crypto/hpke (the scope reference; standard
// library only, no third-party module) as a live oracle.
//
// This is a TEST binary on purpose: testing/cryptotest.SetGlobalRandom, the
// only supported way to make Go's ephemeral keys reproducible, refuses to run
// outside one. The Zig program builds it with `go test -c` and runs it twice,
// the directory, mode and seed handed over in the environment (the test
// skips itself when HPKE_ORACLE_MODE is unset, so a plain `go test` or `go
// vet` here is harmless):
//
//	seal   plan.tsv   -> go_sealed.tsv   Go is the SENDER: it encapsulates to
//	                                     the recipient key the plan names
//	                                     (its ephemeral key is foreign to the
//	                                     Zig side), seals the messages in
//	                                     order and exports.
//	judge  judge.tsv  -> go_verdicts.tsv Go is the RECIPIENT of whatever
//	                                     (enc, ciphertexts) the table holds,
//	                                     sealed by either side or mutated.
//
// Everything on the wire is lowercase hex inside tab-separated lines; lists
// are comma-separated, a pair inside a list is colon-separated. A suite is
// "<kem>/<kdf>/<aead>". A verdict is "E" (the recipient could not be set up)
// or "K|<messages>|<exports>", a message "o<plaintext hex>" or "x" (refused),
// an export its hex or "x".
package oracle

import (
	"bufio"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"testing/cryptotest"
)

type suite struct {
	kem  hpke.KEM
	kdf  hpke.KDF
	aead hpke.AEAD
}

func parseSuite(name string) suite {
	p := strings.Split(name, "/")
	if len(p) != 3 {
		panic("bad suite " + name)
	}
	var s suite
	switch p[0] {
	case "x25519":
		s.kem = hpke.DHKEM(ecdh.X25519())
	case "p256":
		s.kem = hpke.DHKEM(ecdh.P256())
	case "p384":
		s.kem = hpke.DHKEM(ecdh.P384())
	case "p521":
		s.kem = hpke.DHKEM(ecdh.P521())
	case "mlkem768":
		s.kem = hpke.MLKEM768()
	case "mlkem1024":
		s.kem = hpke.MLKEM1024()
	case "xwing":
		s.kem = hpke.MLKEM768X25519()
	case "mlkem768p256":
		s.kem = hpke.MLKEM768P256()
	case "mlkem1024p384":
		s.kem = hpke.MLKEM1024P384()
	default:
		panic("bad kem " + p[0])
	}
	switch p[1] {
	case "hkdf-sha256":
		s.kdf = hpke.HKDFSHA256()
	case "hkdf-sha384":
		s.kdf = hpke.HKDFSHA384()
	case "hkdf-sha512":
		s.kdf = hpke.HKDFSHA512()
	case "shake128":
		s.kdf = hpke.SHAKE128()
	case "shake256":
		s.kdf = hpke.SHAKE256()
	default:
		panic("bad kdf " + p[1])
	}
	switch p[2] {
	case "aes128gcm":
		s.aead = hpke.AES128GCM()
	case "aes256gcm":
		s.aead = hpke.AES256GCM()
	case "chacha20poly1305":
		s.aead = hpke.ChaCha20Poly1305()
	case "exportonly":
		s.aead = hpke.ExportOnly()
	default:
		panic("bad aead " + p[2])
	}
	return s
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// list splits a comma-separated field; the empty field is the empty list.
func list(f string) []string {
	if f == "" {
		return nil
	}
	return strings.Split(f, ",")
}

func pair(item string) (string, string) {
	a, b, ok := strings.Cut(item, ":")
	if !ok {
		panic("bad pair " + item)
	}
	return a, b
}

func lines(path string, fn func(f []string)) {
	fh, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	for sc.Scan() {
		fn(strings.Split(sc.Text(), "\t"))
	}
	if err := sc.Err(); err != nil {
		panic(err)
	}
}

func export(ctx hpkeContext, item string) string {
	cx, n := pair(item)
	length, err := strconv.Atoi(n)
	if err != nil {
		panic(err)
	}
	out, err := ctx.Export(string(unhex(cx)), length)
	if err != nil {
		return "x"
	}
	return hex.EncodeToString(out)
}

type hpkeContext interface {
	Export(exporterContext string, length int) ([]byte, error)
}

// seal: id, suite, sk, info, msgs (aad:pt), exps (ctx:len)
//
//	-> id, enc, cts, export outputs
func doSeal(dir string) {
	out, err := os.Create(filepath.Join(dir, "go_sealed.tsv"))
	if err != nil {
		panic(err)
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	defer w.Flush()
	lines(filepath.Join(dir, "plan.tsv"), func(f []string) {
		s := parseSuite(f[1])
		sk, err := s.kem.NewPrivateKey(unhex(f[2]))
		if err != nil {
			panic(err)
		}
		enc, snd, err := hpke.NewSender(sk.PublicKey(), s.kdf, s.aead, unhex(f[3]))
		if err != nil {
			panic(err)
		}
		var cts, exps []string
		for _, m := range list(f[4]) {
			aad, pt := pair(m)
			ct, err := snd.Seal(unhex(aad), unhex(pt))
			if err != nil {
				panic(err)
			}
			cts = append(cts, hex.EncodeToString(ct))
		}
		for _, e := range list(f[5]) {
			exps = append(exps, export(snd, e))
		}
		fmt.Fprintf(w, "%s\t%x\t%s\t%s\n", f[0], enc, strings.Join(cts, ","), strings.Join(exps, ","))
	})
}

// judge: id, suite, sk, info, enc, msgs (aad:ct), exps (ctx:len) -> id, verdict
func doJudge(dir string) {
	out, err := os.Create(filepath.Join(dir, "go_verdicts.tsv"))
	if err != nil {
		panic(err)
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	defer w.Flush()
	lines(filepath.Join(dir, "judge.tsv"), func(f []string) {
		s := parseSuite(f[1])
		sk, err := s.kem.NewPrivateKey(unhex(f[2]))
		if err != nil {
			panic(err)
		}
		rcv, err := hpke.NewRecipient(unhex(f[4]), sk, s.kdf, s.aead, unhex(f[3]))
		if err != nil {
			fmt.Fprintf(w, "%s\tE\n", f[0])
			return
		}
		var msgs, exps []string
		for _, m := range list(f[5]) {
			aad, ct := pair(m)
			pt, err := rcv.Open(unhex(aad), unhex(ct))
			if err != nil {
				msgs = append(msgs, "x")
			} else {
				msgs = append(msgs, "o"+hex.EncodeToString(pt))
			}
		}
		for _, e := range list(f[6]) {
			exps = append(exps, export(rcv, e))
		}
		fmt.Fprintf(w, "%s\tK|%s|%s\n", f[0], strings.Join(msgs, ","), strings.Join(exps, ","))
	})
}

func TestOracle(t *testing.T) {
	mode := os.Getenv("HPKE_ORACLE_MODE")
	if mode == "" {
		t.Skip("HPKE_ORACLE_MODE unset: this is the Zig interop program's peer")
	}
	dir := os.Getenv("HPKE_ORACLE_DIR")
	seed, err := strconv.ParseUint(os.Getenv("HPKE_ORACLE_SEED"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	cryptotest.SetGlobalRandom(t, seed)
	_ = os.WriteFile(filepath.Join(dir, "go_banner.txt"), []byte("Go crypto/hpke, "+runtime.Version()), 0o644)
	switch mode {
	case "seal":
		doSeal(dir)
	case "judge":
		doJudge(dir)
	default:
		t.Fatal("unknown mode " + mode)
	}
}
