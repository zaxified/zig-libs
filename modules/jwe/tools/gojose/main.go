// SPDX-License-Identifier: MIT

// The foreign side of `modules/jwe/tools/interop.zig`: go-jose v4 (Apache-2.0, a black-box peer; its source is not
// copied) reads and writes JWE JSON serializations with the keys the Zig program generated.
//
//	gojose -mode decrypt -keys keys.json -in ours.jsonl
//	    every line is a document written by `jwe.encryptJsonRecipients`; for every recipient slot of the line the
//	    matching key must open it (`DecryptMulti` returns that recipient's index) to the line's plaintext.
//	gojose -mode encrypt -keys keys.json -out theirs.jsonl
//	    writes go-jose's own multi-recipient (general) and single-recipient (flattened) documents, with and without
//	    an `aad` member, for `jwe.decryptJson` to open.
//
// The recipient slots are shared with the Zig side:
//
//	0 A128KW  1 A256KW  2 A128GCMKW  3 RSA-OAEP  4 RSA-OAEP-256  5 ECDH-ES+A128KW  6 PBES2-HS256+A128KW
//	7 ECDH-ES (direct: a sole recipient only)
//
// Exit 0 = every document agreed.
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	jose "github.com/go-jose/go-jose/v4"
)

type keyFile struct {
	A128KW    string          `json:"a128kw"`
	A256KW    string          `json:"a256kw"`
	A128GCMKW string          `json:"a128gcmkw"`
	Password  string          `json:"password"`
	RSAPem    string          `json:"rsa_pem"`
	EC        json.RawMessage `json:"ec"`
}

type line struct {
	Name      string `json:"name"`
	Plaintext string `json:"plaintext"`
	Doc       string `json:"doc"`
	Slots     []int  `json:"slots"`
}

var slotAlgs = []jose.KeyAlgorithm{
	jose.A128KW, jose.A256KW, jose.A128GCMKW, jose.RSA_OAEP, jose.RSA_OAEP_256,
	jose.ECDH_ES_A128KW, jose.PBES2_HS256_A128KW, jose.ECDH_ES,
}

var encs = []jose.ContentEncryption{jose.A128GCM, jose.A256GCM, jose.A128CBC_HS256, jose.A256CBC_HS512}

type keys struct {
	sym  [3][]byte
	pass []byte
	rsa  *rsa.PrivateKey
	ec   *ecdsa.PrivateKey
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "gojose: "+format+"\n", a...)
	os.Exit(2)
}

func loadKeys(path string) *keys {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal("%v", err)
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		fatal("keys: %v", err)
	}
	k := &keys{pass: []byte(kf.Password)}
	for i, h := range []string{kf.A128KW, kf.A256KW, kf.A128GCMKW} {
		if k.sym[i], err = hex.DecodeString(h); err != nil {
			fatal("keys: %v", err)
		}
	}
	block, _ := pem.Decode([]byte(kf.RSAPem))
	if block == nil {
		fatal("keys: no PEM block")
	}
	if k.rsa, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		fatal("keys: rsa: %v", err)
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(kf.EC); err != nil {
		fatal("keys: ec: %v", err)
	}
	var ok bool
	if k.ec, ok = jwk.Key.(*ecdsa.PrivateKey); !ok {
		fatal("keys: ec is not an ECDSA private key")
	}
	return k
}

// private is the decryption key of a slot, public the encryption key.
func (k *keys) private(slot int) any {
	switch slot {
	case 0, 1, 2:
		return k.sym[slot]
	case 3, 4:
		return k.rsa
	case 5, 7:
		return k.ec
	default:
		return k.pass
	}
}

func (k *keys) recipient(slot int) jose.Recipient {
	r := jose.Recipient{Algorithm: slotAlgs[slot]}
	switch slot {
	case 0, 1, 2:
		r.Key = k.sym[slot]
	case 3, 4:
		r.Key = &k.rsa.PublicKey
	case 5, 7:
		r.Key = &k.ec.PublicKey
	default:
		r.Key = k.pass
		r.PBES2Count = 10000
	}
	return r
}

func decrypt(k *keys, in string) int {
	f, err := os.Open(in)
	if err != nil {
		fatal("%v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	bad, n := 0, 0
	for sc.Scan() {
		var l line
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			fatal("input: %v", err)
		}
		obj, err := jose.ParseEncrypted(l.Doc, slotAlgs, encs)
		if err != nil {
			fmt.Printf("FAIL %s: parse: %v\n", l.Name, err)
			bad++
			continue
		}
		// Every recipient shares the one CEK, so DecryptMulti on the whole document returns the first recipient a
		// key opens, not the one meant. Each recipient is therefore also opened alone, in a document that carries
		// only its entry.
		var raw map[string]json.RawMessage
		var recs []json.RawMessage
		if len(l.Slots) > 1 {
			if json.Unmarshal([]byte(l.Doc), &raw) != nil || json.Unmarshal(raw["recipients"], &recs) != nil || len(recs) != len(l.Slots) {
				fmt.Printf("FAIL %s: not a general document of %d recipients\n", l.Name, len(l.Slots))
				bad++
				continue
			}
		}
		for pos, slot := range l.Slots {
			n++
			one := obj
			if recs != nil {
				single, _ := json.Marshal([]json.RawMessage{recs[pos]})
				raw["recipients"] = single
				doc, _ := json.Marshal(raw)
				if one, err = jose.ParseEncrypted(string(doc), slotAlgs, encs); err != nil {
					fmt.Printf("FAIL %s slot %d: parse alone: %v\n", l.Name, slot, err)
					bad++
					continue
				}
			}
			_, _, pt, err := one.DecryptMulti(k.private(slot))
			switch {
			case err != nil:
				fmt.Printf("FAIL %s slot %d (%s): %v\n", l.Name, slot, slotAlgs[slot], err)
				bad++
			case !bytes.Equal(pt, []byte(l.Plaintext)):
				fmt.Printf("FAIL %s slot %d: plaintext differs\n", l.Name, slot)
				bad++
			}
		}
	}
	fmt.Printf("gojose decrypt: %d recipient openings, %d failed\n", n, bad)
	return bad
}

func encrypt(k *keys, out string) {
	f, err := os.Create(out)
	if err != nil {
		fatal("%v", err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	emit := func(name string, slots []int, enc jose.ContentEncryption, aad []byte) {
		pt := "go-jose to zig-libs: " + name
		var obj *jose.JSONWebEncryption
		var err error
		if len(slots) == 1 {
			var e jose.Encrypter
			if e, err = jose.NewEncrypter(enc, k.recipient(slots[0]), nil); err == nil {
				obj, err = e.EncryptWithAuthData([]byte(pt), aad)
			}
		} else {
			rs := make([]jose.Recipient, len(slots))
			for i, s := range slots {
				rs[i] = k.recipient(s)
			}
			var e jose.Encrypter
			if e, err = jose.NewMultiEncrypter(enc, rs, nil); err == nil {
				obj, err = e.EncryptWithAuthData([]byte(pt), aad)
			}
		}
		if err != nil {
			fatal("%s: %v", name, err)
		}
		b, _ := json.Marshal(line{Name: name, Plaintext: pt, Doc: obj.FullSerialize(), Slots: slots})
		w.Write(b)
		w.WriteByte('\n')
	}
	for _, enc := range encs {
		for _, aad := range [][]byte{nil, []byte("additional authenticated data")} {
			tag := "noaad"
			if aad != nil {
				tag = "aad"
			}
			emit(fmt.Sprintf("general/%s/%s", enc, tag), []int{0, 1, 2, 3, 4, 5, 6}, enc, aad)
		}
		for slot := range slotAlgs {
			emit(fmt.Sprintf("flattened/%s/%s", slotAlgs[slot], enc), []int{slot}, enc, nil)
		}
	}
}

func main() {
	mode := flag.String("mode", "", "decrypt | encrypt")
	keyPath := flag.String("keys", "", "keys.json")
	in := flag.String("in", "", "decrypt: documents written by the Zig side")
	out := flag.String("out", "", "encrypt: documents for the Zig side")
	flag.Parse()
	k := loadKeys(*keyPath)
	switch *mode {
	case "decrypt":
		if decrypt(k, *in) != 0 {
			os.Exit(1)
		}
	case "encrypt":
		encrypt(k, *out)
	default:
		fatal("unknown mode %q", *mode)
	}
}
