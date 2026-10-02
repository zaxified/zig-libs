package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/bnb-chain/tss-lib/v3/common"
	"github.com/bnb-chain/tss-lib/v3/crypto"
	"github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v3/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v3/test"
	"github.com/bnb-chain/tss-lib/v3/tss"
)

const message = "zig-libs threshold_ecdsa / tss-lib interop v1"

// ---- interchange format ----

type Party struct {
	Index     uint32 `json:"index"`
	X         string `json:"x"`
	BigX      string `json:"big_x"`
	PaillierP string `json:"paillier_p"`
	PaillierQ string `json:"paillier_q"`
	NTilde    string `json:"n_tilde"`
	H1        string `json:"h1"`
	H2        string `json:"h2"`
	AuxPSafe  string `json:"aux_p_safe"`
	AuxQSafe  string `json:"aux_q_safe"`
	AuxLambda string `json:"aux_lambda"`
}

type KeySet struct {
	T         uint32  `json:"t"`
	N         uint32  `json:"n"`
	PublicKey string  `json:"public_key"`
	Parties   []Party `json:"parties"`
}

type Sig struct {
	Signers []uint32 `json:"signers"`
	R       string   `json:"r"`
	S       string   `json:"s"`
}

type SigFile struct {
	Message    string `json:"message"`
	Signatures []Sig  `json:"signatures"`
}

func hexN(v *big.Int, size int) string {
	if size == 0 {
		return hex.EncodeToString(v.Bytes())
	}
	return hex.EncodeToString(v.FillBytes(make([]byte, size)))
}

func unhex(s string) (*big.Int, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func compress(p *crypto.ECPoint) string {
	var fx, fy btcec.FieldVal
	fx.SetByteSlice(p.X().FillBytes(make([]byte, 32)))
	fy.SetByteSlice(p.Y().FillBytes(make([]byte, 32)))
	return hex.EncodeToString(btcec.NewPublicKey(&fx, &fy).SerializeCompressed())
}

func decompress(s string) (*crypto.ECPoint, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	pk, err := btcec.ParsePubKey(b)
	if err != nil {
		return nil, err
	}
	return crypto.NewECPoint(tss.S256(), pk.X(), pk.Y())
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// ---- export (tss-lib save data -> interchange) ----

// exportKeys maps tss-lib save data (one entry per party, any order) to the
// interchange format. tss-lib's LocalPreParams.P/Q are the Sophie Germain
// primes p', q' (safe primes are 2p'+1, 2q'+1); Alpha is the discrete log
// h2 = h1^Alpha mod NTilde.
func exportKeys(saves []keygen.LocalPartySaveData, t int) (*KeySet, error) {
	ks := &KeySet{T: uint32(t), N: uint32(len(saves)), PublicKey: compress(saves[0].ECDSAPub)}
	one := big.NewInt(1)
	for _, sd := range saves {
		if compress(sd.ECDSAPub) != ks.PublicKey {
			return nil, fmt.Errorf("parties disagree on the group public key")
		}
		pk := sd.PaillierSK
		pSafe := new(big.Int).Add(new(big.Int).Lsh(sd.P, 1), one)
		qSafe := new(big.Int).Add(new(big.Int).Lsh(sd.Q, 1), one)
		if new(big.Int).Mul(pSafe, qSafe).Cmp(sd.NTildei) != 0 {
			return nil, fmt.Errorf("NTilde != (2P+1)(2Q+1): P/Q semantics wrong")
		}
		bigX := crypto.ScalarBaseMult(tss.S256(), sd.Xi)
		ks.Parties = append(ks.Parties, Party{
			Index:     uint32(sd.ShareID.Uint64()),
			X:         hexN(sd.Xi, 32),
			BigX:      compress(bigX),
			PaillierP: hexN(pk.P, 0),
			PaillierQ: hexN(pk.Q, 0),
			NTilde:    hexN(sd.NTildei, 0),
			H1:        hexN(sd.H1i, 0),
			H2:        hexN(sd.H2i, 0),
			AuxPSafe:  hexN(pSafe, 0),
			AuxQSafe:  hexN(qSafe, 0),
			AuxLambda: hexN(sd.Alpha, 0),
		})
	}
	sort.Slice(ks.Parties, func(i, j int) bool { return ks.Parties[i].Index < ks.Parties[j].Index })
	return ks, nil
}

// ---- import (interchange -> tss-lib save data) ----

func importKeys(ks *KeySet) ([]keygen.LocalPartySaveData, error) {
	n := int(ks.N)
	if len(ks.Parties) != n {
		return nil, fmt.Errorf("n=%d but %d parties", n, len(ks.Parties))
	}
	pub, err := decompress(ks.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("public_key: %w", err)
	}
	parties := append([]Party(nil), ks.Parties...)
	sort.Slice(parties, func(i, j int) bool { return parties[i].Index < parties[j].Index })

	one := big.NewInt(1)
	shared := keygen.NewLocalPartySaveData(n)
	type priv struct {
		pre keygen.LocalPreParams
		xi  *big.Int
		id  *big.Int
	}
	privs := make([]priv, n)
	for j, p := range parties {
		get := func(name, s string) *big.Int {
			if err != nil {
				return nil
			}
			var v *big.Int
			v, err = unhex(s)
			if err != nil {
				err = fmt.Errorf("party %d %s: %w", p.Index, name, err)
			}
			return v
		}
		x := get("x", p.X)
		pp, qq := get("paillier_p", p.PaillierP), get("paillier_q", p.PaillierQ)
		nt, h1, h2 := get("n_tilde", p.NTilde), get("h1", p.H1), get("h2", p.H2)
		ps, qs, lam := get("aux_p_safe", p.AuxPSafe), get("aux_q_safe", p.AuxQSafe), get("aux_lambda", p.AuxLambda)
		if err != nil {
			return nil, err
		}
		bigX, e := decompress(p.BigX)
		if e != nil {
			return nil, fmt.Errorf("party %d big_x: %w", p.Index, e)
		}
		if !crypto.ScalarBaseMult(tss.S256(), x).Equals(bigX) {
			return nil, fmt.Errorf("party %d: x*G != big_x", p.Index)
		}
		if new(big.Int).Mul(ps, qs).Cmp(nt) != 0 {
			return nil, fmt.Errorf("party %d: aux_p_safe*aux_q_safe != n_tilde", p.Index)
		}
		if new(big.Int).Exp(h1, lam, nt).Cmp(h2) != 0 {
			return nil, fmt.Errorf("party %d: h1^aux_lambda != h2 mod n_tilde", p.Index)
		}
		N := new(big.Int).Mul(pp, qq)
		pm1, qm1 := new(big.Int).Sub(pp, one), new(big.Int).Sub(qq, one)
		phi := new(big.Int).Mul(pm1, qm1)
		g := new(big.Int).GCD(nil, nil, pm1, qm1)
		lambdaN := new(big.Int).Div(phi, g)
		// tss-lib P, Q = Sophie Germain primes p', q'; Beta = Alpha^-1 mod p'q'.
		sgP := new(big.Int).Rsh(ps, 1)
		sgQ := new(big.Int).Rsh(qs, 1)
		beta := new(big.Int).ModInverse(lam, new(big.Int).Mul(sgP, sgQ))
		if beta == nil {
			return nil, fmt.Errorf("party %d: aux_lambda not invertible mod p'q'", p.Index)
		}
		id := big.NewInt(int64(p.Index))
		shared.Ks[j] = id
		shared.NTildej[j], shared.H1j[j], shared.H2j[j] = nt, h1, h2
		shared.BigXj[j] = bigX
		shared.PaillierPKs[j] = pkOf(N)
		privs[j] = priv{
			pre: keygen.LocalPreParams{
				PaillierSK: skOf(N, lambdaN, phi, pp, qq),
				NTildei:    nt, H1i: h1, H2i: h2,
				Alpha: lam, Beta: beta, P: sgP, Q: sgQ,
			},
			xi: x, id: id,
		}
	}
	// sanity: every 2-subset... (generally t-subset of first t) reconstructs the group key
	if err := checkInterpolation(pub, shared.Ks, shared.BigXj, int(ks.T)); err != nil {
		return nil, err
	}
	out := make([]keygen.LocalPartySaveData, n)
	for j := range out {
		sd := shared
		sd.LocalPreParams = privs[j].pre
		sd.Xi, sd.ShareID = privs[j].xi, privs[j].id
		sd.ECDSAPub = pub
		out[j] = sd
	}
	return out, nil
}

// checkInterpolation verifies sum_i lambda_i * X_i == Y over the first t parties.
func checkInterpolation(pub *crypto.ECPoint, ks []*big.Int, bigX []*crypto.ECPoint, t int) error {
	q := tss.S256().Params().N
	modQ := common.ModInt(q)
	var acc *crypto.ECPoint
	for i := 0; i < t; i++ {
		lam := big.NewInt(1)
		for j := 0; j < t; j++ {
			if i == j {
				continue
			}
			lam = modQ.Mul(lam, modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ks[j], ks[i]))))
		}
		term := bigX[i].ScalarMult(lam)
		if acc == nil {
			acc = term
		} else {
			var err error
			if acc, err = acc.Add(term); err != nil {
				return err
			}
		}
	}
	if !acc.Equals(pub) {
		return fmt.Errorf("interpolating big_x of the first %d parties does not give public_key", t)
	}
	return nil
}

// ---- signing ----

func digest() []byte {
	d := sha256.Sum256([]byte(message))
	return d[:]
}

// signAll signs the fixed message with every 2-subset and verifies each
// signature with crypto/ecdsa. threshold is tss-lib's (t-1).
func signAll(saves []keygen.LocalPartySaveData, threshold int) (*SigFile, error) {
	saves = append([]keygen.LocalPartySaveData(nil), saves...)
	sort.Slice(saves, func(i, j int) bool { return saves[i].ShareID.Cmp(saves[j].ShareID) < 0 })
	pub := saves[0].ECDSAPub
	sf := &SigFile{Message: message}
	n := len(saves)
	for a := 0; a < n; a++ {
		for b := a + 1; b < n; b++ {
			subset := []keygen.LocalPartySaveData{saves[a], saves[b]}
			r, s, err := signSubset(subset, threshold)
			if err != nil {
				return nil, fmt.Errorf("signers {%d,%d}: %w", subset[0].ShareID, subset[1].ShareID, err)
			}
			pk := ecdsa.PublicKey{Curve: tss.S256(), X: pub.X(), Y: pub.Y()}
			if !ecdsa.Verify(&pk, digest(), r, s) {
				return nil, fmt.Errorf("signers {%d,%d}: ecdsa.Verify failed", subset[0].ShareID, subset[1].ShareID)
			}
			sf.Signatures = append(sf.Signatures, Sig{
				Signers: []uint32{uint32(subset[0].ShareID.Uint64()), uint32(subset[1].ShareID.Uint64())},
				R:       hexN(r, 32), S: hexN(s, 32),
			})
			fmt.Fprintf(os.Stderr, "signers {%d,%d}: verified\n", subset[0].ShareID, subset[1].ShareID)
		}
	}
	return sf, nil
}

func signSubset(keys []keygen.LocalPartySaveData, threshold int) (r, s *big.Int, err error) {
	ids := make(tss.UnSortedPartyIDs, len(keys))
	for i, k := range keys {
		ids[i] = tss.NewPartyID(k.ShareID.String(), fmt.Sprintf("P%s", k.ShareID), k.ShareID)
	}
	sorted := tss.SortPartyIDs(ids)
	ctx := tss.NewPeerContext(sorted)
	byKey := map[string]keygen.LocalPartySaveData{}
	for _, k := range keys {
		byKey[k.ShareID.String()] = k
	}
	m := new(big.Int).SetBytes(digest())
	errCh := make(chan *tss.Error, len(sorted))
	outCh := make(chan tss.Message, len(sorted)*4)
	endCh := make(chan *common.SignatureData, len(sorted))
	parties := make([]*signing.LocalParty, len(sorted))
	for i, pid := range sorted {
		params := tss.NewParameters(tss.S256(), ctx, pid, len(sorted), threshold)
		parties[i] = signing.NewLocalParty(m, params, byKey[pid.KeyInt().String()], outCh, endCh, 32).(*signing.LocalParty)
	}
	for _, p := range parties {
		go func(p *signing.LocalParty) {
			if e := p.Start(); e != nil {
				errCh <- e
			}
		}(p)
	}
	var sigs []*common.SignatureData
	timeout := time.After(10 * time.Minute)
	for len(sigs) < len(parties) {
		select {
		case e := <-errCh:
			return nil, nil, e
		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, p := range parties {
					if p.PartyID().Index != msg.GetFrom().Index {
						go test.SharedPartyUpdater(p, msg, errCh)
					}
				}
			} else {
				go test.SharedPartyUpdater(parties[dest[0].Index], msg, errCh)
			}
		case sd := <-endCh:
			sigs = append(sigs, sd)
		case <-timeout:
			return nil, nil, fmt.Errorf("signing timed out")
		}
	}
	for _, sd := range sigs[1:] {
		if string(sd.R) != string(sigs[0].R) || string(sd.S) != string(sigs[0].S) {
			return nil, nil, fmt.Errorf("parties produced different signatures")
		}
	}
	r = new(big.Int).SetBytes(sigs[0].R)
	s = new(big.Int).SetBytes(sigs[0].S)
	q := tss.S256().Params().N
	if s.Cmp(new(big.Int).Rsh(q, 1)) > 0 { // low-S (tss-lib already does this; keep explicit)
		s.Sub(q, s)
	}
	return r, s, nil
}
