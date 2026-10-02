// Command tsslib-oracle: key-material interop oracle between the Zig module
// threshold_ecdsa and bnb-chain/tss-lib v3 (MIT). See README.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v3/common"
	"github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v3/test"
	"github.com/bnb-chain/tss-lib/v3/tss"
)

const (
	nParties  = 3
	threshold = 1 // tss-lib threshold; t-1 in the interchange format (2 signers)
)

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "tsslib-oracle: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fatal("usage: tsslib-oracle keygen|sign|zigvectors [flags]")
	}
	switch os.Args[1] {
	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		keys := fs.String("keys", "", "output key material JSON")
		sigs := fs.String("sigs", "", "output signatures JSON")
		fs.Parse(os.Args[2:])
		if *keys == "" || *sigs == "" {
			fatal("keygen needs -keys and -sigs")
		}
		cmdKeygen(*keys, *sigs)
	case "sign":
		fs := flag.NewFlagSet("sign", flag.ExitOnError)
		keys := fs.String("keys", "", "input key material JSON")
		sigs := fs.String("sigs", "", "output signatures JSON")
		fs.Parse(os.Args[2:])
		if *keys == "" || *sigs == "" {
			fatal("sign needs -keys and -sigs")
		}
		cmdSign(*keys, *sigs)
	case "zigvectors":
		fs := flag.NewFlagSet("zigvectors", flag.ExitOnError)
		a := fs.String("tsslib-keys", "", "")
		b := fs.String("tsslib-sigs", "", "")
		c := fs.String("zig-keys", "", "")
		d := fs.String("zig-sigs", "", "")
		fs.Parse(os.Args[2:])
		cmdZigVectors(*a, *b, *c, *d)
	default:
		fatal("unknown subcommand %q", os.Args[1])
	}
}

func cmdSign(keysPath, sigsPath string) {
	var ks KeySet
	if err := readJSON(keysPath, &ks); err != nil {
		fatal("%v", err)
	}
	if int(ks.T) != threshold+1 {
		fatal("this oracle signs with t=%d only, got t=%d", threshold+1, ks.T)
	}
	saves, err := importKeys(&ks)
	if err != nil {
		fatal("import: %v", err)
	}
	sf, err := signAll(saves, int(ks.T)-1)
	if err != nil {
		fatal("%v", err)
	}
	if err := writeJSON(sigsPath, sf); err != nil {
		fatal("%v", err)
	}
}

func cmdKeygen(keysPath, sigsPath string) {
	ids := make(tss.UnSortedPartyIDs, nParties)
	for i := range ids {
		k := int64(i + 1)
		ids[i] = tss.NewPartyID(fmt.Sprint(k), fmt.Sprintf("P%d", k), big.NewInt(k))
	}
	sorted := tss.SortPartyIDs(ids)

	// slow: 4 safe primes of 1024 bits per party
	pre := make([]*keygen.LocalPreParams, nParties)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var genErr error
	for i := range pre {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
			defer cancel()
			p, err := keygen.GeneratePreParamsWithContext(ctx, 1)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				genErr = err
				return
			}
			pre[i] = p
			fmt.Fprintf(os.Stderr, "pre-params %d/%d generated\n", i+1, nParties)
		}(i)
	}
	wg.Wait()
	if genErr != nil {
		fatal("pre-params: %v", genErr)
	}

	ctx := tss.NewPeerContext(sorted)
	errCh := make(chan *tss.Error, nParties)
	outCh := make(chan tss.Message, nParties*nParties*2)
	endCh := make(chan *keygen.LocalPartySaveData, nParties)
	parties := make([]*keygen.LocalParty, nParties)
	for i, pid := range sorted {
		params := tss.NewParameters(tss.S256(), ctx, pid, nParties, threshold)
		parties[i] = keygen.NewLocalParty(params, outCh, endCh, *pre[i]).(*keygen.LocalParty)
	}
	for _, p := range parties {
		go func(p *keygen.LocalParty) {
			if e := p.Start(); e != nil {
				errCh <- e
			}
		}(p)
	}
	var saves []keygen.LocalPartySaveData
	timeout := time.After(15 * time.Minute)
	for len(saves) < nParties {
		select {
		case e := <-errCh:
			fatal("keygen: %v", e)
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
			saves = append(saves, *sd)
		case <-timeout:
			fatal("keygen timed out")
		}
	}
	common.Logger.Info("keygen done")
	ks, err := exportKeys(saves, threshold+1)
	if err != nil {
		fatal("export: %v", err)
	}
	if err := writeJSON(keysPath, ks); err != nil {
		fatal("%v", err)
	}
	sf, err := signAll(saves, threshold)
	if err != nil {
		fatal("%v", err)
	}
	if err := writeJSON(sigsPath, sf); err != nil {
		fatal("%v", err)
	}
}
