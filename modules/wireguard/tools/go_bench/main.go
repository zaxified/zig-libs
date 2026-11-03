// SPDX-License-Identifier: MIT

// Go side of `zig build bench-wireguard` (modules/wireguard/tools/bench.zig): the
// reference, wireguard-go b3bc704ef0ee, over the inputs the Zig program wrote
// into the directory given as the first argument, for the workload named by the
// second. Prints one line: name, ns/op, count (tab-separated).
//
//	go.seal_<n>    what RoutineReadFromTUN + RoutineEncryption do per packet, in one
//	               thread: the counter, pad to 16, header, the AEAD wireguard-go's
//	               keypair holds (x/crypto chacha20poly1305). Its queues, goroutines
//	               and locks are not in the time; ours has no such thing to leave out.
//	go.open_<n>    RoutineDecryption + RoutineSequentialReceiver per packet: header
//	               parse, AEAD open, device/replay's filter, the inner IP length, of
//	               the next of 64 messages sealed with counters 0..63 (the filter is
//	               reset once per 64, in the time, as on our side).
//	go.handshake   the real Device API, both roles: CreateMessageInitiation, AddMacs,
//	               CheckMAC1, ConsumeMessageInitiation, CreateMessageResponse,
//	               AddMacs, BeginSymmetricSession, CheckMAC1, ConsumeMessageResponse,
//	               BeginSymmetricSession. Its flood and replay checks would refuse a
//	               second initiation in the same 50 ms: `rearm` clears the two fields
//	               they read, by reflection, per op, in the time (about 10 ns).
//
// Timing matches the Zig side: double the batch until it takes over 100 ms, then
// keep the best of five.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/replay"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

const (
	transportType = 4
	headerLen     = 16
	tagLen        = 16
	padTo         = 16
	ringLen       = 64
	rejectAfter   = ^uint64(0) - (1 << 13)
	banner        = "wireguard-go b3bc704ef0ee, " // the Go version follows
)

var sink uint64

func die(err any) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func timeIt(f func() uint64) (float64, uint64) {
	n := 1
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			sink += f()
		}
		if time.Since(t) > 100*time.Millisecond {
			break
		}
		n *= 2
	}
	best := time.Duration(1<<63 - 1)
	var count uint64
	for k := 0; k < 5; k++ {
		t := time.Now()
		for i := 0; i < n; i++ {
			count = f()
		}
		if d := time.Since(t); d < best {
			best = d
		}
	}
	return float64(best.Nanoseconds()) / float64(n), count
}

func readFile(dir, name string) []byte {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		die(err)
	}
	return b
}

func sealedLen(n int) int {
	pad := (padTo - n%padTo) % padTo
	return headerLen + n + pad + tagLen
}

// sealInto is wireguard-go's per-packet send work; out is reused.
func sealInto(aead interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
}, out, msg []byte, receiver uint32, counter uint64) int {
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint32(out[0:4], transportType)
	binary.LittleEndian.PutUint32(out[4:8], receiver)
	binary.LittleEndian.PutUint64(out[8:16], counter)
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	content := out[headerLen : headerLen+len(msg)]
	copy(content, msg)
	pad := (padTo - len(msg)%padTo) % padTo
	for i := 0; i < pad; i++ {
		out[headerLen+len(msg)+i] = 0
	}
	content = out[headerLen : headerLen+len(msg)+pad]
	sealed := aead.Seal(out[:headerLen], nonce[:], content, nil)
	return len(sealed)
}

func innerLength(p []byte) int {
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			die("short v4 packet")
		}
		return int(binary.BigEndian.Uint16(p[2:4]))
	}
	die("not IPv4")
	return 0
}

type party struct {
	dev *device.Device
	// the other side's key, the same peer object through the whole run
	peer *device.Peer
	gen  device.CookieGenerator
	chk  device.CookieChecker
	// addresses of the two fields the flood and replay checks read
	lastTS *[12]byte
	lastIn *time.Time
}

func pubOf(priv *device.NoisePrivateKey) device.NoisePublicKey {
	// The UAPI gives no public key; the protocol's own derivation does it.
	dev := newBare()
	defer dev.Close()
	if err := dev.IpcSet("private_key=" + hex.EncodeToString(priv[:]) + "\n"); err != nil {
		die(err)
	}
	return readPublicKey(dev)
}

func readPublicKey(dev *device.Device) device.NoisePublicKey {
	// unexported staticIdentity.publicKey, read by reflection: a bench, not an API.
	v := reflect.ValueOf(dev).Elem().FieldByName("staticIdentity").FieldByName("publicKey")
	return *(*device.NoisePublicKey)(unsafe.Pointer(v.UnsafeAddr()))
}

func newBare() *device.Device {
	binds := bindtest.NewChannelBinds()
	return device.NewDevice(tuntest.NewChannelTUN().TUN(), binds[0], device.NewLogger(device.LogLevelSilent, ""))
}

func newParty(priv *device.NoisePrivateKey, ours, theirs device.NoisePublicKey) *party {
	dev := newBare()
	if err := dev.Up(); err != nil {
		die(err)
	}
	conf := "private_key=" + hex.EncodeToString(priv[:]) + "\npublic_key=" + hex.EncodeToString(theirs[:]) + "\nallowed_ip=10.0.0.1/32\n"
	if err := dev.IpcSet(conf); err != nil {
		die(err)
	}
	peer := dev.LookupPeer(theirs)
	if peer == nil {
		die("no peer")
	}
	p := &party{dev: dev, peer: peer}
	p.gen.Init(theirs)
	p.chk.Init(ours)
	h := reflect.ValueOf(peer).Elem().FieldByName("handshake")
	p.lastTS = (*[12]byte)(unsafe.Pointer(h.FieldByName("lastTimestamp").UnsafeAddr()))
	p.lastIn = (*time.Time)(unsafe.Pointer(h.FieldByName("lastInitiationConsumption").UnsafeAddr()))
	return p
}

func (p *party) rearm() {
	*p.lastTS = [12]byte{}
	*p.lastIn = time.Time{}
}

func handshakeOp(a, b *party) uint64 {
	b.rearm()
	m1, err := a.dev.CreateMessageInitiation(a.peer)
	if err != nil {
		die(err)
	}
	p1 := (*[device.MessageInitiationSize]byte)(unsafe.Pointer(m1))[:]
	a.gen.AddMacs(p1)
	if !b.chk.CheckMAC1(p1) {
		die("mac1 of the initiation")
	}
	if b.dev.ConsumeMessageInitiation(m1) == nil {
		die("initiation refused")
	}
	m2, err := b.dev.CreateMessageResponse(b.peer)
	if err != nil {
		die(err)
	}
	p2 := (*[device.MessageResponseSize]byte)(unsafe.Pointer(m2))[:]
	b.gen.AddMacs(p2)
	if err := b.peer.BeginSymmetricSession(); err != nil {
		die(err)
	}
	if !a.chk.CheckMAC1(p2) {
		die("mac1 of the response")
	}
	if a.dev.ConsumeMessageResponse(m2) == nil {
		die("response refused")
	}
	if err := a.peer.BeginSymmetricSession(); err != nil {
		die(err)
	}
	return device.MessageInitiationSize + device.MessageResponseSize
}

func main() {
	if len(os.Args) != 3 {
		die("usage: go_bench <work dir> <workload>")
	}
	dir, name := os.Args[1], os.Args[2]
	fmt.Fprintln(os.Stderr, banner+"x/crypto v0.37.0")

	key := readFile(dir, "key.bin")
	receiver := binary.LittleEndian.Uint32(readFile(dir, "receiver.bin"))
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		die(err)
	}

	switch {
	case name == "go.interop":
		msg := readFile(dir, "msg1424.bin")
		out := make([]byte, sealedLen(len(msg)))
		n := sealInto(aead, out, msg, receiver, 0)
		if err := os.WriteFile(filepath.Join(dir, "go_sealed_1424.bin"), out[:n], 0o644); err != nil {
			die(err)
		}
		return
	case strings.HasPrefix(name, "go.seal_"):
		size, _ := strconv.Atoi(strings.TrimPrefix(name, "go.seal_"))
		msg := readFile(dir, fmt.Sprintf("msg%d.bin", size))
		out := make([]byte, sealedLen(size))
		var counter uint64
		ns, count := timeIt(func() uint64 {
			n := sealInto(aead, out, msg, receiver, counter)
			counter++
			return uint64(n)
		})
		fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
	case strings.HasPrefix(name, "go.open_"):
		size, _ := strconv.Atoi(strings.TrimPrefix(name, "go.open_"))
		msg := readFile(dir, fmt.Sprintf("msg%d.bin", size))
		ring := make([][]byte, ringLen)
		for i := range ring {
			ring[i] = make([]byte, sealedLen(size))
			sealInto(aead, ring[i], msg, receiver, uint64(i))
		}
		plain := make([]byte, sealedLen(size))
		var filter replay.Filter
		pos := 0
		var nonce [chacha20poly1305.NonceSize]byte
		ns, count := timeIt(func() uint64 {
			if pos == ringLen {
				filter.Reset()
				pos = 0
			}
			m := ring[pos]
			pos++
			if binary.LittleEndian.Uint32(m[0:4]) != transportType || binary.LittleEndian.Uint32(m[4:8]) != receiver {
				die("header")
			}
			counter := binary.LittleEndian.Uint64(m[8:16])
			binary.LittleEndian.PutUint64(nonce[4:], counter)
			out, err := aead.Open(plain[:0], nonce[:], m[headerLen:], nil)
			if err != nil {
				die(err)
			}
			if !filter.ValidateCounter(counter, rejectAfter) {
				die("replay")
			}
			return uint64(innerLength(out))
		})
		fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
	case strings.HasPrefix(name, "go.aead_seal_"):
		size, _ := strconv.Atoi(strings.TrimPrefix(name, "go.aead_seal_"))
		msg := readFile(dir, fmt.Sprintf("msg%d.bin", size))
		out := make([]byte, size+tagLen)
		var nonce [chacha20poly1305.NonceSize]byte
		ns, count := timeIt(func() uint64 { return uint64(len(aead.Seal(out[:0], nonce[:], msg, nil))) })
		fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
	case strings.HasPrefix(name, "go.aead_open_"):
		size, _ := strconv.Atoi(strings.TrimPrefix(name, "go.aead_open_"))
		msg := readFile(dir, fmt.Sprintf("msg%d.bin", size))
		var nonce [chacha20poly1305.NonceSize]byte
		ct := aead.Seal(nil, nonce[:], msg, nil)
		out := make([]byte, size)
		ns, count := timeIt(func() uint64 {
			p, err := aead.Open(out[:0], nonce[:], ct, nil)
			if err != nil {
				die(err)
			}
			return uint64(len(p) + tagLen)
		})
		fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
	case name == "go.handshake":
		var si, sr device.NoisePrivateKey
		copy(si[:], readFile(dir, "s_i.bin"))
		copy(sr[:], readFile(dir, "s_r.bin"))
		pi := pubOf(&si)
		pr := pubOf(&sr)
		a := newParty(&si, pi, pr)
		b := newParty(&sr, pr, pi)
		ns, count := timeIt(func() uint64 { return handshakeOp(a, b) })
		fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
	default:
		die("unknown workload " + name)
	}
}
