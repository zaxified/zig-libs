// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-sessions`
// (modules/sessions/tools/bench.zig): times the session middleware of
// github.com/gofiber/fiber/v3 v3.6.1 (middleware/session, with fiber's built-in
// in-memory storage; pinned with its dependencies, fasthttp v1.75.0 among
// them, by go.mod/go.sum) through fiber's public API only, for the one
// workload named by the second argument and the contender named by the third
// (only "fiber" today). The first argument (the Zig side's work directory) is
// unused: like the scs side, the requests are built here, because the cookies
// they carry come from this side's own sessions. Prints one line,
// tab-separated: name, ns/op, count. A workload the contender cannot do prints
// `name<TAB>unsupported` and exits 3 (the Zig side drops the row for it); none
// is unsupported today. One op = 16 requests.
//
//	passthrough  fiber app, a bare handler, no session middleware (net baseline)
//	new_session  no cookie; the handler Sets one value -> Set-Cookie
//	load_read    a valid cookie; the handler Gets the value, writes nothing
//	load_write   a valid cookie; the handler Sets a new value
//	destroy      8 x (a request that creates a session, then one that Destroys it)
//
// What differs from our module and from the reference (alexedwards/scs), stated
// so the rows are not read as more than they are:
//   - Session id: utils.SecureToken (32 random bytes, base64url, 43 chars) vs
//     our 64 hex; the cookie is named `session` here (the middleware's default
//     is `session_id`) via extractors.FromCookie("session"). The count never
//     looks at the id.
//   - Cookie: HttpOnly, Secure, SameSite=Lax, Path empty (no Path attribute is
//     emitted; ours sends Path=/), Max-Age + Expires (the idle timeout; ours
//     only Max-Age). Same attribute set otherwise.
//   - IdleTimeout 30 min and AbsoluteTimeout 12 h, as the scs side (Lifetime).
//     The absolute deadline is a time.Time stored in the session map (gob
//     registered), so every fresh session carries one extra encoded value.
//   - Saving: fiber's middleware saves the session after EVERY request, loaded
//     or not, touched or not (a rolling window: Storage.Set with the idle TTL
//     and a Set-Cookie each time), the same as scs with IdleTimeout > 0 and as
//     ours. Unlike ours (persist_untouched_sessions=false) it would also store
//     an untouched new session; every new_session handler here touches, so
//     that difference does not show. When the data is unchanged since the
//     decode, fiber re-stores the raw bytes it read instead of re-encoding
//     (load_read); a Set marks it dirty and re-encodes (load_write).
//   - Serialization: encoding/gob of the map[any]any (a fresh gob.Encoder per
//     save, so the type descriptors are re-sent each time; a fresh Decoder per
//     load). The tinylib/msgp code in data_msgp.go is NOT on the session path.
//   - Storage: internal/storage/memory (a plain map under an RWMutex; Get and
//     Set copy key and value; expiry in whole seconds). It is internal to
//     fiber, so it cannot be named here: session.NewWithStore with
//     Config.Storage == nil builds it, and the Store is returned. It starts a
//     GC goroutine (10 s ticker that scans the whole map) and, through
//     utils.StartTimeStampUpdater, a 1 s timestamp-updater goroutine. The GC
//     goroutine is stopped right after construction with Storage.Close() (only
//     closes its done channel; Get/Set keep working), matching the scs side's
//     NewWithCleanupInterval(0); the map is unbounded on both sides (ours is
//     bounded, 4096 entries). The timestamp updater (needed for expiry) stays.
//   - Destroy: Middleware.Destroy deletes from storage, resets the data and
//     emits an expired `session` cookie (Max-Age=-1); the middleware then skips
//     the save. Same shape as scs.
//   - Handlers reach the session by session.FromContext(c) (a pooled
//     *Middleware under an RWMutex), values are `any`.
//   - The HTTP stack is fasthttp, driven in-process without sockets: one
//     fasthttp.RequestCtx, Request.Read over the bytes, the app's Handler(),
//     Response.Write into a buffer. No Date/Server headers (those are the
//     fasthttp Server's). The passthrough row measures this stack so the Zig
//     side can take the net cost.
//   - count = the sum of the status codes + one per response carrying a
//     `session` Set-Cookie + the body lengths (as the scs side).
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/extractors"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/valyala/fasthttp"
)

var sink int

func timeIt(f func() int) (float64, int) {
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
	count := 0
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

const nReq = 16

func newApp(withSession bool) *fiber.App {
	app := fiber.New()
	if !withSession {
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("<none>")
		})
		return app
	}
	handler, store := session.NewWithStore(session.Config{
		IdleTimeout:     30 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		Extractor:       extractors.FromCookie("session"),
		CookieSecure:    true,
		CookieHTTPOnly:  true,
		CookieSameSite:  fiber.CookieSameSiteLaxMode,
	})
	// Stop the memory storage's GC goroutine (see the header); Get/Set work on.
	if err := store.Storage.Close(); err != nil {
		panic(err)
	}
	app.Use(handler)
	app.Get("/new", func(c fiber.Ctx) error {
		session.FromContext(c).Set("uid", "42")
		return c.SendString("created")
	})
	app.Get("/read", func(c fiber.Ctx) error {
		v, _ := session.FromContext(c).Get("uid").(string)
		return c.SendString(v)
	})
	app.Get("/write", func(c fiber.Ctx) error {
		session.FromContext(c).Set("uid", "43")
		return c.SendString("updated")
	})
	app.Get("/logout", func(c fiber.Ctx) error {
		if err := session.FromContext(c).Destroy(); err != nil {
			return err
		}
		return c.SendString("bye")
	})
	return app
}

type driver struct {
	handler fasthttp.RequestHandler
	ctx     fasthttp.RequestCtx
	in      bytes.Reader
	br      *bufio.Reader
	out     bytes.Buffer
	bw      *bufio.Writer
	ck      fasthttp.Cookie
}

func newDriver(app *fiber.App) *driver {
	d := &driver{handler: app.Handler()}
	d.br = bufio.NewReader(&d.in)
	d.bw = bufio.NewWriter(&d.out)
	return d
}

// do runs one request (wire bytes) and returns its contribution to the count
// and the session token the response set (if any).
func (d *driver) do(wire []byte) (int, string) {
	d.ctx.Request.Reset()
	d.ctx.Response.Reset()
	d.in.Reset(wire)
	d.br.Reset(&d.in)
	if err := d.ctx.Request.Read(d.br); err != nil {
		panic(err)
	}
	d.handler(&d.ctx)
	d.out.Reset()
	d.bw.Reset(&d.out)
	if err := d.ctx.Response.Write(d.bw); err != nil {
		panic(err)
	}
	if err := d.bw.Flush(); err != nil {
		panic(err)
	}
	sum := d.ctx.Response.StatusCode() + len(d.ctx.Response.Body())
	tok := ""
	d.ck.Reset()
	d.ck.SetKey("session")
	if d.ctx.Response.Header.Cookie(&d.ck) {
		sum++
		tok = string(d.ck.Value())
	}
	return sum, tok
}

const (
	noCookie   = "GET %s HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"
	withCookie = "GET %s HTTP/1.1\r\nHost: t\r\nCookie: session=%s\r\nConnection: close\r\n\r\n"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: go_fast_bench <work dir> <workload> <contender>")
		os.Exit(2)
	}
	name, who := os.Args[2], os.Args[3]
	if who != "fiber" {
		fmt.Fprintln(os.Stderr, "unknown contender", who)
		os.Exit(2)
	}

	var op func() int
	switch name {
	case "passthrough":
		d := newDriver(newApp(false))
		wire := []byte(fmt.Sprintf(noCookie, "/"))
		op = func() int {
			sum := 0
			for i := 0; i < nReq; i++ {
				s, _ := d.do(wire)
				sum += s
			}
			return sum
		}
	case "new_session":
		d := newDriver(newApp(true))
		wire := []byte(fmt.Sprintf(noCookie, "/new"))
		op = func() int {
			sum := 0
			for i := 0; i < nReq; i++ {
				s, _ := d.do(wire)
				sum += s
			}
			return sum
		}
	case "load_read", "load_write":
		d := newDriver(newApp(true))
		path := "/read"
		if name == "load_write" {
			path = "/write"
		}
		newWire := []byte(fmt.Sprintf(noCookie, "/new"))
		var wires [nReq][]byte
		for i := range wires {
			_, tok := d.do(newWire)
			if tok == "" {
				panic("no session cookie from /new")
			}
			wires[i] = []byte(fmt.Sprintf(withCookie, path, tok))
		}
		op = func() int {
			sum := 0
			for i := 0; i < nReq; i++ {
				s, _ := d.do(wires[i])
				sum += s
			}
			return sum
		}
	case "destroy":
		d := newDriver(newApp(true))
		newWire := []byte(fmt.Sprintf(noCookie, "/new"))
		var req []byte
		op = func() int {
			sum := 0
			for i := 0; i < nReq/2; i++ {
				s, tok := d.do(newWire)
				sum += s
				req = fmt.Appendf(req[:0], withCookie, "/logout", tok)
				s, _ = d.do(req)
				sum += s
			}
			return sum
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}

	ns, count := timeIt(op)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
