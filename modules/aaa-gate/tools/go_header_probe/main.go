// SPDX-License-Identifier: MIT

// Header-confusion probe for the aaa-gate field report (2026-10-25): sends the
// same raw request bytes (Authorization header variants) to the credential
// middleware of labstack/echo v5.4.0, gofiber/fiber v2.52.16 and v3.6.1 and
// gin v1.12.0 and prints the status each answers, one row per case. Our side
// of the same cases is pinned by the `lead:` tests in
// modules/aaa-gate/src/root.zig. Every middleware gets a plain (non-hashed)
// validator for the one configured credential: this probe is about WHICH
// requests are admitted, not about timing.
//
//	go_header_probe
//
// Bearer policy: token "s3cr3t". Basic policy: alice/s3cret and
// bob/pw:with:colon.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	fiber2 "github.com/gofiber/fiber/v2"
	basicauth2 "github.com/gofiber/fiber/v2/middleware/basicauth"
	keyauth2 "github.com/gofiber/fiber/v2/middleware/keyauth"
	fiber3 "github.com/gofiber/fiber/v3"
	basicauth3 "github.com/gofiber/fiber/v3/middleware/basicauth"
	keyauth3 "github.com/gofiber/fiber/v3/middleware/keyauth"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/valyala/fasthttp"
)

type kase struct {
	name  string
	lines string // header lines, each ending in \r\n
	want  string // what ours does (pinned by the lead: tests)
}

const A = "Authorization: "

var bearer = []kase{
	{"Bearer s3cr3t (control)", A + "Bearer s3cr3t\r\n", "200"},
	{"bearer s3cr3t (lowercase scheme)", A + "bearer s3cr3t\r\n", "200"},
	{"BEARER s3cr3t (uppercase scheme)", A + "BEARER s3cr3t\r\n", "200"},
	{"Bearer<4 spaces>s3cr3t", A + "Bearer    s3cr3t\r\n", "200"},
	{"Bearer<TAB>s3cr3t", A + "Bearer\ts3cr3t\r\n", "401"},
	{"Bearer s3cr3tx (suffix)", A + "Bearer s3cr3tx\r\n", "401"},
	{"2 headers: valid, then wrong", A + "Bearer s3cr3t\r\n" + A + "Bearer wrong\r\n", "401 (repeated field)"},
	{"2 headers: wrong, then valid", A + "Bearer wrong\r\n" + A + "Bearer s3cr3t\r\n", "401 (repeated field)"},
	{"2 headers: empty, then valid", A + "\r\n" + A + "Bearer s3cr3t\r\n", "401 (repeated field)"},
}

var basic = []kase{
	{"Basic alice:s3cret (control)", A + "Basic YWxpY2U6czNjcmV0\r\n", "200"},
	{"basic alice:s3cret (lowercase scheme)", A + "basic YWxpY2U6czNjcmV0\r\n", "200"},
	{"Basic<3 spaces>alice:s3cret", A + "Basic   YWxpY2U6czNjcmV0\r\n", "200"},
	{"Basic bob:pw:with:colon (colon in password)", A + "Basic Ym9iOnB3OndpdGg6Y29sb24=\r\n", "200"},
	{"Basic<TAB>alice:s3cret", A + "Basic\tYWxpY2U6czNjcmV0\r\n", "401"},
	{"Basic bob:... unpadded base64", A + "Basic Ym9iOnB3OndpdGg6Y29sb24\r\n", "401"},
	{"2 headers: valid, then other user", A + "Basic YWxpY2U6czNjcmV0\r\n" + A + "Basic eDp5\r\n", "401 (repeated field)"},
	{"2 headers: other user, then valid", A + "Basic eDp5\r\n" + A + "Basic YWxpY2U6czNjcmV0\r\n", "401 (repeated field)"},
}

func wireOf(k kase) []byte {
	return []byte("GET / HTTP/1.1\r\nHost: t\r\n" + k.lines + "Connection: close\r\n\r\n")
}

func netStatus(h http.Handler, k kase) string {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(wireOf(k))))
	if err != nil {
		return "unparsed"
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return fmt.Sprint(rec.Code)
}

func fastStatus(h fasthttp.RequestHandler, k kase) string {
	ctx := &fasthttp.RequestCtx{}
	if err := ctx.Request.Read(bufio.NewReader(bytes.NewReader(wireOf(k)))); err != nil {
		return "unparsed"
	}
	h(ctx)
	return fmt.Sprint(ctx.Response.StatusCode())
}

var basicUsers = map[string]string{"alice": "s3cret", "bob": "pw:with:colon"}

func main() {
	gin.SetMode(gin.ReleaseMode)

	// ---- bearer ----
	eb := echo.New()
	eb.Use(middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{
		KeyLookup: "header:Authorization:Bearer ",
		Validator: func(c *echo.Context, key string, _ middleware.ExtractorSource) (bool, error) {
			return key == "s3cr3t", nil
		},
	}))
	eb.GET("/", func(c *echo.Context) error { return c.String(200, "ok") })
	f2b := fiber2.New(fiber2.Config{DisableStartupMessage: true})
	f2b.Use(keyauth2.New(keyauth2.Config{KeyLookup: "header:Authorization", AuthScheme: "Bearer",
		Validator: func(c *fiber2.Ctx, key string) (bool, error) { return key == "s3cr3t", nil }}))
	f2b.Get("/", func(c *fiber2.Ctx) error { return c.SendString("ok") })
	f3b := fiber3.New()
	f3b.Use(keyauth3.New(keyauth3.Config{
		Validator: func(c fiber3.Ctx, key string) (bool, error) { return key == "s3cr3t", nil }}))
	f3b.Get("/", func(c fiber3.Ctx) error { return c.SendString("ok") })

	fmt.Printf("BEARER (policy: token s3cr3t)\n%-46s %-20s %-6s %-8s %-8s\n", "case", "aaa-gate (pinned)", "echo5", "fiber2", "fiber3")
	for _, k := range bearer {
		fmt.Printf("%-46s %-20s %-6s %-8s %-8s\n", k.name, k.want, netStatus(eb, k), fastStatus(f2b.Handler(), k), fastStatus(f3b.Handler(), k))
	}

	// ---- basic ----
	ebb := echo.New()
	ebb.Use(middleware.BasicAuthWithConfig(middleware.BasicAuthConfig{
		Validator: func(c *echo.Context, u, p string) (bool, error) { w, ok := basicUsers[u]; return ok && w == p, nil }}))
	ebb.GET("/", func(c *echo.Context) error { return c.String(200, "ok") })
	f2 := fiber2.New(fiber2.Config{DisableStartupMessage: true})
	f2.Use(basicauth2.New(basicauth2.Config{Users: basicUsers}))
	f2.Get("/", func(c *fiber2.Ctx) error { return c.SendString("ok") })
	f3 := fiber3.New()
	f3.Use(basicauth3.New(basicauth3.Config{Authorizer: func(u, p string, c fiber3.Ctx) bool { w, ok := basicUsers[u]; return ok && w == p }}))
	f3.Get("/", func(c fiber3.Ctx) error { return c.SendString("ok") })
	g := gin.New()
	g.Use(gin.BasicAuth(gin.Accounts(basicUsers)))
	g.GET("/", func(c *gin.Context) { c.String(200, "ok") })

	fmt.Printf("\nBASIC (policy: alice/s3cret, bob/pw:with:colon)\n%-46s %-20s %-6s %-8s %-8s %-6s\n", "case", "aaa-gate (pinned)", "echo5", "fiber2", "fiber3", "gin")
	for _, k := range basic {
		fmt.Printf("%-46s %-20s %-6s %-8s %-8s %-6s\n", k.name, k.want, netStatus(ebb, k), fastStatus(f2.Handler(), k), fastStatus(f3.Handler(), k), netStatus(g, k))
	}
}
