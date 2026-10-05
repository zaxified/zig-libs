// SPDX-License-Identifier: MIT

// Area proxy: which proxy http.ProxyFromEnvironment picks for a URL under a
// given environment. Go reads the environment once per process, so every
// case runs this program again (`-proxycase URL`) with exactly that
// environment.
package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

type proxyCase struct {
	id     string
	env    []string
	target string
}

func pc(id, target string, env ...string) proxyCase { return proxyCase{id, env, target} }

const hp = "HTTP_PROXY=proxy.test:3128"
const hsp = "HTTPS_PROXY=sproxy.test:8443"

var proxyCases = []proxyCase{
	// ── which variable, which scheme ──
	pc("http-uses-http-proxy", "http://example.com/", hp, hsp),
	pc("https-uses-https-proxy", "https://example.com/", hp, hsp),
	pc("https-without-https-proxy", "https://example.com/", hp),
	pc("http-without-http-proxy", "http://example.com/", hsp),
	pc("lowercase-only", "http://example.com/", "http_proxy=lower.test:1"),
	pc("upper-wins", "http://example.com/", "HTTP_PROXY=upper.test:1", "http_proxy=lower.test:1"),
	pc("empty-upper-falls-back", "http://example.com/", "HTTP_PROXY=", "http_proxy=lower.test:1"),
	pc("no-env", "http://example.com/"),
	pc("cgi-http", "http://example.com/", hp, "REQUEST_METHOD=GET"),
	pc("cgi-https", "https://example.com/", hp, hsp, "REQUEST_METHOD=GET"),
	pc("cgi-empty-method", "http://example.com/", hp, "REQUEST_METHOD="),

	// ── proxy URL forms ──
	pc("proxy-with-scheme", "http://example.com/", "HTTP_PROXY=http://p.test:8080"),
	pc("proxy-no-port", "http://example.com/", "HTTP_PROXY=http://p.test"),
	pc("proxy-bare-no-port", "http://example.com/", "HTTP_PROXY=p.test"),
	pc("proxy-path", "http://example.com/", "HTTP_PROXY=http://p.test:8080/some/path"),
	pc("proxy-userinfo", "http://example.com/", "HTTP_PROXY=http://user:pa%20ss@p.test:8080"),
	pc("proxy-user-only", "http://example.com/", "HTTP_PROXY=http://user@p.test:8080"),
	pc("proxy-v6", "http://example.com/", "HTTP_PROXY=http://[2001:db8::1]:8080"),
	pc("proxy-uppercase-scheme", "http://example.com/", "HTTP_PROXY=HTTP://p.test:8080"),
	pc("proxy-https-scheme", "http://example.com/", "HTTP_PROXY=https://p.test:8443"),
	pc("proxy-socks5", "http://example.com/", "HTTP_PROXY=socks5://p.test:1080"),
	pc("proxy-bad-port", "http://example.com/", "HTTP_PROXY=http://p.test:99999"),
	pc("proxy-space", "http://example.com/", "HTTP_PROXY=p test:1"),

	// ── always direct ──
	pc("localhost", "http://localhost/", hp),
	pc("localhost-port", "http://localhost:8080/", hp),
	pc("loopback-v4", "http://127.0.0.1/", hp),
	pc("loopback-v4-other", "http://127.1.2.3/", hp),
	pc("loopback-v6", "http://[::1]/", hp),
	pc("loopback-mapped", "http://[::ffff:127.0.0.1]/", hp),
	pc("not-loopback", "http://128.0.0.1/", hp),
	pc("localhost-subdomain", "http://a.localhost/", hp),

	// ── NO_PROXY ──
	pc("np-exact", "http://example.com/", hp, "NO_PROXY=example.com"),
	pc("np-subdomain", "http://a.b.example.com/", hp, "NO_PROXY=example.com"),
	pc("np-not-suffix-label", "http://notexample.com/", hp, "NO_PROXY=example.com"),
	pc("np-dot-not-self", "http://example.com/", hp, "NO_PROXY=.example.com"),
	pc("np-dot-sub", "http://a.example.com/", hp, "NO_PROXY=.example.com"),
	pc("np-star-dot-sub", "http://a.example.com/", hp, "NO_PROXY=*.example.com"),
	pc("np-star-dot-self", "http://example.com/", hp, "NO_PROXY=*.example.com"),
	pc("np-case", "http://Example.COM/", hp, "NO_PROXY=EXAMPLE.com"),
	pc("np-port-match", "http://example.com:8080/", hp, "NO_PROXY=example.com:8080"),
	pc("np-port-default-miss", "http://example.com/", hp, "NO_PROXY=example.com:8080"),
	pc("np-port-default-https", "https://example.com/", hsp, "NO_PROXY=example.com:443"),
	pc("np-port-default-http80", "http://example.com/", hp, "NO_PROXY=example.com:80"),
	pc("np-list-spaces", "http://example.com/", hp, "NO_PROXY= a.org , example.com "),
	pc("np-star", "http://anything.test/", hp, "NO_PROXY=*"),
	pc("np-star-in-list", "http://anything.test/", hp, "NO_PROXY=a.org,*"),
	pc("np-ip", "http://192.0.2.1/", hp, "NO_PROXY=192.0.2.1"),
	pc("np-ip-miss", "http://192.0.2.2/", hp, "NO_PROXY=192.0.2.1"),
	pc("np-ip-port", "http://192.0.2.1/", hp, "NO_PROXY=192.0.2.1:80"),
	pc("np-ip-port-miss", "http://192.0.2.1/", hp, "NO_PROXY=192.0.2.1:81"),
	pc("np-cidr", "http://192.0.2.77/", hp, "NO_PROXY=192.0.2.0/24"),
	pc("np-cidr-miss", "http://192.0.3.1/", hp, "NO_PROXY=192.0.2.0/24"),
	pc("np-cidr6", "http://[2001:db8::5]/", hp, "NO_PROXY=2001:db8::/32"),
	pc("np-ip6-bracket-port", "http://[2001:db8::1]/", hp, "NO_PROXY=[2001:db8::1]:80"),
	pc("np-ip6-bare", "http://[2001:db8::1]/", hp, "NO_PROXY=2001:db8::1"),
	pc("np-mapped-target", "http://[::ffff:192.0.2.1]/", hp, "NO_PROXY=192.0.2.1"),
	pc("np-cidr-name-target", "http://example.com/", hp, "NO_PROXY=192.0.2.0/24"),
	pc("np-empty-entries", "http://example.com/", hp, "NO_PROXY=,,"),
	pc("np-lowercase-var", "http://example.com/", hp, "no_proxy=example.com"),
	pc("np-trailing-colon", "http://example.com:8080/", hp, "NO_PROXY=example.com:"),
	pc("np-ip-as-domain-suffix", "http://a.1.2.3.4/", hp, "NO_PROXY=1.2.3.4"),
	pc("np-dot-only", "http://example.com/", hp, "NO_PROXY=."),
	pc("np-https", "https://example.com/", hsp, "NO_PROXY=example.com"),
}

// proxyCaseMain is the child: print what ProxyFromEnvironment says for the
// URL, one line: `direct`, `error`, or `proxy host port user password`
// (`-` for an absent user or password).
func proxyCaseMain(target string) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		log.Fatal(err)
	}
	u, err := http.ProxyFromEnvironment(req)
	switch {
	case err != nil:
		fmt.Println("error")
	case u == nil:
		fmt.Println("direct")
	default:
		port := u.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443", "socks5": "1080"}[u.Scheme]
		}
		user, pass := "-", "-"
		if u.User != nil {
			user = u.User.Username()
			if p, ok := u.User.Password(); ok {
				pass = p
			}
		}
		fmt.Printf("proxy %s %s %s %s %s\n", u.Scheme, u.Hostname(), port, user, pass)
	}
}

func runProxyCase(c proxyCase) string {
	self, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	cmd := exec.Command(self, "-proxycase", c.target)
	cmd.Env = c.env
	out, err := cmd.Output()
	if err != nil {
		log.Fatalf("proxy case %s: %v", c.id, err)
	}
	return strings.TrimSpace(string(out))
}

func emitProxy(b *bytes.Buffer) {
	fmt.Fprintf(b, "pub const ProxyCase = struct {\n    id: []const u8,\n")
	fmt.Fprintf(b, "    /// `NAME=value` lines, the whole environment of the case.\n    env: []const []const u8,\n    target: []const u8,\n")
	fmt.Fprintf(b, "    /// `direct`, `error`, or `proxy <scheme> <host> <port> <user|-> <password|->`.\n    go: []const u8,\n};\n\n")
	fmt.Fprintf(b, "/// Go's http.ProxyFromEnvironment, one fresh process per case.\n")
	fmt.Fprintf(b, "pub const proxy = [_]ProxyCase{\n")
	for _, c := range proxyCases {
		var env []string
		for _, e := range c.env {
			env = append(env, zigStr(e))
		}
		fmt.Fprintf(b, "    .{ .id = %s, .env = %s, .target = %s, .go = %s },\n", zigStr(c.id), zigList(env), zigStr(c.target), zigStr(runProxyCase(c)))
	}
	fmt.Fprintf(b, "};\n\n")
}
