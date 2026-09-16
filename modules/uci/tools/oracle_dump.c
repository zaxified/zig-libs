/* SPDX-License-Identifier: MIT
 *
 * ⚠ THIS FILE IS OURS. Nothing here is copied from libuci; it only #includes
 * <uci.h> and calls the library's public API, and it is compiled against a
 * libuci built locally by whoever runs it. libuci is LGPL-2.1 and its source
 * NEVER enters this repository -- see tools/README.md and the root NOTICE §0,
 * whose obligation attaches to third-party source or data TRAVELLING WITH this
 * code. None does.
 *
 * Links against libuci (built from git.openwrt.org/project/uci.git) and
 * prints a canonical, quoting-neutral dump of a parsed config file, so it can
 * be diffed byte-for-byte against the same dump produced by the zig-libs
 * `uci` module (see module_dump.zig).
 *
 * Output grammar (values hex-encoded — no quoting ambiguity):
 *   P <hex-package-name>            (only if a `package` line set one)
 *   S <hex-type> <hex-name|-> <A|N> (A = anonymous, N = named)
 *   O s|l <hex-key> <hex-v> [<hex-v> ...]
 *   ERR <errno> <reason>
 *
 * Build:
 *   gcc -O1 -std=gnu99 -I<uci-src> -o oracle_dump oracle_dump.c \
 *       <uci-src>/{libuci,file,util,delta,parse}.c
 * Run:
 *   ./oracle_dump <confdir> <config-name>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uci.h>

static void hex(const char *s)
{
	if (s == NULL) { fputs("-", stdout); return; }
	if (*s == 0) { fputs(".", stdout); return; } /* empty string marker */
	for (const unsigned char *p = (const unsigned char *)s; *p; p++)
		printf("%02x", *p);
}

int main(int argc, char **argv)
{
	if (argc != 3) { fprintf(stderr, "usage: %s <confdir> <name>\n", argv[0]); return 2; }

	struct uci_context *ctx = uci_alloc_context();
	if (!ctx) return 3;
	uci_set_confdir(ctx, argv[1]);

	struct uci_package *pkg = NULL;
	if (uci_load(ctx, argv[2], &pkg) != UCI_OK || pkg == NULL) {
		char *str = NULL;
		uci_get_errorstr(ctx, &str, NULL);
		printf("ERR %d %s\n", ctx->err, str ? str : "?");
		free(str);
		uci_free_context(ctx);
		return 0;
	}

	/* The package name libuci reports is the requested config name, not a
	 * `package` line from the file; the file's own `package` statements are
	 * handled by uci_switch_config and are not observable here, so this
	 * dumper deliberately does not print a P line. */
	struct uci_element *se;
	uci_foreach_element(&pkg->sections, se) {
		struct uci_section *s = uci_to_section(se);
		fputs("S ", stdout);
		hex(s->type);
		fputc(' ', stdout);
		hex(s->anonymous ? NULL : s->e.name);
		printf(" %c\n", s->anonymous ? 'A' : 'N');

		struct uci_element *oe;
		uci_foreach_element(&s->options, oe) {
			struct uci_option *o = uci_to_option(oe);
			if (o->type == UCI_TYPE_STRING) {
				fputs("O s ", stdout);
				hex(o->e.name);
				fputc(' ', stdout);
				hex(o->v.string);
				fputc('\n', stdout);
			} else {
				fputs("O l ", stdout);
				hex(o->e.name);
				struct uci_element *le;
				uci_foreach_element(&o->v.list, le) {
					fputc(' ', stdout);
					hex(le->name);
				}
				fputc('\n', stdout);
			}
		}
	}
	uci_free_context(ctx);
	return 0;
}
