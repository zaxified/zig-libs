// SPDX-License-Identifier: MIT
//
// Black-box oracle over OpenWRT libubox's blobmsg JSON codec, for
// tools/libubox_oracle.py. Links a libubox and a json-c built locally from
// their own sources into the droppable .zig-cache (recipe in that script);
// nothing of either is copied here.
//
//   oracle_blobmsg enc   one JSON object per stdin line -> the hex of the
//                        blobmsg children blobmsg_add_json_from_string builds
//                        (the body of a ubus DATA attr), or "ERR"
//   oracle_blobmsg dec   one hex string per stdin line (blobmsg children) ->
//                        blobmsg_format_json of them, or "ERR"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blobmsg.h"
#include "blobmsg_json.h"

static char line[1 << 20];

int main(int argc, char **argv) {
	int dec = argc > 1 && strcmp(argv[1], "dec") == 0;
	static struct blob_buf b;
	while (fgets(line, sizeof line, stdin)) {
		size_t n = strcspn(line, "\n");
		line[n] = 0;
		blob_buf_init(&b, 0);
		if (!dec) {
			if (!blobmsg_add_json_from_string(&b, line)) {
				puts("ERR");
				continue;
			}
			unsigned char *p = blob_data(b.head);
			for (unsigned i = 0; i < blob_len(b.head); i++) printf("%02x", p[i]);
			putchar('\n');
		} else {
			size_t len = n / 2;
			unsigned char *raw = malloc(len + 1);
			for (size_t i = 0; i < len; i++) sscanf(line + 2 * i, "%2hhx", &raw[i]);
			blob_put_raw(&b, raw, len);
			free(raw);
			char *s = blobmsg_format_json(b.head, true);
			puts(s ? s : "ERR");
			free(s);
		}
		fflush(stdout);
	}
	return 0;
}
