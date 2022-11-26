/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stdbool.h>
#include <uchar.h>

extern const char hd[];

#define WHITESPACE  " \t\n\r"

int cunescape_one(const char *, size_t, char32_t *, bool *, bool);
size_t utf8_encode_unichar(char *, char32_t) ;
char *cellescape(char *, size_t, const char *);

typedef enum XEscapeFlags {
	XESCAPE_8_BIT			= 1 << 0,
	XESCAPE_FORCE_ELLIPSIS	= 1 << 1,
} XEscapeFlags;
char *xescape_full(const char *, const char *, size_t, XEscapeFlags);
char *hex_escape_char(char, char *);

char *utf8_escape_non_printable_full(const char *, size_t, bool);
int cescape_char(char, char *);

