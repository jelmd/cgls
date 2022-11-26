/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdarg.h>

#include "log.h"

void
_log(const char* format, ...) {
	char s[1024];
	va_list args;
	size_t slen = 0;

	va_start(args,format);
	slen = vsnprintf(s, sizeof(s) - 2 - slen, format, args);
	fwrite(s, slen, 1, stderr);
	fputc('\n', stderr);
	fflush(stderr);
	va_end(args);
}
