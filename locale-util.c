/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>
#include <langinfo.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "locale-util.h"

bool
is_locale_utf8(void) {
	const char *set;
	static int cached_answer = -1;

	// default to 'true' here, since today UTF8 is pretty much supported
	// everywhere.
	if (cached_answer >= 0)
		goto out;

	if (!setlocale(LC_ALL, "")) {
		cached_answer = true;
		goto out;
	}

	set = nl_langinfo(CODESET);
	if (!set) {
		cached_answer = true;
		goto out;
	}

	if (strcmp(set, "UTF-8") == 0) {
		cached_answer = true;
		goto out;
	}

	/* For LC_CTYPE=="C" return true, because CTYPE is effectively unset and
	   everything can do to UTF-8 nowadays. */
	set = setlocale(LC_CTYPE, NULL);
	if (!set) {
		cached_answer = true;
		goto out;
	}

	// Check result, but ignore the result if C was set explicitly.
	cached_answer =
		((set[0] == 'C' && set[1] == '\0') || (strcmp(set, "POSIX") == 0)) &&
		!getenv("LC_ALL") && !getenv("LC_CTYPE") && !getenv("LANG");

out:
	return (bool) cached_answer;
}
