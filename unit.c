/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "log.h"
#include "characters.h"
#include "misc.h"

#include "unit.h"

static const char* const unit_type_table[_UNIT_TYPE_MAX] = {
	[UNIT_SERVICE]		= "service",
	[UNIT_SOCKET]		= "socket",
	[UNIT_TARGET]		= "target",
	[UNIT_DEVICE]		= "device",
	[UNIT_MOUNT]		= "mount",
	[UNIT_AUTOMOUNT]	= "automount",
	[UNIT_SWAP]			= "swap",
	[UNIT_TIMER]		= "timer",
	[UNIT_PATH]			= "path",
	[UNIT_SLICE]		= "slice",
	[UNIT_SCOPE]		= "scope",
};

UnitType
unit_type_from_string(const char *s) {
	if (!s)
		return _UNIT_TYPE_INVALID;
	for (size_t i = 0; i < _UNIT_TYPE_MAX; i++)
		if (strcmp(unit_type_table[i], s) == 0)
			return i;
	return _UNIT_TYPE_INVALID;
}

/**
 * Check whether the given unit name is valid.
 * @param name  unit name to check.
 * @param flags Mask of allowed unit name categories.
 * @return true if valid, false otherwise.
 */
bool
unit_name_is_valid(const char *name, UnitNameFlags flags) {
	const char *e, *i, *at;

	//assert((flags & ~(UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE)) == 0);
	if (flags == 0)
		return false;

	if (name == NULL || name[0] == '\0')
		return false;

	if (strlen(name) >= UNIT_NAME_MAX)
		return false;

	e = strrchr(name, '.');
	if (!e || e == name)
		return false;

	if (unit_type_from_string(e + 1) < 0)
		return false;

	for (i = name, at = NULL; i < e; i++) {
		if (*i == '@' && !at)
			at = i;
		if (!strchr(VALID_CHARS_WITH_AT, *i))
			return false;
	}

	if (at == name)
		return false;

	if (flags & UNIT_NAME_PLAIN)
		if (!at)
			return true;

	if (flags & UNIT_NAME_INSTANCE)
		if (at && e > at + 1)
			return true;

	if (flags & UNIT_NAME_TEMPLATE)
		if (at && e == at + 1)
			return true;

	return false;
}

UnitType
unit_name_to_type(const char *n) {
	const char *e;

	if (!unit_name_is_valid(n, UNIT_NAME_ANY))
		return _UNIT_TYPE_INVALID;

	e = strrchr(n, '.');
	if (e == NULL)
		return _UNIT_TYPE_INVALID;

	return unit_type_from_string(e + 1);
}

/**
 * Simplify the given path (remove redundant parts) and replace NULL, and
 * empty string, '/' with a dash ('-') and all other invalid characters
 * with their escaped version (hex char format).
 * @param f	The path to escape.
 * @param ret	Where to store the pointer to the escaped path on success.
 *		Unchanged on error. Free when done.
 * @return 0 on success, an error code < 0 otherwise.
 */
static int
unit_name_path_escape(const char *f, char **ret) {
	char *p = NULL;
	char *s = NULL;
	int r;

	p = strdup(f);
	if (!p)
		return -ENOMEM;

	r = path_simplify(p);
	if (p == NULL || p[0] == '\0' || (p[0] == '/' && p[1] == '\0')) {
		s = strdup("-");
	} else if (p[0] == '.' && p[1] == '\0') {
		free(p);
		return -EINVAL;
	} else {
		// unit_name_escape
		char *u = (char *) malloc(sizeof(char) * (r * 4 + 1));
		if (!u) {
			free(p);
			return -ENOMEM;
		}
		const char *t = p;
	    s = u;
		if (t[0] == '.') {
			u = hex_escape_char(*t, s);
			t++;
		}
		for (; *t; t++) {
			if (*t == '/')
				*(u++) = '-';
			else if (*t == '-' || *t == '\\' || !strchr(VALID_CHARS, *t))
				u = hex_escape_char(*t, u);
			else
				*(u++) = *t;
		}
		*u = '\0';
	}
	free(p);
	if (!s)
		return -ENOMEM;

	*ret = s;
	return 0;
}

/**
 * Check whether the given path including the given suffix represents a valid
 * unit name and escape the result as needed.
 * @param path	The path to check.
 * @param suffix	The suffix to add to the path.
 * @param ret	Where to store the final validated unit name on success.
 *		Unchanged on error. Free when done.
 * @return The length of the returned unit name without the trailing '\0' on
 *		success, an error code < 0 otherwise.
 */
static int
unit_name_from_path(const char *path, const char *suffix, char **ret) {
	char *p = NULL, *s = NULL;
	int r;

	r = unit_name_path_escape(path, &p);
	if (r < 0)
		return r;

	size_t pl = strlen(p);
	size_t sl =	strlen(suffix) + pl + 1;
	if (sl > UNIT_NAME_MAX) {
		LOG("Unit name '%s%s' too long (%d >= %d). If you really want this,"
			"create an issue on github.", p, suffix, sl, UNIT_NAME_MAX);
		free(p);
		return -EINVAL;
	}

	s = (char *) malloc(sizeof(char) * sl);
	if (!s) {
		free(p);
		return -ENOMEM;
	}
	strcpy(s, p);
	strcpy(s + pl, suffix);
	free(p);

	/* Refuse if this for some other reason didn't result in a valid name */
	if (!unit_name_is_valid(s, UNIT_NAME_PLAIN)) {
		free(s);
		return -EINVAL;
	}

	*ret = s;
	return sl - 1;
}

/**
  * Check whether the given unit name is valid.
  * @param name	unit name to check and mangle.
  * @param ret	Where to store the newly allocated unit name on success.
  *		Unchanged on error. Free when done.
  * @return 0 if the given name got not mangled (is already valid), 1 if the
  *		given name got mangled, a value < 0 on error.
  */
int
unit_name_mangle(const char *name, char **ret) {
	const char *suffix = ".service";

	char *s = NULL, *t = NULL;
	bool mangled = false, suggest_escape = true;
	int r;

	if (name == NULL)
		return -EINVAL;

	/* Already a fully valid unit name? If so, no mangling is necessary... */
	if (unit_name_is_valid(name, UNIT_NAME_ANY))
		goto good;

	/* Already a fully valid globbing expression? If so, no mangling is
	 * necessary either ... */
	if ((!!strpbrk(name, GLOB_CHARS)) &&
		(name[strspn(name, VALID_CHARS_GLOB)] == '\0'))
	{
		LOG("Glob pattern passed, but globs are not supported.", NULL);
		suggest_escape = false;
	}

	// is device?
	if (strncmp(name, "/dev/", 5) == 0 || strncmp(name, "/sys/", 5) == 0) {
		r = unit_name_from_path(name, ".device", ret);
		if (r >= 0)
			return 1;
		if (r != -EINVAL)
			return r;
	}

	if (name[0] == '/') {
		r = unit_name_from_path(name, ".mount", ret);
		if (r >= 0)
			return 1;
		if (r != -EINVAL)
			return r;
	}

	s = (char *) malloc(sizeof(char) * (strlen(name) * 4 + strlen(suffix) + 1));
	if (!s)
		return -ENOMEM;

	// escape
	t = s;
	for (const char *f = name; *f; f++) {
		if (*f == '/') {
			*(t++) = '-';
			mangled = true;
		} else if (!strchr(VALID_CHARS_WITH_AT, *f)) {
			t = hex_escape_char(*f, t);
			mangled = true;
		} else {
			*(t++) = *f;
		}
	}
	*t = '\0';
	if (mangled)
		LOG("Invalid unit name '%s' escaped as '%s'%s.", name, s,
			suggest_escape ? " (maybe you should use systemd-escape?)" : "");

	/* Append a suffix if it doesn't have any, but only if this is not a glob,
	   so that we can allow "foo.*" as a valid glob. */
	if ((!strpbrk(s, GLOB_CHARS)) && unit_name_to_type(s) < 0) {
		strcat(t, suffix);
		mangled = true;
	}

	// Make sure mangling didn't grow this too large.
	if (!unit_name_is_valid(s, UNIT_NAME_ANY)) {
		free(s);
		return -EINVAL;
	}

	*ret = s;
	return mangled;

good:
	s = strdup(name);
	if (!s)
		return -ENOMEM;

	*ret = s;
	return 0;
}
