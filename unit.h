/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#define ERRNO_MAX 4095

/** Types of unit names */
typedef enum UnitNameFlags {
	UNIT_NAME_PLAIN    = 1 << 0, /**< Allow foo.service */
	UNIT_NAME_TEMPLATE = 1 << 1, /**< Allow foo\@\.service */
	UNIT_NAME_INSTANCE = 1 << 2, /**< Allow foo\@bar.service */
	UNIT_NAME_ANY = UNIT_NAME_PLAIN|UNIT_NAME_TEMPLATE|UNIT_NAME_INSTANCE,
	_UNIT_NAME_INVALID = -EINVAL,
} UnitNameFlags;

/** The enum order is used to order unit jobs in the job queue
 * when other criteria (cpu weight, nice level) are identical.
 * In this case service units have the highest priority. */
typedef enum UnitType {
	UNIT_SERVICE,
	UNIT_MOUNT,
	UNIT_SWAP,
	UNIT_SOCKET,
	UNIT_TARGET,
	UNIT_DEVICE,
	UNIT_AUTOMOUNT,
	UNIT_TIMER,
	UNIT_PATH,
	UNIT_SLICE,
	UNIT_SCOPE,
	_UNIT_TYPE_MAX,
	_UNIT_TYPE_INVALID = -EINVAL,
	/** Ensure the whole errno range fits into this enum */
	_UNIT_TYPE_ERRNO_MAX = -ERRNO_MAX,
} UnitType;

#define UNIT_NAME_MAX 256
#define DIGITS "0123456789"
#define LOWERCASE_LETTERS   "abcdefghijklmnopqrstuvwxyz"
#define UPPERCASE_LETTERS   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define LETTERS LOWERCASE_LETTERS UPPERCASE_LETTERS
#define VALID_CHARS DIGITS LETTERS ":-_.\\"
#define VALID_CHARS_WITH_AT "@" VALID_CHARS

#define GLOB_CHARS          "*?["
#define VALID_CHARS_GLOB VALID_CHARS_WITH_AT "[]!-*?"

UnitType unit_type_from_string(const char *);
UnitType unit_name_to_type(const char *);
bool unit_name_is_valid(const char *, UnitNameFlags);
//static int unit_name_path_escape(const char *, char **)
//static int unit_name_from_path(const char *, const char *, char **);
int unit_name_mangle(const char *, char **);
