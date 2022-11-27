/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>

#include "log.h"
#include "misc.h"
#include "unit.h"
#include "sdbus.h"
#include "characters.h"
#include "cgroup.h"

#include "cgls.h"

static OutputFlags arg_output_flags =
	OUTPUT_FULL_WIDTH | OUTPUT_CGROUP_XATTRS | OUTPUT_CGROUP_ID;

static char **all_units = NULL;
static int user_units = 0;
static char **all_paths = NULL;

static int
version(void) {
	fprintf(stdout, "Version: %s\n", VERSION);
	return 0;
}

#define LOG_OOM { LOG("Out Of Memory - exiting\n", ""); return -ENOMEM; }

/**
 * Print a short util usage info and return 0
 */
static int
help(void) {
	printf(
"%s [OPTION ...] [CGROUP ...]\n\n"
"Recursively show control group contents.\n\n"
"  -h --help           Show this help\n"
"  -v --version        Show package version\n"
"  -I --no-cgroup-id   Do not show cgroup ID\n"
"  -X --no-xattr       Do not show cgroup extended attributes\n"
"  -e --empty          Show empty groups as well\n"
"  -k --kernel         Include kernel threads in output\n"
"  -m --me             Same as: -s user-`id -u`.slice\n"
"  -s --system=unit    Show the subtrees of specified system unit\n"
"  -u --user=unit      Show the subtrees of specified user unit\n"
		, program_invocation_short_name);

	return 0;
}

/**
 * Parse cli args and store all cgroup pathes to show in
 * <code>usr_units</code>, <code>sys_units</code>, and <code>sys_pathes</code>.
 * @param argc	number of args in <code>argv</code>.
 * @param argv	List of arguments to parse.
 * @return Number of cgroups to show on success, an error code < 0 otherwise.
 */
static int
parse_argv(int argc, char *argv[]) {
	static const struct option options[] = {
		{ "help",      no_argument,       NULL, 'h' },
		{ "empty",     no_argument,       NULL, 'e' },
		{ "kernel",    no_argument,       NULL, 'k' },
		{ "me",        no_argument,       NULL, 'm' },
		{ "system",    optional_argument, NULL, 's' },
		{ "user",      optional_argument, NULL, 'u' },
		{ "version",   no_argument,       NULL, 'v' },
		{ "no-xattr",  no_argument,       NULL, 'X' },
		{ "no-cgroup-id", no_argument,    NULL, 'I' },
		{}
	};

	int c, s = 0, p = 0;
	char *name;
	char **sys_units = NULL;	// temp store

	while ((c = getopt_long(argc, argv, "ehkms:u:vXI", options, NULL)) >= 0) {
		switch (c) {
			case 'h':
				return help();
			case 'v':
				return version();
			case 'e':
				arg_output_flags |= OUTPUT_SHOW_ALL;
				break;
			case 'k':
				arg_output_flags |= OUTPUT_KERNEL_THREADS;
				break;
			case 'm': {
#define _BUFLEN 22
				char buf[_BUFLEN];
				snprintf(buf, _BUFLEN, "user-%u.slice", geteuid());
				buf[_BUFLEN-1] = '\0';
#undef _BUFLEN
				if (strv_push(&sys_units, buf, true) < 0)
					LOG_OOM;
				s++;
				break;
					  }
			case 's':
				c = unit_name_mangle(optarg, &name);
				if (c < 0) {
					LOG("Invalid system unit name ignored (%d)", c);
					continue;
				}
				if (strv_push(&sys_units, name, false) < 0)
					LOG_OOM;
				s++;
				break;
			case 'u':
				c = unit_name_mangle(optarg, &name);
				if (c < 0) {
					LOG("Invalid user unit name ignored (%d)", c);
					continue;
				}
				if (strv_push(&all_units, name, false) < 0)
					LOG_OOM;
				user_units++;
				break;
			case 'X':
				arg_output_flags &= ~(OUTPUT_CGROUP_XATTRS);
				break;
			case 'I':
				arg_output_flags &= ~(OUTPUT_CGROUP_ID);
				break;
			case '?':
				return -EINVAL;
			default:
				LOG("Unknown option\n", NULL);
		}
	}
	if (sys_units) {
		for (char * const *n = sys_units; *n; n++) {
			if (strv_push(&all_units, *n, false) < 0)
				LOG_OOM;
		}
		free(sys_units);
	}
	// handle remaining operands (cgroup pathes)
	if (optind < argc || s + user_units == 0) {
		char *root = NULL;
		char *fallback = get_current_dir_name();
		int offset = (s + user_units == 0 && optind >= argc) ? argc + 1 : argc;
		int root_len = get_cgroup_root(&root);
		if (root_len < 0)
			LOG("Failed to get the root of the cgroup tree (%d)", root_len);
		root_len = path_simplify(root);

		if (fallback == NULL || strncmp(fallback, "/sys/fs/cgroup", 14)) {
			free((char *) fallback);
			fallback = root ? strdup(root) : NULL; // avoid double free
		} else {
			path_simplify(fallback);
		}
		for (;optind < offset; optind++) {
			int r;
			char *ctl = NULL, *t = NULL, *j = NULL;
			char *path = (optind == argc) ? fallback : argv[optind];
			if (!path)
				continue;

			if (strncmp(path, "/sys/fs/cgroup", 14) == 0) {
				if (strv_push(&all_paths, path, true) < 0)
					LOG_OOM;
				p++;
				continue;
			}

			if (!root) {
				LOG("Skipping '%s' - no root.", path);
				continue;
			}

			r = cg_split_spec(*path == '\0' ? "/" : path, &ctl, &t);
			if (r < 0 || t == NULL) {
				LOG("Skipping unresolvable argument '%s'%s%s", path,
					r < 0 ? "; " : "", r < 0 ? strerror(-r) : "");
				free(t);
				free(ctl);
				continue;
			}
			j = (char *) malloc(sizeof(char) * (root_len + strlen(t) + 2));
			if (!j)
				LOG_OOM;
			if (root_len > 0) {
				strcpy(j, root);
				j[root_len] = '/';
			}
			strcpy(j + ((root_len > 0) ? root_len + 1 : 0), t);
			free(t);
			path = j;
			j = NULL;
			r = cg_get_path(ctl ?: SYSTEMD_CGROUP_CONTROLLER, path, NULL, &j);
			free(ctl);
			free(path);
			path = j;
			if (r < 0)
				continue;
			if (strv_push(&all_paths, path, false) < 0)
				LOG_OOM;
			p++;
		}
		free(root);
		free(fallback);
	}
	return s + user_units + p;
}

int
main(int argc, char *argv[]) {
	int r, errors = 0, i = 0;
	sd_bus *bus = NULL;
	unsigned term_cols;

	if (argc <= 0 || argv[0] == NULL) {
		LOG("Invalid arguments - exciting.\n", NULL);
		exit(99);
	}
	r = parse_argv(argc, argv);
	if (r <= 0)
		return r;

	term_cols = term_columns();

#define _DBUS_PREFIX "/org/freedesktop/systemd1/unit/"
	size_t plen = strlen(_DBUS_PREFIX);
	if (all_units) {
		for (char * const *unit = all_units; *unit; unit++, i++) {
			char *cgroup = NULL, *path = NULL;
			const char *dbus_if;
			sd_bus_error bus_err = SD_BUS_ERROR_NULL;

			if (i == user_units && bus) {
				sd_bus_flush_close_unrefp(&bus);
				bus = NULL;
			}
			dbus_if = strrchr(*unit, '.');
			if (!dbus_if) {	// this should not happen because unit name is valid
				LOG("Skipping invalid %s unit '%s' (no extension).",
					i < user_units ? "user" : "system", *unit);
				continue;
			}
			UnitType utype = unit_type_from_string(dbus_if + 1);
			dbus_if = unit_dbus_interface_from_type(utype);
			if (!dbus_if) {
				LOG("Skipping %s unit '%s' - unknown type.",
					i < user_units ? "user" : "system", *unit);
				continue;
			}
			if (!bus) {
				/* Connect to the bus only if necessary */
				r = bus_connect(&bus, i < user_units);
				if (r < 0) {
					errors++;
					LOG("%s DBus-Connect failed with %d",
						i < user_units ? "User" : "System", r);
					continue;
				}
			}

			path = (char *) malloc(sizeof(char) * (strlen(*unit) * 3 + plen+1));
			if (!path)
				LOG_OOM;

			strcpy(path, _DBUS_PREFIX);
#undef _DBUS_PREFIX
			if (**unit == '\0') {
				path[plen] = '_';
				path[plen+1] = '\0';
			} else {
				// escape unit name
				char c, *f, *t;
				for (f = *unit, t = path + plen; *f; f++) {
					c = *f;
					if (((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) ||
						(f > *unit && c >= '0' && c <= '9'))
					{
						*(t++) = c;
					} else {
						*(t++) = '_';
						*(t++) = hd[(c >> 4) & 15];
						*(t++) = hd[c & 15];
					}
				}
				*t = '\0';
			}
			r = sd_bus_get_property_string(bus,"org.freedesktop.systemd1", path,
				dbus_if, "ControlGroup", &bus_err, &cgroup);
				const char *s = NULL;
			if (r < 0) {
				char buf[1024];	// see strerror(3) NOTES
				if (sd_bus_error_has_name(&bus_err,SD_BUS_ERROR_ACCESS_DENIED)){
					s = "Access denied";
				} else if (bus_err.message) {
					s = bus_err.message;
				} else {
					s = strerror_r(-r, buf, sizeof(buf));
				}
				LOG("Failed to query unit control group path '%s' for '%s': %s",
					path, dbus_if, s);
			}
			free(path);
			sd_bus_error_free(&bus_err);
			if (r < 0 || !cgroup || cgroup[0] == '\0') {
				LOG("%s unit '%s' not found.",
					i < user_units ? "User" : "System", *unit, cgroup);
				free(cgroup);
				errors++;
				continue;
			}

			printf("Unit %s (%s):\n", *unit, cgroup);
			fflush(stdout);

			if (show_cgroup_by_path(cgroup, "", term_cols, arg_output_flags))
				errors++;
			free(cgroup);
		}
		for (char * const *unit = all_units; *unit; unit++) {
			free(*unit);
		}
		free(all_units);
	}
	if (bus)
		sd_bus_flush_close_unrefp(&bus);

	if (all_paths) {
		for (char * const *path = all_paths; *path; path++) {
			printf("Directory '%s':\n", *path);
			fflush(stdout);

			if (show_cgroup_by_path(*path, "", term_cols, arg_output_flags))
				errors++;
			free(*path);
		}
		free(all_paths);
	}
	if (errors)
		(void) sd_notifyf(0, "ERRNO=%i", errors);
	return errors ? EXIT_FAILURE : EXIT_SUCCESS;
}
