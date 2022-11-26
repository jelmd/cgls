/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <threads.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/magic.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>

#include "log.h"
#include "characters.h"
#include "unit.h"
#include "misc.h"
#include "termcolors.h"
#include "glyph-util.h"

#include "cgroup.h"

static thread_local bool unified_systemd_v232;

/**
 * Checks the type of unified hierarchy currently used on the system.
 * @return A value < 0  on error, the detected type of unified hierarchy (which
 *		can be CGROUP_UNIFIED_NONE) otherwise.
 */
static int
cg_unified_cached(void) {
	static thread_local CGroupUnified unified_cache = CGROUP_UNIFIED_UNKNOWN;
	struct statfs fs;

	if (unified_cache >= CGROUP_UNIFIED_NONE)
		return unified_cache;

	if (statfs("/sys/fs/cgroup/", &fs) < 0) {
		LOG("statfs('/sys/fs/cgroup/') failed with %d", errno);
		return -errno;
	}
	if (fs.f_type == (typeof(fs.f_type)) CGROUP2_SUPER_MAGIC) {
		//DBG("Found cgroup2 on /sys/fs/cgroup/, full unified hierarchy", NULL);
		unified_cache = CGROUP_UNIFIED_ALL;
	} else if (fs.f_type == (typeof(fs.f_type)) TMPFS_MAGIC) {
		if (statfs("/sys/fs/cgroup/unified/", &fs) == 0 &&
			(fs.f_type == (typeof(fs.f_type)) CGROUP2_SUPER_MAGIC))
		{
			DBG("Found cgroup2 on /sys/fs/cgroup/unified,"
				" unified hierarchy for systemd controller", NULL);
			unified_cache = CGROUP_UNIFIED_SYSTEMD;
			unified_systemd_v232 = false;
		} else {
			if (statfs("/sys/fs/cgroup/systemd/", &fs) < 0) {
				if (errno == ENOENT) {
					/* Some other software may have set up
					 * /sys/fs/cgroup in a configuration we
					 * do not recognize. */
					LOG("Unsupported cgroupsv1 setup detected: name=systemd "
						"hierarchy not found.", NULL);
					return -ENOMEDIUM;
				}
				LOG("statfs(\"/sys/fs/cgroup/systemd\" failed with %d", errno);
				return -errno;
			}

			if (fs.f_type == (typeof(fs.f_type)) CGROUP2_SUPER_MAGIC) {
				DBG("Found cgroup2 on /sys/fs/cgroup/systemd, unified hierarchy"					" for systemd controller (v232 variant)", NULL);
				unified_cache = CGROUP_UNIFIED_SYSTEMD;
				unified_systemd_v232 = true;
			} else if (fs.f_type == (typeof(fs.f_type)) CGROUP_SUPER_MAGIC) {
				DBG("Found cgroup on /sys/fs/cgroup/systemd, legacy hierarchy",
					NULL);
				unified_cache = CGROUP_UNIFIED_NONE;
			} else {
				LOG("Unexpected filesystem type %llx mounted on "
					"/sys/fs/cgroup/systemd, assuming legacy hierarchy",
					(unsigned long long) fs.f_type);
				unified_cache = CGROUP_UNIFIED_NONE;
			}
		}
	} else if (fs.f_type == (typeof(fs.f_type)) SYSFS_MAGIC) {
		LOG("No filesystem is currently mounted on /sys/fs/cgroup.", NULL);
		return -ENOMEDIUM;
	} else {
		LOG("Unknown filesystem type %llx mounted on /sys/fs/cgroup.",
			(unsigned long long) fs.f_type);
		return -ENOMEDIUM;
	}
	return unified_cache;
}

#define SYSTEMD_CGROUP_CONTROLLER_LEGACY "name=systemd"
#define SYSTEMD_CGROUP_CONTROLLER_HYBRID "name=unified"
#define SYSTEMD_CGROUP_CONTROLLER "_systemd"

/**
 * Get the cgroup path for the given PID.
 * @param pid	PID to lookup. If '0' the PID of the running process is used.
 * @param ret_path	Where to store the pointer to the path found. Becomes NULL
 *		if not found. Unchanged on error. Free when done.
 * @return The length of the returned path without the trailing '\0' on success,
 *		an error code < 0 otherwise.
 */
static int
cg_pid_get_path(pid_t pid, char **ret_path) {
	FILE *f = NULL;
	char fs[6 + PID_MAX_DIGITS + 7 + 1]; // /proc/%i/cgroup
	int unified, r;
	char *line = NULL;

	if (pid == 0)
		pid = getpid();

	unified = cg_unified_cached();
	if (unified < 0)
		return unified;

	sprintf(fs, "/proc/" PID_FMT "/cgroup", pid);
	f = fopen(fs, "re");
	if (!f)
		return (errno == ENOENT) ? -ESRCH : -errno;

	__fsetlocking(f, FSETLOCKING_BYCALLER);
	flockfile(f);
	for (;;) {
		char *e;
		size_t sl, pl;

		free(line);
		line = NULL;
		r = getline(&line, &sl, f);
		if (r <= 0) {
			r = r < 0 ? -errno : -ENODATA;
			free(line);
			break;
		}
		if (line[r-1] == '\n')
			line[r-1] = '\0';	// remove tailing newline
		if (unified > CGROUP_UNIFIED_NONE) {
			// 0::/init.scope
			if (strncmp(line, "0:", 2) != 0)
				continue;
			e = strchr(line + 2, ':');
			if (!e)
				continue;
			e++;
		} else {
			// 1:name=systemd:/init.scope
			char *l = strchr(line, ':');
			if (!l)
				continue;
			e = l + 1;
			sl = strlen(SYSTEMD_CGROUP_CONTROLLER_LEGACY) + 1;
			if (strncmp(e, SYSTEMD_CGROUP_CONTROLLER_LEGACY ":", sl) != 0)
				continue;
			e += sl;
		}

		char *path = strdup(e);
		if (!path) {
			r = -ENOMEM;
		} else {
			/* Truncate suffix indicating the process is a zombie */
#define DELETED " (deleted)"
			sl = strlen(path);
			pl = strlen(DELETED);
			if (sl > pl && strcmp(path + sl - pl, DELETED) == 0) {
				sl -= pl;
				path[sl] = '\0';
			}
#undef DELETED
			*ret_path = path;
			r = sl;
		}
		free(line);
		break;
	}
	funlockfile(f);
	fclose(f);
	return r;
}

#define SPECIAL_INIT_SCOPE "/init.scope"
#define SPECIAL_SYSTEM_SLICE "/system.slice"

/**
 * Get the cgroup root path.
 * @param ret	Where to store the pointer to the path. Free when done.
 * @return The length of the returned path without the trailing '\0' on success,
 *		an error code < 0 otherwise.
 */
int
get_cgroup_root(char **ret) {
	char *root = NULL, *e = NULL;
	//
	int r = cg_pid_get_path(1, &root);

	if (r == -ENOMEDIUM) {
		LOG("Failed to get root control group path.\n"
			"No cgroup filesystem mounted on /sys/fs/cgroup", NULL);
		return r;
	}
	if (r < 0) {
		LOG("Failed to get root control group path (%d)", r);
		return r;
	}
	int len = strlen(SPECIAL_INIT_SCOPE);
	if (r >= len && strcmp(root + r - len, SPECIAL_INIT_SCOPE) == 0)
		e = root + r - len;
	if (!e) {
		len = strlen(SPECIAL_SYSTEM_SLICE);
		if (r >= len && strcmp(root + r - len, SPECIAL_SYSTEM_SLICE) == 0)
			e = root + r - len;
	}
	if (!e) {
		len = strlen("/system");
		if (r >= len && strcmp(root + r - len, "/system") == 0)
			e = root + r - len;
	}
	// cut off special pathes
	if (e) {
		*e = '\0';
		r = e - root;
	}

	*ret = root;

	return r;
}

/**
 * Check whether the given string is a valid controller name, i\.e\.\ consists
 * of letters, digits, and underline(s), only. An optional leading 'name=' gets
 * silently ignored.
 * @param p	The string to check.
 * @return true if valid, false otherwise.
 */
static bool
cg_controller_is_valid(const char *p) {
	const char *t;

	if (!p)
		return false;

	if (strcmp(p, SYSTEMD_CGROUP_CONTROLLER) == 0)
		return true;

	if (strncmp(p, "name=", 5) == 0)
		p += 5;

	if (*p == '\0' || *p == '_')
		return false;

	for (t = p; *t; t++)
		if (!strchr(DIGITS LETTERS "_", *t))
			return false;

	if (t - p > NAME_MAX)
		return false;

	return true;
}

/**
 * Split the given spec into its controller and path parts.
 * @param spec	The string to parse.
 * @param ret_controller	Where to store the name of the extracted controller
 *		on success unless NULL. Free when done.
 * @param ret_path			Where to store the extracted, simplified path
 *		on success unless NULL. Free when done.
 * @return The length of the extracted simplified path without the trailing '\0'
 *		on success, an error code < 0 otherwise.
 */
int
cg_split_spec(const char *spec, char **ret_controller, char **ret_path) {
	char *controller = NULL, *path = NULL;
	int r = 0;

	if (*spec == '/') {
		if (!path_is_normalized(spec))
			return -EINVAL;

		if (ret_path) {
			path = strdup(spec);
			if (!path)
				return -ENOMEM;

			r = path_simplify(path);
		}
	} else {
		const char *e;

		e = strchr(spec, ':');
		if (e) {
			controller = strndup(spec, e - spec);
			if (!controller)
				return -ENOMEM;
			if (!cg_controller_is_valid(controller)) {
				free(controller);
				return -EINVAL;
			}
			if ((e + 1) != NULL && e[1] != '\0') {
				path = strdup(e + 1);
				if (!path) {
					free(controller);
					return -ENOMEM;
				}

				if (!path_is_normalized(path) || path[0] != '/') {
					free(controller);
					free(path);
					return -EINVAL;
				}
				r = path_simplify(path);
			}

		} else {
			if (!cg_controller_is_valid(spec))
				return -EINVAL;

			if (ret_controller) {
				controller = strdup(spec);
				if (!controller)
					return -ENOMEM;
			}
		}
	}

	if (ret_controller)
		*ret_controller = controller;
	if (ret_path)
		*ret_path = path;
	return r;
}

/**
 * Get the full path (i\.e\.\ incl\.\ the path, where the related controller
 * is mounted) for the given cgroup path. Depending on the type of hierarchy
 * in use, something like \e ctrl/path/suffix gets returned.
 * @param ctrl		The name of the controller. Ignored if NULL. A leading
 *					'name=' gets automatically ignored.
 * @param path		cgroup path of interest. If NULL, "/" gets used instead.
 * @param suffix	cgroup path suffix (or filename) to use. Ignored if NULL.
 * @param ret		Where to store the deduced path on success. Unchanged on
 *		error. Free when done.
 * @return The length of the deduced path without the trailing '\0' on success,
 *		an error code < 0 otherwise.
 */
int
cg_get_path(const char *ctrl, const char *path, const char *suffix, char **ret){
	char *j = NULL, *t;
	size_t plen = path ? strlen(path) : 0, slen = suffix ? strlen(suffix) : 0;
	size_t clen = 0, rlen = strlen("/sys/fs/cgroup");
	int r;

	if (ctrl) {
		r = cg_unified_cached();
		if (r < CGROUP_UNIFIED_NONE) {
			LOG("Unable to determine cgroup path for controller '%s' "
				"and path '%s%s%s' - skipped.", ctrl, path, suffix ? "/" : "",
				suffix ? suffix : "");
			return r;
		}
		if (r != CGROUP_UNIFIED_ALL) {
			if (!ctrl || strcmp(ctrl, SYSTEMD_CGROUP_CONTROLLER) == 0) {
				ctrl = ((r == CGROUP_UNIFIED_SYSTEMD) && !unified_systemd_v232)
					? "unified"     // hybrid
					: "systemd";    // legacy
			} else if (strncmp(ctrl, "name=", 5) == 0) {
				ctrl += 5;
			}
			clen = strlen(ctrl);
		}
	} else if (plen == 0 && slen == 0) {
		return -EINVAL;
	} else {
		rlen = 0;
	}
	j = (char *) malloc(sizeof(char) * (rlen + clen + plen + slen + 4));
	if (!j)
		return -ENOMEM;
	t = j;
	if (rlen) {
		strcpy(j, "/sys/fs/cgroup");
		t += rlen;
	}
	if (clen) {
		if (j != t)
			*(t++) = '/';
		strcpy(t, ctrl);
		t += clen;
	}
	if (plen) {
		if (j != t)
			*(t++) = '/';
		strcpy(t, path);
		t += plen;
	}
	if (slen) {
		if (j != t)
			*(t++) = '/';
		strcpy(t, suffix);
	}
	r = path_simplify(j);
	*ret = j;
	return r;
}

/**
 * Get the name of the next valid entry in the given directory stream, but
 * skip directories and '..'.
 * @param d		Directory stream to read.
 * @param fn	Where to store the filename read from the related stream entry.
 *		Unchanged on error. Free when done.
 * @return 1 on success, 0 otherwise.
 */
static int
cg_read_subgroup(DIR *d, char **fn) {
	for (struct dirent *e = readdir_ensure_type(d);; e = readdir_ensure_type(d)) {
		if (!e)
			return (errno > 0) ? -errno : 0;

		if (e->d_type != DT_DIR)
			continue;

		char *path = e->d_name;
		if (path[0] =='.' && (path[1] =='\0' ||(path[1] =='.' && path[2] =='\0')))
			continue;

		path = strdup(e->d_name);
		if (!path)
			return -ENOMEM;

		*fn = path;
		return 1;
	}
	return 0;
}

/**
 * Read the PID (i\.e\.\ an unsigned long) from the given file stream.
 * @param f	file stream to read.
 * @param _pid	Where to store the PID on success. Unchanged on error.
 * @return 1 if a PID could be read, 0 if no valid number was found, an error
 * code < 0 otherwise.
 */
static int
cg_read_pid(FILE *f, pid_t *_pid) {
	unsigned long ul;

	// NOTE cgroup.procs might contain duplicates! See cgroups.txt for details.
	errno = 0;
	if (fscanf(f, "%lu", &ul) != 1)
		return feof(f) ? 0 : ((errno > 0) ? -errno : -EIO);

	if (ul <= 0)
		return -EIO;

	*_pid = (pid_t) ul;
	return 1;
}

/**
 * Check whether the file cgroup.procs in the given cgroup path contains any
 * PID. If not, the related cgroup path is consider to be empty.
 * @param controller	The name of the controller of the given cgroup path.
 * @param path			The cgroup path to check.
 * @return 1 if empty, 0 if not empty, or an error code < 0.
 */
static int
cg_is_empty(const char *controller, const char *path) {
	char *fs = NULL;
	FILE *f = NULL;
	pid_t pid;
	int r;

	r = cg_get_path(controller, path, "cgroup.procs", &fs);
	if (r < 0)
		return r;

	f = fopen(fs, "re");
	free(fs);
	if (r == -ENOENT)
		return true;
	if (!f)
		return -errno;

	r = cg_read_pid(f, &pid);
	fclose(f);

	return (r < 0) ? r : r == 0;
}

/**
 * Lookup the value of the given events in the given controllers cgroup path.
 *
 * @param ctrl	The name of the controller for the given cgroup path.
 * @param path	The cgroup path contianing the cgroup.events file to read.
 * @param event	The event to lookup.
 * @param ret	Where to store the value of the event on success. Unchanged on
 *		error. Free when done.
 * @return 0 on success, an error code < 0 otherwise.
 */
static int
cg_read_event(const char *ctrl, const char *path, const char *event, char **ret) {
	char *fname = NULL, *content = NULL;
	int r;

	r = cg_get_path(ctrl, path, "cgroup.events", &fname);
	if (r < 0)
		return r;

	r = read_virtual_file(fname, SIZE_MAX, &content, NULL);
	free(fname);
	if (r < 0)
		return r;

	for (const char *p = content;;) {
		char *line = NULL, *key = NULL, *val = NULL;
		const char *q;

		r = extract_first_word(&p, &line, "\n", 0);
		if (r < 0)
			goto fail;
		if (r == 0) {
			r = -ENOENT;
			goto fail;
		}
		q = line;
		r = extract_first_word(&q, &key, " ", 0);
		if (r < 0)
			goto fail;
		if (r == 0) {
			r = -EINVAL;
			goto fail;
		}
		if (strcmp(key, event)) {
			free(line);
			free(key);
			continue;
		}
		val = strdup(q);
		if (!val) {
			r = -ENOMEM;
			goto fail;
		}
		r = 0;
fail:
		free(line);
		free(key);
		if (r == 0)
			*ret = val;
		else
			free(val);
		break;
	}
	free(content);
	return r;
}

/**
 * Check whether the given cgroup path for the given controller is empty,
 * i\.e\.\ is either not populated or contains no subdirectories.
 * @param ctrl	The name of the related controller.
 * @param path	The cgroup path to check.
 * @return 1 if empty, 0 if not empty, an error code < 0 otherwise.
 */
static int
cg_is_empty_recursive(const char *ctrl, const char *path) {
	int r;

	// The root cgroup is always populated
	if (ctrl && (!path || path[0]=='\0' || (path[0]=='/' && path[1]=='\0')))
		return false;

	r = cg_unified_cached();
	if (r < 0)
		return r;
	if (r == CGROUP_UNIFIED_ALL ||
		(ctrl && !strcmp(ctrl,SYSTEMD_CGROUP_CONTROLLER)))
	{
		/* On the unified hierarchy we can check empty state via the "populated"
		   attribute of "cgroup.events". */
		char *t = NULL;

		r = cg_read_event(ctrl, path, "populated", &t);
		if (r == -ENOENT)
			return true;
		if (r < 0)
			return r;
		r = strcmp(t, "0") == 0;
		free(t);
		return r;
	} else {
		DIR *d = NULL;
		char *fn, *fs = NULL;

		if ((r = cg_is_empty(ctrl, path)) <= 0)
			return r;

		if ((r = cg_get_path(ctrl, path, NULL, &fs) < 0))
			return r;

		d = opendir(fs);
		free(fs);
		if (!d)
			return (errno == -ENOENT) ? true : -errno;

		size_t plen = strlen(path);
		while ((r = cg_read_subgroup(d, &fn)) > 0) {
			char *p = malloc(sizeof(char) * (plen + strlen(fn) + 2));
			if (!p) {
				closedir(d);
				return -ENOMEM;
			}
			strcpy(p, path);
			p[plen] = '/';
			strcpy(p + plen + 1, fn);
			r = cg_is_empty_recursive(ctrl, p);
			free(p);
			if (r <= 0) {
				closedir(d);
				return r;
			}
		}
		closedir(d);
		if (r < 0)
			return r;
	}
	if (r < 0)
		return r;

	return true;
}

/**
 * Comparator to sort PIDs.
 * @param a		Object to compare with b.
 * @param b		Object to compare with a.
 * @return 0 if equal, -1 if a < b, 1 otherwise.
 */
static int
pid_compare_func(const pid_t *a, const pid_t *b) {
	/* Suitable for usage in qsort() */
	return a == b ? 0 : (a < b ? -1 : 1);
}

/**
 * Sort the given list of PIDs, and print their command line (or if n/a at leats
 * its name) in a tree like fashion to stdout. Duplicates get skipped. If the
 * terminal in use supports colors (is not a dumb terminal and has its TERM env
 * var properly set), ANSI escape sequence are used to color it.
 * @param pids		PIDs of command lines to show.
 * @param n_pids	The number of pids in the passed pids array.
 * @param prefix	Prefix each line with this prefix. Should not be NULL.
 * @param columns	The number of available terminal columns. If an output line
 *		is bigger than this, it gets truncated and the now missing part replaced
 *		by ellipsis (i.e. '...' or the corresponding UTF-8 character if the
 *		terminal supports UTF-8).
 * @param extra		If true, print a triangular bullet instead of a
 *		"tree branch" or "tree right" symbol after the prefix.
 * @param more		True indicates that there are more siblings to follow and
 *		thus would cause to print always a "tree right" symbol after
 *		the prefix unless extra is true (supercedes it).
 * @param flags		Addional flags to adjust command line  formatting. If
 *		OUTPUT_FULL_WIDTH is set, columns gets effectively replaced by SIZE_MAX.
 */
static void
show_pid_array(pid_t pids[], unsigned n_pids, const char *prefix,
	size_t columns, bool extra, bool more, OutputFlags flags)
{
	unsigned i, j, pid_width;

	if (n_pids == 0)
		return;

	if (n_pids > 1)
		qsort(pids, n_pids, sizeof(pids[0]), (comparison_fn_t) pid_compare_func);

	/* Filter duplicates */
	for (j = 0, i = 1; i < n_pids; i++) {
		if (pids[i] == pids[j])
			continue;
		pids[++j] = pids[i];
	}
	n_pids = j + 1;

	i = pids[j];
	pid_width = 1;
	while ((i /= 10) != 0)
		pid_width++;

	if (flags & OUTPUT_FULL_WIDTH)
		columns = SIZE_MAX;
	else {
		if (columns > pid_width + 3) /* something like "├─1114784 " */
			columns -= pid_width + 3;
		else
			columns = 20;
	}
	for (i = 0; i < n_pids; i++) {
		char *t = NULL;

		get_process_cmdline(pids[i], columns,
			PROCESS_CMDLINE_COMM_FALLBACK | PROCESS_CMDLINE_USE_LOCALE, &t);
		if (extra)
			printf("%s%s ", prefix, special_glyph(GLYPH_TRIANGULAR_BULLET));
		else
			printf("%s%s", prefix, special_glyph(((more || i < n_pids - 1)
				? GLYPH_TREE_BRANCH : GLYPH_TREE_RIGHT)));

		printf("%s%*"PID_PRI" %s%s\n", ansi_grey(), (int) pid_width, pids[i],
			 t ?: "n/a", ansi_normal());
		free(t);
	}
}

/**
 * Simplify the given cgroup path and print out all command lines of the
 * processes (or if unable to determine at least their names) in a tree like
 * manner. Kernel threads get ignored unless the OUTPUT_KERNEL_THREADS flag is
 * set.
 * @param prefix	Prefix each line printed to stdout with the given prefix.
 * @param columns	The max. length of an output line. If bigger than this it
 *		gets truncated and the missing part replaced by ellipses.
 * @param more		True indicates that there are more siblings to follow and
 *		output should be formatted accordingly.
 * @param flags		If OUTPUT_KERNEL_THREADS is set, print out kernel threads as
 *		well. If OUTPUT_FULL_WIDTH the max. length of output lines is set to be
 *		SIZE_MAX (supercedes \e columuns).
 * @return 0 on success, an error code < 0 otherwise.
 */
static int
show_cgroup_one_by_path(const char *path, const char *prefix, size_t columns,
	bool more, OutputFlags flags)
{
	pid_t *pids = NULL;
	FILE *f = NULL;
	char *p = NULL, *fn = NULL, *c = NULL;
	size_t n = 0;
	int r;

	if (strncmp(path, "/sys/fs/cgroup", 14) == 0) {
		p = strdup(path);
		if (!p)
			return -ENOMEM;
		r = path_simplify(p);
	} else {
		r = cg_split_spec(path, &c, &fn);
		if (r < 0)
			return r;
		r = cg_get_path(c ?: SYSTEMD_CGROUP_CONTROLLER, fn, NULL, &p);
		free(c);
		free(fn);
		if (r < 0)
			return r;
	}
	n = r;

	fn = (char *) malloc(sizeof(char) * (n + 13 + 1));
	if (!fn) {
		free(p);
		return -errno;
	}
	strcpy(fn, p);
	strcpy(fn + n, "/cgroup.procs");
	f = fopen(fn, "re");
	free(p);
	free(fn);
	if (!f)
		return -errno;

	n = 0;
	for (;;) {
		pid_t pid;

		/* libvirt/qemu uses threaded mode and cgroup.procs cannot be read at
		   the lower levels.
		   From https://docs.kernel.org/admin-guide/cgroup-v2.html#threads,
		   'cgroup.procs' in a threaded domain cgroup contains the PIDs of all
		   processes in the subtree and is not readable in the subtree proper.*/
		r = cg_read_pid(f, &pid);
		if (r == 0 || r == -EOPNOTSUPP)
			break;
		if (r < 0) {
			fclose(f);
			free(pids);
			return r;
		}
		if (!(flags & OUTPUT_KERNEL_THREADS) && is_kernel_thread(pid) > 0)
			continue;

		if (!GREEDY_REALLOC(pids, n + 1)) {
			fclose(f);
			free(pids);
			return -ENOMEM;
		}

		pids[n++] = pid;
	}

	show_pid_array(pids, n, prefix, columns, false, more, flags);
	fclose(f);
	free(pids);

	return 0;
}

/** The structure to pass to name_to_handle_at() on cgroupfs2 */
typedef union {
	struct file_handle file_handle;
	uint8_t space[offsetof(struct file_handle, f_handle) + sizeof(uint64_t)];
} cg_file_handle;

/**
 * Print "prefix + glyph + basename(path)" to stdout. If the related cgroup is
 * delegated, basename gets underlined (if the terminal supports it) and '...'
 * append. Finally if requested via OUTPUT_CGROUP_ID flag, the cgroup ID and if
 * requested via OUTPUT_CGROUP_XATTRS flag, all ext. atributes named "user.*"
 * and "trusted.*" related to this path gets append to the output line.
 * @param path		The cgroup path in question.
 * @param prefix	The prefix to print out first.
 * @param glyph		The glyph to print to render a tree like structure.
 * @param flags		The output modifiers as explained above.
 * @return 0 on success, an error code < 0 otherwise.
 */
static int
show_cgroup_name(const char *path, const char *prefix, SpecialGlyph glyph,
	OutputFlags flags)
{
	uint64_t cgroupid = UINT64_MAX;
	char *b = NULL;
	int fd = -1;
	bool delegate;
	int r;

	if ((flags & OUTPUT_CGROUP_XATTRS) || (flags & OUTPUT_CGROUP_ID)) {
		fd = open(path,O_PATH|O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY|AT_EMPTY_PATH,0);
		if (fd < 0) {
			LOG("Failed to open cgroup '%s' (%d) - ignored.", path, errno);
		}
	}

	delegate = is_delegated(fd, path) > 0;

	if (flags & OUTPUT_CGROUP_ID) {
		cg_file_handle fh = { .file_handle.handle_bytes = sizeof(uint64_t) };
		int mnt_id = -1;

		if (name_to_handle_at(fd < 0 ? AT_FDCWD : fd, fd < 0 ? path : "",
			&fh.file_handle, &mnt_id, fd < 0 ? 0 : AT_EMPTY_PATH) < 0)
		{
			LOG("Failed to determine cgroup ID of %s (%d)", path, errno);
		} else {
			cgroupid = (*(uint64_t*) fh.file_handle.f_handle);
		}
	}

	r = last_path_component(path, &b);
	if (r < 0) {
		close(fd);
		LOG("Failed to extract filename from cgroup path: %s (%d)", path, r);
		return -errno;
	}

	printf("%s%s%s%s%s", prefix, special_glyph(glyph),
		delegate ? ansi_underline() : "", *b == '_' ? b + 1 : b,
		delegate ? ansi_normal() : "");
	free(b);

	if (delegate) {
		printf(" %s%s%s", ansi_highlight(), special_glyph(GLYPH_ELLIPSIS),
			   ansi_normal());
	}

	if (cgroupid != UINT64_MAX)
		printf(" %s(#%" PRIu64 ")%s", ansi_grey(), cgroupid, ansi_normal());

	printf("\n");

	errno = 0;
	if ((flags & OUTPUT_CGROUP_XATTRS) && fd >= 0) {
		char *nl = NULL, *xa;
		int bytes = xattrget(fd, NULL, NULL, &nl);
		if (bytes < 0 && bytes != -ENODATA)
			LOG("Failed to enum xattrs on '%s' (%s)", path, strerror(-bytes));
		errno = 0;

		// listxattr returns a list of null-terminated names ...
		for (xa = nl; xa && *xa && xa <= nl + bytes; xa = strchr(xa, 0) + 1) {
			char *x = NULL, *y = NULL, *buf = NULL, *s, *t;
			int n, nlen;

			if (strncmp(xa, "user.", 5) || strncmp(xa, "trusted.", 8))
				continue;

			n = xattrget(fd, NULL, xa, &buf);
			if (n < 0) {
				if (n != -ENODATA)
					LOG("Failed to read xattr '%s' off '%s' (%s)",
						xa, path, strerror(-n));
				continue;
			}

			nlen = strlen(xa);
			x = (char *) malloc(sizeof(char) * (nlen * 4 + 1));
			if (!x) {
				free(buf);
				errno = ENOMEM;
				break;
			}
			for (s = xa, t = x; s < xa + nlen; s++)
				t += cescape_char(*s, t);
			*t = 0;

			y = (char *) malloc(sizeof(char) * n * 4);
			if (!y) {
				free(x);
				free(buf);
				errno = ENOMEM;
				break;
			}
			for (s = buf, t = y; s < buf + n; s++)
				t += cescape_char(*s, t);
			*t = 0;

			printf("%s%s%s %s%s%s: %s\n", prefix, glyph == GLYPH_TREE_BRANCH
				? special_glyph(GLYPH_TREE_VERTICAL) : "  ",
				special_glyph(GLYPH_ARROW_RIGHT), ansi_blue(), x,
				ansi_normal(), y);
			free(x);
			free(y);
			free(buf);
		}
		free(nl);
	}
	if (fd >= 0)
		close(fd);

	return -errno;
}

/**
 * Simplify the given cgroup path and render the related hierarchy as a tree
 * to stdout. It is basically the entry function for showing a cgroup tree.
 * @param path		The cgroup to show.
 * @param prefix	If != NULL prefix each printed line with this string.
 * @param columns	Max. length of each line. If bigger than this the line gets
 *		truncated and the missing part replaced by ellipses.
 * @param flags			If OUTPUT_KERNEL_THREADS is set, print out kernel
 *		threads as well. If OUTPUT_FULL_WIDTH the max. length of output lines
 *		is set to be SIZE_MAX (supercedes \e columuns).
 */
int
show_cgroup_by_path(const char *path, const char *prefix, size_t columns,
	OutputFlags flags)
{
	char *p1 = NULL, *last = NULL, *p2 = NULL, *fn = NULL, *gn = NULL;
	DIR *d = NULL;
	bool shown_pids = false;
	size_t plen, fnlen;
	int r;

	if (!prefix) {
		prefix = "";
		plen = 0;
	} else {
		plen = strlen(prefix);
	}

	if (strncmp(path, "/sys/fs/cgroup", 14) == 0) {
		fn = strdup(path);
		if (!fn)
			return -ENOMEM;
		fnlen = path_simplify(fn);
	} else {
		char *p = NULL, *c = NULL;
		r = cg_split_spec(path, &c, &p);
		if (r < 0)
			return r;
		r = cg_get_path(c ?: SYSTEMD_CGROUP_CONTROLLER, p ?: "/", NULL, &fn);
		free(c);
		free(p);
		if (r < 0)
			return r;
		fnlen = r;
	}

	d = opendir(fn);
	if (!d) {
		r = -errno;
		goto fail;
	}

	while ((r = cg_read_subgroup(d, &gn)) > 0) {
		char *k = (char *) malloc(sizeof(char) * (fnlen + strlen(gn) + 2));
		if (!k) {
			r = -ENOMEM;
			goto fail;
		}
		strcpy(k, fn); k[fnlen] = '/'; strcpy(k + fnlen + 1, gn);
		free(gn); gn = NULL;

		if (!(flags & OUTPUT_SHOW_ALL) && cg_is_empty_recursive(NULL, k) > 0) {
			free(k);
			continue;
		}
		if (!shown_pids) {
			show_cgroup_one_by_path(path, prefix, columns, true, flags);
			shown_pids = true;
		}

		if (last) {
			r = show_cgroup_name(last, prefix, GLYPH_TREE_BRANCH, flags);
			if (r < 0) {
				free(k);
				goto fail;
			}
			if (!p1) {
				p1 = (char *) malloc(sizeof(char) + plen + 7);
				if (!p1) {
					free(k);
					r = -ENOMEM;
					goto fail;
				}
				strcpy(p1, prefix);
				strcpy(p1 + plen, special_glyph(GLYPH_TREE_VERTICAL));
			}
			show_cgroup_by_path(last, p1, columns - 2, flags);
			free(last);
			last = NULL;
		}
		last = k;
	}

	if (r < 0)
		goto fail;

	if (!shown_pids) {
		// simple process, which has no children
		show_cgroup_one_by_path(path, prefix, columns, !!last, flags);
	}

	if (last) {
		r = show_cgroup_name(last, prefix, GLYPH_TREE_RIGHT, flags);
		if (r < 0)
			goto fail;

		if (!p2) {
			p2 = (char *) malloc(sizeof(char) + plen + 3);
			if (!p2) {
				r = -ENOMEM;
				goto fail;
			}
			strcpy(p2, prefix);
			strcpy(p2 + plen, "  ");
		}
		show_cgroup_by_path(last, p2, columns - 2, flags);
	}
	r = 0;

fail:
	free(last);
	free(gn);
	free(p1);
	free(p2);
	closedir(d);
	free(fn);
	return r;
}
