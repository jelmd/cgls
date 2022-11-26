/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

typedef enum OutputFlags {
	OUTPUT_SHOW_ALL       = 1 << 0,
	OUTPUT_FULL_WIDTH     = 1 << 1,
	OUTPUT_COLOR          = 1 << 2,

	/* Specific to log output */
	OUTPUT_WARN_CUTOFF    = 1 << 3,
	OUTPUT_CATALOG        = 1 << 4,
	OUTPUT_BEGIN_NEWLINE  = 1 << 5,
	OUTPUT_UTC            = 1 << 6,
	OUTPUT_NO_HOSTNAME    = 1 << 7,

	/* Specific to process tree output */
	OUTPUT_KERNEL_THREADS = 1 << 8,
	OUTPUT_CGROUP_XATTRS  = 1 << 9,
	OUTPUT_CGROUP_ID      = 1 << 10,
} OutputFlags;

typedef enum CGroupUnified {
	CGROUP_UNIFIED_UNKNOWN = -1,
	CGROUP_UNIFIED_NONE = 0,	/**< Both systemd and controllers on legacy */
	CGROUP_UNIFIED_SYSTEMD = 1,	/**< Only systemd on unified */
	CGROUP_UNIFIED_ALL = 2,		/**< Both systemd and controllers on unified */
} CGroupUnified;

//static int cg_unified_cached(void);

#define SYSTEMD_CGROUP_CONTROLLER_LEGACY "name=systemd"
#define SYSTEMD_CGROUP_CONTROLLER_HYBRID "name=unified"
#define SYSTEMD_CGROUP_CONTROLLER "_systemd"

//static int cg_pid_get_path(pid_t, char **);

#define SPECIAL_INIT_SCOPE "/init.scope"
#define SPECIAL_SYSTEM_SLICE "/system.slice"

int get_cgroup_root(char **);
//static bool cg_controller_is_valid(const char *p);
int cg_split_spec(const char *, char **, char **);
int cg_get_path(const char *, const char *, const char *, char **);
//static int cg_read_subgroup(DIR *, char **);
//static int cg_read_pid(FILE *, pid_t *);
//static int cg_is_empty(const char *, const char *);
//static int cg_read_event(const char *, const char *, const char *, char **);
//static int cg_is_empty_recursive(const char *, const char *);
//static void show_pid_array(pid_t[], unsigned, const char *, size_t, bool, bool, OutputFlags);
//static int show_cgroup_one_by_path(const char *, const char *, size_t, bool, OutputFlags);
//static int show_cgroup_name(const char *, const char *, SpecialGlyph, OutputFlags);
int show_cgroup_by_path(const char *, const char *, size_t, OutputFlags);
