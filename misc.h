/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stdbool.h>
#include <sys/types.h>
#include <dirent.h>
#include <inttypes.h>

int first_path_component(const char **, const char **);
int path_simplify(char *);
bool path_is_normalized(const char *);
int last_path_component(const char *, char **);

int strv_push(char ***, char *, bool);

struct dirent *readdir_ensure_type(DIR *);

unsigned term_columns(void);

/** The maximum size of the file we'll read in one go (64M). */
#define READ_FULL_BYTES_MAX (64U*1024U*1024U - 1U)

/**
 * The maximum size of virtual files (i\.e\.\ procfs, sysfs, and other virtual
 * "API" files) we'll read in one go in read_virtual_file(). Note that this
 * limit is different (and much lower) than the READ_FULL_BYTES_MAX limit. This
 * reflects the fact that we use different strategies for reading virtual and
 * regular files:
 * - Virtual files we generally have to read in a single read() syscall since
 *   the kernel doesn't support continuation read()s for them. Thankfully they
 *   are somewhat size constrained. Thus we can allocate the full potential
 *   buffer in advance.
 * - Regular files OTOH can be much larger, and there we grow the allocations
 *   exponentially in a loop. We use a size limit of 4M-2 because 4M-1 is the
 *   maximum buffer that /proc/sys/ allows us to read() (larger reads will fail
 *   with ENOMEM), and we want to read one extra byte to detect EOFs.
 */
#define READ_VIRTUAL_BYTES_MAX (4U*1024U*1024U - 2U)

int read_virtual_file(char *, size_t, char **,size_t *);

#define GREEDY_REALLOC(array, need)	\
	greedy_realloc((void**) &(array), (need), sizeof((array)[0]))
void *greedy_realloc(void **, size_t, size_t);

/**
 * Note that if no flags are specified, escaped escape characters will be
 * silently stripped. */
typedef enum ExtractFlags {
	EXTRACT_RELAX						= 1 << 0, /**< Allow unbalanced quote and eat up trailing backslash. */
	EXTRACT_CUNESCAPE					= 1 << 1, /**< Unescape known escape sequences. */
	EXTRACT_UNESCAPE_RELAX				= 1 << 2, /**< Allow and keep unknown escape sequences, allow and keep trailing backslash. */
	EXTRACT_UNESCAPE_SEPARATORS			= 1 << 3, /**< Unescape separators (those specified, or whitespace by default). */
	EXTRACT_KEEP_QUOTE					= 1 << 4, /**< Ignore separators in quoting with "" and ''. */
	EXTRACT_UNQUOTE						= 1 << 5, /**< Ignore separators in quoting with "" and '', and remove the quotes. */
	EXTRACT_DONT_COALESCE_SEPARATORS	= 1 << 6, /**< Don't treat multiple adjacent separators as one */
	EXTRACT_RETAIN_ESCAPE				= 1 << 7, /**< Treat escape character '\' as any other character without special meaning */
	EXTRACT_RETAIN_SEPARATORS			= 1 << 8, /**< Do not advance the original string pointer past the separator(s) */
} ExtractFlags;
int extract_first_word(const char **, char **, const char *, ExtractFlags);

pid_t getpid_cached(void);

// Not exposed yet. Defined at include/linux/sched.h
#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000
#endif

int is_kernel_thread(pid_t pid);

typedef enum ProcessCmdlineFlags {
	PROCESS_CMDLINE_COMM_FALLBACK	= 1 << 0,
	PROCESS_CMDLINE_USE_LOCALE		= 1 << 1,
	PROCESS_CMDLINE_QUOTE			= 1 << 2,
	PROCESS_CMDLINE_QUOTE_POSIX		= 1 << 3,
} ProcessCmdlineFlags;

/**
 * The kernel limits userspace processes to TASK_COMM_LEN (16 bytes), but allows
 * higher values for its own workers, e\.g\.\ "kworker/u9:3-kcryptd/253:0".
 * Let's pick a fixed smallish limit that will work for the kernel.
 */
#define COMM_MAX_LEN 128

/**
 * The maximum thread/process name length including trailing '\0' byte. This
 * mimics the kernel definition of the same name, which we need in userspace at
 * various places but is not defined in userspace currently, neither under this
 * name nor any other.
 * Not exposed yet. Defined at include/linux/sched.h
 */
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define PID_PRI PRIi32
#define PID_FMT "%" PID_PRI
/** Linux: PID_MAX is max. 2^22 = 4M - so max. 7 digits */
#define PID_MAX_DIGITS 7

int get_process_comm(pid_t, char **);
int get_process_cmdline(pid_t, size_t, ProcessCmdlineFlags, char **);
int xattrget(int, const char *, const char *, char **);
int is_delegated(int, const char *);
