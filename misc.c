/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <malloc.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <sys/prctl.h>
#include <sys/xattr.h>
#include <threads.h>

#include "log.h"
#include "characters.h"
#include "locale-util.h"

#include "misc.h"

/**
 * Get the number of elements in the given NULL-terminated list of strings.
 * @param l		List to check.
 * @return number of elements in the given list.
 */
static size_t
strv_length(char * const *l) {
	size_t n = 0;
	if (!l)
		return 0;
	for (; *l; l++)
		n++;
	return n;
}

/**
 * Append the given string to the given list.
 * @param l	The list where to append the given string.
 * @param str	Pointer to the string to add to the list (NULL => noop).
 * @param dup	If true, the given string gets duplicated and the pointer of the
 *		duplicate gets append to the list instead of \e str.
 * @return The number of elements in the given list on success, an error
 *		code < 0 otherwise.
 */
int
strv_push(char ***l, char *value, bool dup) {
	if (!value)
		return 0;

	size_t nsz, sz = strv_length(*l);

	/* Check for overflow */
	if (sz > SIZE_MAX-2)
		return -ENOMEM;

	nsz = sz == 0
		? 2
		: 1UL << (sizeof(sz) * 8 - __builtin_clzl((sz + 2) - 1UL));
	char **c = reallocarray(*l, nsz, sizeof(char*));
	if (!c)
		return -ENOMEM;

	if (dup) {
		value = strdup(value);
		if (!value)
			return -ENOMEM;
	}

	c[sz] = value;
	c[sz+1] = NULL;
	*l = c;

	return sz;
}

/**
 * Find the first component within the given path \e p, set \e ret to its start
 * and move the input pointer \e p to the next component or '\0'. This
 * skips both over any '/' immediately *before* and *after* the first component
 * before returning. Path components with a length > NAME_MAX are accepted but
 * might be not allowed on POSIX compatible filesystems.
 *
 * Examples:<br>
 *   Input:  \e p: "//.//aaa///bbbbb/cc"<br>
 *   Output: \e p: "bbbbb///cc"
 *           \e ret: "aaa///bbbbb/cc"
 *           \e return \e value: 3 (== strlen("aaa"))
 *
 *   Input:  \e p: "aaa//"<br>
 *   Output: \e p: (pointer to NUL)
 *           \e ret: "aaa//"
 *           \e return \e value: 3 (== strlen("aaa"))
 *
 *   Input:  \e p: "/", ".", ""<br>
 *   Output: \e p: (pointer to NUL)
 *           \e ret: NULL
 *           \e return \e value: 0
 *
 *   Input:  \e p: NULL<br>
 *   Output: \e p: NULL
 *           \e ret: NULL
 *           \e return \e value: 0
 *
 *   Input:  \e p: "component_with_>_NAME_MAX_charcters/bla"<br>
 *   Output: \e p: "bla"
 *           \e ret: "component_with_>_NAME_MAX_charcters"
 *           \e return value: strlen(component_with_>_NAME_MAX_charcters)
 *
 *   Input:  \e p: "//..//aaa///bbbbb/cc"<br>
 *   Output: \e p: "aaa///bbbbb/cc"
 *           \e ret: ".."
 *           \e return \e value: 2
 *
 * @param p	Where to store the pointer to next path component found. If it is
 *		!= NULL it points to the end of p if no next component has been found.
 * @param ret	A pointer to the start of the first component found.
 *		Can be NULL if the effective path is invalid or empty.
 * @return The length of the component found exclusive any trailing redundant
 *		stuff like '/' and '\0'.
 */
int
first_path_component(const char **p, const char **ret) {
	const char *first, *end_first, *next;
	size_t len;

	if (*p == NULL) {
		if (ret)
			*ret = NULL;
		return 0;
	}

	// skip leading / and ./ components
	for (first = *p; first[0] != '\0'; first++) {
		if (first[0] == '/' )
			continue;
		if (first[0] == '.' && first[1] == '/') {
			first++;
			continue;
		}
		break;
	}
	if (first[0] == '\0') { // EOS
		*p = first;
		if (ret)
			*ret = NULL;
		return 0;
	}
	if (first[0] == '.' && first[1] == '\0') { // single dot path
		*p = first + 1;
		if (ret)
			*ret = NULL;
		return 0;
	}

	end_first = strchrnul(first, '/');
	len = end_first - first;
	/* actually this function should return the first component and not validate
	   the path. So skip this compliance check.
	if (len > NAME_MAX)
		return -EINVAL;
	*/

	// skip trailing / and ./ components
	for (next = end_first; next != NULL && next[0] != '\0'; next++) {
		if (next[0] == '/' )
			continue;
		if (next[0] == '.' && next[1] == '/') {
			next++;
			continue;
		}
		break;
	}
	// skip trailing dot
	if (next[0] == '.' && next[1] == '\0')
		next++;
	*p = next;
	if (ret)
		*ret = first;
	return len;
}

/**
 * Remove redundant inner and trailing slashes from the given path. Also
 * removes unnecessary dots. Modifies the passed string in-place. However, '..'
 * is kept as is if it represents a single path component. E.g.:
 *
 * ///foo//./bar/.   becomes /foo/bar<br>
 * .//./foo//./bar/. becomes foo/bar
 * @param path	The path to simplify. The function operates on this string, so
 *		no new string gets allocated.
 * @return The length of the simplified path without the trailing '\0'. The
 *		length of the NULL path is 0.
 */
int
path_simplify(char *path) {
	bool add_slash = false;
	char *f = path;
	int r;

	if (path == NULL || path[0] == '\0')
		return 0;

	if (path[0] == '/')
		f++;
	for (const char *p = f;;) {
		const char *e;

		r = first_path_component(&p, &e);
		if (r == 0)
			break;

		if (add_slash)
			*(f++) = '/';
		memmove(f, e, r);
		f += r;
		add_slash = true;
	}

	// If we stripped everything, we need a "." for the current directory.
	if (f == path)
		*f++ = '.';
	*f = '\0';
	return f - path;
}

/**
 * Check, whether the path is safe, i\.e\.\ it is neither NULL or empty,
 * contains valid path components, but no '..' components.
 * @param p	Path to check.
 * @return true if safe, false otherwise.
 */
static bool
path_is_safe(const char *p) {
	if (p == NULL || p[0] == '\0')
		return false;

	for (const char *e = p;;) {
		const char *f;
		int r;
		r = first_path_component(&e, &f);
		if (r > NAME_MAX || (r == 2 && f[0] == '.' && f[1] == '.') ||
			(e - p) > PATH_MAX)
		{
			return false;
		}
		if (*e == '\0')
			return true;
	}
}

/**
 * Check whether the given path is safe and normalized, i\.e\.\ contains no
 * dotted path, or redundant slashes.
 * @param p	Path to check.
 * @return true if normalized, false otherwise.
 */
bool
path_is_normalized(const char *p) {
	if (!path_is_safe(p))
		return false;

	size_t l = strlen(p);
	if ((l >= 1) &&
		((p[0] == '.' && p[1] == '\0') || (p[0] == '.' && p[1] == '/') ||
			(p[l-2] == '/' && p[l-1] == '.') || strstr(p, "/./")))
	{
		return false;
	}

	if (strstr(p, "//"))
		return false;

	return true;
}

/**
 * Get the number of columns of stdout.
 * @return 80 if columns cannot be determined, the numer of columns otherwise.
 */
unsigned
term_columns(void) {
	struct winsize ws = {};
	int c = (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0) ? 0 : ws.ws_col;
	return (c <= 0) ? 80 : c;
}

/**
 * Call statx(2) for the given parameters and if not supported or permission
 * problems try fstatat(2) instead if supported.
 * @return 0 on success, an error code < 0 otherwise.
 */
static int
statx_fallback(int dirfd, const char *pathname, int flags, unsigned mask,
	struct statx *sx)
{
	static bool avoid_statx = false;
	struct stat st;

	if (!avoid_statx) {
		/* If statx() is not supported or if we see EPERM (which might indicate
		   seccomp filtering or so), let's do a fallback. Not that on EACCES
		   we'll not fall back, since that is likely an indication of fs access
		   issues, which we should propagate */
		if (statx(dirfd, pathname, flags, mask, sx) < 0) {
			if (errno != EOPNOTSUPP && errno != ENOTTY && errno != ENOSYS &&
				errno != EAFNOSUPPORT && errno != EPFNOSUPPORT &&
				errno != EPROTONOSUPPORT && errno != ESOCKTNOSUPPORT &&
				errno != EPERM)
			{
				return -errno;
			}
		} else {
			return 0;
		}
		avoid_statx = true;
	}

	/* Only do fallback if fstatat() supports the flag too, or if it's one of
	   the sync flags, which are * OK to ignore */
	if ((flags & ~(AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW |
		AT_STATX_SYNC_AS_STAT | AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC)) != 0)
	{
		return -EOPNOTSUPP;
	}

	if (fstatat(dirfd, pathname, &st, flags &
			(AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW)) < 0)
	{
		return -errno;
	}

	*sx = (struct statx) {
		.stx_mask = STATX_TYPE | STATX_MODE |
					STATX_NLINK | STATX_UID | STATX_GID |
					STATX_ATIME | STATX_MTIME | STATX_CTIME |
					STATX_INO | STATX_SIZE | STATX_BLOCKS,
					.stx_blksize = st.st_blksize,
					.stx_nlink = st.st_nlink,
					.stx_uid = st.st_uid,
					.stx_gid = st.st_gid,
					.stx_mode = st.st_mode,
					.stx_ino = st.st_ino,
					.stx_size = st.st_size,
					.stx_blocks = st.st_blocks,
					.stx_rdev_major = major(st.st_rdev),
					.stx_rdev_minor = minor(st.st_rdev),
					.stx_dev_major = major(st.st_dev),
					.stx_dev_minor = minor(st.st_dev),
					.stx_atime.tv_sec = st.st_atim.tv_sec,
					.stx_atime.tv_nsec = st.st_atim.tv_nsec,
					.stx_mtime.tv_sec = st.st_mtim.tv_sec,
					.stx_mtime.tv_nsec = st.st_mtim.tv_nsec,
					.stx_ctime.tv_sec = st.st_ctim.tv_sec,
					.stx_ctime.tv_nsec = st.st_ctim.tv_nsec,
	};

	return 0;
}

/**
 * Get the next dir entry like readdir(), but fills in .d_type if it is
 * DT_UNKNOWN.
 * @param d		The directory stream to read.
 * @return The entry on success, NULL otherwise. Sets errno if an error occurs.
 *		Do not attempt to free(3) it!
 */
struct dirent *
readdir_ensure_type(DIR *d) {
	struct statx sx;
	int r;

	for (;;) {
		struct dirent *de;
		char *path;

		errno = 0;
		de = readdir(d);
		if (!de)
			return NULL;

		if (de->d_type != DT_UNKNOWN)
			return de;

		path = de->d_name;
		if (path[0] == '.' && path[1] == '.' && path[2] == '\0') {
			de->d_type = DT_DIR;
			return de;
		}

		/* Let's ask only for the type, nothing else. */
		r = statx_fallback(dirfd(d), de->d_name,
			AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT, STATX_TYPE, &sx);
		if (r == 0) {
			//assert((~(sx.stx_mask) & STATX_TYPE) == 0);
			de->d_type = IFTODT(sx.stx_mode);
			// If inode is passed too, report most recent data
			if ((~(sx.stx_mask) & STATX_INO) == 0)
				de->d_ino = sx.stx_ino;
			return de;
		}
		/* We want to be compatible with readdir(), hence propagate error via
		   errno here */
		if (r != -ENOENT) {
			errno = -r;
			return NULL;
		}
		/* Vanished by now? Then skip immediately to next */
	}
}

/**
 * Read the content of a [virtual] file in one row.
 * Virtual filesystems such as sysfs or procfs use kernfs, and kernfs can work
 * with two sorts of virtual files. One sort uses "seq_file", and the results
 * of the first read are buffered for the second read. The other sort uses
 * "raw" reads which always go direct to the device. In the latter case, the
 * content of the virtual file must be retrieved with a single read otherwise
 * a second read might get the new value instead of finding EOF immediately.
 * That's the reason why the usage of fread(3) is prohibited in this case as it
 * always performs a second call to read(2) looking for EOF. See issue #13585.
 *
 * @param path		Path to the file to read.
 * @param max_sz	Specifies a limit on the bytes read. If it is SIZE_MAX, the
 *		full file is read. If the full file is too large to read (i.e. >
 *		READ_VIRTUAL_BYTES_MAX), an error is returned. For other values of
 *		max_size, partial contents may be returned. Though a read is still done
 *		using one syscall but never returns more than READ_VIRTUAL_BYTES_MAX,
 *		or in case of virtual files reporting a size of 0 the minimum of
 *		PAGE_SIZE and READ_VIRTUAL_BYTES_MAX bytes.
 * @param ret_contents	Where to store the pointer to the allocated buffer on
 *		success. Unchanged on error. Free when done.
 * @param ret_sz	On success store the number of characters excluding the
 *		trailing '\0' in the buffer here. If ret_sz is NULL and the buffer
 *		already contains a '\0' (beside a trailing one) an error gets generated
 *		because of ambiguity.
 * @returns 0 on partial success, 1 if untruncated contents were read, an error
 *		code < 0 otherwise.
 */
int
read_virtual_file(char *path, size_t max_sz, char **ret_contents,size_t *ret_sz){
	static thread_local size_t page_sz = 0;
	char *buf = NULL;
	size_t n, size;
	int n_retries, fd;
	bool truncated = false;


	if (!path)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_NOCTTY | O_CLOEXEC);
	if (fd < 0) {
		LOG("read_virtual_file: %s", strerror(errno));
		return -errno;
	}

	n_retries = 3;
	for (;;) {
		struct stat st;

		if (fstat(fd, &st) < 0)
			return -errno;

		if (!S_ISREG(st.st_mode))
			return -EBADF;

		// Be prepared: files from /proc may generally report a file size of 0
		if (st.st_size > 0 && n_retries > 1) {
			/* Let's use the file size if we have more than 1 attempt left.
			   On the last attempt we'll ignore the file size. */
			if (st.st_size > SSIZE_MAX) {
				// Avoid overflow with 32-bit size_t and 64-bit off_t.
				if (max_sz == SIZE_MAX)
					return -EFBIG;

				size = max_sz;
			} else {
				size = ((size_t) st.st_size < max_sz)
					? (size_t) st.st_size
					: max_sz;
				if (size > READ_VIRTUAL_BYTES_MAX)
					return -EFBIG;
			}

			n_retries--;
		} else if (n_retries > 1) {
			if (page_sz == 0)
				page_sz = (size_t) sysconf(_SC_PAGESIZE) - 1;
			/* Files in /proc are generally smaller than the page size so let's
			   start with a page size buffer from malloc and only use the max
			   buffer on the final try. */
			size = (page_sz < READ_VIRTUAL_BYTES_MAX)
				? page_sz
				: READ_VIRTUAL_BYTES_MAX;
			if (max_sz < size)
				size = max_sz;
			n_retries = 1;
		} else {
			size = (READ_VIRTUAL_BYTES_MAX < max_sz)
				? READ_VIRTUAL_BYTES_MAX
				: max_sz;
			n_retries = 0;
		}

		buf = (char *) malloc(sizeof(char) * (size + 1));
		if (!buf)
			return -ENOMEM;

		for (;;) {
			ssize_t k;

			/* Read one more byte so we can detect whether the content of the
			   file has already changed or the guessed size for files from /proc
			   wasn't large enough . */
			k = read(fd, buf, size + 1);
			if (k >= 0) {
				n = k;
				break;
			}
			if (errno != EINTR) {
				free(buf);
				return -errno;
			}
		}

		// Consider a short read as EOF
		if (n <= size)
			break;

		/* If a maximum size is specified and we already read more we know the
		   file is larger, and can handle this as truncation case. Note that if
		   the size of what we read equals the maximum size then this doesn't
		   mean truncation, the file might or might not end on that byte. We
		   need to rerun the loop in that case, with a larger buffer size, so
		   that we read at least one more byte to be able to distinguish EOF
		   from truncation. */
		if (max_sz != SIZE_MAX && n > max_sz) {
			n = size;
			// Make sure we never use more than what we sized the buffer for
			// (have one free byte in it for the trailing '\0' we add below).
			truncated = true;
			break;
		}

		// prepare for next try (if any)
		free(buf);
		buf = NULL;

		/* We have no further attempts left? Then the file is apparently larger
		   than our limits. Give up. */
		if (n_retries <= 0)
			return -EFBIG;

		/* Hmm... either we read too few bytes from /proc or less likely the
		   content of the file might have been changed (and is now bigger) while
		   we were processing, let's try again either with the new file size. */
		if (lseek(fd, 0, SEEK_SET) < 0)
			return -errno;
	}

	if (ret_contents) {
		/* Safety check: if the caller doesn't want to know the size of what we
		   just read it will rely on the trailing '\0' byte. But if there's an
		   embedded NUL byte, then we should refuse operation as otherwise
		   there'd be ambiguity about what we just read. */
		if (!ret_sz && memchr(buf, 0, n)) {
			free(buf);
			return -EBADMSG;
		}

		// Usually size is ~4 KiB and n ~ 100 B: so give away unused space
		if (n < size) {
			char *p = realloc(buf, n + 1);
			if (!p) {
				free(buf);
				return -ENOMEM;
			}
			buf = p;
		}

		buf[n] = 0;
		*ret_contents = buf;
	} else {
		free(buf);
	}

	if (ret_sz)
		*ret_sz = n;

	return !truncated;
}

#define _unlikely_(x) (__builtin_expect(!!(x), 0))

/**
 * Save realloc(2) the given block by doubling its size.
 * We use malloc_usable_size() for determining the current allocated size. On
 * all systems we care about this should be safe to rely on. Should there ever
 * arise the need to avoid relying on this we can instead locally fall back to
 * realloc() on every call, rounded up to the next exponent of 2 or so.
 * @param The pointer to the block, which needs to be resized. On success it
 *		gets adjusted to the pointer to the reallocated block.
 * @param need	The number of new elements needed.
 * @param size	The size of each element.
 * @return The pointer to the new block or NULL on error. Free when done.
 */
void *
greedy_realloc(void **p, size_t need, size_t size) {

	size_t a = 0;
	void *q;

	if (*p) {
		// check: allocated space already sufficient ?
		if (size) {
			size_t b = __builtin_object_size(*p, 0);
			a = malloc_usable_size(*p);
			if (b < a)
				a = b;
		}
		if (size == 0 || a / size >= need)
			return *p;
		a = 0;
	}

	if (size) {
		if (_unlikely_(need > SIZE_MAX / size / 2)) // Overflow check
			return NULL;
		a = need * 2 * size;
	}

	if (a < 64) // Allocate at least 64 bytes
		a = 64;

	q = realloc(*p, a);
	if (!q)
		return NULL;

	return *p = q;
}

/**
 * Parse the first word of a string, and return a copy it in \e ret.
 *
 * @param p		The start of the content to parse. On return it is set to NULL,
 *		if no first word has been found, to the the first character after the
 *		word found otherwise.
 * @param ret	Where to store the pointer to the 1st word on success.
 *		Otherwise it is usually set to NULL. Free when done.
 * @param sep	Characters to consider as word separators.
 * @param flags	Parser flags. Must have at least set either EXTRACT_KEEP_QUOTE
 *		or EXTRACT_UNQUOTE.
 * @return 0 if no 1st word could be extracted, 1 if one could be extracted, an
 *	error code < 0 otherwise.
 */
int
extract_first_word(const char **p, char **ret, const char *sep,
	ExtractFlags flags)
{
	char *s = NULL;
	size_t sz = 0;
	char quote = 0;                 // 0 or ' or "
	bool backslash = false;         // whether we've just seen a backslash
	char c;
	int r;

	// Bail early if called after last value or with no input
	if (!*p)
		goto finish;
	c = **p;

	if (!sep)
		sep = WHITESPACE;

	if (flags & EXTRACT_DONT_COALESCE_SEPARATORS)
		if (!GREEDY_REALLOC(s, sz + 1))
			return -ENOMEM;

	for (;; (*p)++, c = **p) {
		if (c == 0)
			goto finish_force_terminate;
		else if (strchr(sep, c)) {
			if (flags & EXTRACT_DONT_COALESCE_SEPARATORS) {
				if (!(flags & EXTRACT_RETAIN_SEPARATORS))
					(*p)++;
				goto finish_force_next;
			}
		} else {
			/* We found a non-blank character, so we will always want to return
			   a string (even if it is empty), allocate it here. */
			if (!GREEDY_REALLOC(s, sz + 1)) {
				free(s);
				return -ENOMEM;
			}
			break;
		}
	}

	for (;; (*p)++, c = **p) {
		if (backslash) {
			if (!GREEDY_REALLOC(s, sz + 7)) {
				free(s);
				return -ENOMEM;
			}

			if (c == 0) {
				if ((flags & EXTRACT_UNESCAPE_RELAX) &&
						(quote == 0 || flags & EXTRACT_RELAX)) {
					/* If we find an unquoted trailing backslash and we're in
					   EXTRACT_UNESCAPE_RELAX mode, keep it verbatim in the
					   output.
					   Unbalanced quotes will only be allowed in EXTRACT_RELAX
					   mode, EXTRACT_UNESCAPE_RELAX mode does not allow them. */
					s[sz++] = '\\';
					goto finish_force_terminate;
				}
				if (flags & EXTRACT_RELAX)
					goto finish_force_terminate;
				free(s);
				return -EINVAL;
			}

			if (flags & (EXTRACT_CUNESCAPE | EXTRACT_UNESCAPE_SEPARATORS)) {
				bool eight_bit = false;
				char32_t u;

				if ((flags & EXTRACT_CUNESCAPE) &&
					(r = cunescape_one(*p, SIZE_MAX, &u, &eight_bit, false)) >= 1)
				{
					// A valid escaped sequence
					(*p) += r - 1;

					if (eight_bit)
						s[sz++] = u;
					else
						sz += utf8_encode_unichar(s + sz, u);
				} else if ((flags & EXTRACT_UNESCAPE_SEPARATORS) &&
				   (strchr(sep, **p) || **p == '\\'))
				{
					// An escaped separator char or the escape char itself
					s[sz++] = c;
				} else if (flags & EXTRACT_UNESCAPE_RELAX) {
					s[sz++] = '\\';
					s[sz++] = c;
				} else {
					free(s);
					return -EINVAL;
				}
			} else {
				s[sz++] = c;
			}
			backslash = false;
		} else if (quote != 0) {     // inside either single or double quotes
			for (;; (*p)++, c = **p) {
				if (c == 0) {
					if (flags & EXTRACT_RELAX)
						goto finish_force_terminate;
					free(s);
					return -EINVAL;
				} else if (c == quote) {        // found the end quote
					quote = 0;
					if (flags & EXTRACT_UNQUOTE)
						break;
				} else if (c == '\\' && !(flags & EXTRACT_RETAIN_ESCAPE)) {
					backslash = true;
					break;
				}
				if (!GREEDY_REALLOC(s, sz + 2)) {
					free(s);
					return -ENOMEM;
				}
				s[sz++] = c;
				if (quote == 0)
					break;
			}
		} else {
			for (;; (*p)++, c = **p) {
				if (c == 0) {
					goto finish_force_terminate;
				} else if ((c == '\'' || c == '"') &&
					(flags & (EXTRACT_KEEP_QUOTE | EXTRACT_UNQUOTE)))
				{
					quote = c;
					if (flags & EXTRACT_UNQUOTE)
						break;
				} else if (c == '\\' && !(flags & EXTRACT_RETAIN_ESCAPE)) {
					backslash = true;
					break;
				} else if (strchr(sep, c)) {
					if (flags & EXTRACT_DONT_COALESCE_SEPARATORS) {
						if (!(flags & EXTRACT_RETAIN_SEPARATORS))
							(*p)++;
						goto finish_force_next;
					}
					if (!(flags & EXTRACT_RETAIN_SEPARATORS))
						// Skip additional coalesced separators.
						for (;; (*p)++, c = **p) {
							if (c == 0)
								goto finish_force_terminate;
							if (!strchr(sep, c))
								break;
						}
					goto finish;
				}

				if (!GREEDY_REALLOC(s, sz + 2)) {
					free(s);
					return -ENOMEM;
				}
				s[sz++] = c;
				if (quote != 0)
					break;
			}
		}
	}

finish_force_terminate:
	*p = NULL;
finish:
	if (!s) {
		*p = NULL;
		*ret = NULL;
		return 0;
	}

finish_force_next:
	s[sz] = 0;
	*ret = s;

	return 1;
}

#define CACHED_PID_UNSET ((pid_t) 0)
#define CACHED_PID_BUSY ((pid_t) -1)

/** The cached PID, possible values:
 *
 *	== UNSET [0]  → cache not initialized yet
 *	== BUSY [-1]  → some thread is initializing it at the moment
 *	any other     → the cached PID
 */
static pid_t cached_pid = CACHED_PID_UNSET;

/**
 * Reset the cached PID to CACHED_PID_UNSET. Invoked in the child after a
 * fork(), i.e. at the first moment the PID changed.
 * @see getpid_cached()
 */
static void
reset_cached_pid(void) {
	cached_pid = CACHED_PID_UNSET;
}

/**
 * Much like getpid(), but caches the PID in local memory, to avoid having to
 * invoke a system call each time. This restores glibc behaviour from before
 * 2.24, when getpid() was unconditionally cached. Starting with 2.24 getpid()
 * started to become prohibitively expensive when used for detecting when
 * objects were used across fork()s. With this caching the old behaviour is
 * somewhat restored.
 * @see https://bugzilla.redhat.com/show_bug.cgi?id=1443976
 * @see https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=c579f48edba88380635ab98cb612030e3ed8691e
 * @return the pid of this process.
 */
pid_t
getpid_cached(void) {
	static bool installed = false;
	pid_t current_value = CACHED_PID_UNSET;

	__atomic_compare_exchange_n(&cached_pid, &current_value, CACHED_PID_BUSY,
		false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);

	switch (current_value) {
		case CACHED_PID_UNSET: { /* Not initialized yet, then do so now */
			pid_t new_pid = getpid();
			if (!installed) {
				/* __register_atfork() either returns 0 or -ENOMEM, in its glibc
				   impla.. Since it's only half-documented (glibc doesn't
				   document it but LSB does — though only superficially) we'll
				   check for errors only in the most generic fashion possible.*/
				if (pthread_atfork(NULL, NULL, reset_cached_pid) != 0) {
					/* OOM? Let's try again later */
					cached_pid = CACHED_PID_UNSET;
					return new_pid;
				}
				installed = true;
			}
			cached_pid = new_pid;
			return new_pid;
		}
		case CACHED_PID_BUSY: // Somebody else is currently initializing
			return getpid();
		default: // Properly initialized
			return current_value;
	}
}

/**
 * Check whether the process with the given pid is a kernel thread by inspecting
 * /proc/$pid/stat field 9 (flags).
 * @param pid	PID of the ürocess in question.
 * @return 1 if the process is a kernel thread, 0 if not, or an error code < 0.
 */
int
is_kernel_thread(pid_t pid) {
	char *line = NULL, *q, *end;
	unsigned long long flags;
	size_t l = 0, i;
	char fname[12 + PID_MAX_DIGITS];	// 15 + 1 || 6 + PID_MAX_DIGITS + 5 + 1
	FILE *f;
	int r;

	/* pid 1, and we ourselves certainly aren't a kernel thread */
	if (pid == 0 || pid == 1 || pid == getpid_cached())
		return 0;
	if (pid <= 0)
		return -EINVAL;

	if (pid == 0)
		strcpy(fname, "/proc/self/stat");
	else
		sprintf(fname, "/proc/" PID_FMT "/stat", pid);
	f = fopen(fname, "re");
	if (!f)
		return (errno == -ENOENT) ? -ESRCH  : -errno;

	__fsetlocking(f, FSETLOCKING_BYCALLER);
	r = getline(&line, &l, f);
	fclose(f);
	if (r < 0)
		goto fail;

	// Skip past the comm field
	q = strrchr(line, ')');
	if (!q)
		goto fail;
	q++;

	// F3 - skip 6 fields to reach the flags field
	for (i = 0; i < 6; i++) {
		l = strspn(q, WHITESPACE);
		if (l < 1)
			goto fail;
		q += l;

		l = strcspn(q, WHITESPACE);
		if (l < 1)
			goto fail;
		q += l;
	}

	// F9 - chomp whitespace
	l = strspn(q, WHITESPACE);
	if (l < 1)
		goto fail;
	q += l;
	errno = 0;
	flags = strtoull(q, &end, 0);
	if (errno > 0 || q == end)
		goto fail;

	free(line);
	return !!(flags & PF_KTHREAD);

fail:
	free(line);
	return -EINVAL;
}

/**
 * Get the name of the process with the given pid deduced either via prctl(2)
 * or /proc/$pid/comm .
 * @param pid	The PID of the process in question.
 * @param ret	Where to store the name on success. Unchanged on error. Free
 *		when done.
 * @return 0 on success, an error code < 0 otherwise.
 */
int
get_process_comm(pid_t pid, char **ret) {
	char *escaped = NULL, *comm = NULL;
	int r;

	if (pid == 0 || pid == getpid_cached()) {
		// Must fit in 16 byte - see prctl(2)
		comm = (char *) malloc(sizeof(char) * (TASK_COMM_LEN + 1));
		if (!comm)
			return -ENOMEM;

		if (prctl(PR_GET_NAME, comm) < 0)
			return -errno;
	} else {
		char fname[12 + PID_MAX_DIGITS];
		size_t len = 0;

		sprintf(fname, "/proc/" PID_FMT "/comm", pid);
		// NOTE kernel thread process names can be much > TASK_COMM_LEN
		FILE *f = fopen(fname, "re");
		if (!f)
			return (errno == -ENOENT) ? -ESRCH  : -errno;
		__fsetlocking(f, FSETLOCKING_BYCALLER);
		r = getline(&comm, &len, f);
		fclose(f);
		if (r < 0) {
			free(comm);
			return r;
		}
		if (comm[r-1] == '\n')
			comm[r-1] = '\0';
	}

	escaped = (char *) malloc(sizeof(char) * COMM_MAX_LEN);
	if (!escaped) {
		free(comm);
		return -ENOMEM;
	}

	// Escape unprintable characters, just in case, but don't grow the string
	// beyond the underlying size
	cellescape(escaped, COMM_MAX_LEN, comm);
	free(comm);

	*ret = escaped;
	return 0;
}

/**
 * Retrieves a process' command line as a "sized nulstr", i\.e\.\ possibly
 * without the last '\0', but with a specified size.
 *
 * If PROCESS_CMDLINE_COMM_FALLBACK is specified in flags and the process has
 * no command line set (the case for kernel threads), or has a command line
 * that resolves to the empty string, will return the "comm" name of the
 * process instead. This will use at most _SC_ARG_MAX bytes of input data.
 *
 * @param pid	The pid of the process in question.
 * @param max_size	Max. size of the returned string, i.e. gets truncated to
 *		this length if bigger.
 * @param flags	If PROCESS_CMDLINE_COMM_FALLBACK is set and the command line
 *		could not be obtained from /proc/$pid/cmdline, prctl(2) or
 *		/proc/$pid/comm are used to get at least the first 16 characters of the
 *		command line.
 * @param ret	Where to store the pointer to the buffer containing the cmdline
 *		on success. Unchanged on error. Free when done.
 * @param ret_size	The number of characters in the buffer excluding the
 *		trailing '\0' which is usually the size of the returned buffer minus 1.
 * @return 0 if output was read but is truncated, 1 if fully read, an error
 *		code < 0 otherwise.
 */
static int
get_process_cmdline_nulstr(pid_t pid, size_t max_size,
	ProcessCmdlineFlags flags, char **ret, size_t *ret_size)
{
	char fname[15 + PID_MAX_DIGITS];
	char *t = NULL;
	size_t k;
	int r;

	if (pid == 0)
		strcpy(fname, "/proc/self/cmdline");
	else
		sprintf(fname, "/proc/" PID_FMT "/cmdline", pid);

	r = read_virtual_file(fname, max_size, &t, &k);
	if (r < 0)
		return r;

	/* Let's assume that each input byte results in >= 1 columns of output.
	   We ignore zero-width codepoints. */
	if (k == 0) {
		free(t);
		if (!(flags & PROCESS_CMDLINE_COMM_FALLBACK))
			return -ENOENT;

		/* Kernel threads have no argv[] */
		char *comm = NULL;

		r = get_process_comm(pid, &comm);
		if (r < 0)
			return r;

		k = strlen(comm);
		t = (char *) malloc(sizeof(char) * (k + 2 + 1));
		if (!t) {
			free(comm);
			return -ENOMEM;
		}
		t[0] = '[';
		strcpy(t + 1, comm);
		free(comm);
		k++;
		t[k++] = ']';
		t[k] = '\0';
		r = k <= max_size;
		if (r == 0) {	/* truncation */
			t[max_size] = '\0';
			k = max_size;
		}
	}

	*ret = t;
	*ret_size = k;
	return r;
}

/**
 * Retrieve and format a command line in a compact non-roundtrippable form.
 * Non-UTF8 bytes are replaced by �. The returned string is of the specified
 * console width at most, abbreviated with an ellipsis.
 *
 * @param pid	The PID of the command line to lookup.
 * @param cols	Max. length of the output buffer. If command line is longer
 *		than this abbreviate with an ellipsis.
 * @param flags	Takes into account PROCESS_CMDLINE_USE_LOCALE, XESCAPE_8_BIT
 *		and XESCAPE_FORCE_ELLIPSIS when formatting output.
 * @param ret	Where to store the pointer to the buffer containing the possibly
 *		reformatted command line found.
 * @return -ESRCH if the process doesn't exist, and -ENOENT if the process has
 *		no command line (and PROCESS_CMDLINE_COMM_FALLBACK is not specified),
 *		0 otherwise.
 */
int
get_process_cmdline(pid_t pid, size_t cols, ProcessCmdlineFlags flags,
	char **ret)
{
	char *t = NULL;
	size_t len = 0, i;
	char *ans;

	int full = get_process_cmdline_nulstr(pid, cols, flags, &t, &len);
	if (full < 0)
		return full;

	// Arguments are separated by NULs. Let's replace those with spaces.
	for (i = 0; i < len - 1; i++)
		if (t[i] == '\0')
			t[i] = ' ';
	// delete trailing whitespaces
	for (i = len - 1; i >= 1; i--)
		if (!strchr(WHITESPACE, t[i])) {
			t[i+1] = '\0';
			break;
		}
	ans = ((flags & PROCESS_CMDLINE_USE_LOCALE) && !is_locale_utf8())
		? xescape_full(t,"",cols,XESCAPE_8_BIT | !full * XESCAPE_FORCE_ELLIPSIS)
		: utf8_escape_non_printable_full(t, cols, !full);
	free(t);
	if (!ans)
		return -ENOMEM;

	ans = realloc(ans, strlen(ans) + 1) ?: ans;
	*ret = ans;
	return 0;
}

/**
 * A wrapper around getxattr(2), fgetxattr(2), or if the name parameter is NULL,
 * a wrapper around  listxattr(2), flistxattr(2), which automatically resizes
 * the buffer where the attribute value or names gets stored if needed. It also
 * '\0'-terminates the returned buffer (for safety). Last but not least: if one
 * of the following errors occurs, -ENODATA gets returned instead to make error
 * handling easier: ENODATA || ENOSYS || EOPNOTSUPP || ENOTTY || EAFNOSUPPORT ||
 * EPFNOSUPPORT || EPROTONOSUPPORT || ESOCKTNOSUPPORT. If details are needed,
 * one may still inspect errno(3).
 * @param fd	If >= 0 fgetxattr(2)/flistxattr(2) is used to obtain the
 *		attribute value or name list. It must refer to an already opened file
 *		or directory using open(2) and friends (e.g. with
 *		<code>open(path, O_PATH|O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY, 0);</code>).
 *		The path gets ignored in this case completely.
 * @param path	Ignored if fd >= 0, otherwise getxattr(2)/listxattr(2) is used
 *		to obtain the attribute value or name list.
 * @param name	The name of the attribute to lookup. If NULL, on success a list
 *		of '\0'-terminated xattribute names (see listxattr(2) and flistxattr(2))
 *		get returned instead.
 * @param ret	Where to store the pointer to the buffer containing the value or
 *		names found. Unchanged on error or if not found. Free when done.
 * @return On success, a value which is the size (in bytes) of the extended
 *	attribute value or name list <b>including</b> the terminating '\0'. An error
 *	code < 0 otherwise.
 */
int
xattrget(int fd, const char *path, const char *name, char **ret) {
	char *v = NULL;
	unsigned n_attempts = 7;
	size_t l = 100;
	char fdpath[15 + 10];

	if (fd < 0 && (!path || path[0] == '\0'))
		return -EINVAL;

	for (;;) {
		ssize_t n;

		if (n_attempts == 0) {
			// If someone is racing against us, give up eventually
			errno = EBUSY;
			break;
		}

		n_attempts--;
		v = (char *) malloc(sizeof(char) * (l + 1));
		if (!v) {
			errno = ENOMEM;
			break;
		}

		if (!name) {
			n = fd < 0 ? listxattr(path, v, l) : flistxattr(fd, v, l);
		} else {
			n = fd < 0 ? getxattr(path, name, v, l) : fgetxattr(fd, name, v, l);
		}
		if (n < 0) {
			if (errno == EBADF && fd >= 0) {
				free(v);
				v = NULL;
				sprintf(fdpath, "/proc/self/fd/%i", fd);
				path = fdpath;
				fd = -2;
				continue;
			}
			if (errno != ERANGE)
				break;
		} else {
			v[n] = 0; // NUL terminate
			*ret = v;
			return (int) n;
		}
		free(v);
		v = NULL;

		if (!name) {
			n = fd < 0 ? listxattr(path, NULL, 0) : flistxattr(fd, NULL, 0);
		} else {
			n = fd < 0 ? getxattr(path,name,NULL,0) : fgetxattr(fd,name,NULL,0);
		}
		if (n < 0)
			break;

		if (n > INT_MAX) { // We couldn't return this as 'int' anymore
			errno = E2BIG;
			break;
		}

		l = (size_t) n;
	}
	free(v);
	return (errno == ENODATA || errno == EOPNOTSUPP || errno == ENOTTY ||
		errno == ENOSYS || errno == EAFNOSUPPORT || errno == EPFNOSUPPORT ||
		errno == EPROTONOSUPPORT || errno == ESOCKTNOSUPPORT)
		? -ENODATA
		: -errno;
}

/**
 * Check, whether the cgroup associated with the given path or filedescriptor
 * is delegated by inspecting its extended attribute set (lookup
 * "trusted.delegate" and "user.delegate").
 * @param cgfd	A valid filedescriptor to the cgroup in question or '-1' if the
 *		the given cgroup path should be used to query the related xattr instead.
 * @param path	Path to use to query xattrs.
 * @return true if delegated, false otherwise.
 */
int
is_delegated(int cgfd, const char *path) {
	char *b = NULL;
	const char *p = NULL;
	int r;
	char fname[14 + 10 + 1];

	if (cgfd < 0) {
		p = path;
	} else {
		sprintf(fname, "/proc/self/fd/%i", cgfd);
		p = fname;
	}
	// "trusted.delegate" and "user.delegate" are either "1" or removed from the
	// set which would result in -1 and errno == -ENODATA.
	r = xattrget(-1, p, "trusted.delegate", &b);
	if (r < 0 && r == -ENODATA) {
		/* If trusted xattr isn't set (preferred), then check the untrusted one.
		   Under assumption that whoever is trusted enough to own the cgroup, is
		   also trusted enough to decide if it is delegated or not this should
		   be safe. */
		r = xattrget(-1, p, "user.delegate", &b);
		if (r < 0 && r == -ENODATA)
			return false;
	}
	if (r < 0) {
		LOG("Failed to read delegate xattr (%s) - ignored.", strerror(-r));
		return errno;
	}
	r = r == 2 && *b == '1';
	free(b);
	return r;
}

/**
 * Extract the last component (i\.e\.\ right-most component) from a path.
 * Redundant parts of the path get skipped (e.g. / or ./). This function
 * guarantees to return a fully valid filename, i.e. "." and ".." and components
 * with a size > NAME_MAX are not accepted.
 *
 * @param path	Path to check.
 * @param ret	Where to store the pointer to the buffer containing the result.
 *		Unchanged on error. Free when done.
 * @return The length of the last path component if one has been found, an error
 *		code < 0 otherwise. Special error codes are:
 *		-EINVAL			if the path is not valid, e.g if empty ...
 *		-EADDRNOTAVAIL	if only a directory was specified, but no filename,
 *						i.e. the root dir itself or "." is specified
 *		-ENOMEM			no memory
 */
int
last_path_component(const char *path, char **ret) {
	char *a = NULL;
	const char *last = NULL;
	int lastlen = -1;

	if (!path || *path == '\0')
		return -EINVAL;

	// check for valid path and rem the last valid component seen
	for (const char *e = path;;) {
		const char *f;
		int r = first_path_component(&e, &f);
		if (r > NAME_MAX || (r == 2 && f[0] == '.' && f[1] == '.') ||
			(e - path) >= PATH_MAX)
		{
			return -EINVAL;
		}

		if (*e != '\0')
			continue;

		// end of string reached
		last = f;
		lastlen = r;
		break;
	}
	if (!last) /* root directory or invalid path */
		return -EADDRNOTAVAIL;

	a = strdup(last);
	if (!a)
		return -ENOMEM;

	*ret = a;
	return lastlen;
}
