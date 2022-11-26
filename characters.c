/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>

#include "log.h"
#include "locale-util.h"
#include "characters.h"

/** Table of allowed hex digits. Commonly used to map to its byte code, etc.. */
const char hd[16] = "0123456789abcdef";

/**
 * Convert the given octo number digit to its byte code.
 * @param c	octo digit to convert.
 * @return -EINVAL if the given character is not an octo digit, its byte code
 *		otherwise.
 */
static int
unoctchar(char c) {
	if (c >= '0' && c <= '7')
		return c - '0';
	return -EINVAL;
}

/**
 * Convert the given hex digit to its byte code.
 * @param c	Hex digit to convert.
 * @return -EINVAL if the given character is not an hex digit, its byte code
 *		otherwise.
 */
static int
unhexchar(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -EINVAL;
}

/**
 * Check whether the given unicode represents an acceptable character.
 * @param ch	Unicode to check.
 * @return true if acceptable, false otherwise.
 */
static bool
unichar_is_valid(char32_t ch) {
	if (ch >= 0x110000) /* End of unicode space */
		return false;
	if ((ch & 0xFFFFF800) == 0xD800) /* Reserved area for UTF-16 */
		return false;
	if ((ch >= 0xFDD0) && (ch <= 0xFDEF)) /* Reserved */
		return false;
	if ((ch & 0xFFFE) == 0xFFFE) /* BOM (Byte Order Mark) */
		return false;
	return true;
}

/**
 * Convert the given character into the shell hex format, e\.g\.\ $ to \\x24.
 * @param c	Character to convert.
 * @param t Where to append the 4 new characters. The related buffer needs to
 *		be big enough, otherwise buffer overflow. If NULL => SIGSEGV.
 * @return t incremented by 4.
 */
char *
hex_escape_char(char c, char *t) {
	*(t++) = '\\';
	*(t++) = 'x';
	*(t++) = hd[(c >> 4) & 15];
	*(t++) = hd[c & 15];
	return t;
}

/**
 * Convert the first C style escaped character sequence of the given string
 * into its corresponding character, e\.g\.\ if \e p starts with an 'a', \e ret
 * will be set to 0xA (linefeed character). Other acceptable sequences are
 * \\xHH (hex encoded character), \\OOO (octal encoded character), \\uHHHH
 * (C++11 style 16bit unicode), and \\UHHHHHHHH (C++11 style 32bit unicode) -
 * H stands for a hex digit, O for an octal digit, the initial \\ is assumed
 * to be already consumed.
 * @param p		Where to read the first character sequence to encode from.
 * @param length	The minimal number of characters to read in the sequence to
 *			decode. Use SIZE_MAX to autodetect.
 * @param ret		Where to store the decoded character.
 * @param eight_bit	Set to true if the escaped sequence either fits in one byte
 *			in UTF-8 or is a non-unicode literal byte and should instead be
 *			copied directly.
 * @return On success the number of characters read, -EINVAL if \e length is to
 *		small for the detected character sequence.
 */
int
cunescape_one(const char *p, size_t length, char32_t *ret, bool *eight_bit,
	bool accept_nul)
{
	int r = 1;

	if (length != SIZE_MAX && length < 1)
		return -EINVAL;

	switch (p[0]) {
		case 'a':
			*ret = '\a';
			break;
		case 'b':
			*ret = '\b';
			break;
		case 'f':
			*ret = '\f';
			break;
		case 'n':
			*ret = '\n';
			break;
		case 'r':
			*ret = '\r';
			break;
		case 't':
			*ret = '\t';
			break;
		case 'v':
			*ret = '\v';
			break;
		case '\\':
			*ret = '\\';
			break;
		case '"':
			*ret = '"';
			break;
		case '\'':
			*ret = '\'';
			break;
		case 's': /* This is an extension of the XDG syntax files */
			*ret = ' ';
			break;
		case 'x': { /* hexadecimal encoding */
			int a, b;

			if (length != SIZE_MAX && length < 3)
				return -EINVAL;

			a = unhexchar(p[1]);
			if (a < 0)
				return -EINVAL;

			b = unhexchar(p[2]);
			if (b < 0)
				return -EINVAL;

			/* Don't allow NUL bytes */
			if (a == 0 && b == 0 && !accept_nul)
				return -EINVAL;

			*ret = (a << 4U) | b;
			*eight_bit = true;
			r = 3;
			break;
		}
		case 'u': { /* C++11 style 16bit unicode */
			int a[4];
			size_t i;
			uint32_t c;

			if (length != SIZE_MAX && length < 5)
				return -EINVAL;

			for (i = 0; i < 4; i++) {
				a[i] = unhexchar(p[1 + i]);
				if (a[i] < 0)
					return a[i];
			}

			c = ((uint32_t) a[0] << 12U) | ((uint32_t) a[1] << 8U) |
				((uint32_t) a[2] << 4U) | (uint32_t) a[3];

			/* Don't allow 0 chars */
			if (c == 0 && !accept_nul)
				return -EINVAL;

			*ret = c;
			r = 5;
			break;
		}
		case 'U': { /* C++11 style 32bit unicode */
			int a[8];
			size_t i;
			char32_t c;

			if (length != SIZE_MAX && length < 9)
				return -EINVAL;

			for (i = 0; i < 8; i++) {
				a[i] = unhexchar(p[1 + i]);
				if (a[i] < 0)
					return a[i];
			}

			c = ((uint32_t) a[0] << 28U) | ((uint32_t) a[1] << 24U) |
				((uint32_t) a[2] << 20U) | ((uint32_t) a[3] << 16U) |
				((uint32_t) a[4] << 12U) | ((uint32_t) a[5] <<  8U) |
				((uint32_t) a[6] <<  4U) |  (uint32_t) a[7];

			/* Don't allow 0 chars */
			if (c == 0 && !accept_nul)
				return -EINVAL;

			/* Don't allow invalid code points */
			if (!unichar_is_valid(c))
				return -EINVAL;

			*ret = c;
			r = 9;
			break;
		}
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7': { /* octal encoding */
			int a, b, c;
			char32_t m;

			if (length != SIZE_MAX && length < 3)
				return -EINVAL;

			a = unoctchar(p[0]);
			if (a < 0)
				return -EINVAL;

			b = unoctchar(p[1]);
			if (b < 0)
				return -EINVAL;

			c = unoctchar(p[2]);
			if (c < 0)
				return -EINVAL;

			/* don't allow NUL bytes */
			if (a == 0 && b == 0 && c == 0 && !accept_nul)
				return -EINVAL;

			/* Don't allow bytes above 255 */
			m = ((uint32_t) a << 6U) | ((uint32_t) b << 3U) | (uint32_t) c;
			if (m > 255)
				return -EINVAL;

			*ret = m;
			*eight_bit = true;
			r = 3;
			break;
		}
		default:
			return -EINVAL;
	}

	return r;
}

/**
 * Encode a single UCS-4 character as UTF-8 and write it into \e out_utf8.
 *
 * @param out_utf8		Where to store the corresponding UTF-8 character. If
 *		NULL nothing gets stored, otherwise the buffer must have a size of at
 *		least 4 bytes, otherwise a buffer overflow may occure.
 * @param g		UCS-4 character to convert.
 * @return The length in bytes of the UTF-8 character representing the given
 *		UCS-4 character.
 */
size_t
utf8_encode_unichar(char *out_utf8, char32_t g) {
	if (g < (1 << 7)) {
		if (out_utf8)
			out_utf8[0] = g & 0x7f;
		return 1;
	} else if (g < (1 << 11)) {
		if (out_utf8) {
			out_utf8[0] = 0xc0 | ((g >> 6) & 0x1f);
			out_utf8[1] = 0x80 | (g & 0x3f);
		}
		return 2;
	} else if (g < (1 << 16)) {
		if (out_utf8) {
			out_utf8[0] = 0xe0 | ((g >> 12) & 0x0f);
			out_utf8[1] = 0x80 | ((g >> 6) & 0x3f);
			out_utf8[2] = 0x80 | (g & 0x3f);
		}
		return 3;
	} else if (g < (1 << 21)) {
		if (out_utf8) {
			out_utf8[0] = 0xf0 | ((g >> 18) & 0x07);
			out_utf8[1] = 0x80 | ((g >> 12) & 0x3f);
			out_utf8[2] = 0x80 | ((g >> 6) & 0x3f);
			out_utf8[3] = 0x80 | (g & 0x3f);
		}
		return 4;
	}
	return 0;
}

/**
 * Escape the given character into its C-style or Octal represention if needed
 * by appending a backslash and the character sequence to the given buffer. If
 * it is a normal ascii char, it gets append as is to the given buffer.
 * @param c		Character to escape.
 * @param buf	Where to append the escaped character. It should have space for
 *		at least 4 chars otherwise a buffer overflow may occure.
 * @return The number of characters append to \e buf.
 */
int
cescape_char(char c, char *buf) {
	char *buf_old = buf;

	switch (c) {
		case '\a':
			*(buf++) = '\\';
			*(buf++) = 'a';
			break;
		case '\b':
			*(buf++) = '\\';
			*(buf++) = 'b';
			break;
		case '\f':
			*(buf++) = '\\';
			*(buf++) = 'f';
			break;
		case '\n':
			*(buf++) = '\\';
			*(buf++) = 'n';
			break;
		case '\r':
			*(buf++) = '\\';
			*(buf++) = 'r';
			break;
		case '\t':
			*(buf++) = '\\';
			*(buf++) = 't';
			break;
		case '\v':
			*(buf++) = '\\';
			*(buf++) = 'v';
			break;
		case '\\':
			*(buf++) = '\\';
			*(buf++) = '\\';
			break;
		case '"':
			*(buf++) = '\\';
			*(buf++) = '"';
			break;
		case '\'':
			*(buf++) = '\\';
			*(buf++) = '\'';
			break;

		default:
			/* For special chars we prefer octal over hexadecimal encoding,
			   simply because glib's g_strescape() does the same */
			if ((c < ' ') || (c >= 127)) {
				*(buf++) = '\\';
				*(buf++) = '0' + ((c >> 6) & 7);
				*(buf++) = '0' + ((c >> 3) & 7);
				*(buf++) = '0' + ((c) & 7);
			} else
				*(buf++) = c;
			break;
	}

	return buf - buf_old;
}

/**
 * Escape and ellipsize the given string \e s into the buffer \e buf having a
 * size of at least \e len bytes. Only non-control ASCII characters are copied
 * as they are, everything else is C-Style escaped. The result is different
 * then if escaping and ellipsization was performed in two separate steps,
 * because each sequence is either stored in full or skipped.
 *
 * This function should be used for logging about strings which expected to
 * be plain ASCII in a safe way.
 *
 * An ellipsis will be used if the given string is too long. It gets always
 * placed at the very end.
 * @param buf	buffer where to append the escaped given string.
 * @param len	the size of the buffer, i.e. space left.
 * @param s		string to escape.
 * @return the pointer to buf.
 */
char *
cellescape(char *buf, size_t len, const char *s) {
	size_t i = 0, last_char_width[4] = {}, k = 0;

	for (;;) {
		char four[4];
		int w;

		if (*s == 0) // terminating NUL
			goto done;

		w = cescape_char(*s, four);
		if (i + w + 1 > len) // buf exhausted - ellipsize at the prev. location
			break;

		memcpy(buf + i, four, w);
		i += w;
		last_char_width[k] = w;	// remember the width in the ring buffer
		k = (k + 1) % 4;
		s++;
	}

	/* Ellipsation is necessary. This means we might need to truncate the
	   string again to make space for 4 characters ideally, but the buffer is
	   shorter than that in the first place take what we can get */
	for (size_t j=0; j < sizeof(last_char_width)/sizeof(last_char_width[0]);j++)
	{
		if (i + 4 <= len) // space goal reached
			break;

		k = k == 0 ? 3 : k - 1;
		if (last_char_width[k] == 0) // bummer: reached the start of the strings
			break;

		i -= last_char_width[k];
	}

	if (i + 4 <= len) { // enough space for … or ...
		if (is_locale_utf8()) {
			buf[i++] = 0xe2;
			buf[i++] = 0x80;
			buf[i++] = 0xa6;
		} else {
			buf[i++] = '.';
			buf[i++] = '.';
			buf[i++] = '.';
		}
	}
	else if (i + 3 <= len) { // only space for ".."
		buf[i++] = '.';
		buf[i++] = '.';
	} else if (i + 2 <= len) // only space for a single "."
		buf[i++] = '.';

done:
	buf[i] = '\0';
	return buf;
}

/**
 * Escapes all chars in bad, in addition to \\ and all special chars
 * (i\.e\.\  0x00\..0x1F), in hex style (\\xFF). If XESCAPE_8_BIT flag is
 * specified, characters >= 127 are let through unchanged. This corresponds to
 * non-ASCII printable characters in pre-unicode encodings.
 *
 * If width is reached, or XESCAPE_FORCE_ELLIPSIS is set, output is truncated
 * and "..." is appended.
 * @param s		String to escape.
 * @param bad	Escape characters found in this string, too. Use an empty string
 *		if there are no additional characters to escape, but not NULL!
 * @param width	The max. length of the escaped string.
 * @param flags	XESCAPE_FORCE_ELLIPSIS and XESCAPE_8_BIT are honored.
 * @return NULL on error, the escaped string \e s otherwise. Free when done.
 */
char *
xescape_full(const char *s, const char *bad, size_t width, XEscapeFlags flags) {
	char *ans, *t, *prev, *prev2;
	const char *f;
	size_t len = strlen(s);
	bool force_ellipsis = flags & XESCAPE_FORCE_ELLIPSIS;

	if (width == 0)
		return strdup("");

	if (width < len)
		len = width;
	len *= 4;

	ans = (char *) malloc(sizeof(char) * (len + 1));
	if (!ans)
		return NULL;

	memset(ans, '_', len);
	ans[len] = 0;
	for (f = s, t = prev = prev2 = ans; ; f++) {
		char *tmp_t = t;

		if (!*f) {
			if (force_ellipsis)
				break;

			*t = 0;
			return ans;
		}
		if ((unsigned char) *f < ' ' ||
			(!(flags & XESCAPE_8_BIT) && (unsigned char) *f >= 127) ||
			*f == '\\' || strchr(bad, *f))
		{
			if ((size_t) (t - ans) + 4 + 3 * force_ellipsis > width)
				break;
			*(t++) = '\\';
			*(t++) = 'x';
			*(t++) = hd[(*f >> 4) & 15];
			*(t++) = hd[*f & 15];
		} else {
			if ((size_t) (t - ans) + 1 + 3 * force_ellipsis > width)
				break;
			*(t++) = *f;
		}
		// might need to go back two cycles to fit three dots, so remember
		// two positions
		prev2 = prev;
		prev = tmp_t;
	}

	// We can just write where we want, since chars are one-byte
	size_t c = width < 3 ? width : 3u; // If width is too narrow, write fewer'.'
	size_t off;
	if (width - c >= (size_t) (t - ans))
		off = (size_t) (t - ans);
	else if (width - c >= (size_t) (prev - ans))
		off = (size_t) (prev - ans);
	else if (width - c >= (size_t) (prev2 - ans))
		off = (size_t) (prev2 - ans);
	else
		off = width - c;

	memcpy(ans + off, "...", c);
	ans[off + c] = '\0';
	return ans;
}

/**
 * Get the number of bytes used to encode the given UTF-8 char.
 * @param c UTF-8 character to check.
 * @return number of bytes required to represent the character, or 0 if invalid.
 */
static size_t
utf8_encoded_expected_len(uint8_t c) {
	if (c < 0x80)
		return 1;
	if ((c & 0xe0) == 0xc0)
		return 2;
	if ((c & 0xf0) == 0xe0)
		return 3;
	if ((c & 0xf8) == 0xf0)
		return 4;
	if ((c & 0xfc) == 0xf8)
		return 5;
	if ((c & 0xfe) == 0xfc)
		return 6;

	return 0;
}

/**
 * Get the expected number of bytes used to encode the given unicode char
 * @param unichar	The unicode character in question.
 * @return number of bytes required to represent the given unicode character, or
 *		0 if invalid.
 */
static int
utf8_unichar_to_encoded_len(char32_t unichar) {
	if (unichar < 0x80)
		return 1;
	if (unichar < 0x800)
		return 2;
	if (unichar < 0x10000)
		return 3;
	if (unichar < 0x200000)
		return 4;
	if (unichar < 0x4000000)
		return 5;

	return 6;
}

/**
 * Read the first UTF-8 character from the given string and decode it to its
 * unicode.
 * @param str	Where to read the UTF-8 character from.
 * @param ret_unichar	Where to store the unicode.
 * @return 0 on success, an error code < 0 otherwise.
 */
static int
utf8_encoded_to_unichar(const char *str, char32_t *ret_unichar) {
	char32_t unichar;
	size_t len = utf8_encoded_expected_len(str[0]);
	switch (len) {
		case 1:
			*ret_unichar = (char32_t)str[0];
			return 0;
		case 2:
			unichar = str[0] & 0x1f;
			break;
		case 3:
			unichar = (char32_t)str[0] & 0x0f;
			break;
		case 4:
			unichar = (char32_t)str[0] & 0x07;
			break;
		case 5:
			unichar = (char32_t)str[0] & 0x03;
			break;
		case 6:
			unichar = (char32_t)str[0] & 0x01;
			break;
		default:
			return -EINVAL;
	}
	for (size_t i = 1; i < len; i++) {
		if (((char32_t)str[i] & 0xc0) != 0x80)
			return -EINVAL;

		unichar <<= 6;
		unichar |= (char32_t)str[i] & 0x3f;
	}
	*ret_unichar = unichar;

	return 0;
}

/**
 * Read the first UTF-8 character from the given string and check, whether it
 * can be converted to a valid unicode.
 * @param str	Check the first character of the given string.
 * @param length	Max. expected length in bytes of the character. Use SIZE_MAX
 *		to disable any limit.
 * @return The length in bytes of the UTF-8 character read on success, an error
 *		code < 0 otherwise.
 */
static int
utf8_encoded_valid_unichar(const char *str, size_t length) {
	char32_t unichar;
	size_t len;
	int r;

	len = utf8_encoded_expected_len(str[0]);
	if (len == 0)
		return -EINVAL;

	// Do we have a truncated multi-byte character?
	if (len > length)
		return -EINVAL;

	// ascii is valid
	if (len == 1)
		return 1;

	// check if expected encoded chars are available, read at most length bytes.
	for (size_t i = 0; i < len; i++)
		if ((str[i] & 0x80) != 0x80)
			return -EINVAL;

	r = utf8_encoded_to_unichar(str, &unichar);
	if (r < 0)
		return r;

	// check if encoded length matches encoded value
	if (utf8_unichar_to_encoded_len(unichar) != (int) len)
		return -EINVAL;

	// check if value has valid range
	if (!unichar_is_valid(unichar))
		return -EINVAL;

	return (int) len;
}

/**
 * Check whether UTF-8 characters represented by \e len bytes in the given
 * string are printable.
 * @param str	String to read.
 * @param len	Number of bytes to read from the string.
 * @param allow_newline	If true a linefeed character (\\n) is handled as a
 *		printable character, otherwise not.
 * @return true if printable, false otherwise.
 */
static bool
utf8_is_printable(const char* str, size_t len, bool allow_newline) {
	for (const char *p = str; len > 0;) {
		int encoded_len, r;
		char32_t c;

		encoded_len = utf8_encoded_valid_unichar(p, len);
		if (encoded_len < 0)
			return false;

		r = utf8_encoded_to_unichar(p, &c);
		if (r < 0 || (c < ' ' && c != '\t' && c != '\n') ||
			(0x7F <= c && c <= 0x9F) || (!allow_newline && c == '\n'))
		{
			return false;
		}

		len -= encoded_len;
		p += encoded_len;
	}

	return true;
}

#define unichar uint32_t

struct Interval {
	unichar start, end;
};

static int
interval_compare (const void *key, const void *elt) {
	unichar c = (unichar) (long) (key);
	struct Interval *interval = (struct Interval *)elt;

	if (c < interval->start)
		return -1;
	if (c > interval->end)
		return +1;

	return 0;
}

/**
 * Determines if a character is typically rendered in a double-width cell.
 * @param c Unicode character to check.
 *
 * @return value: true if the character is wide, false otherwise.
 * @note The table for unichar_iswide() is generated from the Unicode Character
 *	Database's file extracted/DerivedEastAsianWidth.txt using the
 *	gen-iswide-table.py in this way (last update for Unicode 6.0):
 *	./gen-iswide-table.py < path/to/ucd/extracted/DerivedEastAsianWidth.txt |fmt
 **/
static bool
unichar_iswide (unichar c) {
	/* See NOTE earlier for how to update this table. */
	static const struct Interval wide[] = {
		{0x1100, 0x115F}, {0x2329, 0x232A}, {0x2E80, 0x2E99}, {0x2E9B, 0x2EF3},
		{0x2F00, 0x2FD5}, {0x2FF0, 0x2FFB}, {0x3000, 0x303E}, {0x3041, 0x3096},
		{0x3099, 0x30FF}, {0x3105, 0x312D}, {0x3131, 0x318E}, {0x3190, 0x31BA},
		{0x31C0, 0x31E3}, {0x31F0, 0x321E}, {0x3220, 0x3247}, {0x3250, 0x32FE},
		{0x3300, 0x4DBF}, {0x4E00, 0xA48C}, {0xA490, 0xA4C6}, {0xA960, 0xA97C},
		{0xAC00, 0xD7A3}, {0xF900, 0xFAFF}, {0xFE10, 0xFE19}, {0xFE30, 0xFE52},
		{0xFE54, 0xFE66}, {0xFE68, 0xFE6B}, {0xFF01, 0xFF60}, {0xFFE0, 0xFFE6},
		{0x1B000, 0x1B001}, {0x1F200, 0x1F202}, {0x1F210, 0x1F23A},
		{0x1F240, 0x1F248}, {0x1F250, 0x1F251},
		{0x1F300, 0x1F567}, /* Miscellaneous Symbols and Pictographs */
		{0x20000, 0x2FFFD}, {0x30000, 0x3FFFD},
	};

	return (bsearch ((void *)(uintptr_t)c, wide,
		(sizeof(wide)/sizeof((wide)[0])), sizeof wide[0], interval_compare));
}

#define UTF8_REPLACEMENT_CHARACTER "\xef\xbf\xbd"

/**
 * Escape all non-printable characters of the given UTF-8 string as hex code
 * sequences.
 *
 * @param t		String to escape.
 * @param max	The max. length in characters of the escaped string. Truncate
 *		and add an ellipsis if it would get longer.
 * @param force_ellipsis	If true, always add an ellipsis to the end of the
 *		escaped string, no matter whether it has been truncated or not.
 * @return NULL on error, the escaped string \e t otherwise. Free when done.
 */
char *
utf8_escape_non_printable_full(const char *t, size_t max, bool force_ellipsis) {
	char *p, *s, *prev_s;
	size_t n = 0; // estimated print width

	if (max == 0)
		return strdup("");

	p = s = prev_s = malloc(strlen(t) * 4 + 1);
	if (!p)
		return NULL;

	for (;;) {
		int len;
		char *saved_s = s;

		if (!*t) { // done!
			if (force_ellipsis)
				goto truncation;
			else
				goto finish;
		}

		len = utf8_encoded_valid_unichar(t, SIZE_MAX);
		if (len > 0) {
			if (utf8_is_printable(t, len, true)) {
				int w;
				char32_t c;
				// columns it takes
				w = utf8_encoded_to_unichar(t, &c);	// TBD: detect combining chars
				if (w < 0)
					return NULL;
				w = unichar_iswide(c) ? 2 : 1;

				if (n + w > max)
					goto truncation;

				s = mempcpy(s, t, len);
				t += len;
				n += w;
			} else {
				for (; len > 0; len--) {
					if (n + 4 > max)
						goto truncation;

					*(s++) = '\\';
					*(s++) = 'x';
					*(s++) = hd[((int) *t >> 4) & 15];
					*(s++) = hd[((int) *t) & 15];
					t += 1;
					n += 4;
				}
			}
		} else {
			if (n + 1 > max)
				goto truncation;

			s = mempcpy(s, UTF8_REPLACEMENT_CHARACTER, strlen(UTF8_REPLACEMENT_CHARACTER));
			t += 1;
			n += 1;
		}
		prev_s = saved_s;
	}

truncation:
	// Try to go back one if we don't have enough space for the ellipsis
	if (n + 1 > max)
		s = prev_s;
	s = mempcpy(s, "…", strlen("…"));

finish:
	*s = '\0';
	return realloc(p, strlen(p) + 1) ?: p;
}
