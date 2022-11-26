/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "glyph-util.h"
#include "locale-util.h"
#include <string.h>

/**
 * Check, whether emoji UTF-8 characters should be printed (instead of ASCII).
 * @param envvar	Check the named environment variable's value (if NULL,
 *		SYSTEMD_EMOJI will be used) for a boolean value. If set its deduced
 *		value gets returned. Otherwise true gets returned unless the env var
 *		TERM is set to "dumb" or "linux".
 * @param cache		If true, the current internally cached value gets replaced
 *		by the re-evaluated result. Otherwise, the internally cached value gets
 *		returned if already determined in a previous call.
 * @return true if emojis should be used, false otherwise.
 */
bool
emoji_enabled(const char *envvar, bool cache) {
	static int enabled = -1;

	if (!cache && enabled >= 0)
		return enabled;

	const char *p = envvar ? : "SYSTEMD_EMOJI";
	char *val = getenv(p);
	bool ok = val && *val != '\0' &&
		(((val[1] == '\0') && (*val == '1' || *val == 't' || *val == 'y')) ||
			strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 ||
			strcmp(val, "on") == 0);
	if (!val) {
		val = getenv("TERM");
		ok = is_locale_utf8() &&
			(!val || (strcmp(val, "dumb") && strcmp(val, "linux")));
	}
	if (cache || enabled < 0)
		enabled = ok;
	return ok;
}

/**
 * A list of a number of interesting unicode glyphs we can use to decorate our
 * output. It's probably wise to be conservative here, and primarily stick to
 * the glyphs defined in the eurlatgr font, so that display still works
 * reasonably well on the Linux console. For details see:
 *
 * http://git.altlinux.org/people/legion/packages/kbd.git?p=kbd.git;a=blob;f=data/consolefonts/README.eurlatgr
 */
const char *
special_glyph(SpecialGlyph code) {
	static const char* const draw_table[2][_GLYPH_MAX] = {
		// ASCII fallback
		[false] = {
[GLYPH_TREE_VERTICAL]           = "| ",
[GLYPH_TREE_BRANCH]             = "|-",
[GLYPH_TREE_RIGHT]              = "`-",
[GLYPH_TREE_SPACE]              = "  ",
[GLYPH_TREE_TOP]                = ",-",
[GLYPH_VERTICAL_DOTTED]         = ":",
[GLYPH_TRIANGULAR_BULLET]       = ">",
[GLYPH_BLACK_CIRCLE]            = "*",
[GLYPH_WHITE_CIRCLE]            = "*",
[GLYPH_MULTIPLICATION_SIGN]     = "x",
[GLYPH_CIRCLE_ARROW]            = "*",
[GLYPH_BULLET]                  = "*",
[GLYPH_MU]                      = "u",
[GLYPH_CHECK_MARK]              = "+",
[GLYPH_CROSS_MARK]              = "-",
[GLYPH_LIGHT_SHADE]             = "-",
[GLYPH_DARK_SHADE]              = "X",
[GLYPH_SIGMA]                   = "S",
[GLYPH_ARROW_LEFT]              = "<-",
[GLYPH_ARROW_RIGHT]             = "->",
[GLYPH_ARROW_UP]                = "^",
[GLYPH_ARROW_DOWN]              = "v",
[GLYPH_ELLIPSIS]                = "...",
[GLYPH_EXTERNAL_LINK]           = "[LNK]",
[GLYPH_ECSTATIC_SMILEY]         = ":-]",
[GLYPH_HAPPY_SMILEY]            = ":-}",
[GLYPH_SLIGHTLY_HAPPY_SMILEY]   = ":-)",
[GLYPH_NEUTRAL_SMILEY]          = ":-|",
[GLYPH_SLIGHTLY_UNHAPPY_SMILEY] = ":-(",
[GLYPH_UNHAPPY_SMILEY]          = ":-{",
[GLYPH_DEPRESSED_SMILEY]        = ":-[",
[GLYPH_LOCK_AND_KEY]            = "o-,",
[GLYPH_TOUCH]                   = "O=",		// TBD: better choice
[GLYPH_RECYCLING]               = "~",
[GLYPH_DOWNLOAD]                = "\\",
[GLYPH_SPARKLES]                = "*",
		},

		// UTF-8
		[true] = {
// Multiple glyphs in both ASCII and in UNICODE
[GLYPH_TREE_VERTICAL]           = u8"│ ",
[GLYPH_TREE_BRANCH]             = u8"├─",
[GLYPH_TREE_RIGHT]              = u8"└─",
[GLYPH_TREE_SPACE]              = u8"  ",
[GLYPH_TREE_TOP]                = u8"┌─",

// Single glyphs in both cases
[GLYPH_VERTICAL_DOTTED]         = u8"┆",
[GLYPH_TRIANGULAR_BULLET]       = u8"‣",
[GLYPH_BLACK_CIRCLE]            = u8"●",
[GLYPH_WHITE_CIRCLE]            = u8"○",
[GLYPH_MULTIPLICATION_SIGN]     = u8"×",
[GLYPH_CIRCLE_ARROW]            = u8"↻",
[GLYPH_BULLET]                  = u8"•",
[GLYPH_MU]                      = u8"μ",	// GREEK SMALL LETTER MU
[GLYPH_CHECK_MARK]              = u8"✓",
[GLYPH_CROSS_MARK]              = u8"✗",	// BALLOT X
[GLYPH_LIGHT_SHADE]             = u8"░",
[GLYPH_DARK_SHADE]              = u8"▒",
[GLYPH_SIGMA]                   = u8"Σ",
[GLYPH_ARROW_UP]                = u8"↑",	// UPWARDS ARROW
[GLYPH_ARROW_DOWN]              = u8"↓",	// DOWNWARDS ARROW

// Single glyph in Unicode, two in ASCII
[GLYPH_ARROW_LEFT]              = u8"←",	// LEFTWARDS ARROW
[GLYPH_ARROW_RIGHT]             = u8"→",	// RIGHTWARDS ARROW

// Single glyph in Unicode, three in ASCII
[GLYPH_ELLIPSIS]                = u8"…",	// HORIZONTAL ELLIPSIS

// Three glyphs in Unicode, five in ASCII
[GLYPH_EXTERNAL_LINK]           = u8"[🡕]",	// NORTH EAST SANS-SERIF ARROW

// Single glyph in Unicode, three in ASCII
[GLYPH_ECSTATIC_SMILEY]         = u8"😇",	// SMILING FACE WITH HALO
[GLYPH_HAPPY_SMILEY]            = u8"😀",	// GRINNING FACE
[GLYPH_SLIGHTLY_HAPPY_SMILEY]   = u8"😎",	// SLIGHTLY SMILING FACE¹
[GLYPH_NEUTRAL_SMILEY]          = u8"😐",	// NEUTRAL FACE
[GLYPH_SLIGHTLY_UNHAPPY_SMILEY] = u8"😞",	// SLIGHTLY FROWNING FACE¹
[GLYPH_UNHAPPY_SMILEY]          = u8"😨",	// FEARFUL FACE
[GLYPH_DEPRESSED_SMILEY]        = u8"😰",	// NAUSEATED FACE¹

// Single character cell glyph in Unicode, three in ASCII
[GLYPH_LOCK_AND_KEY]            = u8"🔒",	// CLOSED LOCK WITH KEY¹

// Single character cell glyph in Unicode, and two in ASCII
[GLYPH_TOUCH]                   = u8"👆",	// BACKHAND INDEX POINTING UP

// Single character cell glyphs in Unicode and ASCII.
[GLYPH_RECYCLING]               = u8"♻️",	// UNIVERSAL RECYCLNG SYMBOL
[GLYPH_DOWNLOAD]                = u8"⤵️",	// RIGHT ARROW CURVING DOWN
[GLYPH_SPARKLES]                = u8"❇",	// SPARKLES¹

// ¹ .. slightly different char, because some good fonts (e.g. Liberation)
//      do not have it.
		},
	};

	if (code < 0 || code > _GLYPH_MAX)
		return NULL;

	return draw_table[code >= _GLYPH_FIRST_EMOJI
		? emoji_enabled(NULL, false)
		: is_locale_utf8()][code];
}
