/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "termcolors.h"

static volatile int cached_on_tty = -1;
static volatile int cached_color_mode = _COLOR_INVALID;
static volatile int cached_underline_enabled = -1;

/**
 * We check both stdout and stderr, so that situations where pipes on the shell
 * are used are reliably recognized, regardless if only the output or the errors
 * are piped to some place. Since on_tty() is generally used to default to a
 * safer, non-interactive, non-color mode of operation it's probably good to be
 * defensive here, and check for both. Note that we don't check for
 * STDIN_FILENO, because it should fine to use fancy terminal functionality
 * when outputting stuff, even if the input is piped to us.
 * @return true if stderr and stdout are associated with a tty, false otherwise.
 */
bool
on_tty(void) {
	if (cached_on_tty < 0)
		cached_on_tty = isatty(STDOUT_FILENO) > 0 && isatty(STDERR_FILENO) > 0;

	return cached_on_tty;
}

/**
 * Check whether the calling process is attached to a tty and its TERM env var
 * is set to a value != 'dumb'. If not, it should be considered a dumb terminal.
 * @return true if dumb, false otherwise.
 */
bool
terminal_is_dumb(void) {
	if (!on_tty())
		return true;

	const char *e = getenv("TERM");
	return e ? strcmp(e, "dump") == 0 : false;
}

/**
 * Parse the value of the given env var and deduce the desired color mode.
 * Allowed are '16', '256', 'on', and 'off'.
 * @param envvar	The name of the env var to check. If NULL fallback to
 *		SYSTEMD_COLORS.
 * @return The color mode to use.
 */
ColorMode
parse_colors_env(const char *envvar) {
	const char *e = getenv(envvar ? : "SYSTEMD_COLORS");
	if (!e)
		return _COLOR_INVALID;
	if (strcmp(e, "16") == 0)
		return COLOR_16;
	if (strcmp(e, "256") == 0)
		return COLOR_256;
	if (strcmp(e, "1") == 0 || strcmp(e, "yes") == 0 || strcmp(e, "y") == 0 ||
		strcmp(e, "true") == 0 || strcmp(e, "t") == 0 || strcmp(e, "on") == 0)
	{
		return COLOR_ON;
	}
	if (strcmp(e, "0") == 0 || strcmp(e, "no") == 0 || strcmp(e, "n") == 0 ||
		strcmp(e, "false") == 0 || strcmp(e, "f") == 0 || strcmp(e, "off") == 0)
	{
		return COLOR_OFF;
	}
	return _COLOR_INVALID;
}

/**
 * Get the color mode to be used. For that we check $SYSTEMD_COLORS first
 * (which is the explicit way to change the mode). If that didn't work we
 * turn colors off unless we are on a TTY. And if we are on a TTY we turn it
 * off if $TERM is set to "dumb".
 * There's one special tweak though: if we are PID 1 then we do not check
 * whether we are connected to a TTY, because we don't keep /dev/console open
 * continuously due to fear of SAK, and hence things are a bit weird - colors
 * turned off.
 * @return The color mode to use.
 */
ColorMode
get_color_mode(void) {
	const char *e;
	ColorMode m;

	if (cached_color_mode >= 0)
		return cached_color_mode;

	// check envvar SYSTEMD_COLORS
	m = parse_colors_env("SYSTEMD_COLORS");
	if (m >= 0)
		cached_color_mode = m;
	else if (getenv("NO_COLOR"))	// existence is sufficient
		cached_color_mode = COLOR_OFF;
	else if (getpid() == 1 &&
		(!(e = getenv("TERM")) || strcmp(e, "dumb") == 0))
	{
		/* Note that the Linux console can only display 16 colors. We still
		   enable 256 color mode even for PID1 output though (which typically
		   goes to the Linux console), since the Linux console is able to parse
		   the 256 color sequences and automatically map them to the closest
		   color in the 16 color palette (since kernel 3.16). Doing 256 colors
		   is nice for people who invoke systemd in a container or via a serial
		   link or such, and use a true 256 color terminal to do so. */
		cached_color_mode = COLOR_OFF;
	} else if (terminal_is_dumb()) {
		TRC("TERM is dumb", NULL);
		cached_color_mode = COLOR_OFF;
	} else {
		// fallback to envvar COLORTERM
		e = getenv("COLORTERM");
		cached_color_mode =
			(e && (strcmp(e, "truecolor") == 0 || strcmp(e, "24bit") == 0))
			? COLOR_24BIT
			: COLOR_256;
	}
	return cached_color_mode;
}

/**
 * Check whether underlining make sense: The Linux console doesn't support
 * underlining. So there and on dumb terminals it should be turned off.
 * @return false is underlines should be turned off, true otherwise.
 */
bool
underline_enabled(void) {

	if (cached_underline_enabled >= 0)
		return cached_underline_enabled;

	if (colors_enabled()) {
		const char *e = getenv("TERM");
		cached_underline_enabled = !(e && strcmp(e, "linux") == 0);
	} else {
		cached_underline_enabled = false;
	}
	TRC("underlines = %d", cached_underline_enabled);
	return cached_underline_enabled;
}

