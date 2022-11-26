/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdbool.h>

typedef enum SpecialGlyph {
        GLYPH_TREE_VERTICAL,
        GLYPH_TREE_BRANCH,
        GLYPH_TREE_RIGHT,
        GLYPH_TREE_SPACE,
        GLYPH_TREE_TOP,
        GLYPH_VERTICAL_DOTTED,
        GLYPH_TRIANGULAR_BULLET,
        GLYPH_BLACK_CIRCLE,
        GLYPH_WHITE_CIRCLE,
        GLYPH_MULTIPLICATION_SIGN,
        GLYPH_CIRCLE_ARROW,
        GLYPH_BULLET,
        GLYPH_MU,
        GLYPH_CHECK_MARK,
        GLYPH_CROSS_MARK,
        GLYPH_ARROW_LEFT,
        GLYPH_ARROW_RIGHT,
        GLYPH_ARROW_UP,
        GLYPH_ARROW_DOWN,
        GLYPH_ELLIPSIS,
        GLYPH_LIGHT_SHADE,
        GLYPH_DARK_SHADE,
        GLYPH_SIGMA,
        GLYPH_EXTERNAL_LINK,
        _GLYPH_FIRST_EMOJI,
        GLYPH_ECSTATIC_SMILEY = _GLYPH_FIRST_EMOJI,
        GLYPH_HAPPY_SMILEY,
        GLYPH_SLIGHTLY_HAPPY_SMILEY,
        GLYPH_NEUTRAL_SMILEY,
        GLYPH_SLIGHTLY_UNHAPPY_SMILEY,
        GLYPH_UNHAPPY_SMILEY,
        GLYPH_DEPRESSED_SMILEY,
        GLYPH_LOCK_AND_KEY,
        GLYPH_TOUCH,
        GLYPH_RECYCLING,
        GLYPH_DOWNLOAD,
        GLYPH_SPARKLES,
        _GLYPH_MAX,
        _GLYPH_INVALID = -EINVAL,
} SpecialGlyph;

const char *special_glyph(SpecialGlyph code) __attribute__((__const__));
bool emoji_enabled(const char *envvar, bool cache);
