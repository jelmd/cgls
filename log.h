/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

// very simple but sufficient for now
void _log(const char* format, ...);

#define LOG(fmt, ...)	\
	_log("ERROR: " "%s:%d::%s(): " fmt , __FILE__, __LINE__, __func__, __VA_ARGS__);
#ifdef DEBUG
#define DBG(fmt, ...)	\
	_log("DEBUG: " "%s:%d::%s(): " fmt , __FILE__, __LINE__, __func__, __VA_ARGS__);
#define TRC(fmt, ...)	\
	_log("TRACE: " "%s:%d::%s(): " fmt , __FILE__, __LINE__, __func__, __VA_ARGS__);
#else
#define DBG(fmt, ...)
#define TRC(fmt, ...)
#endif
