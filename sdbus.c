/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>

#include "log.h"
#include "characters.h"
#include "unit.h"
#include "sdbus.h"

/**
 * Connect to the system or user DBus.
 * @param ret_bus	Where to store the pointer to the new bus object on success.
 *		When done release it using sd_bus_flush_close_unrefp().
 * @param user	If true, connect to the user's DBus, to the system DBus
 *		otherwise.
 * @return 0 on success, an error code < 0 otherwise.
 */
int
bus_connect(sd_bus **ret_bus, bool user) {
	sd_bus *bus = NULL;
	char *ee = NULL;
	const char *e;
	struct ucred ucred;
	socklen_t optlen = sizeof(struct ucred);
	int r;

	if (user) {
		e = secure_getenv("XDG_RUNTIME_DIR");
		if (!e)
			return sd_bus_default_user(ret_bus);

#define _PREFIX "unix:path="
#define _SUFFIX "/systemd/private"
		// bus_address_escape
		ee = (char *) malloc(sizeof(char) * (strlen(e) * 3 + 1 +
			strlen(_PREFIX) + strlen(_SUFFIX)));
		if (!ee)
			return -ENOMEM;

		strcpy(ee, _PREFIX);
		char *b = ee + strlen(_PREFIX);

		for (const char *a = e; *a; a++) {
			char c = *a;
			if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z') || strchr("_-/.", c))
			{
				*(b++) = c;
			} else {
				*(b++) = '%';
				*(b++) = hd[(c >> 4) & 15];
				*(b++) = hd[c & 15];
			}
		}
		strcpy(b, _SUFFIX);
#undef _SUFFIX
#undef _PREFIX
	} else {
		if (sd_booted() <= 0) {
			LOG("System has not been booted with systemd as init (PID 1). "
				"Can't operate.", NULL);
			return -EHOSTDOWN;
		}
		if (geteuid() != 0)
			return sd_bus_default_system(ret_bus);
		// as root talk directly to the instance
	}

	r = sd_bus_new(&bus);
	if (r < 0) {
		free(ee);
		return r;
	}

	r = sd_bus_set_address(bus, user ? ee : "unix:path=/run/systemd/private");
	free(ee);
	if (r < 0) {
		sd_bus_unrefp(&bus);
		return r;
	}

	r = sd_bus_start(bus);
	if (r < 0) {
		sd_bus_unrefp(&bus);
		return user
			? sd_bus_default_user(ret_bus)
			: sd_bus_default_system(ret_bus);
	}

	//r = bus_check_peercred(bus);
	r = sd_bus_get_fd(bus);
	if (r < 0) {
		sd_bus_close_unrefp(&bus);
		return r;
	}
	r = getsockopt(r, SOL_SOCKET, SO_PEERCRED, &ucred, &optlen);
	if (r < 0) {
		sd_bus_close_unrefp(&bus);
		return -errno;
	}
	if (optlen != sizeof(struct ucred)) {
		sd_bus_close_unrefp(&bus);
		return -EIO;
	}
	if (ucred.pid == 0) {
		sd_bus_close_unrefp(&bus);
		return -ENODATA;
	}
	if (ucred.uid != 0 && ucred.uid != geteuid()) {
		sd_bus_close_unrefp(&bus);
		return -EPERM;
	}

	*ret_bus = bus;
	return 0;
}

/**
 * Convert the unit type deduced from e\.g\.\ a unit name to its DBus interface
 * name.
 * @param t	Unit type to convert.
 * @returns NULL if unknown or invalid, the DBus interface name otherwise. Do
 *		not modify or free(3) it!
 */
const char *
unit_dbus_interface_from_type(UnitType t) {

	static const char *const table[_UNIT_TYPE_MAX] = {
		[UNIT_SERVICE]   = "org.freedesktop.systemd1.Service",
		[UNIT_SOCKET]    = "org.freedesktop.systemd1.Socket",
		[UNIT_TARGET]    = "org.freedesktop.systemd1.Target",
		[UNIT_DEVICE]    = "org.freedesktop.systemd1.Device",
		[UNIT_MOUNT]     = "org.freedesktop.systemd1.Mount",
		[UNIT_AUTOMOUNT] = "org.freedesktop.systemd1.Automount",
		[UNIT_SWAP]      = "org.freedesktop.systemd1.Swap",
		[UNIT_TIMER]     = "org.freedesktop.systemd1.Timer",
		[UNIT_PATH]      = "org.freedesktop.systemd1.Path",
		[UNIT_SLICE]     = "org.freedesktop.systemd1.Slice",
		[UNIT_SCOPE]     = "org.freedesktop.systemd1.Scope",
	};

	if (t < 0)
		return NULL;
	if (t >= _UNIT_TYPE_MAX)
		return NULL;

	return table[t];
}
