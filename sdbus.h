/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

int bus_connect(sd_bus **, bool);
const char *unit_dbus_interface_from_type(UnitType);
