# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import dbus
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib


def owned_job(bus, unit, operation):
    manager = dbus.Interface(
        bus.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1"),
        "org.freedesktop.systemd1.Manager",
    )
    loop = GLib.MainLoop()
    results = {}
    expected = None
    expired = False

    def removed(_number, path, name, result):
        if str(name) != unit:
            raise RuntimeError("unit signal filter mismatch")
        results[str(path)] = str(result)
        if expected is not None and str(path) == expected:
            loop.quit()

    def timeout():
        nonlocal expired
        expired = True
        loop.quit()
        return GLib.SOURCE_REMOVE

    bus.add_signal_receiver(
        removed,
        signal_name="JobRemoved",
        dbus_interface="org.freedesktop.systemd1.Manager",
        bus_name="org.freedesktop.systemd1",
        path="/org/freedesktop/systemd1",
        arg2=unit,
    )
    manager.Subscribe(timeout=5)
    timer = GLib.timeout_add_seconds(15, timeout)
    try:
        expected = str(operation(manager))
        if expected not in results:
            loop.run()
        if expired or results.get(expected) != "done":
            raise RuntimeError(f"unknown or failed owned job {unit} {expected}: {results}")
        return expected
    finally:
        if not expired:
            GLib.source_remove(timer)
        bus.close()


def user_bus():
    DBusGMainLoop(set_as_default=True)
    return dbus.bus.BusConnection("unix:path=/run/user/1000/bus")
