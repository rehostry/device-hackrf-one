# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Publish the live backend (and the vector base) at the reset vector.

Two things have to happen before any peripheral runs:

* **The USB0 model needs a backend reference.** It is a bus-master controller;
  its queue heads and transfer descriptors live in guest RAM, so the model has
  to read and write guest memory. Models are not handed a backend, so one is
  stashed here (``peripheral_models/hal_link.py``).

* **The backend needs to know the vector base.** ``inject_irq()`` computes the
  handler slot as ``vtor + (16 + irq) * 4`` and ``_vtor`` defaults to 0
  (playbook trap 2.65). Here the table *is* at 0 -- the LPC43xx boot shadow
  region -- so the default is already right, but setting it explicitly means a
  future relocation is a one-line change rather than a silent misdirection.

* **The host bridge is opened here, not in a model constructor.** Peripheral
  models are constructed more than once while a config resolves (playbook trap
  2.3); the first instance would bind the socket and the second would fail
  silently, leaving the listener attached to a discarded object.

The seam is the reset vector itself, which runs exactly once and before
anything else in the image.
"""
from __future__ import annotations

import os
from typing import Any, Optional, Tuple

from halucinator import hal_log
from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler

from ..peripheral_models import hal_link, lpc43xx_usb0, usb_host

log = hal_log.getHalLogger()

#: The LPC43xx M4 boots out of the shadow region at 0, and this image's vector
#: table is its first 0x400 bytes (tools/extract_firmware.py asserts it).
DEFAULT_VTOR = 0x00000000


class BootInit(BPHandler):
    """Wires the backend, the vector base and the host bridge together."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__()
        self.done = False

    def register_handler(self, qemu, addr, func_name, **kwargs):  # noqa: ANN001
        self.qemu = qemu
        return super().register_handler(qemu, addr, func_name, **kwargs)

    @bp_handler(["hackrf_reset_vector"])
    def init(self, qemu, bp_addr) -> Tuple[bool, Optional[int]]:  # noqa: ANN001
        hal_link.set_backend(qemu)
        if self.done:
            return False, None
        self.done = True

        vtor = int(os.environ.get("HAL_HRF_VTOR", hex(DEFAULT_VTOR)), 0)
        try:
            qemu.set_vtor(vtor)
        except Exception as exc:  # noqa: BLE001
            log.error("BootInit: set_vtor(0x%08x) failed: %s", vtor, exc)

        usb = lpc43xx_usb0.get_usb()
        host = usb_host.get_host()
        # The controller calls this on every USBSTS read -- i.e. at the top of
        # the firmware's own usb0_isr(). See usb_host.UsbHost.step().
        usb.on_poll = host.step
        log.info("BootInit: backend published, vector base 0x%08x, USB host "
                 "attached to the controller's status poll", vtor)
        return False, None


class UsbIsrProbe(BPHandler):
    """Counts entries to the firmware's own ``usb0_isr``.

    Pure evidence: it proves the *firmware's* interrupt handler is running,
    which "the injection did not crash" does not (playbook trap 2.65). It never
    changes control flow -- returning ``(False, None)`` lets the real handler
    execute.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__()
        self.entries = 0

    def register_handler(self, qemu, addr, func_name, **kwargs):  # noqa: ANN001
        self.qemu = qemu
        return super().register_handler(qemu, addr, func_name, **kwargs)

    @bp_handler(["hackrf_usb0_isr"])
    def entered(self, qemu, bp_addr) -> Tuple[bool, Optional[int]]:  # noqa: ANN001
        self.entries += 1
        if self.entries in (1, 10, 100, 1000) or self.entries % 5000 == 0:
            log.info("UsbIsrProbe: the firmware's usb0_isr has been entered "
                     "%d time(s)", self.entries)
        return False, None
