# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Breakpoint handlers.

There is exactly one, and it is deliberately minimal: ``boot_init.BootInit``
fires at the reset vector to publish the live backend (the USB controller is a
bus master and has to reach guest memory), set the vector base, and open the
host bridge from a place that runs once.

Nothing in this device intercepts firmware *logic*. The USB seam is modelled at
the register and descriptor level so the firmware's own stack does the work --
and note that adding a breakpoint on ``usb0_isr`` is actively harmful here,
because a breakpoint hit ends the bounded emu chunk that paces the USB tick
(see the note in ``configs/hackrf_one_config.yaml``).
"""
