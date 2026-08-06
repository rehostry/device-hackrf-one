# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""rehostry-hackrf-one -- a Great Scott Gadgets **HackRF One** (1 MHz-6 GHz
half-duplex SDR, NXP LPC4320 / Cortex-M4) rehosted from its stock firmware.

The device is self-contained: its HALucinator config and derived address map
ship as package data and are referenced by the installed module path. The
firmware itself is GPL-2.0 and belongs to Great Scott Gadgets, so it is staged
from the vendor release by ``tools/extract_firmware.py`` rather than shipped.

HALucinator runs in a CHILD process (see :mod:`.spawn`), so this package never
imports the core and needs no ``sys.path`` guard -- ``spawn_env()`` strips
``HALUCINATOR_SRC``/``PYTHONPATH`` from the child's environment instead.
"""
from . import paths, spawn

__version__ = "1.0.0"

__all__ = ["paths", "spawn", "__version__"]
