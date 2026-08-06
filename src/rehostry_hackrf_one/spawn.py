# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The single source of truth for *how to run this device* under HALucinator.

The CLI, the panel and the attack all build their invocation from here, so
there is exactly one spawn recipe: HALucinator on the **unicorn** backend with
this device's configs. HALucinator is a *runtime* dependency reached as a
separate process -- the installed ``halucinator@dev`` in the running
interpreter's environment (``sys.executable``, overridable with ``HAL_PY``). No
source tree is ever spliced onto ``PYTHONPATH``: a polluted ``HALUCINATOR_SRC``
must not resurrect an out-of-tree core, so both are stripped from the child env.

THE ENVIRONMENT IS PART OF THE DEVICE. Four of the variables below are load
bearing, and each corresponds to a playbook trap:

``HAL_CORTEXM_CPU_MODEL=UC_CPU_ARM_CORTEX_M4``
    The yaml ``cpu_model:`` key does **not** select the CPU (trap 2.120); the
    backend reads this. This firmware is built ``-mcpu=cortex-m4
    -mfpu=fpv4-sp-d16``, and unicorn's default M-profile model is an M3 with no
    VFP, which dies on the first FPU instruction at a fixed PC that reads like
    a decode failure.

``HAL_IRQ_CHUNK`` + ``HAL_DET_TICK=8:<n>``
    ``HAL_DET_TICK`` is **inert on cortex-m unless ``HAL_IRQ_CHUNK`` is also
    set** (trap 2.50): the pacer only runs at the end of a *bounded* emu chunk
    and ``irq_chunk`` defaults to 0 for this arch. IRQ 8 is USB0 -- the only
    live interrupt vector in the whole image -- so this tick is what makes the
    firmware's own ``usb0_isr()`` run. Nothing else in this device is periodic.

``HAL_FAST_BP=1``
    A single breakpoint otherwise installs a *global* per-instruction Python
    hook (trap 2.51). This device bit-bangs ~55 000 JTAG clocks through GPIO
    before it reaches USB; the global hook turns that from seconds into
    minutes.
"""
from __future__ import annotations

import os
import sys
from typing import Optional

from . import paths

#: The host-facing seam: a line-oriented TCP bridge onto the USB **control
#: endpoint**. A HackRF One has no console and no network -- vendor control
#: transfers are its entire command surface.
BRIDGE_PORT = 21209
USB_SEAM = "USB0 EP0 control endpoint (hackrf_* vendor requests)"

#: ZMQ peripheral-bus ports. peripheral_server.start() BINDS machine-global ipc
#: endpoints keyed on these, so two devices left on the default (5555/5556)
#: silently share one bus.
DEFAULT_RX_PORT = int(os.environ.get("HAL_HRF_RX_PORT", "6118"))
DEFAULT_TX_PORT = int(os.environ.get("HAL_HRF_TX_PORT", "6119"))

#: Emu instructions per bounded chunk, and chunks per USB0 tick.
#:
#: The period is 20, not 1, and that matters: an exception RETURN also ends a
#: chunk, so with a period of 1 each delivered USB interrupt immediately queues
#: the next one. Measured that way: 605 000 entries to `usb0_isr` in 60 s with
#: the boot making no forward progress at all (playbook trap 2.50, second
#: half). 20 gives the guest ~4 M instructions between ticks when idle, which
#: is enough for the CPLD's 55 000 bit-banged JTAG clocks to finish in about a
#: minute, while still leaving a control transfer only a few ticks long.
DEFAULT_IRQ_CHUNK = "200000"
DEFAULT_DET_TICK = "8:20"


def spawn_argv(python: Optional[str] = None, emulator: str = "unicorn",
               bridge: bool = False,
               rx_port: Optional[int] = None,
               tx_port: Optional[int] = None) -> list:
    """argv for ``python -m halucinator.main`` with this device's configs."""
    argv = [python or os.environ.get("HAL_PY") or sys.executable,
            "-m", "halucinator.main"]
    for f in (paths.CONFIG_FILES + ([paths.BRIDGE_CONFIG] if bridge else [])):
        argv += ["-c", f]
    argv += ["--emulator", emulator]
    argv += ["--rx_port", str(DEFAULT_RX_PORT if rx_port is None else rx_port)]
    argv += ["--tx_port", str(DEFAULT_TX_PORT if tx_port is None else tx_port)]
    return argv


def spawn_cwd() -> str:
    """Run from the packaged configs dir so config basenames and the relative
    ``file: hackrf_one.bin`` resolve."""
    return str(paths.configs_dir())


def spawn_env(halucinator_src: Optional[str] = None,
              extra: Optional[dict] = None) -> dict:
    """Environment for the spawned HALucinator process."""
    env = dict(os.environ)
    env.pop("HALUCINATOR_SRC", None)
    env.pop("PYTHONPATH", None)
    env["PYTHONUNBUFFERED"] = "1"
    # An M4 with an FPU, not unicorn's default M3 (playbook trap 2.120/2.38).
    env.setdefault("HAL_CORTEXM_CPU_MODEL", "UC_CPU_ARM_CORTEX_M4")
    # The USB0 interrupt. Inert without HAL_IRQ_CHUNK on cortex-m (trap 2.50).
    env.setdefault("HAL_IRQ_CHUNK", DEFAULT_IRQ_CHUNK)
    env.setdefault("HAL_DET_TICK", DEFAULT_DET_TICK)
    # Per-address breakpoints, not a global per-instruction hook (trap 2.51).
    env.setdefault("HAL_FAST_BP", "1")
    # The USB control bridge: the only way to reach the vendor-request parser
    # from outside the emulator.
    env.setdefault("HAL_HRF_USB_PORT", str(BRIDGE_PORT))
    if extra:
        env.update(extra)
    return env
