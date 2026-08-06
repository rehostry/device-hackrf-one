# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Resource paths for the packaged HALucinator configs and the staged firmware.

Everything the device needs to run lives inside the installed package, resolved
through ``importlib.resources`` so the device runs from anywhere -- no cwd
assumptions and no PYTHONPATH hacks.

The firmware is **not** redistributed (GPL-2.0, Great Scott Gadgets). Run
``tools/extract_firmware.py`` to stage the vendor release binary into
``configs/``; it hard-fails unless the digest, size, vector table, load base,
USB0 vector and ``firmware_info`` struct all match.
"""
from __future__ import annotations

import importlib.resources as _ir
from pathlib import Path

PACKAGE = "rehostry_hackrf_one"

#: Config files handed to `halucinator.main -c ...`, in load order.
CONFIG_FILES = [
    "hackrf_one_config.yaml",
    "hackrf_one_addrs.yaml",
]

#: Optional overlay, appended on demand. This device's host seam is the USB
#: control bridge, which the base config already carries, so there is nothing
#: to overlay -- the name is kept so `spawn_argv(bridge=True)` stays valid if
#: one is ever added.
BRIDGE_CONFIG = "hackrf_one_bridge.yaml"

FIRMWARE_BIN = "hackrf_one.bin"


def configs_dir() -> Path:
    """Absolute path to the packaged configs/ dir (also where firmware lands)."""
    return Path(str(_ir.files(PACKAGE))) / "configs"


def config_paths(bridge: bool = False) -> list:
    files = list(CONFIG_FILES)
    if bridge:
        files.append(BRIDGE_CONFIG)
    return [configs_dir() / f for f in files]


def firmware_bin() -> Path:
    return configs_dir() / FIRMWARE_BIN


def firmware_present() -> bool:
    return firmware_bin().is_file()
