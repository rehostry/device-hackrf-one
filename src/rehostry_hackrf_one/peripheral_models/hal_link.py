# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A place for peripheral models to find the live backend.

Peripheral models are not handed a backend reference, but the USB0 device
controller genuinely needs one: a Chipidea-style controller is a **bus master**.
Its queue heads and transfer descriptors live in guest RAM, and the data a
control transfer moves is copied by the *controller*, not by the CPU. Modelling
it therefore means reading and writing guest memory from the model.

``read_memory()``/``write_memory()`` are safe to call from an MMIO callback --
and per playbook trap 2.95 that is exactly where the copy belongs: firmware that
busy-waits on its own transfer never reaches any breakpoint seam, so deferring
the copy to a handler would deadlock it. Only *interrupt* delivery is deferred.

The reference is published by ``bp_handlers/boot_init.py``, which fires at the
reset vector -- the first instruction of the image, long before any peripheral
is touched.
"""
from __future__ import annotations

_BACKEND = None


def set_backend(qemu) -> None:
    global _BACKEND
    _BACKEND = qemu


def get_backend():
    """The live backend, or None before the reset-vector handler has run."""
    return _BACKEND


def read_mem(addr: int, length: int) -> bytes:
    """Read ``length`` bytes of guest memory, or b"" if unavailable."""
    be = _BACKEND
    if be is None or length <= 0:
        return b""
    try:
        return bytes(be.read_memory(addr, 1, length, raw=True))
    except Exception:  # noqa: BLE001
        return b""


def write_mem(addr: int, data: bytes) -> bool:
    be = _BACKEND
    if be is None or not data:
        return False
    try:
        be.write_memory(addr, 1, data, num_words=len(data), raw=True)
        return True
    except Exception:  # noqa: BLE001
        return False


def read_u32(addr: int) -> int:
    raw = read_mem(addr, 4)
    return int.from_bytes(raw, "little") if len(raw) == 4 else 0


def write_u32(addr: int, value: int) -> bool:
    return write_mem(addr, int(value & 0xFFFFFFFF).to_bytes(4, "little"))
