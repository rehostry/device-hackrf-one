# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The Winbond **W25Q80BV** serial flash on SSP0, chip-selected by GPIO5[11].

THIS PART CANNOT BE LEFT ABSENT. Playbook trap 2.90 says an unwired bus should
read 0x00 so an absent device fails fast -- but that is advice about parts that
are genuinely not there. This one *is* on the board, and the firmware refuses to
continue without it::

    void w25q80bv_setup(w25q80bv_driver_t* const drv) {
        ...
        do {
            device_id = w25q80bv_get_device_id(drv);
        } while (device_id != W25Q80BV_DEVICE_ID_RES     /* 0x13 */
              && device_id != W25Q16DV_DEVICE_ID_RES
              && device_id != W25Q32JV_DEVICE_ID_RES);
    }

-- an unbounded retry with no timeout and no error path. Measured with the bus
reading zeros: the boot reached `usb_set_descriptor_by_serial_number()` (the
IAP-not-implemented fallback reads this flash for a serial number) and then span
in `spi_ssp_transfer_byte` for ever, with SPI traffic that looked perfectly
healthy the whole time. There is no wall to see, only a device asking a question
nobody answers.

THE CHIP SELECT IS THE FRAME DELIMITER (playbook trap 2.88). `spi_bus_transfer`
asserts GPIO5[11] low, shifts N bytes, and releases it; without tracking that
edge the model cannot tell a command byte from payload. The GPIO model calls
:meth:`select` on every change of that pin.

READS COME OUT OF THE IMAGE, because that is what is really in this part. A
HackRF One boots the M4 out of exactly this flash through the SPIFI window, so
the device's own firmware image *is* its contents -- and the config maps that
window at 0x14000000. A `READ DATA` therefore returns the same bytes the CPU
fetched to get here, rather than an invention.

THE UNIQUE ID IS SYNTHETIC AND SAYS SO. A real unit's 64-bit unique id is a
property of its die; nothing can recover it from a firmware image (playbook
trap 2.80). Serving zeros would read like a failed access, so this serves the
ASCII ``REHOSTRY`` -- a value that could not arise by accident and that shows up
verbatim in the USB serial-number string descriptor the firmware then builds.
"""
from __future__ import annotations

from typing import List, Optional

from halucinator import hal_log

from . import hal_link

log = hal_log.getHalLogger()

# Commands (firmware/common/w25q80bv.c).
CMD_READ_DATA = 0x03
CMD_FAST_READ = 0x0B
CMD_READ_STATUS1 = 0x05
CMD_READ_STATUS2 = 0x35
CMD_WRITE_ENABLE = 0x06
CMD_DEVICE_ID = 0xAB
CMD_UNIQUE_ID = 0x4B
CMD_JEDEC_ID = 0x9F

#: What `w25q80bv_setup()` is waiting to hear. W25Q80BV_DEVICE_ID_RES.
DEVICE_ID = 0x13
#: Winbond manufacturer 0xEF, memory type 0x40, capacity 0x14 (8 Mbit).
JEDEC_ID = (0xEF, 0x40, 0x14)

#: Where the config maps this flash into the guest's address space (the LPC43xx
#: SPIFI window). Reads are served from there, so they return the real image.
SPIFI_WINDOW = 0x14000000
FLASH_SIZE = 1 << 20

#: Obviously-synthetic 64-bit unique id. See the module docstring.
UNIQUE_ID = b"REHOSTRY"


class W25q80bv:
    """A SPI NOR flash: command byte, then a command-specific byte stream."""

    def __init__(self) -> None:
        self.selected = False
        self.cmd: Optional[int] = None
        self.n = 0                    # byte index within the current command
        self.addr = 0
        self.commands: List[int] = []
        self.bytes_out = 0

    def select(self, asserted: bool) -> None:
        if asserted == self.selected:
            return
        self.selected = asserted
        if asserted:
            self.cmd = None
            self.n = 0
            self.addr = 0

    def xfer(self, out: int) -> int:
        """One SPI byte in, one byte out (they overlap, as on the wire)."""
        if not self.selected:
            return 0
        if self.cmd is None:
            self.cmd = out & 0xFF
            self.n = 0
            self.commands.append(self.cmd)
            if len(self.commands) in (1, 2, 3):
                log.info("W25q80bv: command 0x%02x", self.cmd)
            return 0
        self.n += 1
        i = self.n
        self.bytes_out += 1
        cmd = self.cmd

        if cmd == CMD_DEVICE_ID:
            # 0xAB + 3 dummy bytes, then the device id.
            return DEVICE_ID if i >= 4 else 0
        if cmd in (CMD_READ_STATUS1, CMD_READ_STATUS2):
            return 0x00                        # never busy, not write-enabled
        if cmd == CMD_JEDEC_ID:
            return JEDEC_ID[i - 1] if 1 <= i <= 3 else 0
        if cmd == CMD_UNIQUE_ID:
            # 0x4B + 4 dummy bytes, then 8 id bytes.
            if 1 <= i <= 4:
                return 0
            k = i - 5
            return UNIQUE_ID[k] if 0 <= k < len(UNIQUE_ID) else 0
        if cmd in (CMD_READ_DATA, CMD_FAST_READ):
            dummy = 1 if cmd == CMD_FAST_READ else 0
            if i <= 3:                          # 24-bit address, MSB first
                self.addr = ((self.addr << 8) | (out & 0xFF)) & 0xFFFFFF
                return 0
            if i <= 3 + dummy:
                return 0
            off = self.addr + (i - 4 - dummy)
            if off >= FLASH_SIZE:
                return 0xFF
            raw = hal_link.read_mem(SPIFI_WINDOW + off, 1)
            return raw[0] if raw else 0xFF
        return 0

    def summary(self) -> dict:
        return {
            "selected": self.selected,
            "commands": len(self.commands),
            "bytes": self.bytes_out,
            "last_commands": ["0x%02x" % c for c in self.commands[-8:]],
        }


_FLASH: Optional[W25q80bv] = None


def get_flash() -> W25q80bv:
    global _FLASH
    if _FLASH is None:
        _FLASH = W25q80bv()
    return _FLASH
