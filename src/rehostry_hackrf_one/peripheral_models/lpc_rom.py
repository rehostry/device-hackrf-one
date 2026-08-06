# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The LPC43xx boot ROM window at 0x10400000 -- specifically, the IAP entry.

The 64 kB boot ROM is **not in the firmware image** and cannot be. Left
unmapped, the firmware's first look at it aborts the run; left to a catch-all,
the busy-wait breaker eventually hands back an escalating value that the
firmware dereferences as a function pointer (playbook trap 2.122).

There is no need to invent one. The firmware itself checks::

    #define ROM_IAP_ADDR       (0x10400100)
    #define ROM_IAP_UNDEF_ADDR (0x12345678)

    bool iap_is_implemented(void) {
        return *((uint32_t*) ROM_IAP_ADDR) != ROM_IAP_UNDEF_ADDR;
    }

and NXP's own errata (ES_LPC43X0_A §3.5, quoted verbatim in
``firmware/common/rom_iap.c``) says the IAP API **is not present on flashless
parts**. The LPC4320 on a HackRF One is exactly such a part. So answering
``0x12345678`` is not a stub -- it is the truth about this silicon, and it sends
the firmware down the code path it takes on the real board: read the part id
from OTP and the serial number over SPI from the W25Q80BV.

The OTP part-id word at 0x40045000 is served from the SoC catch-all; the SPI
flash is absent, so ``usb_set_descriptor_by_serial_number()`` builds a
deterministic all-zero serial string. That is documented in STATUS.md, because
a real unit's serial is a property of its die and nothing can recover it from an
image (playbook trap 2.80 on the STM32 UID).
"""
from __future__ import annotations

from typing import Any

from halucinator import hal_log
from halucinator.peripheral_models.auto_model import AutoPeripheral

log = hal_log.getHalLogger()

ROM_BASE = 0x10400000
IAP_ENTRY = 0x10400100
IAP_UNDEFINED = 0x12345678


class LpcBootRom(AutoPeripheral):
    """The boot ROM window. Only the IAP entry word is meaningful."""

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        addr = self.address + offset
        if addr == IAP_ENTRY:
            log.info("LpcBootRom: IAP entry read -> 0x%08x (\"not implemented\", "
                     "which is the truth for a flashless LPC4320)", IAP_UNDEFINED)
            return IAP_UNDEFINED
        return 0

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        return True
